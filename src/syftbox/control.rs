use crate::syftbox::config::SyftboxRuntimeConfig;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
#[cfg(not(unix))]
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyftBoxMode {
    Sbenv,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyftBoxState {
    pub running: bool,
    pub mode: SyftBoxMode,
}

pub fn detect_mode(config: &SyftboxRuntimeConfig) -> Result<SyftBoxMode> {
    let data_dir = &config.data_dir;
    Ok(if data_dir.join(".sbenv").exists() {
        SyftBoxMode::Sbenv
    } else {
        SyftBoxMode::Direct
    })
}

pub fn state(config: &SyftboxRuntimeConfig) -> Result<SyftBoxState> {
    let mode = detect_mode(config)?;
    let running = is_running_with_mode(config, mode)?;
    Ok(SyftBoxState { running, mode })
}

pub fn is_syftbox_running(config: &SyftboxRuntimeConfig) -> Result<bool> {
    let mode = detect_mode(config)?;
    is_running_with_mode(config, mode)
}

pub fn start_syftbox(config: &SyftboxRuntimeConfig) -> Result<bool> {
    // Force Direct mode for desktop until daemon supports -c properly
    if is_running_with_mode(config, SyftBoxMode::Direct)? {
        return Ok(false);
    }

    start_direct(config)?;

    if !wait_for(
        || is_running_with_mode(config, SyftBoxMode::Direct),
        true,
        Duration::from_secs(5),
    )? {
        return Err(anyhow!("SyftBox did not start in time"));
    }

    Ok(true)
}

pub fn stop_syftbox(config: &SyftboxRuntimeConfig) -> Result<bool> {
    // Force Direct mode for desktop until daemon supports -c properly
    let pids = running_pids(config, SyftBoxMode::Direct)?;
    if pids.is_empty() {
        return Ok(false);
    }

    stop_direct(&pids)?;

    if !wait_for(
        || is_running_with_mode(config, SyftBoxMode::Direct),
        false,
        Duration::from_secs(5),
    )? {
        return Err(anyhow!("SyftBox did not stop in time"));
    }

    Ok(true)
}

fn wait_for<F>(mut check: F, expected: bool, timeout: Duration) -> Result<bool>
where
    F: FnMut() -> Result<bool>,
{
    let deadline = Instant::now() + timeout;
    loop {
        let current = check()?;
        if current == expected {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

#[allow(dead_code)]
fn start_with_sbenv(config: &SyftboxRuntimeConfig) -> Result<()> {
    let data_dir = &config.data_dir;
    let status = Command::new("sbenv")
        .arg("start")
        .arg("--skip-login-check")
        .current_dir(data_dir)
        .status()
        .context("Failed to execute sbenv start")?;

    if !status.success() {
        return Err(anyhow!("sbenv start exited with status {}", status));
    }

    Ok(())
}

#[allow(dead_code)]
fn stop_with_sbenv(config: &SyftboxRuntimeConfig) -> Result<()> {
    let data_dir = &config.data_dir;
    let status = Command::new("sbenv")
        .arg("stop")
        .current_dir(data_dir)
        .status()
        .context("Failed to execute sbenv stop")?;

    if !status.success() {
        return Err(anyhow!("sbenv stop exited with status {}", status));
    }

    Ok(())
}

fn start_direct(config: &SyftboxRuntimeConfig) -> Result<()> {
    let config_path = &config.config_path;
    let binary_path = resolve_syftbox_binary(config)?;
    eprintln!("🔧 Requested SyftBox binary: {}", binary_path.display());

    // Read config to extract control-plane URL/token so we can pass them explicitly.
    let (client_url, client_token) =
        match crate::syftbox::config::SyftBoxConfigFile::load(config_path) {
            Ok(cfg) => {
                let url = cfg
                    .client_url
                    .unwrap_or_else(|| "http://127.0.0.1:7938".to_string());
                let token = cfg.client_token.unwrap_or_default();
                (url, token)
            }
            Err(_) => ("http://127.0.0.1:7938".to_string(), String::new()),
        };

    if !config_path.exists() {
        return Err(anyhow!(
            "SyftBox config file does not exist: {}",
            config_path.display()
        ));
    }

    eprintln!("📄 Using SyftBox config: {}", config_path.display());

    // Capture stderr initially to detect early crashes (e.g., code signing issues)
    let mut cmd = Command::new(&binary_path);
    cmd.arg("-c")
        .arg(config_path)
        .arg("--control-plane")
        .arg("--client-url")
        .arg(&client_url);
    if !client_token.trim().is_empty() {
        cmd.arg("--client-token").arg(&client_token);
    }
    let mut child = cmd
        .current_dir(&config.data_dir)
        .env("HOME", &config.data_dir)
        .env("SYFTBOX_CONFIG_PATH", &config.config_path)
        .env("SYFTBOX_DATA_DIR", &config.data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "Failed to spawn syftbox process using '{}'",
                binary_path.display()
            )
        })?;

    thread::sleep(Duration::from_secs(2));

    if let Some(status) = child
        .try_wait()
        .context("Failed to check syftbox child status")?
    {
        if status.success() {
            return Ok(());
        }

        // Capture stderr output to report the crash reason
        let mut stderr_output = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            use std::io::Read;
            let _ = stderr.read_to_string(&mut stderr_output);
        }

        let error_msg = if stderr_output.trim().is_empty() {
            format!("SyftBox exited immediately with status {}. Check system logs for crash details (e.g., Console.app → DiagnosticReports)", status)
        } else {
            format!(
                "SyftBox exited immediately with status {}: {}",
                status,
                stderr_output.trim()
            )
        };

        return Err(anyhow!(error_msg));
    }

    std::mem::forget(child);
    Ok(())
}

fn stop_direct(pids: &[u32]) -> Result<()> {
    for pid in pids {
        let mut cmd = Command::new("kill");
        cmd.arg("-TERM").arg(pid.to_string());
        let status = cmd
            .status()
            .with_context(|| format!("Failed to send TERM to process {}", pid))?;
        if !status.success() {
            return Err(anyhow!("Failed to terminate syftbox process {}", pid));
        }
    }
    Ok(())
}

fn is_running_with_mode(config: &SyftboxRuntimeConfig, mode: SyftBoxMode) -> Result<bool> {
    #[cfg(unix)]
    {
        Ok(!running_pids(config, mode)?.is_empty())
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
        let client_url = crate::syftbox::config::SyftBoxConfigFile::load(&config.config_path)
            .ok()
            .and_then(|cfg| cfg.client_url)
            .unwrap_or_else(|| "http://127.0.0.1:7938".to_string());
        Ok(probe_client_url(&client_url))
    }
}

fn running_pids(config: &SyftboxRuntimeConfig, mode: SyftBoxMode) -> Result<Vec<u32>> {
    #[cfg(unix)]
    {
        let output = Command::new("ps")
            .arg("aux")
            .output()
            .context("Failed to execute ps command")?;

        if !output.status.success() {
            return Err(anyhow!("ps command failed"));
        }

        let ps_output = String::from_utf8_lossy(&output.stdout);

        let config_str = config.config_path.to_string_lossy();
        let data_dir_str = config.data_dir.to_string_lossy();

        let mut pids = Vec::new();
        for line in ps_output.lines() {
            if !line.contains("syftbox") {
                continue;
            }

            let matches_mode = match mode {
                SyftBoxMode::Sbenv => line.contains(data_dir_str.as_ref()),
                SyftBoxMode::Direct => {
                    line.contains(config_str.as_ref()) || line.contains(data_dir_str.as_ref())
                }
            };

            if !matches_mode {
                continue;
            }

            if let Some(pid) = parse_pid(line) {
                pids.push(pid);
            }
        }

        Ok(pids)
    }

    #[cfg(not(unix))]
    {
        let _ = config;
        let _ = mode;
        Ok(Vec::new())
    }
}

#[cfg(not(unix))]
fn probe_client_url(client_url: &str) -> bool {
    let (host, port) = match parse_host_port(client_url) {
        Some(v) => v,
        None => ("127.0.0.1".to_string(), 7938),
    };

    let host = if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_string()
    } else {
        host
    };

    let addr: SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

#[cfg(not(unix))]
fn parse_host_port(url: &str) -> Option<(String, u16)> {
    let url = url.trim();
    let without_scheme = url.split("://").nth(1).unwrap_or(url);
    let hostport = without_scheme.split('/').next().unwrap_or(without_scheme);

    let mut parts = hostport.rsplitn(2, ':');
    let port_str = parts.next()?;
    let host = parts.next()?.trim().to_string();
    let port: u16 = port_str.parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

fn resolve_syftbox_binary(config: &SyftboxRuntimeConfig) -> Result<PathBuf> {
    if let Some(path) = config.binary_path.as_ref() {
        if path.is_absolute() && !path.exists() {
            return Err(anyhow!(
                "Configured SyftBox binary not found at {}",
                path.display()
            ));
        }
        eprintln!("ℹ️  Using configured SyftBox binary from config");
        return Ok(path.to_path_buf());
    }

    if let Ok(env_path) = env::var("SYFTBOX_BINARY") {
        let path = PathBuf::from(env_path.trim());
        if path.is_absolute() && !path.exists() {
            return Err(anyhow!(
                "SYFTBOX_BINARY points to missing path: {}",
                path.display()
            ));
        }
        eprintln!("ℹ️  Using SyftBox binary from SYFTBOX_BINARY env var");
        return Ok(path);
    }

    if let Some(path) = find_syftbox_in_sbenv() {
        eprintln!("ℹ️  Detected SyftBox in ~/.sbenv: {}", path.display());
        return Ok(path);
    }

    eprintln!("ℹ️  No custom SyftBox path found; falling back to 'syftbox' in PATH");
    Ok(PathBuf::from("syftbox"))
}

fn find_syftbox_in_sbenv() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    let binaries_dir = home.join(".sbenv").join("binaries");

    if !binaries_dir.exists() {
        return None;
    }

    let mut candidates = Vec::new();

    if let Ok(entries) = fs::read_dir(&binaries_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let syftbox_path = path.join("syftbox");
                if syftbox_path.is_file() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Ok(metadata) = syftbox_path.metadata() {
                            if metadata.permissions().mode() & 0o111 != 0 {
                                candidates.push(syftbox_path);
                            }
                        }
                    }
                    #[cfg(not(unix))]
                    {
                        candidates.push(syftbox_path);
                    }
                }
            }
        }
    }

    if candidates.is_empty() {
        return None;
    }

    candidates.sort_by(|a, b| {
        let a_parent = a
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned());
        let b_parent = b
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned());
        b_parent.cmp(&a_parent)
    });

    candidates.into_iter().next()
}

#[cfg(unix)]
fn parse_pid(line: &str) -> Option<u32> {
    line.split_whitespace()
        .nth(1)
        .and_then(|pid| pid.parse::<u32>().ok())
}

#[cfg(not(unix))]
fn parse_pid(_line: &str) -> Option<u32> {
    None
}

pub fn syftbox_paths(config: &SyftboxRuntimeConfig) -> Result<(PathBuf, PathBuf)> {
    Ok((config.config_path.clone(), config.data_dir.clone()))
}
