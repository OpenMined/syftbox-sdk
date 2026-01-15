use crate::syftbox::config::SyftboxRuntimeConfig;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[cfg(feature = "embedded")]
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const SYFTBOX_PIDFILE_NAME: &str = "syftbox.pid";
#[cfg(feature = "embedded")]
const SYFTBOX_EMBEDDED_PIDFILE_NAME: &str = "syftbox.embedded.pid";

// ============================================================================
// LOGGING HELPERS
// ============================================================================
// All embedded syftbox operations are logged to help debug startup issues.
// Logs go to stderr so they appear in desktop.log via the Tauri process.

fn log_embedded(level: &str, msg: &str) {
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    eprintln!("[{}][SYFTBOX-SDK][{}] {}", ts, level, msg);
}

fn log_info(msg: &str) {
    log_embedded("INFO", msg);
}

fn log_warn(msg: &str) {
    log_embedded("WARN", msg);
}

fn log_error(msg: &str) {
    log_embedded("ERROR", msg);
}

#[cfg(target_os = "windows")]
fn hide_console_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}
fn use_embedded_backend() -> bool {
    #[cfg(feature = "embedded")]
    {
        env::var("BV_SYFTBOX_BACKEND")
            .ok()
            .map(|v| v.eq_ignore_ascii_case("embedded"))
            .unwrap_or(false)
    }

    #[cfg(not(feature = "embedded"))]
    {
        false
    }
}

#[cfg(feature = "embedded")]
struct EmbeddedDaemonState {
    handle: syftbox_rs::daemon::ThreadedDaemonHandle,
    workspace_lock: EmbeddedWorkspaceLock,
}

#[cfg(feature = "embedded")]
static EMBEDDED_DAEMON: OnceLock<Mutex<Option<EmbeddedDaemonState>>> = OnceLock::new();
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
    if use_embedded_backend() {
        log_info("Starting SyftBox with embedded backend");

        // Treat embedded as Direct mode: no external process to inspect.
        if is_running_with_mode(config, SyftBoxMode::Direct)? {
            log_info("SyftBox is already running (control plane responsive), skipping startup");
            return Ok(false);
        }

        log_info("SyftBox not currently running, starting embedded daemon...");

        #[cfg(feature = "embedded")]
        start_embedded(config)?;

        log_info("Waiting for control plane to become responsive (timeout: 10s)...");
        let start_time = Instant::now();
        if !wait_for(
            || is_running_with_mode(config, SyftBoxMode::Direct),
            true,
            Duration::from_secs(10), // Increased from 5s to 10s for robustness
        )? {
            let elapsed = start_time.elapsed();
            log_error(&format!(
                "SyftBox control plane did not become responsive within {:?}. \
                 Check {} for daemon logs.",
                elapsed,
                config
                    .config_path
                    .parent()
                    .unwrap_or(config.config_path.as_path())
                    .join("logs/syftbox.log")
                    .display()
            ));
            return Err(anyhow!(
                "SyftBox did not start in time (waited {:?}). Check logs for details.",
                elapsed
            ));
        }

        let elapsed = start_time.elapsed();
        log_info(&format!(
            "SyftBox embedded daemon started successfully (took {:?})",
            elapsed
        ));

        return Ok(true);
    }

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
    if use_embedded_backend() {
        if !is_running_with_mode(config, SyftBoxMode::Direct)? {
            return Ok(false);
        }

        #[cfg(feature = "embedded")]
        stop_embedded()?;

        if !wait_for(
            || is_running_with_mode(config, SyftBoxMode::Direct),
            false,
            Duration::from_secs(5),
        )? {
            return Err(anyhow!("SyftBox did not stop in time"));
        }

        return Ok(true);
    }

    // Force Direct mode for desktop until daemon supports -c properly
    let pids = running_pids(config, SyftBoxMode::Direct)?;
    if pids.is_empty() {
        return Ok(false);
    }

    stop_direct(&pids)?;
    remove_pidfile(config);

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
    let mut cmd = Command::new("sbenv");
    cmd.arg("start")
        .arg("--skip-login-check")
        .current_dir(data_dir);
    #[cfg(target_os = "windows")]
    hide_console_window(&mut cmd);
    let status = cmd.status().context("Failed to execute sbenv start")?;

    if !status.success() {
        return Err(anyhow!("sbenv start exited with status {}", status));
    }

    Ok(())
}

#[allow(dead_code)]
fn stop_with_sbenv(config: &SyftboxRuntimeConfig) -> Result<()> {
    let data_dir = &config.data_dir;
    let mut cmd = Command::new("sbenv");
    cmd.arg("stop").current_dir(data_dir);
    #[cfg(target_os = "windows")]
    hide_console_window(&mut cmd);
    let status = cmd.status().context("Failed to execute sbenv stop")?;

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
    #[cfg(target_os = "windows")]
    hide_console_window(&mut cmd);
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

    write_pidfile(config, child.id());
    std::mem::forget(child);
    Ok(())
}

fn stop_direct(pids: &[u32]) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        for pid in pids {
            let mut cmd = Command::new("taskkill");
            cmd.args(["/PID", &pid.to_string(), "/T", "/F"]);
            hide_console_window(&mut cmd);
            let output = cmd
                .output()
                .with_context(|| format!("Failed to execute taskkill for pid {}", pid))?;
            if !output.status.success() {
                return Err(anyhow!(
                    "Failed to terminate syftbox process {} (taskkill status: {})",
                    pid,
                    output.status
                ));
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "windows"))]
    {
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
}

fn is_running_with_mode(config: &SyftboxRuntimeConfig, mode: SyftBoxMode) -> Result<bool> {
    if use_embedded_backend() {
        let _ = mode;
        let client_url = resolve_client_url(config);
        let is_running = probe_client_url(&client_url);
        // Debug: log what we're probing (only when checking, not spamming)
        if !is_running {
            log_info(&format!(
                "Probing control plane at {} - not responding",
                client_url
            ));
        }
        return Ok(is_running);
    }

    #[cfg(unix)]
    {
        Ok(!running_pids(config, mode)?.is_empty())
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
        let client_url = resolve_client_url(config);
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
        let _ = mode;

        let config_str = config.config_path.to_string_lossy();
        let data_dir_str = config.data_dir.to_string_lossy();

        let mut pids: Vec<u32> = Vec::new();

        // Best-effort PID enumeration on Windows (enables reliable stop during updates).
        #[cfg(target_os = "windows")]
        {
            let cmd = r#"Get-CimInstance Win32_Process -Filter "Name='syftbox.exe'" | ForEach-Object { "$($_.ProcessId)|$($_.CommandLine)" }"#;
            let mut ps = Command::new("powershell");
            ps.args(["-NoProfile", "-Command", cmd]);
            hide_console_window(&mut ps);
            if let Ok(output) = ps.output() {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        let mut parts = line.splitn(2, '|');
                        let pid_str = parts.next().unwrap_or("").trim();
                        let cmdline = parts.next().unwrap_or("").trim();
                        if pid_str.is_empty() {
                            continue;
                        }
                        if !cmdline.is_empty()
                            && !(cmdline.contains(config_str.as_ref())
                                || cmdline.contains(data_dir_str.as_ref()))
                        {
                            continue;
                        }
                        if let Ok(pid) = pid_str.parse::<u32>() {
                            pids.push(pid);
                        }
                    }
                }
            }
        }

        // Fallback: stored pidfile if present (works cross-platform for non-unix).
        if pids.is_empty() {
            let pid_path = pidfile_path(config);
            if let Some(pid) = fs::read_to_string(&pid_path)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
            {
                pids.push(pid);
            }
        }

        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }
}

/// Check if a SyftBox control plane is actually running at the given URL.
///
/// This does an HTTP GET to /v1/status to verify it's actually a SyftBox control plane,
/// not just any service listening on that port.
fn probe_client_url(client_url: &str) -> bool {
    let (host, port) = match parse_host_port(client_url) {
        Some(v) => v,
        None => ("127.0.0.1".to_string(), 7938),
    };

    let host = normalize_host_for_socket_addr(&host);

    let addr: SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // First check TCP connectivity
    let stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Set timeouts for the HTTP request
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));

    // Make a simple HTTP GET request to /v1/status
    use std::io::{BufRead, BufReader, Write};
    let mut stream = stream;
    let request = format!(
        "GET /v1/status HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        host, port
    );

    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    // Read the response - we just need to check for HTTP 200 OK
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if reader.read_line(&mut status_line).is_err() {
        return false;
    }

    // Check if response is HTTP 200 (SyftBox control plane responds with 200 to /v1/status)
    status_line.contains("200")
}

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

/// Converts hostnames that cannot be parsed by `SocketAddr::parse()` to numeric IPs.
///
/// `SocketAddr::parse()` only accepts numeric IP addresses (e.g., "127.0.0.1:7938"),
/// NOT hostnames like "localhost:7938". This function normalizes common hostnames
/// to their numeric equivalents so they can be used with socket APIs.
///
/// If the host is not a recognized hostname, it is returned unchanged (allowing
/// numeric IPs to pass through, or causing a later parse failure for truly invalid hosts).
fn normalize_host_for_socket_addr(host: &str) -> String {
    if host.eq_ignore_ascii_case("localhost") {
        "127.0.0.1".to_string()
    } else {
        host.to_string()
    }
}

fn resolve_client_url(config: &SyftboxRuntimeConfig) -> String {
    crate::syftbox::config::SyftBoxConfigFile::load(&config.config_path)
        .ok()
        .and_then(|cfg| cfg.client_url)
        .unwrap_or_else(|| "http://127.0.0.1:7938".to_string())
}

#[cfg(feature = "embedded")]
fn embedded_pidfile_path(config: &SyftboxRuntimeConfig) -> PathBuf {
    config
        .config_path
        .parent()
        .unwrap_or(config.data_dir.as_path())
        .join(SYFTBOX_EMBEDDED_PIDFILE_NAME)
}

#[cfg(feature = "embedded")]
fn is_pid_running(pid: u32) -> bool {
    #[cfg(target_os = "windows")]
    {
        let mut cmd = Command::new("tasklist");
        cmd.args(["/FI", &format!("PID eq {}", pid)]);
        hide_console_window(&mut cmd);
        if let Ok(output) = cmd.output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                return stdout.contains(&pid.to_string());
            }
        }
        false
    }

    #[cfg(not(target_os = "windows"))]
    {
        Command::new("ps")
            .args(["-p", &pid.to_string()])
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }
}

/// Check if a SyftBox control plane at the given URL is responsive.
///
/// This verifies the endpoint is actually a SyftBox control plane by hitting /v1/status,
/// not just checking TCP connectivity. This prevents false positives when another service
/// is using the port.
#[cfg(feature = "embedded")]
fn is_control_plane_responsive(client_url: &str, timeout: Duration) -> bool {
    let (host, port) = match parse_host_port(client_url) {
        Some(v) => v,
        None => return false,
    };

    let host = normalize_host_for_socket_addr(&host);
    let addr: SocketAddr = match format!("{host}:{port}").parse() {
        Ok(a) => a,
        Err(_) => return false,
    };

    // Connect with provided timeout
    let stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Set timeouts for the HTTP exchange
    let half_timeout = Duration::from_millis(timeout.as_millis() as u64 / 2);
    let _ = stream.set_read_timeout(Some(half_timeout));
    let _ = stream.set_write_timeout(Some(half_timeout));

    // Make HTTP GET to /v1/status to verify it's actually a SyftBox control plane
    use std::io::{BufRead, BufReader, Write};
    let mut stream = stream;
    let request = format!(
        "GET /v1/status HTTP/1.1\r\nHost: {}:{}\r\nConnection: close\r\n\r\n",
        host, port
    );

    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    if reader.read_line(&mut status_line).is_err() {
        return false;
    }

    status_line.contains("200")
}

/// Kill a process by PID.
#[cfg(feature = "embedded")]
fn kill_process(pid: u32) -> Result<()> {
    log_info(&format!("Attempting to kill stale process (pid={})", pid));

    #[cfg(target_os = "windows")]
    {
        let status = Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("Failed to execute taskkill for pid {}", pid))?;

        if status.success() {
            log_info(&format!("Successfully killed process (pid={})", pid));
            Ok(())
        } else {
            Err(anyhow!(
                "taskkill failed for pid {} (status: {:?})",
                pid,
                status.code()
            ))
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // First try SIGTERM (graceful)
        let status = Command::new("kill")
            .args(["-15", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("Failed to execute kill -15 for pid {}", pid))?;

        if status.success() {
            // Wait a bit for graceful shutdown
            thread::sleep(Duration::from_millis(500));

            // Check if still running, if so use SIGKILL
            if is_pid_running(pid) {
                log_warn(&format!(
                    "Process {} still running after SIGTERM, sending SIGKILL",
                    pid
                ));
                let _ = Command::new("kill")
                    .args(["-9", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                thread::sleep(Duration::from_millis(200));
            }
        }

        if is_pid_running(pid) {
            Err(anyhow!("Failed to kill process {} - still running", pid))
        } else {
            log_info(&format!("Successfully killed process (pid={})", pid));
            Ok(())
        }
    }
}

/// Holds the workspace lock to prevent concurrent access to the data_dir.
#[cfg(feature = "embedded")]
struct EmbeddedWorkspaceLock {
    #[allow(dead_code)]
    lock: syftbox_rs::workspace::WorkspaceLock,
    pidfile: PathBuf,
}

/// Ensure we have exclusive access to run the embedded daemon for this data_dir.
///
/// This function uses a two-layer locking strategy:
/// 1. **flock-based WorkspaceLock**: Kernel-level exclusive lock on data_dir/.data/syftbox.lock
///    - Automatically released on process exit/crash (kernel handles this)
///    - Prevents any concurrent access, even from processes we don't know about
/// 2. **PID file**: Records our PID for diagnostics and stale process detection
///    - Allows us to identify and kill stale processes that didn't clean up properly
///
/// Flow:
/// 1. Try to acquire flock on workspace
/// 2. If flock fails, another process has it - check if that process is healthy
/// 3. If healthy, error out (can't have two)
/// 4. If stale/unresponsive, kill it and retry
/// 5. Write our PID to pidfile
#[cfg(feature = "embedded")]
fn ensure_embedded_lock(config: &SyftboxRuntimeConfig) -> Result<EmbeddedWorkspaceLock> {
    let pidfile = embedded_pidfile_path(config);
    let current_pid = std::process::id();

    log_info(&format!(
        "Acquiring workspace lock: data_dir={}, current_pid={}",
        config.data_dir.display(),
        current_pid
    ));

    // First, try to acquire the flock-based workspace lock
    match syftbox_rs::workspace::WorkspaceLock::try_lock(&config.data_dir) {
        Ok(lock) => {
            log_info("Workspace lock acquired successfully (flock)");

            // Clean up any stale pidfile and write our PID
            if let Some(parent) = pidfile.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("Failed to create pidfile directory: {}", parent.display())
                })?;
            }
            fs::write(&pidfile, format!("{}\n", current_pid))
                .with_context(|| format!("Failed to write pidfile: {}", pidfile.display()))?;

            log_info(&format!(
                "Wrote pidfile: path={}, pid={}",
                pidfile.display(),
                current_pid
            ));

            Ok(EmbeddedWorkspaceLock { lock, pidfile })
        }
        Err(e) => {
            // Lock acquisition failed - check if it's a "locked" error
            let is_locked = e.chain().any(|cause| {
                cause
                    .downcast_ref::<syftbox_rs::workspace::WorkspaceLockedError>()
                    .is_some()
            });

            if !is_locked {
                // Some other error (permissions, disk full, etc.)
                log_error(&format!("Failed to acquire workspace lock: {}", e));
                return Err(e);
            }

            log_warn("Workspace is locked by another process, investigating...");

            // Read pidfile to find the other process
            let existing_pid = fs::read_to_string(&pidfile)
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());

            if let Some(pid) = existing_pid {
                log_info(&format!("Found pidfile with pid={}", pid));

                // Check if that process is healthy
                let client_url =
                    crate::syftbox::config::SyftBoxConfigFile::load(&config.config_path)
                        .ok()
                        .and_then(|c| c.client_url)
                        .unwrap_or_else(|| "http://127.0.0.1:7938".to_string());

                if is_control_plane_responsive(&client_url, Duration::from_secs(2)) {
                    log_error(&format!(
                        "Cannot start: another instance (pid={}) is running and healthy for data_dir={}",
                        pid,
                        config.data_dir.display()
                    ));
                    return Err(anyhow!(
                        "Another BioVault instance (pid {}) is already running for {}. \
                         The control plane is responsive at {}.",
                        pid,
                        config.data_dir.display(),
                        client_url
                    ));
                }

                // Not responsive - try to kill it
                log_warn(&format!(
                    "Existing process (pid={}) is not responsive, attempting to kill...",
                    pid
                ));

                if let Err(kill_err) = kill_process(pid) {
                    log_error(&format!(
                        "Failed to kill stale process (pid={}): {}",
                        pid, kill_err
                    ));
                    return Err(anyhow!(
                        "Workspace is locked by stale process (pid {}), failed to kill: {}",
                        pid,
                        kill_err
                    ));
                }

                log_info(&format!("Killed stale process (pid={})", pid));

                // Wait for lock to be released
                thread::sleep(Duration::from_millis(500));

                // Retry acquiring the lock
                log_info("Retrying workspace lock acquisition...");
                match syftbox_rs::workspace::WorkspaceLock::try_lock(&config.data_dir) {
                    Ok(lock) => {
                        log_info("Workspace lock acquired on retry");
                        fs::write(&pidfile, format!("{}\n", current_pid)).with_context(|| {
                            format!("Failed to write pidfile: {}", pidfile.display())
                        })?;
                        Ok(EmbeddedWorkspaceLock { lock, pidfile })
                    }
                    Err(retry_err) => {
                        log_error(&format!(
                            "Failed to acquire lock after killing stale process: {}",
                            retry_err
                        ));
                        Err(retry_err)
                    }
                }
            } else {
                // No pidfile, but workspace is locked - something weird
                log_error("Workspace locked but no pidfile found - cannot identify holder");
                Err(anyhow!(
                    "Workspace at {} is locked by an unknown process (no pidfile). \
                     Try removing {}/.data/syftbox.lock manually.",
                    config.data_dir.display(),
                    config.data_dir.display()
                ))
            }
        }
    }
}

#[cfg(feature = "embedded")]
fn release_embedded_lock(lock: EmbeddedWorkspaceLock) {
    log_info(&format!(
        "Releasing embedded lock: {}",
        lock.pidfile.display()
    ));
    let _ = fs::remove_file(&lock.pidfile);
    // WorkspaceLock is automatically released on drop via flock(LOCK_UN)
}

#[cfg(feature = "embedded")]
fn start_embedded(config: &SyftboxRuntimeConfig) -> Result<()> {
    log_info("================================================================================");
    log_info("EMBEDDED SYFTBOX DAEMON STARTUP");
    log_info("================================================================================");

    let config_path = &config.config_path;
    log_info(&format!("Config path: {}", config_path.display()));
    log_info(&format!("Data dir: {}", config.data_dir.display()));
    log_info(&format!("Email: {}", config.email));

    if !config_path.exists() {
        log_error(&format!(
            "Config file does not exist: {}",
            config_path.display()
        ));
        return Err(anyhow!(
            "SyftBox config file does not exist: {}",
            config_path.display()
        ));
    }

    // Load SyftBox config file for control-plane hints (optional).
    let cfg_file = crate::syftbox::config::SyftBoxConfigFile::load(config_path).ok();
    let client_url = cfg_file
        .as_ref()
        .and_then(|c| c.client_url.clone())
        .unwrap_or_else(|| "http://127.0.0.1:7938".to_string());
    let client_token = cfg_file
        .as_ref()
        .and_then(|c| c.client_token.clone())
        .unwrap_or_default();

    log_info(&format!("Configured client_url: {}", client_url));
    log_info(&format!("Has client_token: {}", !client_token.is_empty()));

    // Match CLI behavior: prefer binding to the configured control-plane address.
    //
    // IMPORTANT: The syftbox-rs daemon uses `addr.parse::<SocketAddr>()` which CANNOT
    // resolve hostnames like "localhost" - it only accepts numeric IP addresses.
    // We MUST convert "localhost" to "127.0.0.1" here, otherwise the control plane
    // will silently fail to bind and the daemon will appear to hang.
    // See: embedded_backend_works_with_localhost_client_url test
    let http_addr = parse_host_port(&client_url)
        .map(|(host, port)| {
            let normalized_host = normalize_host_for_socket_addr(&host);
            if host != normalized_host {
                log_info(&format!(
                    "Normalized hostname '{}' -> '{}' for socket binding",
                    host, normalized_host
                ));
            }
            format!("{normalized_host}:{port}")
        })
        .unwrap_or_else(|| {
            log_warn("Could not parse client_url, falling back to 127.0.0.1:7938");
            "127.0.0.1:7938".to_string()
        });

    log_info(&format!(
        "Will attempt to bind control plane to: {}",
        http_addr
    ));

    let overrides = syftbox_rs::config::ConfigOverrides {
        data_dir: Some(config.data_dir.clone()),
        email: Some(config.email.clone()),
        server_url: None,
        client_url: Some(client_url.clone()),
        client_token: Some(client_token),
    };

    log_info("Loading syftbox-rs config with overrides...");
    let cfg = match syftbox_rs::config::Config::load_with_overrides(config_path, overrides) {
        Ok(c) => {
            log_info("Config loaded successfully");
            c
        }
        Err(e) => {
            log_error(&format!("Failed to load config: {}", e));
            return Err(e);
        }
    };

    let log_path = config
        .config_path
        .parent()
        .unwrap_or(config.config_path.as_path())
        .join("logs")
        .join("syftbox.log");

    log_info(&format!("Daemon log path: {}", log_path.display()));

    let opts = syftbox_rs::daemon::DaemonOptions {
        http_addr: Some(http_addr.clone()),
        http_token: None,
        // Retry forever: don't exit if server is temporarily down.
        healthz_max_attempts: None,
        log_path: Some(log_path.clone()),
    };

    // Check if we already have a running daemon in this process
    let cell = EMBEDDED_DAEMON.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().unwrap();
    if guard.is_some() {
        // Verify the control plane is actually responsive before skipping
        if is_control_plane_responsive(&client_url, Duration::from_secs(1)) {
            log_info("Embedded daemon already running in this process, skipping startup");
            return Ok(());
        } else {
            log_warn("Embedded daemon state exists but control plane not responsive, cleaning up stale state");
            if let Some(state) = guard.take() {
                release_embedded_lock(state.workspace_lock);
            }
        }
    }

    // Ensure we have exclusive access (handles stale processes)
    log_info("Acquiring workspace lock...");
    let workspace_lock = match ensure_embedded_lock(config) {
        Ok(lock) => {
            log_info(&format!(
                "Workspace lock acquired: {}",
                lock.pidfile.display()
            ));
            lock
        }
        Err(e) => {
            log_error(&format!("Failed to acquire workspace lock: {}", e));
            return Err(e);
        }
    };

    // Start the daemon
    log_info("Starting syftbox-rs daemon thread...");
    match syftbox_rs::daemon::start_threaded(cfg, opts) {
        Ok(handle) => {
            log_info("Daemon thread started successfully");
            *guard = Some(EmbeddedDaemonState {
                handle,
                workspace_lock,
            });

            // Log startup complete
            log_info(&format!(
                "================================================================================\n\
                 EMBEDDED SYFTBOX DAEMON STARTED\n\
                 Control plane: {}\n\
                 Data dir: {}\n\
                 Log file: {}\n\
                 ================================================================================",
                http_addr,
                config.data_dir.display(),
                log_path.display()
            ));

            Ok(())
        }
        Err(e) => {
            log_error(&format!("Failed to start daemon thread: {}", e));
            release_embedded_lock(workspace_lock);
            Err(e)
        }
    }
}

#[cfg(feature = "embedded")]
fn stop_embedded() -> Result<()> {
    log_info("Stopping embedded daemon...");
    if let Some(cell) = EMBEDDED_DAEMON.get() {
        let mut guard = cell.lock().unwrap();
        if let Some(state) = guard.take() {
            log_info("Sending stop signal to daemon thread...");
            match state.handle.stop() {
                Ok(()) => log_info("Daemon thread stopped successfully"),
                Err(e) => log_error(&format!("Error stopping daemon thread: {}", e)),
            }
            release_embedded_lock(state.workspace_lock);
            log_info("Embedded daemon stopped");
        } else {
            log_info("No embedded daemon running in this process");
        }
    } else {
        log_info("Embedded daemon was never initialized");
    }
    Ok(())
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
#[allow(dead_code)]
fn parse_pid(_line: &str) -> Option<u32> {
    None
}

fn pidfile_path(config: &SyftboxRuntimeConfig) -> PathBuf {
    config.data_dir.join(".syftbox").join(SYFTBOX_PIDFILE_NAME)
}

fn write_pidfile(config: &SyftboxRuntimeConfig, pid: u32) {
    let path = pidfile_path(config);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, pid.to_string());
}

fn remove_pidfile(config: &SyftboxRuntimeConfig) {
    let _ = fs::remove_file(pidfile_path(config));
}

pub fn syftbox_paths(config: &SyftboxRuntimeConfig) -> Result<(PathBuf, PathBuf)> {
    Ok((config.config_path.clone(), config.data_dir.clone()))
}
