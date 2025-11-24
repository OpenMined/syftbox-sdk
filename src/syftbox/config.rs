use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_PATH: &str = ".syftbox/config.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyftBoxConfigFile {
    pub data_dir: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub server_url: String,
    #[serde(default)]
    pub client_url: Option<String>,
    #[serde(default)]
    pub client_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
}

impl SyftBoxConfigFile {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read SyftBox config: {}", path.display()))?;
        let mut parsed: SyftBoxConfigFile = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse SyftBox config JSON: {}", path.display()))?;
        parsed.email = parsed.email.trim().to_string();
        parsed.server_url = parsed.server_url.trim().to_string();
        if parsed.data_dir.is_empty() {
            if let Some(dir) = env::var_os("SYFTBOX_DATA_DIR") {
                parsed.data_dir = dir.to_string_lossy().to_string();
            }
        }
        Ok(parsed)
    }
}

#[derive(Debug, Clone)]
pub struct SyftboxRuntimeConfig {
    pub email: String,
    pub config_path: PathBuf,
    pub data_dir: PathBuf,
    pub binary_path: Option<PathBuf>,
    pub vault_path: Option<PathBuf>,
    pub disable_crypto: bool,
}

impl SyftboxRuntimeConfig {
    pub fn new(
        email: impl Into<String>,
        config_path: impl Into<PathBuf>,
        data_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            email: email.into(),
            config_path: config_path.into(),
            data_dir: data_dir.into(),
            binary_path: None,
            vault_path: None,
            disable_crypto: false,
        }
    }

    pub fn with_binary_path(mut self, path: Option<PathBuf>) -> Self {
        self.binary_path = path;
        self
    }

    pub fn with_vault_path(mut self, path: Option<PathBuf>) -> Self {
        self.vault_path = path;
        self
    }

    pub fn with_disable_crypto(mut self, disable: bool) -> Self {
        self.disable_crypto = disable;
        self
    }
}

pub fn default_syftbox_config_path() -> Result<PathBuf> {
    if let Ok(config_path) = env::var("SYFTBOX_CONFIG_PATH") {
        return Ok(PathBuf::from(config_path));
    }
    let home_dir =
        dirs::home_dir().ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
    Ok(home_dir.join(DEFAULT_CONFIG_PATH))
}

pub fn load_runtime_config(email: &str) -> Result<SyftboxRuntimeConfig> {
    let config_path = default_syftbox_config_path()?;
    let config = SyftBoxConfigFile::load(&config_path)?;
    let data_dir = PathBuf::from(config.data_dir.trim());
    Ok(SyftboxRuntimeConfig::new(
        email.to_string(),
        config_path,
        data_dir,
    ))
}
