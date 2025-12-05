pub mod app;
#[cfg(feature = "auth")]
pub mod auth;
pub mod config;
pub mod control;
pub mod endpoint;
pub mod rpc;
pub mod storage;
pub mod syc;
pub mod types;

pub use app::SyftBoxApp;
#[cfg(feature = "auth")]
pub use auth::{request_otp, verify_otp, OtpRequestPayload, OtpTokens, OtpVerifyOutcome};
pub use config::{
    default_syftbox_config_path, load_runtime_config, SyftBoxConfigFile, SyftboxRuntimeConfig,
};
pub use control::{
    detect_mode, is_syftbox_running, start_syftbox, state as syftbox_state, stop_syftbox,
    SyftBoxMode, SyftBoxState,
};
pub use endpoint::Endpoint;
pub use rpc::{check_requests, send_response};
pub use storage::{SyftBoxStorage, SyftStorageConfig};
pub use syc::{
    detect_identity, import_public_bundle, provision_local_identity,
    provision_local_identity_with_options, resolve_identity,
};
pub use types::{RpcHeaders, RpcRequest, RpcResponse};

use anyhow::Result;
use std::path::Path;

/// Initialize a SyftBox app with the given name in the specified data directory
pub fn init_app(data_dir: &Path, email: &str, app_name: &str) -> Result<SyftBoxApp> {
    SyftBoxApp::new(data_dir, email, app_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn init_app_creates_structure() {
        let td = TempDir::new().unwrap();
        let app = init_app(td.path(), "u@example.com", "bv").unwrap();
        assert!(app.app_data_dir.exists());
        assert!(app.rpc_dir.exists());
    }
}
