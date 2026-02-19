pub mod syft_url;
pub mod syftbox;

pub use syft_url::SyftURL;

pub use syft_crypto_protocol::datasite::{context::sanitize_identity, crypto::PublicBundleInfo};
pub use syft_crypto_protocol::envelope::{
    has_sbc_magic, parse_envelope, ParsedEnvelope, SenderInfo,
};
pub use syft_crypto_protocol::identity::identity_material_from_recovery_key;
pub use syft_crypto_protocol::SyftRecoveryKey;
pub use syftbox::app::SyftBoxApp;
pub use syftbox::config::{
    default_syftbox_config_path, load_runtime_config, SyftBoxConfigFile, SyftboxRuntimeConfig,
};
pub use syftbox::control::{
    detect_mode, is_syftbox_running, start_syftbox, state as syftbox_state, stop_syftbox,
    SyftBoxMode, SyftBoxState,
};
pub use syftbox::endpoint::Endpoint;
pub use syftbox::rpc::{check_requests, send_response};
pub use syftbox::sbc::{
    cache_bundle_from_datasite, datasite_bundle_path, detect_identity, import_public_bundle,
    load_datasite_bundle, parse_public_bundle_file, provision_local_identity,
    provision_local_identity_with_options, resolve_identity, resolve_sender_bundle,
    restore_identity_from_mnemonic, BundleResolutionError, DatasiteBundleInfo,
    IdentityProvisioningOutcome,
};
pub use syftbox::storage::{ReadPolicy, SyftBoxStorage, SyftStorageConfig, WritePolicy};
pub use syftbox::types::{RpcHeaders, RpcRequest, RpcResponse, COMPONENT_ATTR, TRACEPARENT_HEADER};

#[cfg(feature = "telemetry")]
pub use syftbox::types::trace_context;

#[cfg(feature = "auth")]
pub use syftbox::auth::{request_otp, verify_otp, OtpRequestPayload, OtpTokens, OtpVerifyOutcome};
