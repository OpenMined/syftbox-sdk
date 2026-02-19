use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use syft_crypto_protocol::datasite::context::{ensure_vault_layout, sanitize_identity};
use syft_crypto_protocol::datasite::crypto::{
    load_private_keys_from_file, parse_public_bundle, PublicBundleInfo,
};
use syft_crypto_protocol::identity::{
    generate_identity_material, identity_material_from_recovery_key,
};
use syft_crypto_protocol::SyftRecoveryKey;

const VAULT_DIR_NAME: &str = ".sbc";
const CONFIG_DIR: &str = "config";
const DATASITE_JSON: &str = "datasite.json";
const PUBLIC_DID_RELATIVE: &str = "public/crypto/did.json";
const SHADOW_DIR_NAME: &str = "unencrypted";

pub fn vault_path_for_home(home: &Path) -> PathBuf {
    if home.file_name().map(|n| n == "datasites").unwrap_or(false) {
        home.parent()
            .map(|p| p.join(VAULT_DIR_NAME))
            .unwrap_or_else(|| home.join(VAULT_DIR_NAME))
    } else {
        home.join(VAULT_DIR_NAME)
    }
}

pub fn shadow_root_for_data_root(data_root: &Path) -> PathBuf {
    let base = if data_root
        .file_name()
        .map(|n| n == "datasites")
        .unwrap_or(false)
    {
        data_root.parent().unwrap_or(data_root)
    } else {
        data_root
    };
    base.join(SHADOW_DIR_NAME)
}

pub fn resolve_encrypted_root(data_root: &Path) -> PathBuf {
    if data_root
        .file_name()
        .map(|n| n == "datasites")
        .unwrap_or(false)
    {
        data_root.to_path_buf()
    } else {
        // Always prefer the datasites subdir for encrypted content; callers
        // will create the directory if it does not already exist.
        data_root.join("datasites")
    }
}

#[derive(Debug, Clone)]
pub struct IdentityProvisioningOutcome {
    pub identity: String,
    pub generated: bool,
    pub recovery_mnemonic: Option<String>,
    pub vault_path: PathBuf,
    pub bundle_path: PathBuf,
    pub public_bundle_path: PathBuf,
}

#[derive(Serialize)]
struct DatasiteConfigFile<'a> {
    encrypted_root: &'a str,
    shadow_root: &'a str,
}

pub fn provision_local_identity(
    identity: &str,
    data_root: &Path,
    vault_override: Option<&Path>,
) -> Result<IdentityProvisioningOutcome> {
    provision_local_identity_with_options(identity, data_root, vault_override, false)
}

/// Provision local identity with option to overwrite existing keys.
pub fn provision_local_identity_with_options(
    identity: &str,
    data_root: &Path,
    vault_override: Option<&Path>,
    overwrite: bool,
) -> Result<IdentityProvisioningOutcome> {
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] provision_local_identity: identity={} overwrite={} data_root={} vault_override={}",
            identity,
            overwrite,
            data_root.display(),
            vault_override.map(|v| v.display().to_string()).unwrap_or_else(|| "<none>".to_string())
        );
        eprintln!(
            "[sbc][debug] env: SBC_VAULT={:?} SYFTBOX_DATA_DIR={:?} BIOVAULT_HOME={:?}",
            env::var("SBC_VAULT").ok(),
            env::var("SYFTBOX_DATA_DIR").ok(),
            env::var("BIOVAULT_HOME").ok()
        );
    }
    let data_root = data_root
        .canonicalize()
        .unwrap_or_else(|_| data_root.to_path_buf());
    let encrypted_root = resolve_encrypted_root(&data_root);
    let shadow_root = shadow_root_for_data_root(&encrypted_root);
    fs::create_dir_all(&shadow_root).with_context(|| {
        format!(
            "failed to create shadow directory: {}",
            shadow_root.display()
        )
    })?;

    let vault_path = resolve_vault_path(vault_override);
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] provision_local_identity: encrypted_root={} shadow_root={} vault_path={}",
            encrypted_root.display(),
            shadow_root.display(),
            vault_path.display()
        );
    }
    ensure_vault_layout(&vault_path).map_err(|err| {
        anyhow!(
            "failed to prepare Syft Crypto vault at {}: {err}",
            vault_path.display()
        )
    })?;

    write_datasite_config(&vault_path, &encrypted_root, &shadow_root)?;

    let outcome = if overwrite {
        let generated_identity = generate_identity_material(identity)?;
        write_identity_material(
            identity,
            generated_identity,
            &vault_path,
            &encrypted_root,
            true,
            true,
        )?
    } else {
        write_identity_material_if_missing(identity, &vault_path, &encrypted_root)?
    };
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] provision_local_identity: generated={} bundle_path={} public_bundle_path={}",
            outcome.generated,
            outcome.bundle_path.display(),
            outcome.public_bundle_path.display()
        );
    }
    Ok(outcome)
}

/// Restore identity from a BIP-39 mnemonic into the given data root/vault.
pub fn restore_identity_from_mnemonic(
    identity: &str,
    mnemonic: &str,
    data_root: &Path,
    vault_override: Option<&Path>,
) -> Result<IdentityProvisioningOutcome> {
    let data_root = data_root
        .canonicalize()
        .unwrap_or_else(|_| data_root.to_path_buf());
    let encrypted_root = resolve_encrypted_root(&data_root);
    let shadow_root = shadow_root_for_data_root(&encrypted_root);
    fs::create_dir_all(&shadow_root).with_context(|| {
        format!(
            "failed to create shadow directory: {}",
            shadow_root.display()
        )
    })?;

    let vault_path = resolve_vault_path(vault_override);
    ensure_vault_layout(&vault_path).map_err(|err| {
        anyhow!(
            "failed to prepare Syft Crypto vault at {}: {err}",
            vault_path.display()
        )
    })?;

    write_datasite_config(&vault_path, &encrypted_root, &shadow_root)?;

    let recovery_key =
        SyftRecoveryKey::from_mnemonic(mnemonic).context("failed to parse recovery mnemonic")?;
    let material = identity_material_from_recovery_key(identity.trim(), &recovery_key)?;
    write_identity_material(
        identity,
        material,
        &vault_path,
        &encrypted_root,
        true,
        false,
    )
}

fn write_identity_material_if_missing(
    identity: &str,
    vault_path: &Path,
    encrypted_root: &Path,
) -> Result<IdentityProvisioningOutcome> {
    let identity = identity.trim();
    let slug = sanitize_identity(identity);
    let key_path = vault_path.join("keys").join(format!("{slug}.key"));
    let bundle_path = vault_path.join("bundles").join(format!("{slug}.json"));

    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] write_identity_material_if_missing: identity={} key_path={} bundle_path={} key_exists={} bundle_exists={}",
            identity,
            key_path.display(),
            bundle_path.display(),
            key_path.exists(),
            bundle_path.exists()
        );
    }
    if !key_path.exists() || !bundle_path.exists() {
        let generated_identity = generate_identity_material(identity)?;
        let outcome = write_identity_material(
            identity,
            generated_identity,
            vault_path,
            encrypted_root,
            false,
            true,
        )?;
        return Ok(outcome);
    }

    let contents = fs::read_to_string(&bundle_path)
        .with_context(|| format!("failed to read bundle file: {}", bundle_path.display()))?;
    let public_bundle: Value =
        serde_json::from_str(&contents).context("failed to parse existing bundle JSON")?;

    let public_bundle_path = export_public_bundle(identity, &public_bundle, encrypted_root)?;
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] write_identity_material_if_missing: using existing bundle public_path={}",
            public_bundle_path.display()
        );
    }

    Ok(IdentityProvisioningOutcome {
        identity: identity.to_string(),
        generated: false,
        recovery_mnemonic: None,
        vault_path: vault_path.to_path_buf(),
        bundle_path,
        public_bundle_path,
    })
}

fn write_identity_material(
    identity: &str,
    material: syft_crypto_protocol::identity::IdentityMaterial,
    vault_path: &Path,
    encrypted_root: &Path,
    overwrite: bool,
    generated: bool,
) -> Result<IdentityProvisioningOutcome> {
    let identity = identity.trim();
    let slug = sanitize_identity(identity);
    let key_path = vault_path.join("keys").join(format!("{slug}.key"));
    let bundle_path = vault_path.join("bundles").join(format!("{slug}.json"));

    if key_path.exists() && !overwrite {
        return Err(anyhow!(
            "identity {} already has key material in vault; refusing to overwrite",
            identity
        ));
    }
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] write_identity_material: identity={} overwrite={} generated={} key_path={} bundle_path={}",
            identity,
            overwrite,
            generated,
            key_path.display(),
            bundle_path.display()
        );
    }

    fs::create_dir_all(key_path.parent().unwrap())
        .with_context(|| format!("failed to ensure keys dir: {}", key_path.display()))?;
    fs::create_dir_all(bundle_path.parent().unwrap())
        .with_context(|| format!("failed to ensure bundles dir: {}", bundle_path.display()))?;

    fs::write(&key_path, &material.key_file)
        .with_context(|| format!("failed to write private key file: {}", key_path.display()))?;
    fs::write(
        &bundle_path,
        serde_json::to_vec_pretty(&material.public_bundle)?,
    )
    .with_context(|| format!("failed to write bundle file: {}", bundle_path.display()))?;

    let public_bundle_path =
        export_public_bundle(identity, &material.public_bundle, encrypted_root)?;
    if sbc_debug_enabled() {
        if let Ok(info) = parse_public_bundle_file(&public_bundle_path) {
            eprintln!(
                "[sbc][debug] write_identity_material: public bundle fingerprint={} public_path={}",
                info.fingerprint,
                public_bundle_path.display()
            );
        }
    }

    Ok(IdentityProvisioningOutcome {
        identity: identity.to_string(),
        generated,
        recovery_mnemonic: Some(material.recovery_key_mnemonic.to_string()),
        vault_path: vault_path.to_path_buf(),
        bundle_path,
        public_bundle_path,
    })
}

pub fn import_public_bundle(
    bundle_path: &Path,
    expected_identity: Option<&str>,
    vault_path: &Path,
    export_root: Option<&Path>,
    refresh_identity: Option<&str>,
) -> Result<PublicBundleInfo> {
    ensure_vault_layout(vault_path)
        .map_err(|err| anyhow!("failed to prepare Syft Crypto vault: {err}"))?;

    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] import_public_bundle: bundle_path={} expected_identity={:?} vault_path={} export_root={} refresh_identity={:?}",
            bundle_path.display(),
            expected_identity,
            vault_path.display(),
            export_root.map(|p| p.display().to_string()).unwrap_or_else(|| "<none>".to_string()),
            refresh_identity
        );
    }
    let bundle_bytes = fs::read(bundle_path)
        .with_context(|| format!("failed to read bundle at {}", bundle_path.display()))?;
    let bundle_str = String::from_utf8(bundle_bytes)
        .with_context(|| format!("bundle at {} is not valid UTF-8", bundle_path.display()))?;
    let bundle: Value = serde_json::from_str(&bundle_str)
        .with_context(|| format!("failed to parse bundle JSON at {}", bundle_path.display()))?;
    let parsed = parse_public_bundle_from_str(&bundle_str)?;

    if let Some(expected) = expected_identity {
        if parsed.identity != expected {
            return Err(anyhow!(
                "bundle identity mismatch: expected {}, found {}",
                expected,
                parsed.identity
            ));
        }
    }

    let slug = sanitize_identity(&parsed.identity);
    let target = vault_path.join("bundles").join(format!("{slug}.json"));
    fs::create_dir_all(target.parent().unwrap())?;
    fs::write(&target, serde_json::to_vec_pretty(&bundle)?)
        .with_context(|| format!("failed to write bundle to {}", target.display()))?;
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] import_public_bundle: identity={} fingerprint={} target={}",
            parsed.identity,
            parsed.fingerprint,
            target.display()
        );
    }

    // If this is our own identity, ensure public bundle copy is refreshed.
    if refresh_identity
        .map(|id| id == parsed.identity)
        .unwrap_or(false)
    {
        if let Some(data_root) = export_root {
            let _ = export_public_bundle(&parsed.identity, &bundle, data_root);
        }
    }

    Ok(parsed)
}

fn write_datasite_config(
    vault_path: &Path,
    encrypted_root: &Path,
    shadow_root: &Path,
) -> Result<()> {
    let config_dir = vault_path.join(CONFIG_DIR);
    fs::create_dir_all(&config_dir)?;
    let json = DatasiteConfigFile {
        encrypted_root: &encrypted_root.to_string_lossy(),
        shadow_root: &shadow_root.to_string_lossy(),
    };
    let payload = serde_json::to_string_pretty(&json)?;
    fs::write(config_dir.join(DATASITE_JSON), payload)?;
    Ok(())
}

fn export_public_bundle(identity: &str, bundle: &Value, data_root: &Path) -> Result<PathBuf> {
    // Ensure bundles live under the datasites root even if the caller passes a
    // top-level data dir without an existing datasites folder yet.
    let base = resolve_encrypted_root(data_root);
    let public_dir = base.join(identity).join(PUBLIC_DID_RELATIVE);
    if let Some(parent) = public_dir.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory: {}", parent.display()))?;
    }
    fs::write(&public_dir, serde_json::to_vec_pretty(bundle)?)
        .with_context(|| format!("failed to export bundle to {}", public_dir.display()))?;
    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] export_public_bundle: identity={} public_path={}",
            identity,
            public_dir.display()
        );
    }
    Ok(public_dir)
}

fn parse_public_bundle_from_str(body: &str) -> Result<PublicBundleInfo> {
    parse_public_bundle(body).map_err(|err| anyhow!("invalid bundle: {err}"))
}

/// Parse a public bundle JSON file into structured info (identity, fingerprint, DID, bundle).
pub fn parse_public_bundle_file(path: &Path) -> Result<PublicBundleInfo> {
    let body = fs::read_to_string(path)
        .with_context(|| format!("failed to read bundle at {}", path.display()))?;
    parse_public_bundle_from_str(&body)
}

/// Validate that a private key file is parseable by the current sbc key format.
///
/// This is used by callers to detect legacy/unreadable key material and trigger
/// recovery/onboarding flows.
pub fn validate_private_key_file(path: &Path) -> Result<()> {
    load_private_keys_from_file(path)
        .with_context(|| format!("failed to parse private key file: {}", path.display()))?;
    Ok(())
}

fn resolve_vault_path(vault_override: Option<&Path>) -> PathBuf {
    if let Some(v) = vault_override {
        return v.to_path_buf();
    }
    if let Some(env_vault) = std::env::var_os("SBC_VAULT") {
        return PathBuf::from(env_vault);
    }
    // Default to global ~/.sbc to avoid accidental churn; callers can override via SBC_VAULT or explicit arg.
    dirs::home_dir()
        .map(|h| h.join(".sbc"))
        .unwrap_or_else(|| PathBuf::from(".sbc"))
}

fn sbc_debug_enabled() -> bool {
    env::var_os("BIOVAULT_DEV_SYFTBOX").is_some() || env::var_os("SYFTBOX_DEBUG_CRYPTO").is_some()
}

/// Detect identity from vault, handling multiple keys gracefully.
///
/// If multiple .key files exist, warns and returns the first one alphabetically.
/// This is an improved version that doesn't error on multiple identities.
pub fn detect_identity(vault: &Path) -> Result<String> {
    use syft_crypto_protocol::datasite::context::{
        fallback_identity_from_path, read_identity_from_key,
    };

    let keys_dir = vault.join("keys");
    let mut identities: Vec<(String, PathBuf)> = Vec::new();

    if keys_dir.exists() {
        for entry in fs::read_dir(&keys_dir)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_file() {
                // Only consider .key files (skip backups like .key.backup)
                if path.extension().and_then(|e| e.to_str()) == Some("key") {
                    let identity = read_identity_from_key(path.clone())
                        .unwrap_or_else(|_| fallback_identity_from_path(path.clone()));
                    identities.push((identity, path));
                }
            }
        }
    }

    // Sort for consistent selection when multiple keys exist
    identities.sort_by(|a, b| a.0.cmp(&b.0));

    match identities.len() {
        0 => Err(anyhow!(
            "no identities found in vault (run `sbc key generate` first)"
        )),
        1 => Ok(identities.remove(0).0),
        _ => {
            // Multiple keys found - warn and use the first one (sorted alphabetically)
            eprintln!(
                "⚠️  Warning: Multiple identity keys found in vault ({}):",
                vault.display()
            );
            for (identity, path) in &identities {
                eprintln!("    - {} ({})", identity, path.display());
            }
            let selected = identities.remove(0);
            eprintln!(
                "    Using first identity: {} (to change, specify --sender/--identity or remove extra .key files)",
                selected.0
            );
            Ok(selected.0)
        }
    }
}

/// Resolve identity: use provided identity or detect from vault.
///
/// This wraps detect_identity with the option to provide an explicit identity.
pub fn resolve_identity(provided: Option<&str>, vault: &Path) -> Result<String> {
    match provided {
        Some(identity) => Ok(identity.to_owned()),
        None => detect_identity(vault),
    }
}

// =============================================================================
// Bundle Resolution with Typed Errors
// =============================================================================

use std::fmt;
use syft_crypto_protocol::datasite::context::AppContext;
use syft_crypto_protocol::datasite::crypto::load_cached_bundle;
use syft_crypto_protocol::envelope::ParsedEnvelope;
use syft_crypto_protocol::SyftPublicKeyBundle;

/// Information about a bundle available in a datasite's public directory.
#[derive(Debug, Clone)]
pub struct DatasiteBundleInfo {
    pub identity: String,
    pub fingerprint: String,
    pub matches_expected: bool,
    pub path: PathBuf,
}

/// Typed errors for bundle resolution - allows callers to decide policy.
///
/// Unlike the base crypto library which just returns anyhow errors,
/// this enum provides structured information about what went wrong
/// and what alternatives are available, letting callers make policy
/// decisions (e.g., whether to auto-import from datasite).
#[derive(Debug, Clone)]
pub enum BundleResolutionError {
    /// No bundle found in vault cache for this identity.
    NotCached {
        identity: String,
        /// Bundle available in datasite directory (caller can import if desired)
        datasite_available: Option<Box<DatasiteBundleInfo>>,
    },
    /// Cached bundle fingerprint doesn't match envelope's expected fingerprint.
    FingerprintMismatch {
        identity: String,
        expected: String,
        cached: String,
        /// Bundle available in datasite directory (caller can import if desired)
        datasite_available: Option<Box<DatasiteBundleInfo>>,
    },
    /// Error loading or parsing bundle.
    LoadError { identity: String, source: String },
}

impl fmt::Display for BundleResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCached {
                identity,
                datasite_available,
            } => {
                write!(f, "sender bundle not cached for {}", identity)?;
                if let Some(info) = datasite_available {
                    write!(
                        f,
                        " (datasite bundle available at {}, fingerprint: {}, matches: {})",
                        info.path.display(),
                        info.fingerprint,
                        info.matches_expected
                    )?;
                }
                Ok(())
            }
            Self::FingerprintMismatch {
                identity,
                expected,
                cached,
                datasite_available,
            } => {
                write!(
                    f,
                    "sender bundle fingerprint mismatch for {}: expected {}, cached {}",
                    identity, expected, cached
                )?;
                if let Some(info) = datasite_available {
                    write!(
                        f,
                        " (datasite bundle available at {}, fingerprint: {}, matches: {})",
                        info.path.display(),
                        info.fingerprint,
                        info.matches_expected
                    )?;
                }
                Ok(())
            }
            Self::LoadError { identity, source } => {
                write!(f, "failed to load bundle for {}: {}", identity, source)
            }
        }
    }
}

impl std::error::Error for BundleResolutionError {}

/// Load a public bundle from a datasite's public crypto directory.
///
/// Looks for bundle at `{data_root}/{identity}/public/crypto/did.json`.
/// Returns the parsed bundle info and raw body (for caching by caller if desired).
pub fn load_datasite_bundle(
    data_root: &Path,
    identity: &str,
) -> Result<Option<(PublicBundleInfo, String)>> {
    let path = data_root.join(identity).join(PUBLIC_DID_RELATIVE);

    if !path.exists() {
        return Ok(None);
    }

    let body = fs::read_to_string(&path)
        .with_context(|| format!("failed to read DID bundle at {}", path.display()))?;
    let info = parse_public_bundle(&body)
        .map_err(|e| anyhow!("invalid DID bundle at {}: {e}", path.display()))?;

    if info.identity != identity {
        return Err(anyhow!(
            "datasite bundle identity mismatch: expected {}, found {} at {}",
            identity,
            info.identity,
            path.display()
        ));
    }

    Ok(Some((info, body)))
}

/// Path to a datasite's public bundle.
pub fn datasite_bundle_path(data_root: &Path, identity: &str) -> PathBuf {
    data_root.join(identity).join(PUBLIC_DID_RELATIVE)
}

/// Resolve sender bundle for decryption with typed errors.
///
/// This is the SDK-level wrapper around the crypto library's bundle resolution.
/// It provides typed errors that allow callers to make policy decisions about
/// what to do when bundles are missing or mismatched.
///
/// Unlike the base crypto library, this function:
/// - Does NOT auto-import from datasite (caller decides)
/// - Returns structured errors with datasite availability info
/// - Validates fingerprints against envelope expectations
///
/// # Returns
/// - `Ok(bundle)` if a matching bundle is found in vault cache
/// - `Err(NotCached { datasite_available })` if no cache, with datasite info
/// - `Err(FingerprintMismatch { ... })` if cache exists but fingerprint wrong
pub fn resolve_sender_bundle(
    context: &AppContext,
    parsed: &ParsedEnvelope,
) -> std::result::Result<SyftPublicKeyBundle, BundleResolutionError> {
    let sender_identity = &parsed.prelude.sender.identity;
    let expected_fp = parsed.prelude.sender.ik_fingerprint.as_str();

    // Check datasite bundle availability (for error reporting)
    let datasite_info = match load_datasite_bundle(&context.data_root, sender_identity) {
        Ok(Some((info, _body))) => {
            let matches = expected_fp.is_empty() || info.fingerprint == expected_fp;
            if sbc_debug_enabled() && !matches {
                eprintln!(
                    "[sbc][debug] datasite bundle fingerprint mismatch for {}: expected {}, datasite {}",
                    sender_identity, expected_fp, info.fingerprint
                );
            }
            Some(Box::new(DatasiteBundleInfo {
                identity: info.identity,
                fingerprint: info.fingerprint,
                matches_expected: matches,
                path: datasite_bundle_path(&context.data_root, sender_identity),
            }))
        }
        Ok(None) => None,
        Err(e) => {
            if sbc_debug_enabled() {
                eprintln!(
                    "[sbc][debug] failed to load datasite bundle for {}: {}",
                    sender_identity, e
                );
            }
            None
        }
    };

    // Try cached bundle from vault
    let cached_result = load_cached_bundle(context, sender_identity);
    let cached_info = match cached_result {
        Ok(info) => info,
        Err(e) => {
            return Err(BundleResolutionError::LoadError {
                identity: sender_identity.clone(),
                source: e.to_string(),
            });
        }
    };

    match cached_info {
        Some(info) => {
            // Validate identity matches
            if info.identity != *sender_identity {
                return Err(BundleResolutionError::LoadError {
                    identity: sender_identity.clone(),
                    source: format!(
                        "cached bundle identity mismatch: expected {}, found {}",
                        sender_identity, info.identity
                    ),
                });
            }

            // Check fingerprint (empty expected_fp means accept any)
            if expected_fp.is_empty() || info.fingerprint == expected_fp {
                return Ok(info.bundle);
            }

            // Fingerprint mismatch - TOFU violation
            if sbc_debug_enabled() {
                eprintln!(
                    "[sbc][debug] cached bundle fingerprint mismatch for {}: expected {}, cached {}",
                    sender_identity, expected_fp, info.fingerprint
                );
            }

            Err(BundleResolutionError::FingerprintMismatch {
                identity: sender_identity.clone(),
                expected: expected_fp.to_string(),
                cached: info.fingerprint,
                datasite_available: datasite_info,
            })
        }
        None => {
            // No cached bundle
            Err(BundleResolutionError::NotCached {
                identity: sender_identity.clone(),
                datasite_available: datasite_info,
            })
        }
    }
}

/// Cache a bundle from datasite to vault.
///
/// This is a separate function so callers can explicitly decide when to import.
/// It does NOT happen automatically during resolution.
pub fn cache_bundle_from_datasite(
    vault_path: &Path,
    data_root: &Path,
    identity: &str,
) -> Result<PublicBundleInfo> {
    let (info, body) = load_datasite_bundle(data_root, identity)?
        .ok_or_else(|| anyhow!("no datasite bundle found for {}", identity))?;

    let slug = sanitize_identity(identity);
    let target = vault_path.join("bundles").join(format!("{slug}.json"));

    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&target, body.as_bytes())
        .with_context(|| format!("failed to cache bundle to {}", target.display()))?;

    if sbc_debug_enabled() {
        eprintln!(
            "[sbc][debug] cached bundle for {} from datasite to {}",
            identity,
            target.display()
        );
    }

    Ok(info)
}
