use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use syft_crypto_protocol::datasite::context::{ensure_vault_layout, sanitize_identity};
use syft_crypto_protocol::datasite::crypto::{parse_public_bundle, PublicBundleInfo};
use syft_crypto_protocol::identity::{
    generate_identity_material, identity_material_from_recovery_key,
};
use syft_crypto_protocol::SyftRecoveryKey;

const VAULT_DIR_NAME: &str = ".syc";
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

    Ok(IdentityProvisioningOutcome {
        identity: identity.to_string(),
        generated,
        recovery_mnemonic: Some(material.recovery_key_mnemonic),
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

fn resolve_vault_path(vault_override: Option<&Path>) -> PathBuf {
    if let Some(v) = vault_override {
        return v.to_path_buf();
    }
    if let Some(env_vault) = std::env::var_os("SYC_VAULT") {
        return PathBuf::from(env_vault);
    }
    // Default to global ~/.syc to avoid accidental churn; callers can override via SYC_VAULT or explicit arg.
    dirs::home_dir()
        .map(|h| h.join(".syc"))
        .unwrap_or_else(|| PathBuf::from(".syc"))
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
            "no identities found in vault (run `syc key generate` first)"
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
