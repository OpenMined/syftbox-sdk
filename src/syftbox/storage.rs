use crate::syftbox::sbc;
use crate::syftbox::sbc::BundleResolutionError;
use anyhow::{anyhow, bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use syft_crypto_protocol::datasite::{
    bytes::{read_bytes, write_bytes, BytesReadOpts, BytesWriteOpts, BytesWriteOutcome},
    context::{bundle_path_for_identity, ensure_vault_layout, resolve_vault, AppContext},
};
use syft_crypto_protocol::envelope::ParsedEnvelope;
use tracing::{instrument, warn};
use walkdir::WalkDir;

/// Result from read_with_shadow when metadata is requested
#[derive(Debug, Clone)]
pub struct ReadWithShadowResult {
    /// Decrypted plaintext data
    pub data: Vec<u8>,
    /// Verified sender identity (email), or "(plaintext)" if file was not encrypted
    pub sender: String,
    /// Sender's identity key fingerprint (SHA256 hex), or "(none)" if file was not encrypted
    pub fingerprint: String,
}

#[derive(Debug, Clone)]
pub struct SyftBoxStorage {
    root: PathBuf,
    backend: StorageBackend,
    debug: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SyftStorageConfig {
    pub vault_path: Option<PathBuf>,
    pub disable_crypto: bool,
    pub debug: bool,
}

fn sbc_paths_match(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => left == right,
    }
}

fn looks_like_sbc_envelope(bytes: &[u8]) -> bool {
    syft_crypto_protocol::envelope::has_sbc_magic(bytes)
}

#[derive(Debug, Clone, Copy)]
pub enum ReadPolicy {
    AllowPlaintext,
    RequireEnvelope,
}

#[derive(Debug, Clone)]
pub enum WritePolicy {
    Plaintext,
    Envelope {
        recipients: Vec<String>,
        hint: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum StorageBackend {
    SbctCrypto(SbctCryptoBackend),
    PlainFs,
}

#[derive(Debug, Clone)]
struct SbctCryptoBackend {
    context: AppContext,
}

impl SyftBoxStorage {
    pub fn new(root: &Path) -> Self {
        Self::with_config(root, &SyftStorageConfig::default())
    }

    pub fn with_config(root: &Path, config: &SyftStorageConfig) -> Self {
        let disable_crypto = config.disable_crypto
            || cfg!(feature = "test-plaintext")
            || env::var("SYFTBOX_DISABLE_SBC")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            || cfg!(test);
        let debug = config.debug
            || env::var_os("BIOVAULT_DEV_SYFTBOX").is_some()
            || env::var_os("SYFTBOX_DEBUG_CRYPTO").is_some();

        let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let encrypted_root = sbc::resolve_encrypted_root(&canonical_root);

        let backend = if disable_crypto {
            StorageBackend::PlainFs
        } else {
            SbctCryptoBackend::new(&encrypted_root, config.vault_path.as_deref())
                .map(StorageBackend::SbctCrypto)
                .unwrap_or_else(|err| {
                    warn!(
                        "sbc backend unavailable ({}); falling back to plaintext filesystem access",
                        err
                    );
                    StorageBackend::PlainFs
                })
        };

        if debug {
            match &backend {
                StorageBackend::SbctCrypto(b) => {
                    eprintln!(
                        "[sbc][debug] SyftBoxStorage initialized: root={} crypto=true vault_path={} data_root={} shadow_root={}",
                        encrypted_root.display(),
                        b.context.vault_path.display(),
                        b.context.data_root.display(),
                        b.context.shadow_root.display()
                    );
                }
                StorageBackend::PlainFs => {
                    eprintln!(
                        "[sbc][debug] SyftBoxStorage initialized: root={} crypto=false",
                        encrypted_root.display()
                    );
                }
            }
        }

        Self {
            root: encrypted_root,
            backend,
            debug,
        }
    }

    pub fn uses_crypto(&self) -> bool {
        matches!(self.backend, StorageBackend::SbctCrypto(_))
    }

    pub fn write_plaintext_file(
        &self,
        absolute_path: &Path,
        data: &[u8],
        overwrite: bool,
    ) -> Result<()> {
        self.write_with_policy(absolute_path, data, WritePolicy::Plaintext, overwrite)?;
        Ok(())
    }

    pub fn write_encrypted_file(
        &self,
        absolute_path: &Path,
        data: &[u8],
        recipients: Vec<String>,
        hint: Option<String>,
        overwrite: bool,
    ) -> Result<()> {
        self.write_with_policy(
            absolute_path,
            data,
            WritePolicy::Envelope { recipients, hint },
            overwrite,
        )?;
        Ok(())
    }

    /// Write encrypted file using shadow folder pattern:
    /// 1. Write plaintext to shadow folder
    /// 2. Encrypt from shadow → datasites
    #[instrument(skip(self, data), fields(component = "storage", size = data.len(), encrypted = true), err)]
    pub fn write_encrypted_with_shadow(
        &self,
        datasite_path: &Path,
        data: &[u8],
        recipients: Vec<String>,
        hint: Option<String>,
        overwrite: bool,
    ) -> Result<()> {
        if recipients.is_empty() {
            bail!("at least one recipient is required for encryption");
        }

        match &self.backend {
            StorageBackend::SbctCrypto(backend) => {
                // Get relative path from datasite root
                let relative = self.relative_from_root(datasite_path)?;

                // Write plaintext to shadow folder
                use syft_crypto_protocol::datasite::context::resolve_shadow_path;
                let shadow_path = resolve_shadow_path(&backend.context, &relative);
                if let Some(parent) = shadow_path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("failed to create shadow parent {:?}", parent))?;
                }
                fs::write(&shadow_path, data).with_context(|| {
                    format!("failed to write plaintext to shadow {:?}", shadow_path)
                })?;
                // Encrypt from shadow to datasites through the unified write path,
                // which supports multi-recipient envelopes.
                self.write_with_policy(
                    datasite_path,
                    data,
                    WritePolicy::Envelope { recipients, hint },
                    overwrite,
                )?;
                Ok(())
            }
            StorageBackend::PlainFs => {
                // Fallback to direct write for PlainFs backend
                self.write_plaintext_file(datasite_path, data, overwrite)
            }
        }
    }

    pub fn read_plaintext_file(&self, absolute_path: &Path) -> Result<Vec<u8>> {
        self.read_with_policy(absolute_path, ReadPolicy::AllowPlaintext)
    }

    /// Read encrypted file using shadow folder pattern:
    /// 1. Decrypt from datasites → shadow
    /// 2. Read plaintext from shadow
    #[instrument(skip(self), fields(component = "storage"), err)]
    pub fn read_with_shadow(&self, datasite_path: &Path) -> Result<Vec<u8>> {
        match &self.backend {
            StorageBackend::SbctCrypto(backend) => {
                // Get relative path from datasite root
                let relative = self.relative_from_root(datasite_path)?;
                use syft_crypto_protocol::datasite::context::resolve_shadow_path;
                let shadow_path = resolve_shadow_path(&backend.context, &relative);
                if self.debug {
                    eprintln!("DEBUG read_with_shadow:");
                    eprintln!("  datasite: {:?}", datasite_path);
                    eprintln!("  relative: {:?}", relative);
                    eprintln!("  shadow: {:?}", shadow_path);
                    eprintln!("  shadow_root: {:?}", backend.context.shadow_root);
                }

                // If shadow copy exists and is newer, use it
                if shadow_path.exists() && datasite_path.exists() {
                    let shadow_meta = fs::metadata(&shadow_path)?;
                    let datasite_meta = fs::metadata(datasite_path)?;
                    if shadow_meta.modified()? >= datasite_meta.modified()? {
                        return fs::read(&shadow_path).with_context(|| {
                            format!("failed to read from shadow {:?}", shadow_path)
                        });
                    }
                }

                // Decrypt from datasites to shadow using sbc file decrypt pattern
                use crate::syftbox::sbc::resolve_sender_bundle;
                use syft_crypto_protocol::datasite::crypto::{
                    decrypt_envelope_for_recipient, load_private_keys_for_identity,
                    parse_optional_envelope,
                };

                let bytes = fs::read(datasite_path)?;

                // Try to decrypt - ONLY cache if we get plaintext
                let envelope = parse_optional_envelope(&bytes)?;
                if self.debug {
                    if let Some(env) = &envelope {
                        eprintln!(
                            "[sbc][debug] read_with_shadow: encrypted sender={} sender_fp={} recipients={} path={}",
                            env.prelude.sender.identity,
                            env.prelude.sender.ik_fingerprint,
                            env.prelude.recipients.len(),
                            datasite_path.display()
                        );
                    } else {
                        eprintln!(
                            "[sbc][debug] read_with_shadow: plaintext path={}",
                            datasite_path.display()
                        );
                    }
                }

                let plaintext = if let Some(envelope) = envelope {
                    // File is encrypted, MUST decrypt successfully to cache
                    let identity = sbc::resolve_identity(None, &backend.context.vault_path)?;
                    let recipient_keys =
                        load_private_keys_for_identity(&backend.context, &identity)?;
                    let sender_bundle = match resolve_sender_bundle(&backend.context, &envelope) {
                        Ok(bundle) => bundle,
                        Err(err) => {
                            log_bundle_resolution_error(
                                self.debug,
                                &err,
                                &backend.context,
                                &envelope,
                                datasite_path,
                            );
                            return Err(err.into());
                        }
                    };
                    if self.debug {
                        eprintln!(
                            "[sbc][debug] read_with_shadow: decrypt as identity={} sender_bundle_fp={}",
                            identity,
                            sender_bundle.identity_fingerprint()
                        );
                    }
                    decrypt_envelope_for_recipient(
                        &identity,
                        &recipient_keys,
                        &sender_bundle,
                        &envelope,
                    )?
                } else {
                    // File is plaintext
                    bytes
                };

                // Cache ONLY successfully decrypted plaintext
                if let Some(parent) = shadow_path.parent() {
                    match fs::create_dir_all(parent) {
                        Ok(_) => {
                            if self.debug {
                                eprintln!("  ✓ Created shadow parent: {:?}", parent);
                            }
                        }
                        Err(e) => {
                            if self.debug {
                                eprintln!(
                                    "  ✗ Failed to create shadow parent: {:?}: {}",
                                    parent, e
                                );
                            }
                        }
                    }
                }
                match fs::write(&shadow_path, &plaintext) {
                    Ok(_) => {
                        if self.debug {
                            eprintln!("✓ Cached PLAINTEXT to shadow: {:?}", shadow_path);
                        }
                        // Sanity check: ensure we didn't cache encrypted data
                        if looks_like_sbc_envelope(&plaintext) {
                            panic!(
                                "BUG: Cached encrypted data to shadow folder! Path: {:?}",
                                shadow_path
                            );
                        }
                    }
                    Err(e) => {
                        if self.debug {
                            eprintln!("✗ Failed to cache shadow: {:?}: {}", shadow_path, e);
                        }
                    }
                }

                Ok(plaintext)
            }
            StorageBackend::PlainFs => {
                // Fallback to direct read for PlainFs backend
                self.read_plaintext_file(datasite_path)
            }
        }
    }

    /// Read encrypted file using shadow folder pattern, returning metadata about the sender.
    /// This is the same as read_with_shadow but also returns verified sender identity.
    #[instrument(skip(self), fields(component = "storage"), err)]
    pub fn read_with_shadow_metadata(&self, datasite_path: &Path) -> Result<ReadWithShadowResult> {
        match &self.backend {
            StorageBackend::SbctCrypto(backend) => {
                // Get relative path from datasite root
                let relative = self.relative_from_root(datasite_path)?;
                use syft_crypto_protocol::datasite::context::resolve_shadow_path;
                let shadow_path = resolve_shadow_path(&backend.context, &relative);

                // Decrypt from datasites to shadow using sbc file decrypt pattern
                use crate::syftbox::sbc::resolve_sender_bundle;
                use syft_crypto_protocol::datasite::crypto::{
                    decrypt_envelope_for_recipient, load_private_keys_for_identity,
                    parse_optional_envelope,
                };

                let bytes = fs::read(datasite_path)?;
                let envelope = parse_optional_envelope(&bytes)?;

                if let Some(envelope) = envelope {
                    if self.debug {
                        eprintln!(
                            "[sbc][debug] read_with_shadow_metadata: encrypted sender={} sender_fp={} recipients={} path={}",
                            envelope.prelude.sender.identity,
                            envelope.prelude.sender.ik_fingerprint,
                            envelope.prelude.recipients.len(),
                            datasite_path.display()
                        );
                    }
                    // Extract sender metadata from the envelope prelude
                    let sender_identity = envelope.prelude.sender.identity.clone();
                    let sender_fingerprint = envelope.prelude.sender.ik_fingerprint.clone();

                    // File is encrypted, decrypt it
                    let identity = sbc::resolve_identity(None, &backend.context.vault_path)?;
                    let recipient_keys =
                        load_private_keys_for_identity(&backend.context, &identity)?;
                    let sender_bundle = match resolve_sender_bundle(&backend.context, &envelope) {
                        Ok(bundle) => bundle,
                        Err(err) => {
                            log_bundle_resolution_error(
                                self.debug,
                                &err,
                                &backend.context,
                                &envelope,
                                datasite_path,
                            );
                            return Err(err.into());
                        }
                    };
                    if self.debug {
                        eprintln!(
                            "[sbc][debug] read_with_shadow_metadata: decrypt as identity={} sender_bundle_fp={}",
                            identity,
                            sender_bundle.identity_fingerprint()
                        );
                    }
                    let plaintext = decrypt_envelope_for_recipient(
                        &identity,
                        &recipient_keys,
                        &sender_bundle,
                        &envelope,
                    )?;

                    // Cache to shadow
                    if let Some(parent) = shadow_path.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    let _ = fs::write(&shadow_path, &plaintext);

                    Ok(ReadWithShadowResult {
                        data: plaintext,
                        sender: sender_identity,
                        fingerprint: sender_fingerprint,
                    })
                } else {
                    // File is plaintext - no sender metadata available
                    Ok(ReadWithShadowResult {
                        data: bytes,
                        sender: "(plaintext)".to_string(),
                        fingerprint: "(none)".to_string(),
                    })
                }
            }
            StorageBackend::PlainFs => {
                // Fallback - no crypto means no sender verification
                let data = fs::read(datasite_path)
                    .with_context(|| format!("failed to read {:?}", datasite_path))?;
                Ok(ReadWithShadowResult {
                    data,
                    sender: "(plaintext)".to_string(),
                    fingerprint: "(none)".to_string(),
                })
            }
        }
    }

    pub fn read_plaintext_string(&self, absolute_path: &Path) -> Result<String> {
        let bytes = self.read_plaintext_file(absolute_path)?;
        let content = String::from_utf8(bytes)
            .with_context(|| format!("failed to decode utf-8 from {:?}", absolute_path))?;
        Ok(content)
    }

    pub fn read_json<T: DeserializeOwned>(
        &self,
        absolute_path: &Path,
        policy: ReadPolicy,
    ) -> Result<T> {
        let bytes = self.read_with_policy(absolute_path, policy)?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse JSON from {:?}", absolute_path))
    }

    /// Read JSON using shadow folder pattern for encrypted files
    pub fn read_json_with_shadow<T: DeserializeOwned>(&self, absolute_path: &Path) -> Result<T> {
        let bytes = self.read_with_shadow(absolute_path)?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse JSON from {:?}", absolute_path))
    }

    /// Write with shadow folder pattern - creates both encrypted file and plaintext shadow
    /// This makes unencrypted/ a true mirror of datasites/
    #[instrument(skip(self, plaintext), fields(component = "storage", size = plaintext.len()), err)]
    pub fn write_with_shadow(
        &self,
        absolute_path: &Path,
        plaintext: &[u8],
        policy: WritePolicy,
        overwrite: bool,
    ) -> Result<BytesWriteOutcome> {
        if self.debug {
            match &policy {
                WritePolicy::Plaintext => {
                    eprintln!(
                        "[sbc][debug] write_with_shadow: plaintext size={} path={}",
                        plaintext.len(),
                        absolute_path.display()
                    );
                }
                WritePolicy::Envelope { recipients, hint } => {
                    eprintln!(
                        "[sbc][debug] write_with_shadow: envelope size={} recipients={} hint={:?} path={}",
                        plaintext.len(),
                        recipients.len(),
                        hint,
                        absolute_path.display()
                    );
                }
            }
        }
        // Check if we'll need to create a shadow (before policy is moved)
        let needs_shadow = matches!(&policy, WritePolicy::Envelope { .. });

        // First write the encrypted file (or plaintext if policy is Plaintext)
        let outcome = self.write_with_policy(absolute_path, plaintext, policy, overwrite)?;

        // If crypto is enabled and we wrote an encrypted file, also cache the plaintext to shadow
        if let StorageBackend::SbctCrypto(ref backend) = self.backend {
            if needs_shadow {
                // Calculate shadow path
                // Normalize paths to handle Windows extended-length path prefix (\\?\)
                let normalized_path = strip_windows_prefix(absolute_path);
                let normalized_root = strip_windows_prefix(&self.root);
                if let Ok(relative) = normalized_path.strip_prefix(&normalized_root) {
                    let shadow_path = backend.context.shadow_root.join(relative);

                    if self.debug {
                        eprintln!("DEBUG write_with_shadow:");
                        eprintln!("  datasite: {:?}", absolute_path);
                        eprintln!("  relative: {:?}", relative);
                        eprintln!("  shadow: {:?}", shadow_path);
                        eprintln!("  shadow_root: {:?}", backend.context.shadow_root);
                    }

                    // Create parent directory for shadow
                    if let Some(shadow_parent) = shadow_path.parent() {
                        if let Err(e) = fs::create_dir_all(shadow_parent) {
                            if self.debug {
                                eprintln!(
                                    "✗ Failed to create shadow parent: {:?}: {}",
                                    shadow_parent, e
                                );
                            }
                        } else if self.debug {
                            eprintln!("  ✓ Created shadow parent: {:?}", shadow_parent);
                        }
                    }

                    // Write plaintext to shadow
                    match fs::write(&shadow_path, plaintext) {
                        Ok(_) => {
                            if self.debug {
                                eprintln!(
                                    "✓ Cached PLAINTEXT to shadow (write): {:?}",
                                    shadow_path
                                );
                            }
                            // Sanity check: ensure we didn't cache encrypted data
                            if looks_like_sbc_envelope(plaintext) {
                                panic!("BUG: Tried to cache encrypted data to shadow folder during write! Path: {:?}", shadow_path);
                            }
                        }
                        Err(e) => {
                            if self.debug {
                                eprintln!(
                                    "✗ Failed to cache shadow (write): {:?}: {}",
                                    shadow_path, e
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(outcome)
    }

    /// Write JSON with shadow folder pattern - creates both encrypted file and plaintext shadow
    pub fn write_json_with_shadow<T: Serialize>(
        &self,
        absolute_path: &Path,
        value: &T,
        policy: WritePolicy,
        overwrite: bool,
    ) -> Result<()> {
        let data = serde_json::to_vec_pretty(value)
            .with_context(|| format!("failed to serialize JSON for {:?}", absolute_path))?;
        self.write_with_shadow(absolute_path, &data, policy, overwrite)?;
        Ok(())
    }

    /// Write JSON using the old method (no shadow) - deprecated, use write_json_with_shadow instead
    pub fn write_json<T: Serialize>(
        &self,
        absolute_path: &Path,
        value: &T,
        policy: WritePolicy,
        overwrite: bool,
    ) -> Result<()> {
        let data = serde_json::to_vec_pretty(value)
            .with_context(|| format!("failed to serialize JSON for {:?}", absolute_path))?;
        self.write_with_policy(absolute_path, &data, policy, overwrite)?;
        Ok(())
    }

    pub fn remove_path(&self, absolute_path: &Path) -> Result<()> {
        self.ensure_within_root(absolute_path)?;

        // Remove the main file/directory if it exists
        if absolute_path.exists() {
            if absolute_path.is_dir() {
                fs::remove_dir_all(absolute_path)
                    .with_context(|| format!("failed to remove directory {:?}", absolute_path))?;
            } else {
                fs::remove_file(absolute_path)
                    .with_context(|| format!("failed to remove file {:?}", absolute_path))?;
            }
        }

        // If crypto is enabled, also remove the corresponding shadow file/directory
        if let StorageBackend::SbctCrypto(ref backend) = self.backend {
            // Calculate shadow path: strip datasites root, add to shadow root
            // Normalize paths to handle Windows extended-length path prefix (\\?\)
            let normalized_path = strip_windows_prefix(absolute_path);
            let normalized_root = strip_windows_prefix(&self.root);
            if let Ok(relative) = normalized_path.strip_prefix(&normalized_root) {
                let shadow_path = backend.context.shadow_root.join(relative);

                if shadow_path.exists() {
                    if shadow_path.is_dir() {
                        fs::remove_dir_all(&shadow_path).with_context(|| {
                            format!("failed to remove shadow directory {:?}", shadow_path)
                        })?;
                        if self.debug {
                            eprintln!("✓ Removed shadow directory: {:?}", shadow_path);
                        }
                    } else {
                        fs::remove_file(&shadow_path).with_context(|| {
                            format!("failed to remove shadow file {:?}", shadow_path)
                        })?;
                        if self.debug {
                            eprintln!("✓ Removed shadow file: {:?}", shadow_path);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn ensure_dir(&self, dir: &Path) -> Result<()> {
        self.ensure_within_root(dir)?;
        fs::create_dir_all(dir).with_context(|| format!("failed to ensure directory {:?}", dir))?;
        Ok(())
    }

    pub fn contains(&self, path: &Path) -> bool {
        // Normalize both paths to handle Windows extended-length path prefix (\\?\)
        let normalized_root = strip_windows_prefix(&self.root);
        let normalized_path = strip_windows_prefix(path);
        normalized_path.starts_with(&normalized_root)
    }

    pub fn list_dir(&self, dir: &Path) -> Result<Vec<PathBuf>> {
        self.ensure_within_root(dir)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            entries.push(entry.path());
        }
        Ok(entries)
    }

    pub fn path_exists(&self, absolute_path: &Path) -> Result<bool> {
        self.ensure_within_root(absolute_path)?;
        Ok(absolute_path.exists())
    }

    pub fn copy_raw_file(&self, src: &Path, dst: &Path) -> Result<()> {
        self.ensure_within_root(src)?;
        self.ensure_within_root(dst)?;
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to ensure parent {:?}", parent))?;
        }
        fs::copy(src, dst).with_context(|| format!("failed to copy {:?} -> {:?}", src, dst))?;
        Ok(())
    }

    pub fn copy_tree<F>(
        &self,
        src: &Path,
        dst: &Path,
        mut skip: F,
        write_policy: WritePolicy,
    ) -> Result<()>
    where
        F: FnMut(&Path) -> bool,
    {
        self.ensure_within_root(src)?;
        self.ensure_within_root(dst)?;
        self.ensure_dir(dst)?;

        for entry in WalkDir::new(src).into_iter().filter_map(|e| e.ok()) {
            let rel = entry
                .path()
                .strip_prefix(src)
                .with_context(|| format!("failed to relativize {:?}", entry.path()))?;
            let target = dst.join(rel);

            if entry.file_type().is_dir() {
                self.ensure_dir(&target)?;
                continue;
            }

            if skip(entry.path()) {
                continue;
            }

            if let Some(parent) = target.parent() {
                self.ensure_dir(parent)?;
            }

            let data = self.read_plaintext_file(entry.path())?;
            self.write_with_policy(&target, &data, write_policy.clone(), true)?;
        }

        Ok(())
    }

    fn write_with_policy(
        &self,
        absolute_path: &Path,
        data: &[u8],
        policy: WritePolicy,
        overwrite: bool,
    ) -> Result<BytesWriteOutcome> {
        let relative = self.relative_from_root(absolute_path)?;
        let (recipients, plaintext, hint) = match policy {
            WritePolicy::Plaintext => (Vec::new(), true, None),
            WritePolicy::Envelope { recipients, hint } => (recipients, false, hint),
        };
        let mut opts = BytesWriteOpts {
            relative,
            recipients,
            sender: None,
            plaintext,
            overwrite,
            hint,
        };
        match &self.backend {
            StorageBackend::SbctCrypto(backend) => {
                if opts.sender.is_none() && !opts.plaintext && !opts.recipients.is_empty() {
                    opts.sender = Some(sbc::resolve_identity(None, &backend.context.vault_path)?);
                }
                write_bytes(&backend.context, &opts, data)
                    .map_err(|err| anyhow!("sbc write failed: {err}"))
            }
            StorageBackend::PlainFs => {
                if absolute_path.exists() && !overwrite {
                    bail!(
                        "refusing to overwrite existing path {:?} without explicit permission",
                        absolute_path
                    );
                }
                if let Some(parent) = absolute_path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("failed to ensure parent {:?}", parent))?;
                }
                fs::write(absolute_path, data)
                    .with_context(|| format!("failed to write {:?}", absolute_path))?;
                Ok(BytesWriteOutcome {
                    destination: absolute_path.to_path_buf(),
                    bytes_written: data.len(),
                    encrypted: false,
                })
            }
        }
    }

    fn read_with_policy(&self, absolute_path: &Path, policy: ReadPolicy) -> Result<Vec<u8>> {
        match &self.backend {
            StorageBackend::SbctCrypto(backend) => {
                let relative = self.relative_from_root(absolute_path)?;
                let identity = sbc::resolve_identity(None, &backend.context.vault_path)?;
                let opts = BytesReadOpts {
                    relative,
                    identity: Some(identity),
                    require_envelope: matches!(policy, ReadPolicy::RequireEnvelope),
                };
                let result = read_bytes(&backend.context, &opts)
                    .map_err(|err| anyhow!("sbc read failed: {err}"))?;
                Ok(result.plaintext)
            }
            StorageBackend::PlainFs => fs::read(absolute_path)
                .with_context(|| format!("failed to read {:?}", absolute_path)),
        }
    }

    /// Canonicalize path to handle symlinks (e.g., /var -> /private/var on macOS)
    /// For non-existent paths, find first existing ancestor, canonicalize it, and rebuild path
    fn canonicalize_for_comparison(&self, path: &Path) -> PathBuf {
        if path.exists() {
            return path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        }

        // Find first existing ancestor
        let mut current = path;
        let mut components = Vec::new();

        while !current.exists() {
            if let Some(name) = current.file_name() {
                components.push(name);
            }
            if let Some(parent) = current.parent() {
                current = parent;
            } else {
                // No existing ancestor found, return as-is
                return path.to_path_buf();
            }
        }

        // Canonicalize the existing ancestor
        let canonical_base = current
            .canonicalize()
            .unwrap_or_else(|_| current.to_path_buf());

        // Rebuild path from canonical base
        components.reverse();
        let mut result = canonical_base;
        for component in components {
            result = result.join(component);
        }
        result
    }

    fn relative_from_root(&self, absolute: &Path) -> Result<PathBuf> {
        let canonical_absolute = self.canonicalize_for_comparison(absolute);

        // Normalize paths to handle Windows extended-length path prefix (\\?\)
        let normalized_absolute = strip_windows_prefix(&canonical_absolute);
        let normalized_root = strip_windows_prefix(&self.root);

        normalized_absolute
            .strip_prefix(&normalized_root)
            .map(|p| p.to_path_buf())
            .map_err(|_| {
                anyhow!(
                    "path {:?} is outside of SyftBox root {:?}",
                    canonical_absolute,
                    self.root
                )
            })
    }

    fn ensure_within_root(&self, absolute: &Path) -> Result<()> {
        let canonical_absolute = self.canonicalize_for_comparison(absolute);

        // Normalize paths to handle Windows extended-length path prefix (\\?\)
        let normalized_absolute = strip_windows_prefix(&canonical_absolute);
        let normalized_root = strip_windows_prefix(&self.root);

        if normalized_absolute.starts_with(&normalized_root) {
            Ok(())
        } else {
            Err(anyhow!(
                "path {:?} is outside of SyftBox root {:?}",
                canonical_absolute,
                self.root
            ))
        }
    }
}

fn log_bundle_resolution_error(
    debug: bool,
    err: &BundleResolutionError,
    context: &AppContext,
    envelope: &ParsedEnvelope,
    datasite_path: &Path,
) {
    if !debug {
        return;
    }

    let sender_identity = envelope.prelude.sender.identity.as_str();
    let expected_fp = envelope.prelude.sender.ik_fingerprint.as_str();
    let local_bundle_path = bundle_path_for_identity(&context.vault_path, sender_identity);
    let datasite_bundle_path = context
        .data_root
        .join(sender_identity)
        .join("public")
        .join("crypto")
        .join("did.json");

    eprintln!(
        "[sbc][debug] bundle resolution error: sender={} expected_fp={} vault={} local_bundle={} datasite_bundle={} file={}",
        sender_identity,
        expected_fp,
        context.vault_path.display(),
        local_bundle_path.display(),
        datasite_bundle_path.display(),
        datasite_path.display()
    );

    match err {
        BundleResolutionError::NotCached {
            identity,
            datasite_available,
        } => {
            if let Some(info) = datasite_available {
                eprintln!(
                    "[sbc][debug] bundle not cached: identity={} datasite_fp={} datasite_matches={} datasite_path={}",
                    identity,
                    info.fingerprint,
                    info.matches_expected,
                    info.path.display()
                );
            } else {
                eprintln!(
                    "[sbc][debug] bundle not cached: identity={} datasite_fp=none",
                    identity
                );
            }
        }
        BundleResolutionError::FingerprintMismatch {
            identity,
            expected,
            cached,
            datasite_available,
        } => {
            if let Some(info) = datasite_available {
                eprintln!(
                    "[sbc][debug] bundle fingerprint mismatch: identity={} expected={} cached={} datasite_fp={} datasite_matches={} datasite_path={}",
                    identity,
                    expected,
                    cached,
                    info.fingerprint,
                    info.matches_expected,
                    info.path.display()
                );
            } else {
                eprintln!(
                    "[sbc][debug] bundle fingerprint mismatch: identity={} expected={} cached={} datasite_fp=none",
                    identity,
                    expected,
                    cached
                );
            }
        }
        BundleResolutionError::LoadError { identity, source } => {
            eprintln!(
                "[sbc][debug] bundle load error: identity={} source={}",
                identity, source
            );
        }
    }
}

/// Strip Windows extended-length path prefix (\\?\) for consistent path comparison.
/// This handles the case where paths from different sources may have different prefix styles.
fn strip_windows_prefix(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if let Some(stripped) = path_str.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

impl SbctCryptoBackend {
    fn new(root: &Path, vault_override: Option<&Path>) -> Result<Self> {
        let vault_env = env::var_os("SBC_VAULT").map(PathBuf::from);
        let expected_from_data_dir = env::var_os("SYFTBOX_DATA_DIR")
            .map(PathBuf::from)
            .map(|dir| dir.join(".sbc"));
        if let (Some(expected), Some(env_vault)) = (&expected_from_data_dir, &vault_env) {
            if !sbc_paths_match(expected, env_vault) {
                return Err(anyhow!(
                    "SBC_VAULT must match SYFTBOX_DATA_DIR/.sbc (SBC_VAULT={}, expected={})",
                    env_vault.display(),
                    expected.display()
                ));
            }
        }

        if vault_env.is_none()
            && vault_override.is_none()
            && root.file_name().map(|n| n == ".biovault").unwrap_or(false)
        {
            return Err(anyhow!(
                "Refusing to default SBC_VAULT under BIOVAULT_HOME; set SBC_VAULT or SYFTBOX_DATA_DIR"
            ));
        }

        let vault_base = vault_env
            .as_deref()
            .or(vault_override)
            .map(PathBuf::from)
            .or(expected_from_data_dir)
            .unwrap_or_else(|| root.join(".sbc"));
        let vault_path = resolve_vault(Some(vault_base));
        ensure_vault_layout(&vault_path)
            .map_err(|err| anyhow!("failed to prepare sbc vault: {err}"))?;

        let data_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let encrypted_root = sbc::resolve_encrypted_root(&data_root);
        let shadow_root = sbc::shadow_root_for_data_root(&encrypted_root);
        fs::create_dir_all(&shadow_root)
            .with_context(|| format!("failed to prepare shadow root {:?}", shadow_root))?;

        Ok(Self {
            context: AppContext {
                vault_path,
                data_root: encrypted_root,
                shadow_root,
            },
        })
    }
}
