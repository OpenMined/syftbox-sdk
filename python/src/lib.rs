use std::path::{Path, PathBuf};

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

// Avoid name clash with the PyO3 module name by aliasing the Rust crate.
use ::syftbox_sdk as core;
use core::{
    default_syftbox_config_path, load_runtime_config,
    syftbox::storage::{ReadWithShadowResult, SyftStorageConfig, WritePolicy},
    syftbox::syc::{provision_local_identity, import_public_bundle, IdentityProvisioningOutcome},
    SyftBoxApp, SyftBoxStorage, SyftURL as CoreSyftURL,
    SyftboxRuntimeConfig,
};

fn map_err(err: impl std::fmt::Display) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

#[pyclass(name = "SyftURL", module = "syftbox_sdk")]
#[derive(Clone)]
struct SyftURL {
    inner: CoreSyftURL,
}

#[pymethods]
impl SyftURL {
    #[new]
    fn new(email: String, path: String) -> Self {
        Self {
            inner: CoreSyftURL::new(email, path),
        }
    }

    #[staticmethod]
    fn parse(url: &str) -> PyResult<Self> {
        CoreSyftURL::parse(url)
            .map(|inner| Self { inner })
            .map_err(map_err)
    }

    #[staticmethod]
    fn from_http_relay_url(url: &str, relay_server: &str) -> PyResult<Self> {
        CoreSyftURL::from_http_relay_url(url, relay_server)
            .map(|inner| Self { inner })
            .map_err(map_err)
    }

    #[getter]
    fn email(&self) -> String {
        self.inner.email.clone()
    }

    #[getter]
    fn path(&self) -> String {
        self.inner.path.clone()
    }

    #[getter]
    fn fragment(&self) -> Option<String> {
        self.inner.fragment.clone()
    }

    fn with_fragment(&self, fragment: &str) -> Self {
        Self {
            inner: self.inner.clone().with_fragment(fragment.to_string()),
        }
    }

    fn to_http_relay_url(&self, relay_server: &str) -> String {
        self.inner.to_http_relay_url(relay_server)
    }

    fn __str__(&self) -> String {
        self.inner.to_string()
    }

    fn __repr__(&self) -> String {
        format!("SyftURL('{}')", self.inner)
    }
}

#[pyclass(name = "SyftBoxRuntimeConfig", module = "syftbox_sdk")]
#[derive(Clone)]
struct PySyftRuntimeConfig {
    inner: SyftboxRuntimeConfig,
}

#[pymethods]
impl PySyftRuntimeConfig {
    #[getter]
    fn email(&self) -> String {
        self.inner.email.clone()
    }

    #[getter]
    fn config_path(&self) -> String {
        self.inner.config_path.to_string_lossy().into_owned()
    }

    #[getter]
    fn data_dir(&self) -> String {
        self.inner.data_dir.to_string_lossy().into_owned()
    }

    #[getter]
    fn binary_path(&self) -> Option<String> {
        self.inner
            .binary_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[getter]
    fn vault_path(&self) -> Option<String> {
        self.inner
            .vault_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
    }

    #[getter]
    fn disable_crypto(&self) -> bool {
        self.inner.disable_crypto
    }
}

#[pyclass(name = "SyftBoxApp", module = "syftbox_sdk")]
#[derive(Clone)]
struct PySyftBoxApp {
    inner: SyftBoxApp,
}

#[pymethods]
impl PySyftBoxApp {
    #[new]
    fn new(data_dir: String, email: String, app_name: String) -> PyResult<Self> {
        let inner = SyftBoxApp::new(Path::new(&data_dir), &email, &app_name).map_err(map_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn app_name(&self) -> String {
        self.inner.app_name.clone()
    }

    #[getter]
    fn email(&self) -> String {
        self.inner.email.clone()
    }

    #[getter]
    fn data_dir(&self) -> String {
        self.inner.data_dir.to_string_lossy().into_owned()
    }

    #[getter]
    fn rpc_dir(&self) -> String {
        self.inner.rpc_dir.to_string_lossy().into_owned()
    }

    fn register_endpoint(&self, endpoint_name: &str) -> PyResult<String> {
        let path = self
            .inner
            .register_endpoint(endpoint_name)
            .map_err(map_err)?;
        Ok(path.to_string_lossy().into_owned())
    }

    fn endpoint_exists(&self, endpoint_name: &str) -> bool {
        self.inner.endpoint_exists(endpoint_name)
    }

    fn list_endpoints(&self) -> PyResult<Vec<String>> {
        self.inner.list_endpoints().map_err(map_err)
    }

    fn build_syft_url(&self, endpoint_name: &str) -> String {
        self.inner.build_syft_url(endpoint_name)
    }

    /// Ensure a peer can read (and optionally write) under the owner's datasite path.
    #[pyo3(signature = (relative_path, peer_email, allow_write=false))]
    fn ensure_peer_can_read(
        &self,
        relative_path: String,
        peer_email: String,
        allow_write: bool,
    ) -> PyResult<String> {
        let path = self
            .inner
            .ensure_peer_can_read(relative_path, &peer_email, allow_write)
            .map_err(map_err)?;
        Ok(path.to_string_lossy().into_owned())
    }
}

#[pyclass(name = "SyftBoxStorage", module = "syftbox_sdk")]
#[derive(Clone)]
struct PySyftBoxStorage {
    inner: SyftBoxStorage,
}

#[pymethods]
impl PySyftBoxStorage {
    #[new]
    #[pyo3(signature = (root, vault_path=None, disable_crypto=false, debug=false))]
    fn new(root: String, vault_path: Option<String>, disable_crypto: bool, debug: bool) -> PyResult<Self> {
        let config = SyftStorageConfig {
            vault_path: vault_path.map(PathBuf::from),
            disable_crypto,
            debug,
        };
        Ok(Self {
            inner: SyftBoxStorage::with_config(Path::new(&root), &config),
        })
    }

    fn uses_crypto(&self) -> bool {
        self.inner.uses_crypto()
    }

    fn write_text(&self, absolute_path: String, data: String, overwrite: bool) -> PyResult<()> {
        self.inner
            .write_plaintext_file(Path::new(&absolute_path), data.as_bytes(), overwrite)
            .map_err(map_err)
    }

    fn read_text(&self, absolute_path: String) -> PyResult<String> {
        self.inner
            .read_plaintext_string(Path::new(&absolute_path))
            .map_err(map_err)
    }

    fn path_exists(&self, absolute_path: String) -> PyResult<bool> {
        self.inner
            .path_exists(Path::new(&absolute_path))
            .map_err(map_err)
    }

    fn remove_path(&self, absolute_path: String) -> PyResult<()> {
        self.inner
            .remove_path(Path::new(&absolute_path))
            .map_err(map_err)
    }

    fn list_dir(&self, dir: String) -> PyResult<Vec<String>> {
        self.inner
            .list_dir(Path::new(&dir))
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|p| p.to_string_lossy().into_owned())
                    .collect()
            })
            .map_err(map_err)
    }

    /// Write bytes to a file (plaintext mode)
    fn write_bytes(&self, absolute_path: String, data: &[u8], overwrite: bool) -> PyResult<()> {
        self.inner
            .write_plaintext_file(Path::new(&absolute_path), data, overwrite)
            .map_err(map_err)
    }

    /// Read bytes from a file (plaintext mode)
    fn read_bytes<'py>(&self, py: Python<'py>, absolute_path: String) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner
            .read_plaintext_file(Path::new(&absolute_path))
            .map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Write encrypted file using shadow folder pattern.
    /// Writes plaintext to shadow folder, encrypted to datasites.
    #[pyo3(signature = (datasite_path, data, recipients, hint=None, overwrite=true))]
    fn write_encrypted_with_shadow(
        &self,
        datasite_path: String,
        data: &[u8],
        recipients: Vec<String>,
        hint: Option<String>,
        overwrite: bool,
    ) -> PyResult<()> {
        self.inner
            .write_encrypted_with_shadow(
                Path::new(&datasite_path),
                data,
                recipients,
                hint,
                overwrite,
            )
            .map_err(map_err)
    }

    /// Read encrypted file using shadow folder pattern.
    /// Decrypts from datasites to shadow, returns plaintext.
    fn read_with_shadow<'py>(&self, py: Python<'py>, datasite_path: String) -> PyResult<Bound<'py, PyBytes>> {
        let bytes = self.inner
            .read_with_shadow(Path::new(&datasite_path))
            .map_err(map_err)?;
        Ok(PyBytes::new_bound(py, &bytes))
    }

    /// Write with shadow folder pattern - creates both encrypted file and plaintext shadow.
    /// Policy can be "plaintext" or provide recipients list for encryption.
    #[pyo3(signature = (absolute_path, data, recipients=None, hint=None, overwrite=true))]
    fn write_with_shadow(
        &self,
        absolute_path: String,
        data: &[u8],
        recipients: Option<Vec<String>>,
        hint: Option<String>,
        overwrite: bool,
    ) -> PyResult<()> {
        let policy = match recipients {
            Some(r) if !r.is_empty() => WritePolicy::Envelope { recipients: r, hint },
            _ => WritePolicy::Plaintext,
        };
        self.inner
            .write_with_shadow(Path::new(&absolute_path), data, policy, overwrite)
            .map_err(map_err)?;
        Ok(())
    }

    /// Ensure a directory exists
    fn ensure_dir(&self, dir: String) -> PyResult<()> {
        self.inner
            .ensure_dir(Path::new(&dir))
            .map_err(map_err)
    }

    /// Read encrypted file using shadow folder pattern, returning sender metadata.
    /// Returns a ReadWithShadowResult with data, sender identity, and fingerprint.
    fn read_with_shadow_metadata(&self, datasite_path: String) -> PyResult<PyReadWithShadowResult> {
        let result = self.inner
            .read_with_shadow_metadata(Path::new(&datasite_path))
            .map_err(map_err)?;
        Ok(PyReadWithShadowResult { inner: result })
    }
}

/// Result from read_with_shadow_metadata containing decrypted data and verified sender info
#[pyclass(name = "ReadWithShadowResult", module = "syftbox_sdk")]
struct PyReadWithShadowResult {
    inner: ReadWithShadowResult,
}

#[pymethods]
impl PyReadWithShadowResult {
    /// Get the decrypted data as bytes
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new_bound(py, &self.inner.data)
    }

    /// Get the verified sender identity (email)
    /// Returns "(plaintext)" if the file was not encrypted
    #[getter]
    fn sender(&self) -> String {
        self.inner.sender.clone()
    }

    /// Get the sender's identity key fingerprint (SHA256 hex)
    /// Returns "(none)" if the file was not encrypted
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "ReadWithShadowResult(sender='{}', fingerprint='{}...', data_len={})",
            self.inner.sender,
            &self.inner.fingerprint[..std::cmp::min(12, self.inner.fingerprint.len())],
            self.inner.data.len()
        )
    }
}

#[pyfunction]
fn default_config_path() -> PyResult<String> {
    default_syftbox_config_path()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(map_err)
}

#[pyfunction]
fn load_runtime(email: &str) -> PyResult<PySyftRuntimeConfig> {
    load_runtime_config(email)
        .map(|inner| PySyftRuntimeConfig { inner })
        .map_err(map_err)
}

#[pyfunction]
fn build_syft_url(email: &str, path: &str, fragment: Option<&str>) -> PyResult<SyftURL> {
    let mut url = CoreSyftURL::new(email.to_string(), path.to_string());
    if let Some(fragment) = fragment {
        url = url.with_fragment(fragment);
    }
    Ok(SyftURL { inner: url })
}

#[pyfunction]
fn parse_syft_url(url: &str) -> PyResult<SyftURL> {
    SyftURL::parse(url)
}

/// Result of provisioning a local identity
#[pyclass(name = "IdentityProvisioningResult", module = "syftbox_sdk")]
struct PyIdentityProvisioningResult {
    inner: IdentityProvisioningOutcome,
}

#[pymethods]
impl PyIdentityProvisioningResult {
    #[getter]
    fn identity(&self) -> String {
        self.inner.identity.clone()
    }

    #[getter]
    fn generated(&self) -> bool {
        self.inner.generated
    }

    #[getter]
    fn recovery_mnemonic(&self) -> Option<String> {
        self.inner.recovery_mnemonic.clone()
    }

    #[getter]
    fn vault_path(&self) -> String {
        self.inner.vault_path.to_string_lossy().into_owned()
    }

    #[getter]
    fn bundle_path(&self) -> String {
        self.inner.bundle_path.to_string_lossy().into_owned()
    }

    #[getter]
    fn public_bundle_path(&self) -> String {
        self.inner.public_bundle_path.to_string_lossy().into_owned()
    }
}

/// Provision a local identity (generate keypair if needed)
#[pyfunction]
#[pyo3(signature = (identity, data_root, vault_override=None))]
fn provision_identity(
    identity: &str,
    data_root: &str,
    vault_override: Option<&str>,
) -> PyResult<PyIdentityProvisioningResult> {
    let result = provision_local_identity(
        identity,
        Path::new(data_root),
        vault_override.map(Path::new),
    )
    .map_err(map_err)?;
    Ok(PyIdentityProvisioningResult { inner: result })
}

/// Import a peer's public bundle into the vault
#[pyfunction]
#[pyo3(signature = (bundle_path, vault_path, expected_identity=None, export_root=None, refresh_identity=None))]
fn import_bundle(
    bundle_path: &str,
    vault_path: &str,
    expected_identity: Option<&str>,
    export_root: Option<&str>,
    refresh_identity: Option<&str>,
) -> PyResult<String> {
    let info = import_public_bundle(
        Path::new(bundle_path),
        expected_identity,
        Path::new(vault_path),
        export_root.map(Path::new),
        refresh_identity,
    )
    .map_err(map_err)?;
    Ok(info.identity)
}

#[pymodule]
fn syftbox_sdk(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SyftURL>()?;
    m.add_class::<PySyftRuntimeConfig>()?;
    m.add_class::<PySyftBoxApp>()?;
    m.add_class::<PySyftBoxStorage>()?;
    m.add_class::<PyIdentityProvisioningResult>()?;
    m.add_class::<PyReadWithShadowResult>()?;

    m.add_function(wrap_pyfunction!(build_syft_url, m)?)?;
    m.add_function(wrap_pyfunction!(parse_syft_url, m)?)?;
    m.add_function(wrap_pyfunction!(default_config_path, m)?)?;
    m.add_function(wrap_pyfunction!(load_runtime, m)?)?;
    m.add_function(wrap_pyfunction!(provision_identity, m)?)?;
    m.add_function(wrap_pyfunction!(import_bundle, m)?)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "__doc__",
        "Python bindings for the syftbox-sdk Rust library using PyO3.",
    )?;

    Ok(())
}
