use std::path::{Path, PathBuf};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use syftbox_sdk::{
    default_syftbox_config_path, load_runtime_config, syftbox::storage::SyftStorageConfig,
    SyftBoxApp, SyftBoxStorage, SyftURL as CoreSyftURL, SyftboxRuntimeConfig,
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

#[pyclass(name = "SyftBoxApp", module = "syftbox_sdk", unsendable)]
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
}

#[pyclass(name = "SyftBoxStorage", module = "syftbox_sdk", unsendable)]
#[derive(Clone)]
struct PySyftBoxStorage {
    inner: SyftBoxStorage,
}

#[pymethods]
impl PySyftBoxStorage {
    #[new]
    #[pyo3(signature = (root, vault_path=None, disable_crypto=false))]
    fn new(root: String, vault_path: Option<String>, disable_crypto: bool) -> PyResult<Self> {
        let config = SyftStorageConfig {
            vault_path: vault_path.map(PathBuf::from),
            disable_crypto,
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

#[pymodule]
fn syftbox_sdk(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<SyftURL>()?;
    m.add_class::<PySyftRuntimeConfig>()?;
    m.add_class::<PySyftBoxApp>()?;
    m.add_class::<PySyftBoxStorage>()?;

    m.add_function(wrap_pyfunction!(build_syft_url, m)?)?;
    m.add_function(wrap_pyfunction!(parse_syft_url, m)?)?;
    m.add_function(wrap_pyfunction!(default_config_path, m)?)?;
    m.add_function(wrap_pyfunction!(load_runtime, m)?)?;

    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "__doc__",
        "Python bindings for the syftbox-sdk Rust library using PyO3.",
    )?;

    // Silence unused variable lint in case PyO3 adds new requirements.
    let _ = py;
    Ok(())
}
