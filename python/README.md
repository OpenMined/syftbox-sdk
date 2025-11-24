# syftbox-sdk Python bindings

Python bindings for the `syftbox-sdk` Rust library, built with [PyO3](https://pyo3.rs/) and packaged via [maturin](https://www.maturin.rs/).

## Building and installing

```bash
# from the repository root
cd python
maturin develop  # or `maturin build` to create wheels under target/wheels/
```

If you prefer pip:

```bash
cd python
pip install .
```

## Usage

```python
import syftbox_sdk as syft

url = syft.SyftURL.parse("syft://user@example.com/public/data/file.yaml")
print(url.to_http_relay_url("syftbox.net"))

cfg = syft.load_runtime("user@example.com")
print(cfg.data_dir)

app = syft.SyftBoxApp("/tmp/data", "user@example.com", "my_app")
print(app.list_endpoints())
```
