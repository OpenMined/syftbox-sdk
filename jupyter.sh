#!/bin/bash
set -e

cd "$(dirname "$0")"

uv venv --clear

# Install build tools and dependencies into venv
uv pip install -U maturin jupyter pandas cyvcf2 pytest

# Build syftbox-sdk wheel
cd python
uv run maturin build --release
cd ..

# Install the built wheel
uv pip install --force-reinstall $(find ./python/target/wheels -name "*.whl" | head -1)

uv run jupyter lab
