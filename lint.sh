#!/usr/bin/env bash
set -euo pipefail

echo "==> cargo fmt (check)"
cargo fmt --all -- --check

echo "==> cargo clippy (warnings as errors)"
cargo clippy --all-targets --all-features --no-deps -- -D warnings

echo "✓ Lint checks passed"
