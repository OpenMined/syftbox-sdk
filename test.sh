#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Running standard tests..."
cargo test

echo ""
echo "Running embedded tests (single-threaded)..."
# NOTE: Embedded tests share a process-global EMBEDDED_DAEMON singleton,
# so they MUST run with --test-threads=1 to avoid race conditions.
cargo test --features embedded -- --test-threads=1
