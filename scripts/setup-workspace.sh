#!/bin/bash
set -euo pipefail

# Setup script for syftbox-sdk workspace
# Syncs dependencies using the repo tool (with HTTPS for CI)
#
# In a repo-managed parent workspace (biovault-desktop), dependencies
# are already synced - this script detects that and exits early.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PARENT_DIR="$(dirname "$REPO_ROOT")"

echo "Setting up syftbox-sdk workspace..."

# Check if we're in a repo-managed workspace (parent has .repo)
if [[ -d "$PARENT_DIR/.repo" ]]; then
    echo "Detected repo-managed parent workspace - dependencies already synced"
    exit 0
fi

# Check if syft-crypto-core already exists as sibling
if [[ -d "$PARENT_DIR/syft-crypto-core" ]]; then
    echo "syft-crypto-core already exists at $PARENT_DIR/syft-crypto-core"
    exit 0
fi

# Use repo tool if available
if [[ -f "$REPO_ROOT/repo" ]]; then
    echo "Using repo tool to sync dependencies..."
    cd "$REPO_ROOT"
    chmod +x repo

    # Use --https for CI environments (no SSH keys)
    ./repo --init --https
    ./repo sync

    echo "Workspace setup complete!"
    exit 0
fi

# Fallback: clone directly with git (HTTPS for CI compatibility)
echo "Cloning syft-crypto-core to $PARENT_DIR/syft-crypto-core..."
git clone --recursive https://github.com/OpenMined/syft-crypto-core.git "$PARENT_DIR/syft-crypto-core"

echo "Workspace setup complete!"
