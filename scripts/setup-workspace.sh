#!/bin/bash
set -euo pipefail

# Setup script for syftbox-sdk workspace
# Clones dependencies to PARENT directory as siblings
#
# Dependencies:
#   - syft-crypto-core (required for crypto protocol)
#   - syftbox (optional, for embedded feature)
#
# In a repo-managed parent workspace (biovault-desktop), dependencies
# are already synced - this script detects that and exits early.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
PARENT_DIR="$(dirname "$REPO_ROOT")"

echo "Setting up syftbox-sdk workspace..."
echo "  REPO_ROOT: $REPO_ROOT"
echo "  PARENT_DIR: $PARENT_DIR"

# Configure git to use HTTPS instead of SSH for GitHub (needed for CI)
# This rewrites git@github.com: URLs to https://github.com/
git config --global url."https://github.com/".insteadOf "git@github.com:"

# Check if we're in a repo-managed workspace (parent has .repo)
if [[ -d "$PARENT_DIR/.repo" ]]; then
    echo "Detected repo-managed parent workspace - dependencies already synced"
    exit 0
fi

# Clone syft-crypto-core (required) to parent directory
if [[ -d "$PARENT_DIR/syft-crypto-core" ]]; then
    echo "syft-crypto-core already exists at $PARENT_DIR/syft-crypto-core"
elif [[ -L "$REPO_ROOT/syft-crypto-core" ]]; then
    # Remove stale symlink if it exists
    echo "Removing stale syft-crypto-core symlink..."
    rm -f "$REPO_ROOT/syft-crypto-core"
    echo "Cloning syft-crypto-core to $PARENT_DIR/syft-crypto-core..."
    git clone --recursive https://github.com/OpenMined/syft-crypto-core.git "$PARENT_DIR/syft-crypto-core"
else
    echo "Cloning syft-crypto-core to $PARENT_DIR/syft-crypto-core..."
    git clone --recursive https://github.com/OpenMined/syft-crypto-core.git "$PARENT_DIR/syft-crypto-core"
fi

# Clone syftbox (for embedded feature) to parent directory
if [[ -d "$PARENT_DIR/syftbox" ]]; then
    echo "syftbox already exists at $PARENT_DIR/syftbox"
elif [[ -L "$REPO_ROOT/syftbox" ]]; then
    # Remove stale symlink if it exists
    echo "Removing stale syftbox symlink..."
    rm -f "$REPO_ROOT/syftbox"
    echo "Cloning syftbox to $PARENT_DIR/syftbox..."
    git clone -b madhava/biovault https://github.com/OpenMined/syftbox.git "$PARENT_DIR/syftbox"
else
    echo "Cloning syftbox to $PARENT_DIR/syftbox..."
    git clone -b madhava/biovault https://github.com/OpenMined/syftbox.git "$PARENT_DIR/syftbox"
fi

echo "Workspace setup complete!"
echo "Dependencies are at:"
echo "  $PARENT_DIR/syft-crypto-core"
echo "  $PARENT_DIR/syftbox"
