#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_BIN_DIR="${REPO_BIN_DIR:-$ROOT_DIR/.repo-bin}"
REPO_BIN="${REPO_BIN:-$REPO_BIN_DIR/repo}"

mkdir -p "$REPO_BIN_DIR"

if [[ -x "$REPO_BIN" ]]; then
  echo "$REPO_BIN"
else
  if command -v python >/dev/null 2>&1; then
    python - <<'PY'
import pathlib
import urllib.request

dest = pathlib.Path(".repo-bin/repo")
dest.write_bytes(urllib.request.urlopen("https://storage.googleapis.com/git-repo-downloads/repo").read())
dest.chmod(0o755)
print(dest)
PY
  elif command -v curl >/dev/null 2>&1; then
    curl -s https://storage.googleapis.com/git-repo-downloads/repo -o "$REPO_BIN"
    chmod +x "$REPO_BIN"
    echo "$REPO_BIN"
  else
    echo "Missing python or curl to download repo tool." >&2
    exit 1
  fi
fi

repo_cmd="$REPO_BIN"
if command -v python3 >/dev/null 2>&1; then
  repo_cmd="python3 $REPO_BIN"
elif command -v python >/dev/null 2>&1; then
  repo_cmd="python $REPO_BIN"
fi

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "REPO_TOOL=$repo_cmd" >> "$GITHUB_ENV"
fi

echo "$repo_cmd"
