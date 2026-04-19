#!/usr/bin/env bash
# PR #28.2 wasm-pack driver for openhost-pkarr-wasm.
#
# Builds the shim with `wasm-pack build --target web` and drops the
# resulting pkg into `extension/wasm/pkg/`, which `extension/src/dev/
# resolver-probe.js` imports from.
#
# Prerequisites (install once):
#   - Rust toolchain matching `rust-toolchain.toml`
#   - rustup target add wasm32-unknown-unknown
#   - cargo install wasm-pack   (or the init.sh installer from
#     https://rustwasm.github.io/wasm-pack/installer/)
#
# The script is intentionally dependency-free on the JS side — `npm`
# is not required. `extension/package.json` just delegates to this
# script so there's a single invocation point.

set -euo pipefail

EXT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$EXT_ROOT/.." && pwd)"
CRATE_DIR="$REPO_ROOT/crates/openhost-pkarr-wasm"
OUT_DIR="$EXT_ROOT/wasm/pkg"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "error: wasm-pack is not installed." >&2
  echo "install: cargo install wasm-pack" >&2
  echo "         or: curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh" >&2
  exit 127
fi

echo "==> wasm-pack build (crate=$CRATE_DIR, out=$OUT_DIR)"
wasm-pack build \
  "$CRATE_DIR" \
  --target web \
  --release \
  --out-dir "$OUT_DIR" \
  --out-name openhost_pkarr

echo ""
echo "==> wasm pkg ready:"
ls -la "$OUT_DIR" || true

cat <<'EOF'

Next steps:
  1. chrome://extensions -> Load unpacked -> select extension/ directory.
  2. Open the service worker's devtools console.
  3. To exercise the four resolver exports, uncomment the probe lines
     at the bottom of extension/src/background.js and reload the
     extension. See extension/src/dev/resolver-probe.js for the
     hardcoded test pubkey.
EOF
