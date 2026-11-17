#!/usr/bin/env bash
# Rebuild src/browser-tls-rustls/ from packages/lite/rust/browser-tls-rustls.
#
# Output must not depend on the machine: no home directory, no checkout path.
# rustc embeds the path of every source file it compiles (panic locations), so
# this script remaps the three prefixes that vary between machines, then
# refuses to finish if any home path is left in the binary.
set -euo pipefail

lite_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate_dir="$lite_dir/rust/browser-tls-rustls"
out_dir="$lite_dir/src/browser-tls-rustls"
repo_root="$(cd "$lite_dir/../.." && pwd)"

cd "$crate_dir"

# rust-toolchain.toml pins the compiler. rustup does not install it on demand.
if ! rustc --version >/dev/null 2>&1; then
  rustup toolchain install --profile minimal
fi

# One source of truth for the CLI version: the wasm-bindgen crate in Cargo.lock.
wbg_version="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/[^0-9.]/, "", $0); print; exit }' Cargo.lock)"
wbg_cli="${WASM_BINDGEN:-wasm-bindgen}"
if [ "$("$wbg_cli" --version 2>/dev/null | awk '{ print $2 }')" != "$wbg_version" ]; then
  echo "error: need wasm-bindgen CLI $wbg_version to match Cargo.lock." >&2
  echo "  Download the prebuilt release for your platform:" >&2
  echo "  https://github.com/wasm-bindgen/wasm-bindgen/releases/tag/$wbg_version" >&2
  echo "  (not 'cargo install': that build stamps different metadata into the wasm)" >&2
  echo "  (set WASM_BINDGEN to use a CLI that is not on PATH)" >&2
  exit 1
fi

# Later --remap-path-prefix flags win, so list the broadest prefix first.
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
sysroot="$(rustc --print sysroot)"
export RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$repo_root=/src --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rustup"

target_dir="${CARGO_TARGET_DIR:-$crate_dir/target}"
CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --target wasm32-unknown-unknown

staging="$(mktemp -d)"
trap 'rm -rf "$staging"' EXIT
"$wbg_cli" --target web --out-dir "$staging" --out-name browser_tls_rustls \
  "$target_dir/wasm32-unknown-unknown/release/browser_tls_rustls.wasm"

mkdir -p "$out_dir"
cp "$staging/browser_tls_rustls_bg.wasm" "$out_dir/browser_tls_rustls_bg.wasm"
cp "$staging/browser_tls_rustls.d.ts" "$out_dir/browser_tls_rustls.d.ts"
# The glue is generated code: keep ESLint out of it.
{ echo "/* eslint-disable */"; cat "$staging/browser_tls_rustls.js"; } >"$out_dir/browser_tls_rustls.js"

"$repo_root/scripts/check-binary-home-paths.sh" "$out_dir/browser_tls_rustls_bg.wasm"
echo "built $out_dir/browser_tls_rustls_bg.wasm (wasm-bindgen $wbg_version, $(rustc --version))"
