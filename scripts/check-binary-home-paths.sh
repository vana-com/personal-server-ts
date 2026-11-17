#!/usr/bin/env bash
# Fail if a binary carries a home-directory path (/Users/<name>, /home/<name>).
#
# Compiled output embeds the build machine's source paths, so a committed
# binary can leak a username. With no arguments this checks every tracked
# *.wasm, *.node, *.so, *.dylib, *.pyc, *.a, *.rlib, *.o, *.dll, *.exe and *.map
# file; with arguments it checks those files. It prints the file and the number
# of matches, never the matched path.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

if [ "$#" -gt 0 ]; then
  files=("$@")
else
  mapfile -t files < <(git ls-files -- '*.wasm' '*.node' '*.so' '*.dylib' '*.pyc' \
    '*.a' '*.rlib' '*.o' '*.dll' '*.exe' '*.map')
fi

status=0
for file in "${files[@]}"; do
  count="$({ grep -aoE '/(Users|home)/[A-Za-z0-9_.-]+' "$file" || true; } | wc -l)"
  if [ "$count" -gt 0 ]; then
    echo "error: $file contains $count home-directory path(s)" >&2
    status=1
  fi
done

if [ "$status" -ne 0 ]; then
  echo "Rebuild without machine paths (see packages/lite/rust/browser-tls-rustls/README.md) or stop tracking the file." >&2
fi
echo "checked ${#files[@]} binary file(s)"
exit "$status"
