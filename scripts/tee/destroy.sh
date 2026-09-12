#!/usr/bin/env bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <uuid>" >&2
  exit 1
fi

phala cvms delete "$1" --force
