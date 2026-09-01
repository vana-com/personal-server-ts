#!/usr/bin/env bash
# Wrapper for the set-resolution experiment against Gemini.
# Usage: scripts/run-setres.sh <label> <out.json> [extra args...]
set -euo pipefail

export INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export INFERENCE_MODEL="${INFERENCE_MODEL:-gemini-3.7-flash}"
export INFERENCE_E2EE=false
export INFERENCE_REQUEST_FIELDS='{"temperature":0}'

LABEL="$1"; shift
OUT="$1"; shift

ENV_FILE=.env
[ -f "$ENV_FILE" ] || ENV_FILE=../../../.env

exec npx tsx --env-file-if-exists="$ENV_FILE" \
  scripts/query-set-resolution.ts \
  --repeat 3 --live --label "$LABEL" --out "$OUT" "$@"
