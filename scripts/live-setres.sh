#!/usr/bin/env bash
# Live set-resolution runs against Gemini, with the resolution field captured.
#
# Same pinned settings as live-gemini.sh and for the same reasons: Gemini
# rejects unknown top-level body fields (so no Vana/Phala `provider` hint),
# E2EE is Phala-specific, and `seed` is rejected outright — only
# `temperature`/`top_p` are usable.
#
# Usage: scripts/live-setres.sh --repeat 3 --only Q1,Q6,Q14,Q18
set -euo pipefail

export INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export INFERENCE_MODEL=${INFERENCE_MODEL:-gemini-3.7-flash}
export INFERENCE_E2EE=false
export INFERENCE_REQUEST_FIELDS='{"temperature":0}'

# Referenced from the main checkout, never copied: a key copied into a worktree
# is a key waiting to be committed.
ENV_FILE=.env
[ -f "$ENV_FILE" ] || ENV_FILE=../../../.env

exec npx tsx --env-file-if-exists="$ENV_FILE" \
  scripts/query-set-resolution.ts --live "$@"
