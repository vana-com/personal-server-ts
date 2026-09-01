#!/usr/bin/env bash
# Run the query eval against Gemini's OpenAI-compatible endpoint.
#
# Reads INFERENCE_API_KEY from .env (never echoed). All other settings are
# pinned here because they are not defaults and getting them wrong is a silent
# failure rather than a loud one:
#   - REQUEST_FIELDS must not carry the Vana/Phala `provider` hint; Gemini
#     rejects unknown top-level body fields with a hard 400.
#   - E2EE must be off: it is Phala-attestation-specific.
#   - `seed` is NOT usable — Gemini rejects it. Only `temperature`/`top_p`.
#
# Usage: scripts/live-gemini.sh --profile dogfood --only Q3,Q10,Q17
set -euo pipefail

export INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export INFERENCE_MODEL=gemini-3.7-flash
export INFERENCE_E2EE=false
export INFERENCE_REQUEST_FIELDS='{"temperature":0}'

# The key lives in the main checkout's .env, not in a worktree. Referenced
# rather than copied: a key copied into a worktree is a key waiting to be
# committed.
ENV_FILE=.env
[ -f "$ENV_FILE" ] || ENV_FILE=../../../.env

exec npx tsx --env-file-if-exists="$ENV_FILE" scripts/query-eval.ts --answerer live "$@"
