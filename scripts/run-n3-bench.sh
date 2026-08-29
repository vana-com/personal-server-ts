#!/usr/bin/env bash
# One-shot driver for the N=3 live benchmark.
#
# Exists because the run is ~20 minutes — longer than a foreground tool call —
# so it has to be launched detached with its output captured to disk. Keeping
# the env pinned here (rather than assembling it at the call site) is the same
# reasoning as live-gemini.sh: every one of these is a silent failure if wrong.
set -euo pipefail

SP="${SCRATCH:-/private/tmp/claude-501/-Users-kahtaf-Documents-workspace-vana-personal-server-ts/c2f9a359-54a1-4212-82e7-a0146c6c980c/scratchpad}"
mkdir -p "$SP"

export INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export INFERENCE_MODEL=gemini-3.7-flash
export INFERENCE_E2EE=false
export INFERENCE_REQUEST_FIELDS='{"temperature":0}'

# The key lives in the main checkout's .env; referenced, never copied into a
# worktree, and never echoed.
ENV_FILE=.env
[ -f "$ENV_FILE" ] || ENV_FILE=../../../.env

npx tsx --env-file-if-exists="$ENV_FILE" scripts/query-benchmark.ts \
  --profile dogfood --live --judge --repeat 3 \
  --out "$SP/dogfood-n3-final.json" \
  >"$SP/dogfood-n3-stdout.txt" 2>"$SP/dogfood-n3-stderr.txt"

echo "done: $?"
