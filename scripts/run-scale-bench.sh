#!/usr/bin/env bash
# Scale-sweep driver (design §19.16). Same pinned env as run-n3-bench.sh, but
# the profile and arm are arguments because this sweep runs the same protocol
# over a second corpus size and both arms.
#
#   ./scripts/run-scale-bench.sh <outdir> <profile> <arm> [extra args...]
#
# `query-benchmark.ts` appends each row as it lands and resumes from what is
# already there, so re-running with the SAME outdir continues a killed sweep.
set -euo pipefail

SP="${1:?outdir required}"
PROFILE="${2:-dogfood-xl}"
ARM="${3:-agent}"
shift 3 || true
mkdir -p "$SP"
TAG="$PROFILE-$ARM"
echo "output: $SP (profile=$PROFILE arm=$ARM)"

date -u +"=== %Y-%m-%dT%H:%M:%SZ start ===" | tee -a "$SP/$TAG-stdout.txt" >>"$SP/$TAG-stderr.txt"

export INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export INFERENCE_MODEL="${INFERENCE_MODEL:-gemini-3.7-flash}"
export INFERENCE_E2EE=false
export INFERENCE_REQUEST_FIELDS='{"temperature":0}'
export QUERY_INFERENCE_DIAG="$SP/$TAG-reply-shapes.jsonl"

# The key lives in the main checkout's .env; referenced, never copied into a
# worktree, and never echoed.
ENV_FILE=.env
[ -f "$ENV_FILE" ] || ENV_FILE=../../../.env

npx tsx --env-file-if-exists="$ENV_FILE" scripts/query-benchmark.ts \
  --profile "$PROFILE" --answerer "$ARM" --live --judge --repeat 3 \
  --out "$SP/$TAG-final.json" "$@" \
  >>"$SP/$TAG-stdout.txt" 2>>"$SP/$TAG-stderr.txt"

echo "done: $?"
