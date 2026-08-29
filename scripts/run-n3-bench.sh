#!/usr/bin/env bash
# One-shot driver for the N=3 live benchmark.
#
# Exists because the run is ~20-50 minutes — longer than a foreground tool call
# — so it has to be launched detached with its output captured to disk. Keeping
# the env pinned here (rather than assembling it at the call site) is the same
# reasoning as live-gemini.sh: every one of these is a silent failure if wrong.
#
#   ./scripts/run-n3-bench.sh                 # SCRATCH, or ./bench-out
#   ./scripts/run-n3-bench.sh /path/to/out    # explicit directory
#
# `query-benchmark.ts` appends each row as it lands and resumes from what is
# already there, so re-running this after a kill continues the sweep. That only
# works if the output directory is the SAME one — which is why the path is
# taken from an argument or `$SCRATCH` rather than baked in. It used to carry a
# hardcoded session id that went stale the moment the session ended, silently
# writing a resumable dataset somewhere nobody would look for it again.
set -euo pipefail

SP="${1:-${SCRATCH:-$PWD/bench-out}}"
mkdir -p "$SP"
echo "output: $SP"

# Appended, not truncated: a resumed sweep must not erase the log of the pass
# that was killed — that log is usually the only record of why it died.
date -u +"=== %Y-%m-%dT%H:%M:%SZ start ===" | tee -a "$SP/dogfood-n3-stdout.txt" >>"$SP/dogfood-n3-stderr.txt"

export INFERENCE_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
export INFERENCE_MODEL="${INFERENCE_MODEL:-gemini-3.7-flash}"
export INFERENCE_E2EE=false
export INFERENCE_REQUEST_FIELDS='{"temperature":0}'

# The key lives in the main checkout's .env; referenced, never copied into a
# worktree, and never echoed.
ENV_FILE=.env
[ -f "$ENV_FILE" ] || ENV_FILE=../../../.env

npx tsx --env-file-if-exists="$ENV_FILE" scripts/query-benchmark.ts \
  --profile dogfood --live --judge --repeat 3 \
  --out "$SP/dogfood-n3-final.json" \
  >>"$SP/dogfood-n3-stdout.txt" 2>>"$SP/dogfood-n3-stderr.txt"

echo "done: $?"
