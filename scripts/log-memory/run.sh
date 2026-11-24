#!/usr/bin/env bash
# One measured case of the stream-sync log's memory paths: a fresh process per
# step over the state the steps before it left on disk.
#   scripts/log-memory/run.sh <label> <records> <pad-bytes> [step ...]
# Steps default to all of them (see STEPS in the workload). Each measured step
# prints one JSON line; they are kept in $OUT/<label>.jsonl (default
# ~/.tmp/log-memory-out). The databases and blobs live in $WORK/<label>
# (default ~/.tmp/log-memory-work) and are removed afterwards.
# Needs Node 22 (the better-sqlite3 ABI), waits for >= 12 GiB MemAvailable
# before each step, and holds the host's heavy-run lock for the whole case.
set -euo pipefail
label=$1 records=$2 pad=$3
shift 3
steps=("$@")
[ ${#steps[@]} -gt 0 ] || steps=(intake1 publish restore compaction intake2 replace progressive)
root=$(cd "$(dirname "$0")/../.." && pwd)
work=${WORK:-$HOME/.tmp/log-memory-work}/$label
out=${OUT:-$HOME/.tmp/log-memory-out}
mkdir -p "$out" "$work"
trap 'rm -rf "$work"' EXIT
: > "$out/$label.jsonl"
# A caller that already holds the lock for several cases sets HEAVY_LOCK_HELD.
if [ -z "${HEAVY_LOCK_HELD:-}" ]; then
  exec 9>"$HOME/.tmp/heavy-run.lock"
  flock 9
fi
cd "$root"
for step in "${steps[@]}"; do
  # Wait (up to 30 minutes) for the host to have the memory a step needs.
  for _ in $(seq 1 180); do
    avail_kib=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    [ "$avail_kib" -ge $((12 * 1024 * 1024)) ] && break
    sleep 10
  done
  if [ "$avail_kib" -lt $((12 * 1024 * 1024)) ]; then
    echo "MemAvailable $((avail_kib / 1024)) MiB < 12 GiB: not running $label/$step" >&2
    exit 3
  fi
  nice -n 19 ionice -c3 node --expose-gc --import tsx \
    packages/server/src/localdb/bench/log-memory.workload.ts \
    --step "$step" --dir "$work" --records "$records" --pad "$pad" \
    >> "$out/$label.jsonl" 2> "$out/$label.$step.err" \
    || { tail -20 "$out/$label.$step.err" >&2; exit 1; }
done
cat "$out/$label.jsonl"
