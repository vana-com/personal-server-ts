#!/usr/bin/env bash
# Stop what up.sh started: processes by saved PID, then the Postgres container.
set -u
STACK_DIR="${STACK_DIR:-$HOME/.tmp/stream-sync-real-stack}"
PG_NAME="${PG_NAME:-stream-sync-real-pg}"
for name in gateway storage rpc; do
  f="$STACK_DIR/$name.pid"
  [ -f "$f" ] || continue
  pid="$(cat "$f")"
  # tsx wraps the real server in a child; stop children first, then the PID.
  pkill_children() { for c in $(ps -o pid= --ppid "$1" 2>/dev/null); do pkill_children "$c"; kill "$c" 2>/dev/null; done; }
  pkill_children "$pid"
  kill "$pid" 2>/dev/null || true
  rm -f "$f"
done
docker rm -f "$PG_NAME" >/dev/null 2>&1 && echo "removed $PG_NAME"
true
