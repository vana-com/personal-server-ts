#!/usr/bin/env bash
# Run one LateSeed config under the repo's load rules: one job, WORKERS workers
# (default 4), nice 19, ionice idle. Usage: run.sh Good [TLC_OUT]
set -u
cfg="$1"
out="${2:-${TMPDIR:-$HOME/.tmp}/late-seed-tlc}"
jar="${TLA2TOOLS:?set TLA2TOOLS to tla2tools.jar}"
mkdir -p "$out"
cd "$(dirname "$0")"
nice -n 19 ionice -c3 java -XX:+UseParallelGC -Xmx4g -cp "$jar" \
  tlc2.TLC -workers "${WORKERS:-4}" -metadir "$out/$cfg" -config "$cfg.cfg" LateSeed \
  > "$out/$cfg.log" 2>&1
status=$?
tail -n 14 "$out/$cfg.log"
exit "$status"
