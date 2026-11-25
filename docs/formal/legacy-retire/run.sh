#!/usr/bin/env bash
# Run one LegacyRetire config under the repo's load rules: one heavy job at a
# time (flock), WORKERS workers (default 4), nice 19, ionice idle.
# Usage: TLA2TOOLS=<tla2tools.jar> run.sh Good [TLC_OUT]
set -u
cfg="$1"
out="${2:-${TMPDIR:-$HOME/.tmp}/legacy-retire-tlc}"
jar="${TLA2TOOLS:?set TLA2TOOLS to tla2tools.jar}"
java="${JAVA:-java}"
lock="${HEAVY_RUN_LOCK:-$HOME/.tmp/heavy-run.lock}"
mkdir -p "$out"
cd "$(dirname "$0")"
nice -n 19 ionice -c3 flock "$lock" "$java" -XX:+UseParallelGC -Xmx4g -cp "$jar" \
  tlc2.TLC -workers "${WORKERS:-4}" -metadir "$out/$cfg" -config "$cfg.cfg" LegacyRetire \
  > "$out/$cfg.log" 2>&1
status=$?
tail -n 14 "$out/$cfg.log"
exit "$status"
