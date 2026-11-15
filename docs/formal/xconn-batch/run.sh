#!/bin/bash
# usage: run.sh <cfg-name-without-.cfg>
# One TLC job, 4 workers, low priority. TLA2TOOLS: path to tla2tools.jar.
# The metadir is a temp dir, deleted when the run ends.
set -u
D=$(cd "$(dirname "$0")" && pwd)
JAR=${TLA2TOOLS:-$HOME/.local/share/mise/installs/github-tlaplus-tlaplus/1.7.4/tla2tools.jar}
cd "$D" || exit 1
mkdir -p out
META=$(mktemp -d "$HOME/.tmp/tlc-xconn.XXXXXX")
nice -n 19 java -XX:+UseParallelGC -Xmx2g -cp "$JAR" tlc2.TLC \
  -workers 4 -metadir "$META/$1" -config "$1.cfg" XConnBatch.tla > "out/$1.out" 2>&1
echo "exit $?" >> "out/$1.out"
rm -rf "$META"
grep -E "Error:|Invariant|Model checking completed|states generated|distinct states|^exit" "out/$1.out" | head -8
