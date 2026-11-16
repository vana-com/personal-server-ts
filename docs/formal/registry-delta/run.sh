#!/bin/bash
# usage: run.sh <cfg-name-without-.cfg>
# One TLC job, 4 workers, low priority. TLA2TOOLS: path to tla2tools.jar.
set -u
D=$(cd "$(dirname "$0")" && pwd)
JAR=${TLA2TOOLS:-$HOME/.local/share/mise/installs/github-tlaplus-tlaplus/1.7.4/tla2tools.jar}
cd "$D" || exit 1
mkdir -p out
META=$(mktemp -d)
nice -n 19 java -XX:+UseParallelGC -Xmx2g -cp "$JAR" tlc2.TLC \
  -workers 4 -metadir "$META/$1" -config "$1.cfg" RegistryDelta.tla > "out/$1.out" 2>&1
echo "exit $?" >> "out/$1.out"
# Keep local paths out of the committed output.
sed -i "s#$D/##" "out/$1.out"
rm -rf "$META"
grep -E "Error:|Invariant|Model checking completed|states generated|distinct states|^exit" "out/$1.out" | head -8
