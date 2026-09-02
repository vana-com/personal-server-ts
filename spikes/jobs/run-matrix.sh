#!/usr/bin/env bash
# Load matrix: 1 and 3 workers x 1, 10, 50 jobs/min, 180 s each, 50% wait clients.
set -u
REPO=/Users/kahtaf/Documents/workspace_vana/data-gateway-spike-jobs
S=$SCRATCH
TSX=$REPO/node_modules/.bin/tsx
DURATION=180
cd "$REPO"
for W in 1 3; do
  for R in 1 10 50; do
    echo "=== workers=$W rate=$R/min ($(date -u +%H:%M:%SZ)) ==="
    pids=()
    for i in $(seq 1 $W); do
      GATEWAY_URL=http://localhost:3000 NODE_ID="w$i" $TSX scripts/jobs-worker.ts > "$S/results/worker-w${W}-r${R}-$i.log" 2>&1 &
      pids+=($!)
    done
    sleep 2
    $TSX $S/conn-sampler.mts $((DURATION + 30)) > "$S/results/conns-w${W}-r${R}.json" 2>&1 &
    sampler=$!
    $TSX load-tests/jobs-load.ts --rate $R --duration $DURATION --wait-fraction 0.5 --out "$S/results/jobs-w${W}-r${R}.json" 2>&1 | tail -12
    wait $sampler
    cat "$S/results/conns-w${W}-r${R}.json"
    pkill -f jobs-worker.ts; sleep 2
  done
done
echo "=== matrix done ($(date -u +%H:%M:%SZ)) ==="
