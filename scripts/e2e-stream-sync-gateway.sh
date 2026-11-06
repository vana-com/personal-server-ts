#!/usr/bin/env bash
# Start a disposable Postgres + the real data-gateway, run the stream-sync
# skeleton e2e against it, stop both.
# Usage: STREAM_SYNC_GATEWAY_DIR=<data-gateway checkout, npm ci done> \
#        bash scripts/e2e-stream-sync-gateway.sh
# Needs docker, a built workspace (npm run build), and the fake RPC below.
set -uo pipefail
PS=$(cd "$(dirname "$0")/.." && pwd)
GW=${STREAM_SYNC_GATEWAY_DIR:?set STREAM_SYNC_GATEWAY_DIR to a data-gateway checkout}
S=$(mktemp -d)
PGNAME=stream-sync-registry-pg
PGPORT=55440
GWPORT=55441
RPCPORT=55442
mkdir -p "$S/run"
PIDS=""
cleanup() {
  for f in gw rpc; do
    [ -f "$S/run/$f.pid" ] && kill "$(cat "$S/run/$f.pid")" 2>/dev/null
  done
  docker rm -f "$PGNAME" >/dev/null 2>&1
  rm -rf "$S"
}
trap cleanup EXIT

docker rm -f "$PGNAME" >/dev/null 2>&1
docker run -d --name "$PGNAME" -e POSTGRES_USER=gateway -e POSTGRES_PASSWORD=gateway -e POSTGRES_DB=gateway \
  -p 127.0.0.1:$PGPORT:5432 postgres:16 >/dev/null || exit 2
for i in $(seq 1 60); do docker exec "$PGNAME" pg_isready -U gateway -d gateway >/dev/null 2>&1 && break; sleep 1; done
sleep 2

nohup node "$PS/scripts/fake-chain-rpc.mjs" $RPCPORT > "$S/run/rpc.log" 2>&1 &
echo $! > "$S/run/rpc.pid"

cd "$GW" || exit 2
NEON_URL=postgres://gateway:gateway@127.0.0.1:$PGPORT/gateway nice -n 10 node_modules/.bin/drizzle-kit push --force > "$S/run/push.log" 2>&1 || { tail -20 "$S/run/push.log"; exit 3; }

REPO="$GW" PORT=$GWPORT NEON_URL=postgres://gateway:gateway@127.0.0.1:$PGPORT/gateway USE_LOCAL_DB=1 \
  CHAIN_ID=14800 DATA_REGISTRY_CONTRACT=0x8f1eFCdff3d0d5BB535e32620721c7EBed151867 \
  GATEWAY_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  RPC_URL=http://127.0.0.1:$RPCPORT DATA_PORTABILITY_ESCROW_CONTRACT=0x07d7769081adc3a3DBe91f5E4B98E9A5a6B292e3 \
  FEE_REGISTRY_CONTRACT=0xb4FA18443E0FA6cdC0280D20b8cCDB2377D13Bf2 \
  nohup node_modules/.bin/tsx scripts/dev-server.ts > "$S/run/gw.log" 2>&1 &
echo $! > "$S/run/gw.pid"
for i in $(seq 1 90); do grep -q "listening" "$S/run/gw.log" && break; sleep 1; done
tail -2 "$S/run/gw.log"

# Register SERVER_KEY (anvil #2) as a confirmed server of OWNER (anvil #0).
cd "$PS" || exit 2
ADDRS=$(node --input-type=module -e '
import { privateKeyToAccount } from "viem/accounts";
const o = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const s = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
console.log(o.address, s.address, s.publicKey);')
set -- $ADDRS
docker exec "$PGNAME" psql -U gateway -d gateway -q -c \
  "insert into servers (id, owner_address, server_address, public_key, server_url, signature, status) values ('0x$(printf '%064d' 1)', '$1', '$2', '$3', 'http://127.0.0.1:1', '0x', 'confirmed')" \
  || exit 4

STREAM_SYNC_ORACLE_GATEWAY_URL=http://127.0.0.1:$GWPORT nice -n 10 npm run e2e:stream-sync-skeleton 2>&1 | tee "$S/run/e2e.out"
exit "${PIPESTATUS[0]}"
