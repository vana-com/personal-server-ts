#!/usr/bin/env bash
# Start the local stream-sync stack: disposable Postgres, fake JSON-RPC, the
# data-gateway dev server and a write-once blob store. Dev only; production
# services, Doppler and Vercel are never touched.
#
#   GATEWAY_DIR   data-gateway checkout with node_modules (required)
#   STACK_DIR     state directory (default ~/.tmp/stream-sync-real-stack)
#   PG_PORT RPC_PORT GATEWAY_PORT STORAGE_PORT  (defaults 55449 55450 55451 55452)
#
#   DATA_REGISTRY_CONTRACT  must equal the PS default gateway.contracts.dataRegistry
#
# Prints the URLs to use. Stop with down.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${GATEWAY_DIR:?set GATEWAY_DIR to a data-gateway checkout}"
STACK_DIR="${STACK_DIR:-$HOME/.tmp/stream-sync-real-stack}"
PG_PORT="${PG_PORT:-55449}"
RPC_PORT="${RPC_PORT:-55450}"
GATEWAY_PORT="${GATEWAY_PORT:-55451}"
STORAGE_PORT="${STORAGE_PORT:-55452}"
PG_NAME="${PG_NAME:-stream-sync-real-pg}"
mkdir -p "$STACK_DIR"

docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
docker run -d --name "$PG_NAME" -e POSTGRES_USER=gateway -e POSTGRES_PASSWORD=gateway \
  -e POSTGRES_DB=gateway -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null
for _ in $(seq 1 60); do
  docker exec "$PG_NAME" pg_isready -U gateway -d gateway >/dev/null 2>&1 && break
  sleep 1
done

node "$HERE/fake-rpc.mjs" "$RPC_PORT" >"$STACK_DIR/rpc.log" 2>&1 &
echo $! >"$STACK_DIR/rpc.pid"
node "$HERE/storage.mjs" "$STORAGE_PORT" >"$STACK_DIR/storage.log" 2>&1 &
echo $! >"$STACK_DIR/storage.pid"

cd "$GATEWAY_DIR"
NEON_URL="postgres://gateway:gateway@127.0.0.1:$PG_PORT/gateway" \
  node_modules/.bin/drizzle-kit push --force >"$STACK_DIR/push.log" 2>&1 \
  || { tail -20 "$STACK_DIR/push.log"; exit 1; }

REPO="$GATEWAY_DIR" PORT="$GATEWAY_PORT" \
  NEON_URL="postgres://gateway:gateway@127.0.0.1:$PG_PORT/gateway" USE_LOCAL_DB=1 \
  CHAIN_ID=14800 DATA_REGISTRY_CONTRACT="${DATA_REGISTRY_CONTRACT:-0x8f1eFCdff3d0d5BB535e32620721c7EBed151867}" \
  GATEWAY_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  RPC_URL="http://127.0.0.1:$RPC_PORT" \
  FEE_REGISTRY_CONTRACT=0xb4FA18443E0FA6cdC0280D20b8cCDB2377D13Bf2 \
  nohup node_modules/.bin/tsx scripts/dev-server.ts >"$STACK_DIR/gateway.log" 2>&1 &
echo $! >"$STACK_DIR/gateway.pid"
for _ in $(seq 1 90); do
  grep -q "listening" "$STACK_DIR/gateway.log" && break
  sleep 1
done
grep -q "listening" "$STACK_DIR/gateway.log" || { tail -20 "$STACK_DIR/gateway.log"; exit 1; }

cat >"$STACK_DIR/env" <<ENV
STREAM_SYNC_REAL_GATEWAY_URL=http://127.0.0.1:$GATEWAY_PORT
STREAM_SYNC_REAL_STORAGE_URL=http://127.0.0.1:$STORAGE_PORT
STREAM_SYNC_REAL_PG_NAME=$PG_NAME
STREAM_SYNC_REAL_PG_PORT=$PG_PORT
ENV
cat "$STACK_DIR/env"
