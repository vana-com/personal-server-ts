#!/usr/bin/env bash
# Prerequisite: in data-gateway, start the stand-in with `npm run dev:pg`, then
# `npm run dev:server`, configured with the values from
# `scripts/dev-identity-env.example` (including this fake app ID and KMS root).

set -u

readonly FAKE_APP_ID="0xe2e0000000000000000000000000000000000001"
readonly AGENT_SECRET="${ENCLAVE_AGENT_SECRET:-dev-agent-secret}"
readonly AGENT_URL="http://127.0.0.1:8787"
agent_pid=""

cleanup() {
  if [[ -n "$agent_pid" ]]; then
    kill "$agent_pid" 2>/dev/null || true
    wait "$agent_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -f packages/enclave/dist/agent/main.js ]]; then
  npm run build -w @opendatalabs/personal-server-ts-enclave || exit $?
fi

DSTACK_FAKE=1 \
  DSTACK_FAKE_APP_ID="${FAKE_APP_ID#0x}" \
  ENCLAVE_AGENT_SECRET="$AGENT_SECRET" \
  ENCLAVE_AGENT_PORT=8787 \
  node packages/enclave/dist/agent/main.js &
agent_pid=$!

for _attempt in {1..50}; do
  if curl --fail --silent \
    --header "Authorization: Bearer $AGENT_SECRET" \
    "$AGENT_URL/agent/v1/health" >/dev/null; then
    npm run e2e:identity
    exit $?
  fi
  if ! kill -0 "$agent_pid" 2>/dev/null; then
    echo "Fake enclave agent exited before becoming healthy" >&2
    exit 1
  fi
  sleep 0.2
done

echo "Timed out waiting for $AGENT_URL/agent/v1/health" >&2
exit 1
