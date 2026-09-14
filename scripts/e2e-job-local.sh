#!/usr/bin/env bash
# Gateway prerequisites: run `npm run dev:pg`, apply migrations, then run
# `npm run dev:server` in data-gateway-jobs with OPERATOR_SECRET configured.

set -euo pipefail

readonly GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:3000}"

if [[ ! -f packages/enclave/dist/agent/main.js || ! -f packages/server/dist/index.js ]]; then
  npm run build
fi

if ! curl --fail --silent "${GATEWAY_URL%/}/health" >/dev/null; then
  echo "Gateway is not healthy at ${GATEWAY_URL%/}/health" >&2
  exit 1
fi

npm run e2e:job
