#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <name> <source-cvm-uuid> [--node-id <phala-placement-id>] [--tee-node-id <gateway-node-id>]" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

name=$1
source_uuid=$2
shift 2

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/common.sh"
phala_node_id=18
NODE_ID=$name
readonly CVM_READY_ATTEMPTS=120
readonly CVM_READY_INTERVAL_SECONDS=5

while [[ $# -gt 0 ]]; do
  case $1 in
    --node-id)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      phala_node_id=$2
      shift 2
      ;;
    --tee-node-id)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      NODE_ID=$2
      shift 2
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

: "${ENCLAVE_AGENT_SECRET:?ENCLAVE_AGENT_SECRET must be set in the environment}"
: "${GATEWAY_URL:?GATEWAY_URL must be set in the environment}"
: "${GIT_REF:?GIT_REF must be set in the environment}"
: "${PS_IMAGE:?PS_IMAGE must be set in the environment}"
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v phala >/dev/null || { echo "phala CLI is required" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js is required" >&2; exit 1; }

NODE_SECRET=$(openssl rand -hex 32)
create_secure_env_file
printf 'ENCLAVE_AGENT_SECRET=%s\nGIT_REF=%s\n' \
  "$ENCLAVE_AGENT_SECRET" "$GIT_REF" >"$env_file"
printf 'NODE_SECRET=%s\nNODE_ID=%s\nGATEWAY_URL=%s\nPS_IMAGE=%s\n' \
  "$NODE_SECRET" "$NODE_ID" "$GATEWAY_URL" "$PS_IMAGE" >>"$env_file"
for optional_name in SANDBOX_MAX SANDBOX_IDLE_TTL_SECONDS LEASE_SECONDS VERCEL_PROTECTION_BYPASS WORK_DELAY_MS SANDBOX_SYNC; do
  optional_value=${!optional_name:-}
  if [[ -n $optional_value ]]; then
    printf '%s=%s\n' "$optional_name" "$optional_value" >>"$env_file"
  fi
done

source_cvm_json=$(phala cvms get "$source_uuid" --json)
app_id=$(
  node -e '
    const value = JSON.parse(process.argv[1]);
    const appId = value.app_id ?? value.appId;
    if (typeof appId !== "string" || appId.length === 0) process.exit(1);
    process.stdout.write(appId);
  ' "$source_cvm_json"
)

replica_json=$(
  phala cvms replicate "$source_uuid" \
    --node-id "$phala_node_id" \
    --json \
    -e "$env_file"
)
uuid=$(
  node -e '
    const value = JSON.parse(process.argv[1]);
    const uuid = value.vm_uuid ?? value.uuid ?? value.id;
    if (typeof uuid !== "string" || uuid.length === 0) process.exit(1);
    process.stdout.write(uuid);
  ' "$replica_json"
)

for ((attempt = 1; attempt <= CVM_READY_ATTEMPTS; attempt += 1)); do
  cvm_json=$(phala cvms get "$uuid" --json)
  cvm_status=$(
    node -e '
      const value = JSON.parse(process.argv[1]);
      const status = typeof value.status === "string" ? value.status : value.status?.status;
      process.stdout.write(typeof status === "string" ? status : "unknown");
    ' "$cvm_json"
  )
  if [[ $cvm_status == running ]]; then
    break
  fi
  if [[ $attempt -eq $CVM_READY_ATTEMPTS ]]; then
    echo "Replica did not reach running status; raw 'phala cvms get' JSON follows:" >&2
    echo "$cvm_json" >&2
    exit 1
  fi
  sleep "$CVM_READY_INTERVAL_SECONDS"
done

compose_hash=$(
  node -e '
    const value = JSON.parse(process.argv[1]);
    const candidates = [
      value.compose_hash,
      value.composeHash,
      value.app_compose_hash,
      value.cvm?.compose_hash,
      value.status?.compose_hash,
    ];
    const hash = candidates.find((candidate) => typeof candidate === "string" && candidate.length > 0);
    if (!hash) process.exit(1);
    process.stdout.write(hash);
  ' "$cvm_json"
)
domain_result=$(
  node -e '
    const value = JSON.parse(process.argv[1]);
    const candidates = [
      ["dstack_app_domain", value.dstack_app_domain],
      ["gateway_domain", value.gateway_domain],
      ["gateway.base_domain", value.gateway?.base_domain],
      ["default_gateway_domain", value.default_gateway_domain],
    ];
    const match = candidates.find(([, domain]) => typeof domain === "string" && domain.length > 0);
    if (!match) process.exit(1);
    process.stdout.write(`${match[0]} ${match[1]}`);
  ' "$cvm_json" 2>/dev/null
) || true

agent_url=unavailable
domain_path=unavailable
if [[ -n $domain_result ]]; then
  domain_path=${domain_result%% *}
  domain=${domain_result#* }
  domain=${domain#https://}
  domain=${domain#http://}
  domain=${domain%%/*}
  agent_url="https://${app_id}-8787.${domain}"
else
  echo "Could not locate the public app domain; raw 'phala cvms get' JSON follows:" >&2
  echo "$cvm_json" >&2
fi

printf 'uuid=%s\napp_id=%s\nagent_url=%s\nagent_url_source=%s\n' \
  "$uuid" "$app_id" "$agent_url" "$domain_path"
capacity=${SANDBOX_MAX:-20}
print_registration_payload "$NODE_ID" "$app_id" "$compose_hash" "$agent_url" "$capacity"
