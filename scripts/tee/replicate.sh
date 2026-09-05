#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <name> <source-cvm-uuid> [--node-id <phala-placement-id>] [--tee-node-id <gateway-node-id>] (--secret-out <path> | --secret-keychain <service>/<account>)" >&2
}

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

name=$1
source_uuid=$2
shift 2

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
source "$script_dir/common.sh"
phala_node_id=18
NODE_ID=$name
secret_out=
secret_keychain=

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
    --secret-out)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      secret_out=$2
      shift 2
      ;;
    --secret-keychain)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      secret_keychain=$2
      shift 2
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

if [[ -n $secret_out && -n $secret_keychain ]] || [[ -z $secret_out && -z $secret_keychain ]]; then
  echo "Exactly one of --secret-out or --secret-keychain is required." >&2
  usage
  exit 1
fi
if [[ -n $secret_out && ( -e $secret_out || -L $secret_out ) ]]; then
  echo "Secret output already exists; refusing to overwrite: $secret_out" >&2
  exit 1
fi
if [[ -n $secret_keychain ]]; then
  if [[ $secret_keychain != */* ]]; then
    echo "--secret-keychain must be <service>/<account>." >&2
    exit 1
  fi
  keychain_service=${secret_keychain%%/*}
  keychain_account=${secret_keychain#*/}
  if [[ -z $keychain_service || -z $keychain_account ]]; then
    echo "--secret-keychain requires a non-empty service and account." >&2
    exit 1
  fi
fi

source_images_env "$repo_root/deploy/dstack/images.env"
: "${ENCLAVE_AGENT_SECRET:?ENCLAVE_AGENT_SECRET must be set in the environment}"
: "${GATEWAY_URL:?GATEWAY_URL must be set in the environment}"
: "${GIT_REF:?GIT_REF must be set in the environment}"
: "${PS_IMAGE:?PS_IMAGE must be set in the environment}"
validate_image_digests
assert_ps_image_ref
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v phala >/dev/null || { echo "phala CLI is required" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
if [[ -n $secret_keychain ]]; then
  command -v security >/dev/null || { echo "macOS security CLI is required for --secret-keychain" >&2; exit 1; }
fi

NODE_SECRET=$(openssl rand -hex 32)
if [[ -n $secret_out ]]; then
  if ! (umask 077; set -o noclobber; printf '%s\n' "$NODE_SECRET" >"$secret_out"); then
    echo "Could not create secret output without overwriting: $secret_out" >&2
    exit 1
  fi
else
  security add-generic-password \
    -s "$keychain_service" \
    -a "$keychain_account" \
    -w "$NODE_SECRET"
fi
create_secure_env_file
printf 'ENCLAVE_AGENT_SECRET=%s\nGIT_REF=%s\nAGENT_IMAGE=%s\nDIND_IMAGE=%s\n' \
  "$ENCLAVE_AGENT_SECRET" "$GIT_REF" "$AGENT_IMAGE" "$DIND_IMAGE" >"$env_file"
printf 'NODE_SECRET=%s\nNODE_ID=%s\nGATEWAY_URL=%s\nPS_IMAGE=%s\n' \
  "$NODE_SECRET" "$NODE_ID" "$GATEWAY_URL" "$PS_IMAGE" >>"$env_file"
for optional_name in SANDBOX_MAX SANDBOX_MEMORY SANDBOX_CPUS SANDBOX_PIDS_LIMIT SANDBOX_IDLE_TTL_SECONDS LEASE_SECONDS VERCEL_PROTECTION_BYPASS WORK_DELAY_MS SANDBOX_SYNC SANDBOX_DEBUG JOB_RESULT_MAX_BYTES STORAGE_API_URL CHAIN_ID DATA_REGISTRY_CONTRACT DATA_PORTABILITY_SERVER_CONTRACT DATA_PORTABILITY_GRANTEES_CONTRACT DATA_PORTABILITY_PERMISSIONS_CONTRACT; do
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

resolve_cvm_registration_metadata "$cvm_json" "$app_id"

printf 'uuid=%s\napp_id=%s\nagent_url=%s\nagent_url_source=%s\n' \
  "$uuid" "$app_id" "$agent_url" "$domain_path"
verify_agent_node_id "$agent_url" "$NODE_ID" "$ENCLAVE_AGENT_SECRET" "$uuid"
capacity=${SANDBOX_MAX:-20}
print_registration_payload "$NODE_ID" "$app_id" "$compose_hash" "$agent_url" "$capacity"
