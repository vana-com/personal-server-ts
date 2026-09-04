#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <cvm-uuid> --tee-node-id <new-id> [--compose <file>] [--ref <40-hex>] (--secret-out <path> | --secret-keychain <service>/<account>)" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

uuid=$1
shift

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
source "$script_dir/common.sh"
compose="$repo_root/deploy/dstack/docker-compose.enclave.inline.yml"
git_ref=$(git -C "$repo_root" rev-parse HEAD)
NODE_ID=
secret_out=
secret_keychain=

while [[ $# -gt 0 ]]; do
  case $1 in
    --tee-node-id)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      NODE_ID=$2
      shift 2
      ;;
    --compose)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      compose=$2
      shift 2
      ;;
    --ref)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      git_ref=$2
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

if [[ -z $NODE_ID ]]; then
  echo "--tee-node-id is required." >&2
  usage
  exit 1
fi
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
if [[ ! $git_ref =~ ^[[:xdigit:]]{40}$ ]]; then
  echo "--ref must be a 40-hex commit SHA." >&2
  exit 1
fi

: "${ENCLAVE_AGENT_SECRET:?ENCLAVE_AGENT_SECRET must be set in the environment}"
: "${GATEWAY_URL:?GATEWAY_URL must be set in the environment}"
: "${PS_IMAGE:?PS_IMAGE must be set in the environment}"
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
command -v phala >/dev/null || { echo "phala CLI is required" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js is required" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }
[[ -f $compose ]] || { echo "Compose file not found: $compose" >&2; exit 1; }
if [[ -n $secret_keychain ]]; then
  command -v security >/dev/null || { echo "macOS security CLI is required for --secret-keychain" >&2; exit 1; }
fi
if ! git -C "$repo_root" fetch -q origin "$git_ref"; then
  echo "Git ref '$git_ref' is not available on origin; push the commit before updating the CVM." >&2
  exit 1
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
printf 'ENCLAVE_AGENT_SECRET=%s\nGIT_REF=%s\n' \
  "$ENCLAVE_AGENT_SECRET" "$git_ref" >"$env_file"
printf 'NODE_SECRET=%s\nNODE_ID=%s\nGATEWAY_URL=%s\nPS_IMAGE=%s\n' \
  "$NODE_SECRET" "$NODE_ID" "$GATEWAY_URL" "$PS_IMAGE" >>"$env_file"
for optional_name in SANDBOX_MAX SANDBOX_IDLE_TTL_SECONDS LEASE_SECONDS VERCEL_PROTECTION_BYPASS WORK_DELAY_MS SANDBOX_SYNC STORAGE_API_URL CHAIN_ID DATA_REGISTRY_CONTRACT DATA_PORTABILITY_SERVER_CONTRACT DATA_PORTABILITY_GRANTEES_CONTRACT DATA_PORTABILITY_PERMISSIONS_CONTRACT; do
  optional_value=${!optional_name:-}
  if [[ -n $optional_value ]]; then
    printf '%s=%s\n' "$optional_name" "$optional_value" >>"$env_file"
  fi
done

cvm_json=$(phala cvms get "$uuid" --json)
app_id=$(
  node -e '
    const value = JSON.parse(process.argv[1]);
    const appId = value.app_id ?? value.appId;
    if (typeof appId !== "string" || appId.length === 0) process.exit(1);
    process.stdout.write(appId);
  ' "$cvm_json"
)

phala deploy \
  --cvm-id "$uuid" \
  -c "$compose" \
  -e "$env_file" \
  --wait \
  --json >/dev/null

started=false
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
  if [[ $cvm_status == stopped && $started == false ]]; then
    phala cvms start "$uuid"
    started=true
  fi
  if [[ $attempt -eq $CVM_READY_ATTEMPTS ]]; then
    echo "Updated CVM did not reach running status; raw 'phala cvms get' JSON follows:" >&2
    echo "$cvm_json" >&2
    exit 1
  fi
  sleep "$CVM_READY_INTERVAL_SECONDS"
done

resolve_cvm_registration_metadata "$cvm_json" "$app_id"
printf 'uuid=%s\napp_id=%s\nagent_url=%s\nagent_url_source=%s\n' \
  "$uuid" "$app_id" "$agent_url" "$domain_path"

# The old agent can remain healthy briefly after deploy. Wait until the health
# endpoint reports the replacement identity before running strict checks.
new_node_ready=false
for ((attempt = 1; attempt <= CVM_READY_ATTEMPTS; attempt += 1)); do
  if ! health_response=$(curl -sS \
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" \
    --max-time "$CURL_MAX_TIME_SECONDS" \
    -H "Authorization: Bearer $ENCLAVE_AGENT_SECRET" \
    -w $'\n%{http_code}' \
    "${agent_url}/agent/v1/health" 2>/dev/null); then
    if [[ $attempt -lt $CVM_READY_ATTEMPTS ]]; then
      sleep "$CVM_READY_INTERVAL_SECONDS"
    fi
    continue
  fi
  http_status=${health_response##*$'\n'}
  health_json=${health_response%$'\n'*}
  if [[ ! $http_status =~ ^2[[:digit:]]{2}$ ]]; then
    if [[ $attempt -lt $CVM_READY_ATTEMPTS ]]; then
      sleep "$CVM_READY_INTERVAL_SECONDS"
    fi
    continue
  fi
  actual_node_id=$(
    node -e '
      const value = JSON.parse(process.argv[1]);
      if (typeof value.nodeId !== "string") process.exit(1);
      process.stdout.write(value.nodeId);
    ' "$health_json" 2>/dev/null || true
  )
  if [[ $actual_node_id == "$NODE_ID" ]]; then
    new_node_ready=true
    break
  fi
  if [[ $attempt -lt $CVM_READY_ATTEMPTS ]]; then
    sleep "$CVM_READY_INTERVAL_SECONDS"
  fi
done
if [[ $new_node_ready == false ]]; then
  echo "Updated agent did not report NODE_ID '$NODE_ID' after $CVM_READY_ATTEMPTS attempts: ${agent_url}/agent/v1/health" >&2
  print_agent_logs "$uuid"
  exit 1
fi

verify_agent_node_id "$agent_url" "$NODE_ID" "$ENCLAVE_AGENT_SECRET" "$uuid"
capacity=${SANDBOX_MAX:-20}
print_registration_payload "$NODE_ID" "$app_id" "$compose_hash" "$agent_url" "$capacity"
