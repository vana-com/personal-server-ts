#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "Usage: $0 <name> [--ref <git-ref>] [--node-id <id>] [--compose <path> | --inline (registry-free jobs)] [--app-id <id> --nonce <n>]" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

name=$1
shift

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
source "$script_dir/common.sh"
git_ref=main
node_id=18
inline_compose="$repo_root/deploy/dstack/docker-compose.enclave.inline.yml"
compose="$repo_root/deploy/dstack/docker-compose.enclave.yml"
app_id=
nonce=

while [[ $# -gt 0 ]]; do
  case $1 in
    --ref)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      git_ref=$2
      shift 2
      ;;
    --node-id)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      node_id=$2
      shift 2
      ;;
    --compose)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      compose=$2
      shift 2
      ;;
    --inline)
      compose=$inline_compose
      shift
      ;;
    --app-id)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      app_id=$2
      shift 2
      ;;
    --nonce)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      nonce=$2
      shift 2
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

: "${ENCLAVE_AGENT_SECRET:?ENCLAVE_AGENT_SECRET must be set in the environment}"
command -v phala >/dev/null || { echo "phala CLI is required" >&2; exit 1; }
command -v node >/dev/null || { echo "Node.js is required" >&2; exit 1; }
[[ -f $compose ]] || { echo "Compose file not found: $compose" >&2; exit 1; }

identity_only=false
if [[ ${compose##*/} == docker-compose.agent.inline.yml ]]; then
  identity_only=true
else
  : "${NODE_SECRET:?NODE_SECRET must be set in the environment}"
  : "${NODE_ID:?NODE_ID must be set in the environment}"
  : "${GATEWAY_URL:?GATEWAY_URL must be set in the environment}"
  : "${PS_IMAGE:?PS_IMAGE must be set in the environment}"
  if [[ ${compose##*/} == docker-compose.enclave.inline.yml ]]; then
    if [[ ! $PS_IMAGE =~ ^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$ ]]; then
      echo "PS_IMAGE must be a local image tag such as vanaorg/personal-server:level-b" >&2
      exit 1
    fi
  elif [[ ! $PS_IMAGE =~ ^.+@sha256:[[:xdigit:]]{64}$ ]]; then
    echo "PS_IMAGE must be an image digest such as vanaorg/personal-server@sha256:<64 hex characters>" >&2
    exit 1
  fi
  if [[ ! $git_ref =~ ^[[:xdigit:]]{40}$ ]]; then
    echo "--ref must be a 40-hex commit SHA for the enclave compose; branch names are mutable" >&2
    exit 1
  fi
fi

if [[ -n $app_id || -n $nonce ]]; then
  if [[ -z $app_id || -z $nonce ]]; then
    echo "--app-id and --nonce must be supplied together" >&2
    exit 1
  fi
else
  pair_json=$(phala api /kms/phala/next_app_id -f counts=1)
  read -r app_id nonce < <(
    node -e '
      const chunks = [];
      process.stdin.on("data", (chunk) => chunks.push(chunk));
      process.stdin.on("end", () => {
        const pair = JSON.parse(Buffer.concat(chunks).toString()).app_ids?.[0];
        if (!pair || typeof pair.app_id !== "string" || !Number.isInteger(pair.nonce)) process.exit(1);
        process.stdout.write(`${pair.app_id} ${pair.nonce}\n`);
      });
    ' <<<"$pair_json"
  )
fi

[[ $app_id =~ ^[0-9a-fA-F]{40}$ ]] || { echo "app_id must be 40 hexadecimal characters" >&2; exit 1; }
[[ $nonce =~ ^[0-9]+$ ]] || { echo "nonce must be a non-negative integer" >&2; exit 1; }

create_secure_env_file
printf 'ENCLAVE_AGENT_SECRET=%s\nGIT_REF=%s\n' \
  "$ENCLAVE_AGENT_SECRET" "$git_ref" >"$env_file"
if [[ $identity_only == false ]]; then
  printf 'NODE_SECRET=%s\nNODE_ID=%s\nGATEWAY_URL=%s\nPS_IMAGE=%s\n' \
    "$NODE_SECRET" "$NODE_ID" "$GATEWAY_URL" "$PS_IMAGE" >>"$env_file"
  for optional_name in SANDBOX_MAX SANDBOX_IDLE_TTL_SECONDS LEASE_SECONDS VERCEL_PROTECTION_BYPASS WORK_DELAY_MS SANDBOX_SYNC; do
    optional_value=${!optional_name:-}
    if [[ -n $optional_value ]]; then
      printf '%s=%s\n' "$optional_name" "$optional_value" >>"$env_file"
    fi
  done
fi

deploy_json=$(
  phala deploy \
    -n "$name" \
    -c "$compose" \
    --custom-app-id "$app_id" \
    --nonce "$nonce" \
    --image dstack-0.5.9-bd369a8c \
    --instance-type tdx.small \
    --node-id "$node_id" \
    --kms phala \
    --wait \
    --public-logs \
    --json \
    -e "$env_file"
)

# `phala deploy --json` prints progress lines before the JSON body; keep the body only.
deploy_json=$(printf '%s\n' "$deploy_json" | sed -n '/^{/,$p')

uuid=$(
  node -e '
    const value = JSON.parse(process.argv[1]);
    const uuid = value.vm_uuid ?? value.uuid ?? value.id;
    if (typeof uuid !== "string" || uuid.length === 0) process.exit(1);
    process.stdout.write(uuid);
  ' "$deploy_json"
)

cvm_json=$(phala cvms get "$uuid" --json)
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
  ' "$cvm_json" 2>/dev/null
) || true
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

printf 'uuid=%s\napp_id=%s\nnonce=%s\nagent_url=%s\nagent_url_source=%s\n' \
  "$uuid" "$app_id" "$nonce" "$agent_url" "$domain_path"

if [[ $identity_only == false ]]; then
  capacity=${SANDBOX_MAX:-20}
  print_registration_payload "$NODE_ID" "$app_id" "$compose_hash" "$agent_url" "$capacity"
fi
