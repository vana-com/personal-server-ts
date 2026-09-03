#!/usr/bin/env bash

create_secure_env_file() {
  env_file=$(mktemp)
  chmod 600 "$env_file"
  trap 'rm -f "$env_file"' EXIT
}

print_registration_payload() {
  local node_id=$1
  local app_id=$2
  local compose_hash=$3
  local public_url=$4
  local capacity=$5

  echo "Register this node with POST /v1/tee-nodes using this payload:"
  node -e '
    const [nodeId, appId, composeHash, publicUrl, capacity] = process.argv.slice(1);
    const payload = {
      nodeId,
      appId: appId.startsWith("0x") ? appId : `0x${appId}`,
      ...(composeHash ? { composeHash: composeHash.startsWith("0x") ? composeHash : `0x${composeHash}` } : {}),
      publicUrl,
      capacity: Number(capacity),
      secret: "<NODE_SECRET: send once>",
    };
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
  ' "$node_id" "$app_id" "$compose_hash" "$public_url" "$capacity"
  echo "Replace the secret placeholder in the registration body once; NODE_SECRET is not printed."
}
