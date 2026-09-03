#!/usr/bin/env bash

readonly CVM_READY_ATTEMPTS=${CVM_READY_ATTEMPTS:-120}
readonly CVM_READY_INTERVAL_SECONDS=${CVM_READY_INTERVAL_SECONDS:-5}
readonly CURL_CONNECT_TIMEOUT_SECONDS=5
readonly CURL_MAX_TIME_SECONDS=10

create_secure_env_file() {
  env_file=$(mktemp)
  chmod 600 "$env_file"
  trap 'rm -f "$env_file"' EXIT
}

verify_agent_node_id() {
  local agent_url=$1
  local expected_node_id=$2
  local agent_secret=$3
  local health_json
  local actual_node_id
  local attempt

  for ((attempt = 1; attempt <= CVM_READY_ATTEMPTS; attempt += 1)); do
    if health_json=$(curl -fsS \
      --connect-timeout "$CURL_CONNECT_TIMEOUT_SECONDS" \
      --max-time "$CURL_MAX_TIME_SECONDS" \
      -H "Authorization: Bearer $agent_secret" \
      "${agent_url}/agent/v1/health" 2>/dev/null) && \
      actual_node_id=$(
        node -e '
          const value = JSON.parse(process.argv[1]);
          if (!Object.prototype.hasOwnProperty.call(value, "nodeId")) process.exit(1);
          if (value.nodeId !== null && typeof value.nodeId !== "string") process.exit(1);
          process.stdout.write(value.nodeId ?? "null");
        ' "$health_json" 2>/dev/null
      ); then
      if [[ $actual_node_id != "$expected_node_id" ]]; then
        echo "Agent NODE_ID mismatch: expected '$expected_node_id', health reported '$actual_node_id'." >&2
        return 1
      fi
      return 0
    fi
    if [[ $attempt -eq $CVM_READY_ATTEMPTS ]]; then
      echo "Agent health did not become reachable after $CVM_READY_ATTEMPTS attempts: ${agent_url}/agent/v1/health" >&2
      return 1
    fi
    sleep "$CVM_READY_INTERVAL_SECONDS"
  done
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
