import {
  userPsId,
  type IdentityResponse,
} from "@opendatalabs/vana-sdk/protocol/identity";
import type { McpConnectionRecord } from "@opendatalabs/personal-server-ts-core/mcp";
import type {
  McpDurableState,
  McpOwnerBinding,
  McpWakeupIdentity,
} from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { unseal } from "../sealing/envelope.js";
import { sandboxSpec, type PrewarmDeps } from "../jobs/run.js";

export type McpDispatchDeps = PrewarmDeps & {
  state: McpDurableState;
  fetch?: typeof fetch;
};

export async function currentMcpIdentity(
  binding: McpOwnerBinding,
  deps: Pick<McpDispatchDeps, "state" | "gatewayUrl" | "chainId" | "fetch">,
): Promise<McpWakeupIdentity> {
  if (binding.chainId !== deps.chainId)
    throw new Error("MCP identity chain mismatch");
  const id = userPsId(binding.chainId, binding.owner);
  const cached = await deps.state.getIdentity(id);
  if (!cached) throw new Error("MCP identity requires owner prewarm");
  const url = new URL("/v1/identity", deps.gatewayUrl);
  url.searchParams.set("owner", binding.owner);
  url.searchParams.set("chainId", String(binding.chainId));
  const response = await (deps.fetch ?? fetch)(url, {
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("MCP identity is unavailable");
  const live = (await response.json()) as IdentityResponse;
  if (
    live.state !== "sealed" ||
    !live.sealed ||
    !live.identity ||
    live.identity.userPsId !== id ||
    live.identity.ownerAddress.toLowerCase() !== binding.owner.toLowerCase() ||
    live.identity.chainId !== binding.chainId ||
    live.identity.epoch !== cached.epoch ||
    live.identity.address.toLowerCase() !==
      cached.enclaveAddress.toLowerCase() ||
    live.identity.publicKey.toLowerCase() !==
      cached.enclavePublicKey.toLowerCase()
  ) {
    throw new Error("MCP identity is no longer current");
  }
  return cached;
}

/** Raw MCP messages remain on the CVM's private Docker network. */
export async function dispatchOwnerMcp(
  request: Request,
  connection: McpConnectionRecord,
  binding: McpOwnerBinding,
  deps: McpDispatchDeps,
): Promise<Response> {
  const identity = await currentMcpIdentity(binding, deps);
  const derived = await deriveEnclaveIdentity(
    deps.client,
    identity.userPsId,
    identity.epoch,
  );
  if (
    derived.address.toLowerCase() !== identity.enclaveAddress.toLowerCase() ||
    derived.publicKey.toLowerCase() !== identity.enclavePublicKey.toLowerCase()
  )
    throw new Error("MCP identity derivation mismatch");
  const signature = await unseal(
    deps.client,
    identity.userPsId,
    identity.epoch,
    identity.sealedEnvelope,
  );
  const key = `${identity.userPsId}:${identity.epoch}`;
  let acquired = false;
  try {
    const sandbox = await deps.registry.acquire(
      key,
      (accessToken) =>
        sandboxSpec(
          identity,
          deps,
          accessToken,
          signature,
          [...new Set(connection.grants.flatMap((grant) => grant.scopes))].join(
            ",",
          ),
          () => {},
          () => {},
        ),
      request.signal,
    );
    acquired = true;
    signature.fill(0);
    const response = await fetch(`${sandbox.handle.origin}/enclave/v1/mcp`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${sandbox.accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        owner: binding.owner,
        connection,
        request: await request.json(),
      }),
      signal: AbortSignal.any([request.signal, AbortSignal.timeout(120_000)]),
    });
    // MCP's existing engine returns one bounded JSON/SSE response per call.
    // Consume it before releasing the sandbox lease so idle eviction cannot
    // destroy the producer while the HTTP client is still reading.
    const bytes = await response.arrayBuffer();
    return new Response(bytes.byteLength ? bytes : null, {
      status: response.status,
      headers: {
        "content-type":
          response.headers.get("content-type") ?? "application/json",
        "cache-control": "no-store",
      },
    });
  } finally {
    signature.fill(0);
    if (acquired) deps.registry.release(key);
  }
}
