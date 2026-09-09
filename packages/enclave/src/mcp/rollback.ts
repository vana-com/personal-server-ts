import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import type {
  McpOwnerBinding,
  McpWakeupIdentity,
} from "@opendatalabs/personal-server-ts-server/mcp/tee";
import { recoverMessageAddress, toHex } from "viem";
import type { DstackClient } from "../dstack/client.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { unseal, type SealedEnvelope } from "../sealing/envelope.js";
import { MASTER_KEY_MESSAGE } from "../agent/seal.js";

export interface McpRollbackIdentityDeps {
  client: DstackClient;
  chainId: number;
  gatewayUrl: string;
  nodeId: string;
  nodeSecret: string;
  fetch?: typeof fetch;
}

const MAX_RESPONSE_BYTES = 16 * 1024;

/** Proves rollback can serve the current owner before any cache is committed. */
export async function resolveMcpRollbackIdentity(
  binding: McpOwnerBinding,
  deps: McpRollbackIdentityDeps,
): Promise<{ identity: McpWakeupIdentity; generation: number }> {
  if (binding.chainId !== deps.chainId) throw invalid();
  const id = userPsId(binding.chainId, binding.owner);
  const identityUrl = new URL("/v1/identity", deps.gatewayUrl);
  identityUrl.searchParams.set("owner", binding.owner);
  identityUrl.searchParams.set("chainId", String(binding.chainId));
  const live = record(await readJson(identityUrl, {}, deps));
  const current = record(live.identity);
  if (
    live.state !== "sealed" ||
    live.sealed !== true ||
    current.userPsId !== id ||
    current.chainId !== binding.chainId ||
    !sameHex(current.ownerAddress, binding.owner) ||
    !positiveInteger(current.epoch) ||
    !isHex(current.address, 20) ||
    !isHex(current.publicKey, 65)
  )
    throw invalid();

  const owner = {
    chainId: binding.chainId,
    userPsId: id,
    identityEpoch: current.epoch,
  };
  const material = record(
    await readJson(
      new URL("/v1/fleet?action=recovery-envelope", deps.gatewayUrl),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Node-Id": deps.nodeId,
          Authorization: `Bearer ${deps.nodeSecret}`,
        },
        body: JSON.stringify({ owner }),
      },
      deps,
    ),
  );
  const recoveryOwner = record(material.owner);
  const recovered = record(material.identity);
  if (
    recoveryOwner.chainId !== owner.chainId ||
    recoveryOwner.userPsId !== id ||
    recoveryOwner.identityEpoch !== owner.identityEpoch ||
    !Number.isSafeInteger(material.generation) ||
    typeof material.generation !== "number" ||
    material.generation < 0 ||
    recovered.userPsId !== id ||
    recovered.epoch !== current.epoch ||
    !sameHex(recovered.enclaveAddress, current.address) ||
    !sameHex(recovered.enclavePublicKey, current.publicKey)
  )
    throw invalid();
  const identity: McpWakeupIdentity = {
    userPsId: id,
    epoch: current.epoch,
    enclaveAddress: current.address,
    enclavePublicKey: current.publicKey,
    sealedEnvelope: envelope(recovered.sealedEnvelope),
  };
  const derived = await deriveEnclaveIdentity(deps.client, id, identity.epoch);
  if (
    !sameHex(derived.address, identity.enclaveAddress) ||
    !sameHex(derived.publicKey, identity.enclavePublicKey)
  )
    throw invalid();
  const signature = await unseal(
    deps.client,
    id,
    identity.epoch,
    identity.sealedEnvelope,
  );
  try {
    if (signature.length !== 65) throw invalid();
    const signer = await recoverMessageAddress({
      message: MASTER_KEY_MESSAGE,
      signature: toHex(signature),
    });
    if (!sameHex(signer, binding.owner)) throw invalid();
  } finally {
    signature.fill(0);
  }
  return { identity, generation: material.generation };
}

async function readJson(
  url: URL,
  init: RequestInit,
  deps: McpRollbackIdentityDeps,
): Promise<unknown> {
  const response = await (deps.fetch ?? fetch)(url, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok || !response.body) throw invalid();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw invalid();
      chunks.push(chunk.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw invalid();
  return value as Record<string, unknown>;
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isHex(value: unknown, bytes: number): value is `0x${string}` {
  return (
    typeof value === "string" &&
    new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(value)
  );
}

function sameHex(value: unknown, expected: string): boolean {
  return (
    typeof value === "string" && value.toLowerCase() === expected.toLowerCase()
  );
}

function base64(value: unknown, bytes: number): string {
  if (typeof value !== "string") throw invalid();
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== bytes || decoded.toString("base64") !== value)
    throw invalid();
  return value;
}

function envelope(value: unknown): SealedEnvelope {
  const box = record(value);
  const wrapped = record(box.wrappedContentKey);
  if (box.v !== 1) throw invalid();
  return {
    v: 1,
    iv: base64(box.iv, 12),
    tag: base64(box.tag, 16),
    ciphertext: base64(box.ciphertext, 65),
    wrappedContentKey: {
      iv: base64(wrapped.iv, 12),
      tag: base64(wrapped.tag, 16),
      ciphertext: base64(wrapped.ciphertext, 32),
    },
  };
}

function invalid(): Error {
  return new Error("MCP rollback identity is unavailable or no longer current");
}
