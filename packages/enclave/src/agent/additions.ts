import { randomUUID } from "node:crypto";
import {
  buildWeb3SignedHeader,
  ADD_DATA_TYPES,
} from "@opendatalabs/vana-sdk/node";
import {
  encodeAbiParameters,
  getAddress,
  isAddress,
  keccak256,
  stringToHex,
} from "viem";
import type { AgentServerOptions } from "./http.js";
import { userPsId } from "../identity/paths.js";
import { deriveEnclaveAccount } from "../identity/wallet.js";

export class AdditionsRefused extends Error {}
const uint = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(0|[1-9][0-9]{0,77})$/.test(value) &&
  BigInt(value) < 2n ** 256n;
const hash = (value: unknown): value is `0x${string}` =>
  typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
const scopeValid = (value: unknown): value is string =>
  typeof value === "string" &&
  Buffer.byteLength(value) > 0 &&
  Buffer.byteLength(value) <= 256;
const checkpointScope = (scope: string, source: unknown) => {
  if (scope === "vana.system.additions") return source === undefined;
  if (!scopeValid(source) || source.startsWith("vana.system.")) return false;
  const literal = `vana.system.additions.${source}`;
  const derived =
    Buffer.byteLength(literal) <= 256
      ? literal
      : `vana.system.additions-hash.${keccak256(stringToHex(source)).slice(2)}`;
  return scope === derived && !/[\\/]/.test(derived);
};
const tombstones = new Set<string>([
  keccak256(stringToHex("vana.data-point.tombstone.v1")),
  keccak256(stringToHex("vana.data-point.tombstone.metadata.v1")),
]);

function origin(value: string): string {
  const url = new URL(value);
  if (
    (url.protocol !== "https:" &&
      !(
        url.protocol === "http:" &&
        ["127.0.0.1", "localhost"].includes(url.hostname)
      )) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/"
  )
    throw new AdditionsRefused("Invalid configured origin");
  return url.origin;
}

/** A closed signing vocabulary: no caller-selected origins, domains or methods. */
export async function signAdditions(
  options: AgentServerOptions,
  token: string,
  value: unknown,
): Promise<{ authorization: string } | { signature: `0x${string}` }> {
  const jobs = options.jobs;
  if (!jobs?.additions || typeof value !== "object" || value === null)
    throw new AdditionsRefused("Additions unavailable");
  const body = value as Record<string, unknown>;
  const lookup = jobs.lookupSandbox(token);
  if (
    lookup.kind !== "active" ||
    typeof body.owner !== "string" ||
    !isAddress(body.owner) ||
    !scopeValid(body.scope) ||
    body.chainId !== jobs.chainId ||
    userPsId(jobs.chainId, body.owner) !== lookup.identity.userPsId
  )
    throw new AdditionsRefused("Identity or selector refused");
  const owner = getAddress(body.owner);
  const scope = body.scope;
  const gatewayOrigin = origin(jobs.additions.gatewayUrl);
  const storageOrigin = origin(jobs.storageApiUrl);
  const account = await deriveEnclaveAccount(
    options.client,
    lookup.identity.userPsId,
    lookup.identity.epoch,
  );
  const current = () => {
    const fresh = jobs.lookupSandbox(token);
    if (
      fresh.kind !== "active" ||
      fresh.key !== lookup.key ||
      fresh.generation !== lookup.generation ||
      fresh.identity.userPsId !== lookup.identity.userPsId ||
      fresh.identity.epoch !== lookup.identity.epoch
    )
      throw new AdditionsRefused("Placement changed");
  };
  current();
  const id = keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "string" }],
      [owner, scope],
    ),
  );
  const inventoryUri = (after: string, limit: string) =>
    `/v1/data/${id}/versions?${new URLSearchParams({ user: owner.toLowerCase(), scope, after, limit })}`;
  const sign = async (
    aud: string,
    method: string,
    uri: string,
    bodyHash?: string,
  ) => {
    const iat = Math.floor(Date.now() / 1000);
    const authorization = await buildWeb3SignedHeader({
      signMessage: account.signMessage,
      aud,
      method,
      uri,
      bodyHash,
      iat,
      exp: iat + 60,
      nonce: randomUUID(),
    });
    current();
    return authorization;
  };
  if (body.kind === "inventory") {
    if (
      Object.keys(body).some(
        (key) =>
          !["kind", "owner", "chainId", "scope", "after", "limit"].includes(
            key,
          ),
      ) ||
      !uint(body.after) ||
      typeof body.limit !== "string" ||
      !/^[1-9][0-9]{0,3}$/.test(body.limit) ||
      Number(body.limit) > 1000
    )
      throw new AdditionsRefused("Inventory selectors refused");
    return {
      authorization: await sign(
        gatewayOrigin,
        "GET",
        inventoryUri(body.after, body.limit),
      ),
    };
  }
  if (
    !checkpointScope(scope, body.sourceScope) ||
    !uint(body.version) ||
    body.version === "0"
  )
    throw new AdditionsRefused("Checkpoint selector refused");
  // The inventory route checks current registration on every request. A cached
  // identity or a derivable key alone never authorizes checkpoint writes.
  const uri = inventoryUri("0", "1");
  const response = await fetch(`${gatewayOrigin}${uri}`, {
    headers: { Authorization: await sign(gatewayOrigin, "GET", uri) },
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new AdditionsRefused("Current registration unavailable");
  }
  // A successful proxy/error page is not registration evidence.
  const reader = response.body?.getReader();
  if (!reader) throw new AdditionsRefused("Missing registration evidence");
  let evidenceText = "";
  const decoder = new TextDecoder();
  let evidenceBytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      evidenceBytes += value.byteLength;
      if (evidenceBytes > 64 * 1024)
        throw new AdditionsRefused("Registration evidence too large");
      evidenceText += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel();
  }
  const evidence: unknown = JSON.parse(evidenceText + decoder.decode());
  if (
    typeof evidence !== "object" ||
    evidence === null ||
    !("data" in evidence) ||
    typeof evidence.data !== "object" ||
    evidence.data === null ||
    !("ownerAddress" in evidence.data) ||
    evidence.data.ownerAddress !== owner ||
    !("dataPointId" in evidence.data) ||
    evidence.data.dataPointId !== id ||
    !("scope" in evidence.data) ||
    evidence.data.scope !== scope ||
    !("versions" in evidence.data) ||
    !Array.isArray(evidence.data.versions)
  )
    throw new AdditionsRefused("Invalid registration evidence");
  current();
  if (body.kind === "upload") {
    if (
      Object.keys(body).some(
        (key) =>
          ![
            "kind",
            "owner",
            "chainId",
            "scope",
            "version",
            "bodyHash",
            "sourceScope",
          ].includes(key),
      ) ||
      typeof body.bodyHash !== "string" ||
      !/^sha256:[0-9a-f]{64}$/.test(body.bodyHash)
    )
      throw new AdditionsRefused("Upload commitment refused");
    const key = [scope, body.version].map(encodeURIComponent).join("/");
    return {
      authorization: await sign(
        storageOrigin,
        "PUT",
        `/v1/chains/${jobs.chainId}/blobs/${owner.toLowerCase()}/${key}`,
        body.bodyHash,
      ),
    };
  }
  if (
    body.kind === "register" &&
    !Object.keys(body).some(
      (key) =>
        ![
          "kind",
          "owner",
          "chainId",
          "scope",
          "version",
          "dataHash",
          "metadataHash",
          "sourceScope",
        ].includes(key),
    ) &&
    hash(body.dataHash) &&
    hash(body.metadataHash) &&
    !tombstones.has(body.dataHash.toLowerCase()) &&
    !tombstones.has(body.metadataHash.toLowerCase())
  ) {
    const signature = await account.signTypedData({
      domain: {
        name: "Vana Data Portability",
        version: "1",
        chainId: jobs.chainId,
        verifyingContract: jobs.additions.dataRegistry,
      },
      types: { AddData: [...ADD_DATA_TYPES.AddData] },
      primaryType: "AddData",
      message: {
        ownerAddress: owner,
        scope,
        expectedVersion: BigInt(body.version),
        dataHash: body.dataHash,
        metadataHash: body.metadataHash,
      },
    });
    current();
    return { signature };
  }
  throw new AdditionsRefused("Operation refused");
}
