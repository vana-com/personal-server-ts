import { z } from "zod";
import { getAddress, keccak256, stringToHex } from "viem";
import {
  buildWeb3SignedHeader,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";
import {
  readBoundedResponse,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";
import { resolveVanaStorageEndpoint } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import type { RequestSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { PsLiteStateStore } from "./state.js";

/** Hosts may expose these only when cancelling actually settles their wallet request. */
export interface PsLiteBoundedOwnerSigner {
  signMessageBounded(
    message: string,
    signal?: AbortSignal,
  ): Promise<`0x${string}`>;
  signAddDataBounded(
    message: Parameters<ServerSigner["signAddData"]>[0],
    signal?: AbortSignal,
  ): Promise<`0x${string}`>;
}

const hash = z.string().regex(/^0x[0-9a-fA-F]{64}$/);
const publicationSchema = z.object({
  scope: z.string().min(1).max(256),
  expectedVersion: z.string().regex(/^[1-9][0-9]*$/),
  dataHash: hash,
  metadataHash: hash,
  encrypted: z.array(z.number().int().min(0).max(255)),
});
export interface PsLitePreparedPublication {
  scope: string;
  expectedVersion: string;
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
  encrypted: Uint8Array;
}
const sealedSchema = z.object({
  iv: z.array(z.number().int().min(0).max(255)).length(12),
  ciphertext: z.array(z.number().int().min(0).max(255)),
});

export function createPsLiteAdditionsTransport(options: {
  config: ServerConfig;
  ownerAddress: string;
  stateStore: PsLiteStateStore;
  masterKey: Uint8Array;
  ownerSigner: PsLiteBoundedOwnerSigner;
  fetch?: typeof globalThis.fetch;
}) {
  const candidateStore = options.stateStore.bounded;
  if (!candidateStore)
    throw new Error("Bounded additions persistence unavailable");
  const stateStore = candidateStore;
  const owner = getAddress(options.ownerAddress).toLowerCase();
  const storage = resolveVanaStorageEndpoint(options.config);
  const gateway = options.config.gateway.url.replace(/\/+$/, "");
  const network = `vana:${options.config.gateway.chainId}:${new URL(gateway).origin}`;
  const fetcher = options.fetch ?? globalThis.fetch;
  const binding = (scope: string) => JSON.stringify([owner, network, scope]);
  const journalKey = (scope: string): `additions-publication-v1:${string}` =>
    `additions-publication-v1:${keccak256(stringToHex(binding(scope)))}`;
  const blobUrl = (scope: string, version: string) =>
    `${storage}/v1/chains/${options.config.gateway.chainId}/blobs/${owner}/${scope.split("/").map(encodeURIComponent).join("/")}/${version}`;
  const key = crypto.subtle.importKey(
    "raw",
    Uint8Array.from(
      deriveScopeKey(options.masterKey, "ps-lite.additions-journal.v1"),
    ),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );

  async function fetchBounded(
    input: {
      url: string;
      method?: string;
      headers?: [string, string][];
      body?: Uint8Array;
    },
    budget: ByteBudget,
  ) {
    budget.charge(input.body?.byteLength ?? 0);
    const response = await fetcher(input.url, {
      method: input.method ?? "GET",
      headers: input.headers,
      body: input.body ? Uint8Array.from(input.body) : undefined,
      signal: budget.signal,
      redirect: "error",
      cache: "no-store",
    });
    const body = await readBoundedResponse(response, budget);
    budget.charge();
    return {
      status: response.status,
      headers: Array.from(response.headers.entries()),
      body,
    };
  }

  async function signRequest(
    params: Parameters<RequestSigner["signRequest"]>[0],
    signal?: AbortSignal,
  ) {
    signal?.throwIfAborted();
    const result = await buildWeb3SignedHeader({
      ...params,
      signMessage: (message: string) =>
        options.ownerSigner.signMessageBounded(message, signal),
    });
    signal?.throwIfAborted();
    return result;
  }

  async function readPending(
    scope: string,
    budget: ByteBudget,
  ): Promise<PsLitePreparedPublication | null> {
    budget.charge();
    const value: unknown = await stateStore.get(
      journalKey(scope),
      budget.signal,
    );
    budget.charge();
    if (value === null) return null;
    const entry = sealedSchema.parse(value);
    budget.charge(entry.ciphertext.length * 16);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: Uint8Array.from(entry.iv),
        additionalData: new TextEncoder().encode(binding(scope)),
      },
      await key,
      Uint8Array.from(entry.ciphertext),
    );
    budget.charge(plaintext.byteLength * 8);
    const parsed = publicationSchema.parse(
      JSON.parse(new TextDecoder().decode(plaintext)),
    );
    if (parsed.scope !== scope)
      throw new Error("Checkpoint journal scope mismatch");
    return {
      ...parsed,
      dataHash: hash.parse(parsed.dataHash) as `0x${string}`,
      metadataHash: hash.parse(parsed.metadataHash) as `0x${string}`,
      encrypted: Uint8Array.from(parsed.encrypted),
    };
  }

  async function clearPending(scope: string, budget: ByteBudget) {
    budget.charge();
    await stateStore.delete(journalKey(scope), budget.signal);
    budget.charge();
  }

  async function publish(
    prepared: PsLitePreparedPublication,
    budget: ByteBudget,
  ) {
    budget.charge(prepared.encrypted.byteLength * 32);
    const pending = await readPending(prepared.scope, budget);
    if (
      pending &&
      (pending.expectedVersion !== prepared.expectedVersion ||
        pending.dataHash !== prepared.dataHash ||
        pending.metadataHash !== prepared.metadataHash ||
        pending.encrypted.length !== prepared.encrypted.length ||
        pending.encrypted.some(
          (byte, index) => byte !== prepared.encrypted[index],
        ))
    ) {
      throw new Error(
        "Interrupted checkpoint must be reconciled before replacement",
      );
    }
    if (!pending) {
      const plaintext = new TextEncoder().encode(
        JSON.stringify({
          ...prepared,
          encrypted: Array.from(prepared.encrypted),
        }),
      );
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: new TextEncoder().encode(binding(prepared.scope)),
        },
        await key,
        plaintext,
      );
      budget.charge();
      await stateStore.set(
        journalKey(prepared.scope),
        {
          iv: Array.from(iv),
          ciphertext: Array.from(new Uint8Array(ciphertext)),
        },
        budget.signal,
      );
      budget.charge();
    }
    const url = blobUrl(prepared.scope, prepared.expectedVersion);
    const authorization = await signRequest(
      {
        aud: storage,
        method: "PUT",
        uri: new URL(url).pathname,
        body: prepared.encrypted,
      },
      budget.signal,
    );
    const uploaded = await fetchBounded(
      {
        url,
        method: "PUT",
        headers: [
          ["authorization", authorization],
          ["content-type", "application/octet-stream"],
        ],
        body: prepared.encrypted,
      },
      budget,
    );
    if (uploaded.status < 200 || uploaded.status >= 300)
      throw new Error(`Checkpoint upload failed (${uploaded.status})`);
    budget.charge();
    const signature = await options.ownerSigner.signAddDataBounded(
      {
        ownerAddress: getAddress(owner),
        scope: prepared.scope,
        dataHash: prepared.dataHash,
        metadataHash: prepared.metadataHash,
        expectedVersion: BigInt(prepared.expectedVersion),
      },
      budget.signal,
    );
    budget.charge();
    const body = new TextEncoder().encode(
      JSON.stringify({
        ownerAddress: owner,
        scope: prepared.scope,
        dataHash: prepared.dataHash,
        metadataHash: prepared.metadataHash,
        expectedVersion: prepared.expectedVersion,
      }),
    );
    const registered = await fetchBounded(
      {
        url: `${gateway}/v1/data`,
        method: "POST",
        headers: [
          ["Content-Type", "application/json"],
          ["Authorization", `Web3Signed ${signature}`],
        ],
        body,
      },
      budget,
    );
    if (registered.status < 200 || registered.status >= 300)
      throw new Error(`Checkpoint registration failed (${registered.status})`);
    // Keep the journal until the worker verifies inventory AND decrypted blob commitments.
  }
  async function download(key: string, budget: ByteBudget) {
    const slash = key.lastIndexOf("/");
    const scope = key.slice(0, slash);
    const version = key.slice(slash + 1);
    if (slash < 1 || !/^[1-9][0-9]*$/.test(version))
      throw new Error("Invalid checkpoint blob key");
    const response = await fetchBounded(
      { url: blobUrl(scope, version) },
      budget,
    );
    if (response.status < 200 || response.status >= 300)
      throw new Error(`Checkpoint download failed (${response.status})`);
    return response.body;
  }
  return {
    fetch: fetchBounded,
    signRequest,
    publish,
    readPending,
    clearPending,
    download,
  };
}

export type PsLiteAdditionsTransport = ReturnType<
  typeof createPsLiteAdditionsTransport
>;
