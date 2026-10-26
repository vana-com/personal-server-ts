import { z } from "zod";
import { getAddress, keccak256, stringToHex } from "viem";
import {
  buildWeb3SignedHeader,
  deriveScopeKey,
} from "@opendatalabs/vana-sdk/browser";
import {
  readBoundedResponse,
  createVersionInventoryClient,
  additionsLedgerScope,
  ADDITIONS_SUMMARY_SCOPE,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";
import { createGatewayDeleteDataPort } from "@opendatalabs/personal-server-ts-core/sync";
import {
  resolveVanaStorageEndpoint,
  StoredBlobConflictError,
} from "@opendatalabs/personal-server-ts-core/storage/adapters";
import {
  publishPreparedVersion,
  NeedsFencedPublicationError,
  type PublicationRecord,
} from "@opendatalabs/personal-server-ts-core/publication";
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
const publicationHeaderSchema = z.object({
  scope: z.string().min(1).max(256),
  expectedVersion: z.string().regex(/^[1-9][0-9]*$/),
  dataHash: hash,
  metadataHash: hash,
});
const publicationSchema = publicationHeaderSchema.extend({
  encrypted: z.array(z.number().int().min(0).max(255)),
});
export interface PsLitePreparedPublication {
  scope: string;
  expectedVersion: string;
  dataHash: `0x${string}`;
  metadataHash: `0x${string}`;
  encrypted: Uint8Array;
}
const legacySealedSchema = z.object({
  iv: z.array(z.number().int().min(0).max(255)).length(12),
  ciphertext: z.array(z.number().int().min(0).max(255)),
});

const binarySealedSchema = z.object({
  version: z.literal(2),
  iv: z.instanceof(Uint8Array).refine((bytes) => bytes.byteLength === 12),
  ciphertext: z.instanceof(Uint8Array),
});

export function createPsLiteAdditionsTransport(options: {
  config: ServerConfig;
  ownerAddress: string;
  stateStore: PsLiteStateStore;
  masterKey: Uint8Array;
  ownerSigner: PsLiteBoundedOwnerSigner;
  /** Authentication origin may differ from a preview Storage endpoint. */
  storageAudience?: string;
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

  // Each session belongs to one Web Lock and one worker lifetime. Cache only
  // authenticated fingerprints, since returning candidate buffers transfers ownership.
  function openSession() {
    const fingerprints = new Map<string, string | null>();
    function fingerprint(prepared: PsLitePreparedPublication) {
      return JSON.stringify([
        prepared.scope,
        prepared.expectedVersion,
        prepared.dataHash,
        prepared.metadataHash,
        keccak256(prepared.encrypted),
      ]);
    }
    async function persistPending(
      prepared: PsLitePreparedPublication,
      budget: ByteBudget,
    ) {
      const { encrypted, ...metadata } = prepared;
      const header = new TextEncoder().encode(JSON.stringify(metadata));
      if (header.byteLength > 4096)
        throw new Error("Checkpoint journal header too large");
      budget.charge((header.byteLength + 20) * 8);
      const plaintext = new Uint8Array(
        4 + header.byteLength + encrypted.byteLength,
      );
      new DataView(plaintext.buffer).setUint32(0, header.byteLength);
      plaintext.set(header, 4);
      plaintext.set(encrypted, 4 + header.byteLength);
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
        { version: 2, iv, ciphertext: new Uint8Array(ciphertext) },
        budget.signal,
      );
      budget.charge();
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
      if (value === null) {
        fingerprints.set(scope, null);
        return null;
      }
      // Bound clone/validation work before a schema can materialize legacy arrays.
      // Inspect only the container and length here; array validation happens after admission.
      if (!value || typeof value !== "object" || !("ciphertext" in value))
        throw new Error("Invalid checkpoint journal");
      const bytes = value.ciphertext;
      if (!(bytes instanceof Uint8Array) && !Array.isArray(bytes))
        throw new Error("Invalid checkpoint journal ciphertext");
      budget.charge(bytes.length * 16);
      const binary = binarySealedSchema.safeParse(value);
      const entry = binary.success
        ? binary.data
        : legacySealedSchema.parse(value);
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
      let prepared: PsLitePreparedPublication;
      if (binary.success) {
        if (plaintext.byteLength < 4)
          throw new Error("Invalid checkpoint journal header");
        const headerLength = new DataView(plaintext).getUint32(0);
        if (headerLength > 4096 || headerLength > plaintext.byteLength - 4)
          throw new Error("Invalid checkpoint journal header length");
        const header = publicationHeaderSchema.parse(
          JSON.parse(
            new TextDecoder().decode(
              new Uint8Array(plaintext, 4, headerLength),
            ),
          ),
        );
        prepared = {
          ...header,
          dataHash: hash.parse(header.dataHash) as `0x${string}`,
          metadataHash: hash.parse(header.metadataHash) as `0x${string}`,
          encrypted: new Uint8Array(plaintext, 4 + headerLength),
        };
      } else {
        const parsed = publicationSchema.parse(
          JSON.parse(new TextDecoder().decode(plaintext)),
        );
        prepared = {
          ...parsed,
          dataHash: hash.parse(parsed.dataHash) as `0x${string}`,
          metadataHash: hash.parse(parsed.metadataHash) as `0x${string}`,
          encrypted: Uint8Array.from(parsed.encrypted),
        };
      }
      if (prepared.scope !== scope)
        throw new Error("Checkpoint journal scope mismatch");
      if (!binary.success) {
        // An old admitted intent may need a separate capped migration pass.
        // Commit the compact representation before attempting network retries.
        budget.charge(prepared.encrypted.byteLength * 8 + 32 * 1024);
        await persistPending(prepared, budget);
      }
      fingerprints.set(scope, fingerprint(prepared));
      return prepared;
    }

    async function clearPending(scope: string, budget: ByteBudget) {
      budget.charge();
      await stateStore.delete(journalKey(scope), budget.signal);
      fingerprints.set(scope, null);
      budget.charge();
    }

    async function publish(
      prepared: PsLitePreparedPublication,
      budget: ByteBudget,
    ) {
      budget.charge(prepared.encrypted.byteLength * 32);
      if (!fingerprints.has(prepared.scope))
        await readPending(prepared.scope, budget);
      const pending = fingerprints.get(prepared.scope);
      const candidate = fingerprint(prepared);
      if (pending && pending !== candidate)
        throw new Error(
          "Interrupted checkpoint must be reconciled before replacement",
        );
      const inventory = createVersionInventoryClient({
        gatewayUrl: gateway,
        ownerAddress: owner,
        ownerSigner: { signRequest },
        boundedOwnerSigner: signRequest,
        fetch: fetcher,
      });
      async function readHead(): Promise<PublicationRecord | null> {
        const page = await inventory.page(prepared.scope, { limit: 1, budget });
        return page.data.head
          ? { ...page.data.head, id: page.data.dataPointId }
          : null;
      }
      const wanted = {
        dataHash: prepared.dataHash,
        metadataHash: prepared.metadataHash,
        sizeBytes: prepared.encrypted.byteLength,
        lineage: null,
      };
      try {
        const result = await publishPreparedVersion({
          ownerAddress: owner,
          scope: prepared.scope,
          preferredVersion: BigInt(prepared.expectedVersion),
          head: await readHead(),
          readHead,
          async prepare() {
            return {
              encrypted: prepared.encrypted,
              wanted,
              async verifyStored(bytes) {
                budget.charge(bytes.byteLength);
                if (
                  bytes.byteLength !== prepared.encrypted.byteLength ||
                  !bytes.every(
                    (byte, index) => byte === prepared.encrypted[index],
                  )
                )
                  throw new NeedsFencedPublicationError(
                    prepared.scope,
                    "stored bytes differ from the authenticated checkpoint journal",
                    false,
                  );
                return wanted;
              },
            };
          },
          storageAdapter: {
            urlForKey: (key) => {
              const slash = key.lastIndexOf("/");
              return blobUrl(key.slice(0, slash), key.slice(slash + 1));
            },
            async upload(key, bytes) {
              const version = key.slice(key.lastIndexOf("/") + 1);
              if (
                !fingerprints.get(prepared.scope) ||
                version !== prepared.expectedVersion
              ) {
                // Rebase the durable intent before leaving bytes at the new key.
                prepared = { ...prepared, expectedVersion: version };
                await persistPending(prepared, budget);
                fingerprints.set(prepared.scope, fingerprint(prepared));
              }
              const url = blobUrl(prepared.scope, version);
              const authorization = await signRequest(
                {
                  aud: options.storageAudience ?? storage,
                  method: "PUT",
                  uri: new URL(url).pathname,
                  body: bytes,
                },
                budget.signal,
              );
              const response = await fetchBounded(
                {
                  url,
                  method: "PUT",
                  headers: [
                    ["authorization", authorization],
                    ["content-type", "application/octet-stream"],
                  ],
                  body: bytes,
                },
                budget,
              );
              if (response.status === 409)
                throw new StoredBlobConflictError(key);
              if (response.status < 200 || response.status >= 300)
                throw new Error(
                  `Checkpoint upload failed (${response.status})`,
                );
              return url;
            },
            async download(url) {
              const response = await fetchBounded({ url }, budget);
              if (response.status < 200 || response.status >= 300)
                throw new Error(
                  `Checkpoint download failed (${response.status})`,
                );
              return response.body;
            },
            async exists(url) {
              const response = await fetchBounded(
                { url, method: "HEAD" },
                budget,
              );
              if (response.status === 404) return false;
              if (response.status < 200 || response.status >= 300)
                throw new Error(
                  `Checkpoint availability check failed (${response.status})`,
                );
              return true;
            },
            delete: async () => {
              throw new Error("Publication cannot delete ciphertext");
            },
          },
          signer: {
            async signAddData(message) {
              budget.charge();
              const signature = await options.ownerSigner.signAddDataBounded(
                message,
                budget.signal,
              );
              budget.charge();
              return signature;
            },
          },
          gateway: {
            async registerDataPoint({ signature, ...registration }) {
              const body = new TextEncoder().encode(
                JSON.stringify(registration),
              );
              const response = await fetchBounded(
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
              if (response.status < 200 || response.status >= 300) {
                const message = new TextDecoder().decode(response.body);
                throw new Error(
                  `Gateway error: ${response.status} Checkpoint registration failed: ${message}`,
                );
              }
              const receipt = z
                .object({ dataPointId: hash.optional(), id: hash.optional() })
                .parse(JSON.parse(new TextDecoder().decode(response.body)));
              return {
                dataPointId: hash.parse(receipt.dataPointId ?? receipt.id),
              };
            },
          },
        });
        if (
          !fingerprints.get(prepared.scope) ||
          String(result.version) !== prepared.expectedVersion
        ) {
          prepared = { ...prepared, expectedVersion: String(result.version) };
          await persistPending(prepared, budget);
          fingerprints.set(prepared.scope, fingerprint(prepared));
        }
        // Keep the journal until the worker verifies inventory AND blob commitments.
        return {
          expectedVersion: String(result.version),
          dataHash: result.dataHash,
          metadataHash: result.metadataHash,
        };
      } catch (error) {
        if (error instanceof NeedsFencedPublicationError)
          throw new NeedsFencedPublicationError(
            error.scope,
            error.reason,
            false,
          );
        throw error;
      }
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
  async function tombstone(scope: string, budget: ByteBudget) {
    budget.charge();
    if (
      scope !== "vana.system.additions" &&
      !scope.startsWith("vana.system.additions.") &&
      !/^vana\.system\.additions-hash\.[0-9a-f]{64}$/.test(scope)
    )
      throw new Error("Bounded deletion is limited to additions scopes");
    const inventory = createVersionInventoryClient({
      gatewayUrl: gateway,
      ownerAddress: options.ownerAddress,
      ownerSigner: { signRequest },
      boundedOwnerSigner: signRequest,
      fetch: fetcher,
    });
    const port = createGatewayDeleteDataPort({
      gatewayUrl: gateway,
      serverOwner: getAddress(options.ownerAddress),
      dataPointFeed: {
        async getDataPoint({ ownerAddress, scope }) {
          if (ownerAddress.toLowerCase() !== owner)
            throw new Error("Deletion owner changed");
          const page = await inventory.page(scope, {
            limit: 1,
            budget,
            signal: budget.signal,
          });
          const head = page.data.head;
          return head
            ? {
                ...head,
                id: page.data.dataPointId,
                ownerAddress,
                scope,
                addedAt: page.data.versions[0]?.addedAt ?? "",
              }
            : null;
        },
        listDataPointsByOwner: async () => {
          throw new Error("Deletion cannot enumerate data");
        },
      },
      signer: {
        signAddData: (message) =>
          options.ownerSigner.signAddDataBounded(message, budget.signal),
      },
      storage: {
        endpoint: storage,
        audience: options.storageAudience,
        chainId: options.config.gateway.chainId,
        signMessage: (message) =>
          options.ownerSigner.signMessageBounded(message, budget.signal),
      },
      fetch: async (url, init) => {
        const result = await fetchBounded(
          {
            url: String(url),
            method: init?.method,
            headers: Array.from(new Headers(init?.headers).entries()),
            body:
              typeof init?.body === "string"
                ? new TextEncoder().encode(init.body)
                : undefined,
          },
          budget,
        );
        return new Response(
          result.body.length ? Uint8Array.from(result.body) : null,
          { status: result.status, headers: result.headers },
        );
      },
    });
    const outcome = await port.tombstone(scope);
    budget.charge();
    return outcome;
  }
  async function deleteScope(scope: string, budget: ByteBudget) {
    if (scope.startsWith("vana.system.")) return;
    const intent: `additions-deletion-v1:${string}` = `additions-deletion-v1:${keccak256(stringToHex(binding(scope)))}`;
    const pending = await stateStore.get<boolean>(intent, budget.signal);
    budget.charge();
    const ledger = additionsLedgerScope(scope);
    // Write intent before touching the registry: a crash after the ledger
    // tombstone must still retry summary invalidation and journal clearing.
    await stateStore.set(intent, true, budget.signal);
    const outcome = await tombstone(ledger, budget);
    await openSession().clearPending(ledger, budget);
    if (pending || outcome.status === "tombstoned") {
      await tombstone(ADDITIONS_SUMMARY_SCOPE, budget);
      await openSession().clearPending(ADDITIONS_SUMMARY_SCOPE, budget);
    }
    // Repeated polls must not invalidate a subsequently rebuilt summary.
    await stateStore.delete(intent, budget.signal);
    budget.charge();
  }
  return { ...openSession(), openSession, tombstone, deleteScope };
}

export type PsLiteAdditionsTransport = ReturnType<
  typeof createPsLiteAdditionsTransport
>;
