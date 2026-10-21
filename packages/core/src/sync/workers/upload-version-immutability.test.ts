/**
 * Upload-before-registration conflicts must never change a committed
 * version's bytes (BUI-911).
 *
 * The worker uploads ciphertext to `{scope}/{version}` before the gateway
 * decides whether that version is still free. vana-storage keys are
 * write-once: a PUT of different bytes to an existing key answers 409
 * BLOB_EXISTS and keeps the stored bytes. These tests drive the production
 * upload worker and the production Vana storage adapter (SDK provider, real
 * HTTP requests) against an emulator of that storage contract, with real
 * OpenPGP encryption and a gateway fake that enforces the gateway's
 * contiguous-version rule.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as openpgp from "openpgp";
import { keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  decryptWithPassword,
  deriveScopeKey,
  encryptWithPassword,
  type DataFileEnvelope,
  type DataPointRecord,
  type GatewayClient,
} from "@opendatalabs/vana-sdk/browser";

import { ServerConfigSchema } from "../../schemas/server-config.js";
import type { ServerSigner } from "../../signing/signer.js";
import type { StorageAdapter } from "../../storage/adapters/interface.js";
import { createVanaSyncStorageAdapter } from "../../storage/adapters/vana.js";
import { createMemoryDataStorage } from "../../test-utils/memory-storage.js";
import type { Logger } from "../../logger/index.js";
import { uploadOne } from "./upload.js";
import type { FencedPublicationPort } from "../../publication/publish.js";
import { TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH } from "../tombstone.js";

const ENDPOINT = "https://storage.test";
const CHAIN_ID = 14800;
const SCOPE = "linkedin.profile";
const DATA_POINT_ID = `0x${"ab".repeat(32)}`;
const owner = privateKeyToAccount(`0x${"11".repeat(32)}`);
const OWNER = owner.address;
const masterKey = new Uint8Array(65).fill(0xaa);
const scopeKeyHex = Buffer.from(deriveScopeKey(masterKey, SCOPE)).toString(
  "hex",
);

/**
 * In-memory vana-storage: write-once PUT, GET, DELETE (src/blobs/routes.ts).
 * `writeOnce: false` models the storage deployed before BUI-911, whose PUT
 * replaced whatever the key held.
 */
class WriteOnceStorage {
  readonly blobs = new Map<string, Uint8Array>();
  readonly puts: string[] = [];

  constructor(private readonly writeOnce = true) {}

  keyFor(version: number | bigint): string {
    return `/v1/chains/${CHAIN_ID}/blobs/${OWNER.toLowerCase()}/${SCOPE}/${version}`;
  }

  async handle(input: RequestInfo | URL, init?: RequestInit) {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const key = decodeURIComponent(url.pathname);
    const method = init?.method ?? "GET";
    const stored = this.blobs.get(key);
    if (method === "PUT") {
      this.puts.push(key);
      const body = new Uint8Array(init!.body as ArrayBuffer | Uint8Array);
      if (stored && this.writeOnce) {
        if (Buffer.from(stored).equals(Buffer.from(body))) {
          return Response.json(
            { key, url: url.href, size: body.length },
            {
              status: 200,
            },
          );
        }
        return Response.json(
          {
            error: "BLOB_EXISTS",
            message: "Blob already exists with different content",
          },
          { status: 409, statusText: "Conflict" },
        );
      }
      this.blobs.set(key, body);
      return Response.json(
        { key, url: url.href, size: body.length },
        {
          status: 201,
        },
      );
    }
    if (method === "DELETE") {
      if (!stored) return new Response(null, { status: 404 });
      this.blobs.delete(key);
      return Response.json({ deleted: true });
    }
    if (!stored)
      return new Response(null, { status: 404, statusText: "Not Found" });
    return new Response(new Uint8Array(stored), { status: 200 });
  }
}

/**
 * Gateway registry for one scope: contiguous versions, 409 otherwise. With
 * `pendingRefresh`, every row stays pending and a same-version POST replaces
 * it, as the gateway allows before a row is broadcast.
 */
class Registry {
  readonly versions = new Map<bigint, DataPointRecord>();
  failNextRegistration = false;
  pendingRefresh = false;
  generation = 0;
  readonly lineageAtVersion = new Map<bigint, readonly string[] | undefined>();

  deleteScope() {
    this.generation++;
    const version = BigInt(this.head()?.expectedVersion ?? "0") + 1n;
    this.commit(version, TOMBSTONE_DATA_HASH, TOMBSTONE_METADATA_HASH);
    Object.assign(this.versions.get(version)!, {
      deletedAt: "2026-10-21T01:00:00Z",
      status: "pending",
    });
  }

  fenced(): FencedPublicationPort {
    const snapshot = () => ({
      generation: String(this.generation),
      head: this.head() ? { ...this.head()! } : null,
    });
    return {
      read: async () => snapshot(),
      commit: async (request) => {
        const before = this.beforeRegister;
        this.beforeRegister = undefined;
        await before?.();
        if (JSON.stringify(request.fence) !== JSON.stringify(snapshot()))
          throw new Error("Gateway error: 409 PUBLICATION_FENCE_CHANGED");
        if (this.failNextRegistration) {
          this.failNextRegistration = false;
          throw new Error("fetch failed");
        }
        const version = BigInt(request.expectedVersion);
        if (request.mode === "register") {
          if (version !== BigInt(this.head()?.expectedVersion ?? "0") + 1n)
            throw new Error("Gateway error: 409 wrong next version");
          this.commit(version, request.dataHash, request.metadataHash);
          this.lineageAtVersion.set(version, request.lineage);
          this.afterCommit?.();
        } else {
          const head = this.head();
          if (
            !head ||
            head.expectedVersion !== request.expectedVersion ||
            head.dataHash !== request.dataHash ||
            head.metadataHash !== request.metadataHash ||
            (head as { deletedAt?: string }).deletedAt
          )
            throw new Error("Gateway error: 409 adoption mismatch");
        }
        return { dataPointId: DATA_POINT_ID, fence: snapshot() };
      },
    };
  }
  beforeRegister?: () => Promise<void>;
  afterCommit?: () => void;

  head(): DataPointRecord | null {
    const top = [...this.versions.keys()].sort((a, b) => (a < b ? 1 : -1))[0];
    return top === undefined ? null : this.versions.get(top)!;
  }

  commit(
    version: bigint,
    dataHash: string,
    metadataHash = `0x${"00".repeat(32)}`,
  ) {
    this.versions.set(version, {
      id: DATA_POINT_ID,
      ownerAddress: OWNER,
      scope: SCOPE,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      addedAt: "2026-10-21T00:00:00Z",
    });
  }

  client(): GatewayClient {
    return {
      getDataPoint: vi.fn(async () => this.head()),
      registerDataPoint: vi.fn(async (request) => {
        await this.beforeRegister?.();
        if (this.failNextRegistration) {
          this.failNextRegistration = false;
          throw new Error("fetch failed");
        }
        const version = BigInt(request.expectedVersion);
        const head = BigInt(this.head()?.expectedVersion ?? "0");
        const next = head + 1n;
        const refresh = this.pendingRefresh && version === head;
        if (version < next && !refresh) {
          throw new Error(
            `Gateway error: 409 Stale expectedVersion ${version}. Next valid version is ${next}.`,
          );
        }
        if (version > next) {
          throw new Error(
            `Gateway error: 409 Gap in version sequence: next valid version is ${next}`,
          );
        }
        this.commit(version, request.dataHash, request.metadataHash);
        return { dataPointId: DATA_POINT_ID };
      }),
    } as unknown as GatewayClient;
  }
}

function envelope(name: string): DataFileEnvelope {
  return {
    version: "1.0",
    scope: SCOPE,
    collectedAt: `2026-10-21T00:00:0${name.length % 10}Z`,
    data: { name },
  };
}

function plaintextOf(env: DataFileEnvelope): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(env));
}

function hashOf(env: DataFileEnvelope): string {
  return keccak256(plaintextOf(env));
}

const logger = {
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  debug: vi.fn(),
} as unknown as Logger;

const signer = {
  signAddData: vi.fn(async () => `0x${"11".repeat(65)}` as `0x${string}`),
  signLineageAttestation: vi.fn(
    async () => `0x${"22".repeat(65)}` as `0x${string}`,
  ),
} as Pick<ServerSigner, "signAddData" | "signLineageAttestation">;

function vanaAdapter(): StorageAdapter {
  return createVanaSyncStorageAdapter({
    config: ServerConfigSchema.parse({
      storage: { backend: "vana", config: { vana: { apiUrl: ENDPOINT } } },
      gateway: { chainId: CHAIN_ID },
    }),
    serverOwner: OWNER,
    serverAccount: {
      address: OWNER,
      signMessage: (message: string) => owner.signMessage({ message }),
    },
  });
}

/** One Personal Server replica with a single unsynced local entry. */
async function replica(content: DataFileEnvelope, localVersion: number) {
  const storage = createMemoryDataStorage();
  const write = await storage.writeEnvelope(content);
  storage.insertEntry({
    fileId: null,
    schemaId: null,
    path: write.relativePath,
    scope: SCOPE,
    collectedAt: content.collectedAt,
    sizeBytes: write.sizeBytes,
    version: localVersion,
    dataPointId: null,
  });
  return { storage };
}

describe("upload worker against write-once storage", () => {
  let blobs: WriteOnceStorage;
  let registry: Registry;
  let gateway: GatewayClient;

  beforeEach(() => {
    blobs = new WriteOnceStorage();
    registry = new Registry();
    gateway = registry.client();
    vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) =>
      blobs.handle(input, init),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function upload(
    r: Awaited<ReturnType<typeof replica>>,
    options: {
      feed?: boolean;
      fenced?: boolean;
      afterDownload?: () => Promise<void>;
      configureAdapter?: (adapter: StorageAdapter) => void;
    } = {},
  ) {
    const adapter = vanaAdapter();
    const download = adapter.download.bind(adapter);
    adapter.download = async (url) => {
      const result = await download(url);
      await options.afterDownload?.();
      return result;
    };
    options.configureAdapter?.(adapter);
    return uploadOne(
      {
        storage: r.storage,
        storageAdapter: adapter,
        fencedPublication:
          options.fenced === false ? undefined : registry.fenced(),
        gateway,
        signer,
        masterKey,
        serverOwner: OWNER,
        logger,
        ...(options.feed
          ? {
              dataPointFeed: {
                getDataPoint: async () => registry.head(),
                listDataPointsByOwner: vi.fn(),
              },
            }
          : {}),
      },
      r.storage.entries[0]!,
    );
  }

  /** Every registered version's stored bytes match both its commitments. */
  async function expectCommittedBytesMatch() {
    for (const [version, record] of registry.versions) {
      const stored = blobs.blobs.get(blobs.keyFor(version));
      expect(stored, `blob for committed version ${version}`).toBeDefined();
      const plaintext = await decryptWithPassword(stored!, scopeKeyHex);
      expect(keccak256(plaintext)).toBe(record.dataHash);
      const { collectedAt } = JSON.parse(new TextDecoder().decode(plaintext));
      expect(record.metadataHash).toBe(
        keccak256(
          stringToHex(
            JSON.stringify({
              scope: SCOPE,
              collectedAt,
              sizeBytes: stored!.length,
            }),
          ),
        ),
      );
    }
  }

  it("refuses another writer's interrupted publication without a deletion fence", async () => {
    const occupant = await encryptWithPassword(
      plaintextOf(envelope("another writer")),
      scopeKeyHex,
    );
    blobs.blobs.set(blobs.keyFor(1), occupant);
    const r = await replica(envelope("interrupted"), 1);

    await expect(upload(r, { fenced: false })).rejects.toMatchObject({
      code: "NEEDS_FENCED_PUBLICATION",
      retryable: true,
    });
    expect(registry.versions.size).toBe(0);
    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(occupant);
    expect(r.storage.entries[0]?.dataPointId).toBeNull();
  });

  // Production wiring today: the registry feed is wired, no fence adapter
  // exists. A failure there leaves the scope unsynced until a gateway change.
  const production = { fenced: false, feed: true } as const;

  it("with production wiring, a retry after a failed registration publishes its own stored bytes", async () => {
    const content = envelope("registration failed");
    const r = await replica(content, 1);
    registry.failNextRegistration = true;
    await expect(upload(r, production)).rejects.toThrow("fetch failed");
    const firstBytes = blobs.blobs.get(blobs.keyFor(1));

    await upload(r, production);

    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(firstBytes);
    expect(registry.versions.get(1n)?.dataHash).toBe(hashOf(content));
    expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
    await expectCommittedBytesMatch();
  });

  it("with production wiring, a local version ahead of the registry leaves no blob at a future version", async () => {
    const first = await replica(envelope("local ahead"), 3);
    await upload(first, production);
    expect(registry.versions.get(1n)?.dataHash).toBe(
      hashOf(envelope("local ahead")),
    );
    expect(blobs.blobs.has(blobs.keyFor(3))).toBe(false);

    await upload(await replica(envelope("second"), 2), production);
    const third = await replica(envelope("third entry"), 3);
    await upload(third, production);

    expect(registry.versions.get(3n)?.dataHash).toBe(
      hashOf(envelope("third entry")),
    );
    expect(third.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
    await expectCommittedBytesMatch();
  });

  it("keeps a fresh uncontended upload working without the new capability", async () => {
    const r = await replica(envelope("fresh"), 1);
    await upload(r, { fenced: false });
    expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
    await expectCommittedBytesMatch();
  });

  it("fences deletion after downloading an orphan and before registering it", async () => {
    const old = envelope("abandoned");
    const occupant = await encryptWithPassword(plaintextOf(old), scopeKeyHex);
    blobs.blobs.set(blobs.keyFor(1), occupant);
    const r = await replica(envelope("mine"), 1);
    await expect(
      upload(r, { afterDownload: async () => registry.deleteScope() }),
    ).rejects.toThrow("PUBLICATION_FENCE_CHANGED");
    expect(registry.head()?.dataHash).toBe(TOMBSTONE_DATA_HASH);
    expect(registry.versions.size).toBe(1);
    expect(r.storage.entries[0]?.dataPointId).toBeNull();
    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(occupant);
  });

  it("does not adopt a same-version matching registration with missing bytes", async () => {
    const content = envelope("missing");
    registry.commit(1n, hashOf(content)); // metadata is not satisfiable by a new encryption
    const r = await replica(content, 1);
    await expect(upload(r, { feed: true })).rejects.toThrow(
      "metadata commitment mismatch",
    );
    expect(r.storage.entries[0]?.dataPointId).toBeNull();
    expect(blobs.blobs.has(blobs.keyFor(1))).toBe(false);
  });

  it("returns the adopted v7 URL even when a stale local v1 points at different bytes", async () => {
    await upload(await replica(envelope("history"), 1));
    const content = envelope("current");
    const bytes = await encryptWithPassword(plaintextOf(content), scopeKeyHex);
    blobs.blobs.set(blobs.keyFor(7), bytes);
    registry.commit(
      7n,
      hashOf(content),
      keccak256(
        stringToHex(
          JSON.stringify({
            scope: SCOPE,
            collectedAt: content.collectedAt,
            sizeBytes: bytes.byteLength,
          }),
        ),
      ),
    );
    const r = await replica(content, 1);
    const result = await upload(r, { feed: true });
    expect(result.url).toBe(vanaAdapter().urlForKey(`${SCOPE}/7`));
    expect(r.storage.entries[0]?.version).toBe(7);
    expect(
      await decryptWithPassword(
        await vanaAdapter().download(result.url),
        scopeKeyHex,
      ),
    ).toEqual(plaintextOf(content));
  });

  it("adopts a live registration of its own verified bytes without a fence or a write", async () => {
    const content = envelope("same");
    await upload(await replica(content, 1));
    const putsBefore = blobs.puts.length;
    const r = await replica(content, 1);

    await upload(r, production);

    expect(blobs.puts.length).toBe(putsBefore);
    expect(registry.versions.size).toBe(1);
    expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
  });

  it("requires a fence before recreating the missing bytes of a registered version", async () => {
    const content = envelope("same");
    await upload(await replica(content, 1));
    blobs.blobs.delete(blobs.keyFor(1));
    const r = await replica(content, 1);
    await expect(upload(r, production)).rejects.toMatchObject({
      code: "NEEDS_FENCED_PUBLICATION",
    });
    expect(blobs.blobs.has(blobs.keyFor(1))).toBe(false);
    expect(r.storage.entries[0]?.dataPointId).toBeNull();
  });

  it("registers an acknowledged re-add strictly after the tombstone with a fence", async () => {
    registry.deleteScope();
    const r = await replica(envelope("re-added"), 1);
    r.storage.entries[0]!.afterTombstoneVersion = 1;
    await upload(r, { feed: true });
    expect(registry.versions.get(1n)?.dataHash).toBe(TOMBSTONE_DATA_HASH);
    expect(registry.versions.get(2n)?.dataHash).toBe(
      hashOf(envelope("re-added")),
    );
    expect(r.storage.entries[0]?.version).toBe(2);
  });

  it.each([
    "before upload",
    "after upload",
    "before register",
    "after register",
    "before version acknowledgement",
    "after version acknowledgement",
    "before synced acknowledgement",
    "after synced acknowledgement",
  ])(
    "recovers after a crash %s without changing committed bytes",
    async (transition) => {
      await upload(await replica(envelope("original"), 1));
      const original = blobs.blobs.get(blobs.keyFor(1));
      const content = envelope("next");
      const r = await replica(content, 1);
      const crash = () => {
        throw new Error(`crash ${transition}`);
      };
      const versionUpdate = r.storage.updateEntryVersion.bind(r.storage);
      const syncedUpdate = r.storage.updateDataPointId.bind(r.storage);
      if (transition.includes("version acknowledgement"))
        r.storage.updateEntryVersion = (...args) => {
          if (transition.startsWith("before")) crash();
          versionUpdate(...args);
          return crash();
        };
      if (transition.includes("synced acknowledgement"))
        r.storage.updateDataPointId = (...args) => {
          if (transition.startsWith("before")) crash();
          syncedUpdate(...args);
          return crash();
        };
      if (transition === "before register")
        registry.beforeRegister = async () => crash();
      if (transition === "after register") registry.afterCommit = crash;
      await expect(
        upload(r, {
          configureAdapter: (adapter) => {
            if (!transition.includes("upload")) return;
            const put = adapter.upload.bind(adapter);
            adapter.upload = async (...args) => {
              if (transition === "before upload") crash();
              await put(...args);
              return crash();
            };
          },
        }),
      ).rejects.toThrow(`crash ${transition}`);
      r.storage.updateEntryVersion = versionUpdate;
      r.storage.updateDataPointId = syncedUpdate;
      registry.afterCommit = undefined;
      await upload(r);
      expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
      expect(r.storage.entries[0]?.version).toBe(2);
      expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(original);
      await expectCommittedBytesMatch();
    },
  );

  it.each([false, true])(
    "uses the contiguous fenced version when the local counter is ahead (existing head: %s)",
    async (existing) => {
      if (existing) await upload(await replica(envelope("original"), 1));
      const r = await replica(envelope("ahead"), 999);
      await upload(r);
      expect(r.storage.entries[0]?.version).toBe(existing ? 2 : 1);
      expect(blobs.blobs.has(blobs.keyFor(999))).toBe(false);
      await expectCommittedBytesMatch();
    },
  );

  it("fences deletion between orphan registration and superseding publication", async () => {
    const occupant = await encryptWithPassword(
      plaintextOf(envelope("orphan")),
      scopeKeyHex,
    );
    blobs.blobs.set(blobs.keyFor(1), occupant);
    const r = await replica(envelope("mine"), 1);
    await expect(
      upload(r, {
        configureAdapter: (adapter) => {
          const put = adapter.upload.bind(adapter);
          adapter.upload = async (key, bytes) => {
            if (key === `${SCOPE}/2`) registry.deleteScope();
            return put(key, bytes);
          };
        },
      }),
    ).rejects.toThrow("PUBLICATION_FENCE_CHANGED");
    expect(registry.versions.get(1n)?.dataHash).toBe(
      hashOf(envelope("orphan")),
    );
    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(occupant);
    expect(registry.versions.get(2n)?.dataHash).toBe(TOMBSTONE_DATA_HASH);
    expect(r.storage.entries[0]?.dataPointId).toBeNull();
  });

  it("preserves a foreign orphan's lineage when registering before superseding", async () => {
    const orphan = envelope("derivative");
    const sources = [`0x${"cd".repeat(32)}`];
    Object.assign(orphan.data, {
      $lineage: { sources, writtenAt: "2026-10-21T00:00:00Z" },
    });
    const bytes = await encryptWithPassword(plaintextOf(orphan), scopeKeyHex);
    blobs.blobs.set(blobs.keyFor(1), bytes);
    await upload(await replica(envelope("mine"), 1));
    expect(registry.lineageAtVersion.get(1n)).toEqual(sources);
    expect(registry.lineageAtVersion.get(2n)).toBeUndefined();
    expect(signer.signLineageAttestation).toHaveBeenCalledWith(
      expect.objectContaining({
        expectedVersion: 1n,
        dataHash: hashOf(orphan),
        sources,
      }),
    );
    await expectCommittedBytesMatch();
  });

  it("heals a missing same-version blob only when both registered commitments match", async () => {
    const content = envelope("heal");
    const lostBytes = await encryptWithPassword(
      plaintextOf(content),
      scopeKeyHex,
    );
    registry.commit(
      1n,
      hashOf(content),
      keccak256(
        stringToHex(
          JSON.stringify({
            scope: SCOPE,
            collectedAt: content.collectedAt,
            sizeBytes: lostBytes.byteLength,
          }),
        ),
      ),
    );
    const r = await replica(content, 1);
    const result = await upload(r, { feed: true });
    expect(result.url).toBe(vanaAdapter().urlForKey(`${SCOPE}/1`));
    expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
    expect(registry.versions.size).toBe(1);
    await expectCommittedBytesMatch();
  });

  it("a stale replica cannot replace the bytes of a committed version", async () => {
    const original = envelope("original");
    await upload(await replica(original, 1));
    const committedBytes = blobs.blobs.get(blobs.keyFor(1));

    const stale = envelope("stale replica edit");
    const staleReplica = await replica(stale, 1);
    await upload(staleReplica);

    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(committedBytes);
    expect(registry.versions.get(1n)?.dataHash).toBe(hashOf(original));
    expect(registry.versions.get(2n)?.dataHash).toBe(hashOf(stale));
    expect(staleReplica.storage.entries[0]?.version).toBe(2);
    await expectCommittedBytesMatch();
  });

  it("retrying an upload whose registration failed reuses the stored bytes", async () => {
    const content = envelope("retried");
    const r = await replica(content, 1);
    registry.failNextRegistration = true;
    await expect(upload(r)).rejects.toThrow("fetch failed");
    const firstBytes = blobs.blobs.get(blobs.keyFor(1));

    // Re-encryption yields different ciphertext for the same plaintext.
    await upload(r);

    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(firstBytes);
    expect(registry.versions.get(1n)?.dataHash).toBe(hashOf(content));
    expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
    await expectCommittedBytesMatch();
  });

  it("adopts a foreign unregistered reservation and supersedes it when its writer never returns", async () => {
    const occupant = await encryptWithPassword(
      new TextEncoder().encode(JSON.stringify(envelope("in flight elsewhere"))),
      scopeKeyHex,
    );
    blobs.blobs.set(blobs.keyFor(1), occupant);
    const r = await replica(envelope("mine"), 1);

    await upload(r);

    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(occupant);
    expect(registry.versions.get(1n)?.dataHash).toBe(
      hashOf(envelope("in flight elsewhere")),
    );
    expect(registry.versions.get(2n)?.dataHash).toBe(hashOf(envelope("mine")));
    expect(r.storage.entries[0]?.dataPointId).toBe(DATA_POINT_ID);
    await expectCommittedBytesMatch();
  });

  it("with the registry feed wired, does not fill a committed version that lost its bytes", async () => {
    const lost = envelope("committed but blob lost");
    registry.commit(1n, hashOf(lost));
    const r = await replica(envelope("newer"), 1);

    await upload(r, { feed: true });

    expect(blobs.puts).toEqual([blobs.keyFor(2)]);
    expect(blobs.blobs.has(blobs.keyFor(1))).toBe(false);
    expect(registry.versions.get(2n)?.dataHash).toBe(hashOf(envelope("newer")));
  });

  it("never deletes bytes another replica verified and registered while this attempt waited", async () => {
    const shared = envelope("shared content");
    const paused = await replica(shared, 1);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    registry.beforeRegister = async () => {
      registry.beforeRegister = undefined;
      await gate;
    };
    // Creates v1, then waits inside its registration.
    const first = upload(paused);
    await vi.waitFor(() => expect(blobs.blobs.has(blobs.keyFor(1))).toBe(true));
    // Same plaintext elsewhere: it verifies the stored bytes and registers v1.
    await upload(await replica(shared, 1));
    // The registry head moves past v1.
    await upload(await replica(envelope("later"), 2));

    release();
    await expect(first).rejects.toThrow("PUBLICATION_FENCE_CHANGED");
    await upload(paused);

    expect(blobs.blobs.has(blobs.keyFor(1))).toBe(true);
    await expectCommittedBytesMatch();
  });

  it("commits to the size of the stored ciphertext when a retry reuses it", async () => {
    const content = envelope("reused");
    // An earlier attempt, made with other encryption settings, stored a
    // differently sized encryption of the same plaintext.
    const earlier = await openpgp.encrypt({
      message: await openpgp.createMessage({ binary: plaintextOf(content) }),
      passwords: [scopeKeyHex],
      format: "binary",
      config: {
        preferredCompressionAlgorithm: openpgp.enums.compression.zlib,
      },
    });
    const fresh = await encryptWithPassword(plaintextOf(content), scopeKeyHex);
    expect(earlier.byteLength).not.toBe(fresh.byteLength);
    blobs.blobs.set(blobs.keyFor(1), earlier);

    await upload(await replica(content, 1));

    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(earlier);
    expect(registry.versions.get(1n)?.metadataHash).toBe(
      keccak256(
        stringToHex(
          JSON.stringify({
            scope: SCOPE,
            collectedAt: content.collectedAt,
            sizeBytes: earlier.byteLength,
          }),
        ),
      ),
    );
  });

  it("with the registry feed wired, never writes to a version the registry committed", async () => {
    // Pre-BUI-911 storage overwrites, so only the worker's head check
    // protects history here. Sequential only: concurrent writers on such
    // storage can still race, so this is a mitigation, not a rollout proof.
    blobs = new WriteOnceStorage(false);
    const original = envelope("original");
    await upload(await replica(original, 1), { feed: true });
    const committedBytes = blobs.blobs.get(blobs.keyFor(1));
    blobs.puts.length = 0;

    const stale = envelope("stale replica edit");
    await upload(await replica(stale, 1), { feed: true });

    expect(blobs.puts).toEqual([blobs.keyFor(2)]);
    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(committedBytes);
    expect(registry.versions.get(2n)?.dataHash).toBe(hashOf(stale));
    await expectCommittedBytesMatch();
  });

  it("keeps every committed version's bytes intact when replicas race", async () => {
    // Worst case for the gateway: rows stay pending, so a same-version POST
    // could rebind a version if a writer registered bytes it did not verify.
    registry.pendingRefresh = true;
    const replicas = await Promise.all(
      ["replica a", "replica bb", "replica ccc"].map((name) =>
        replica(envelope(name), 1),
      ),
    );

    // A replica that loses the race stays unsynced until a later cycle.
    for (let cycle = 0; cycle < 3; cycle += 1) {
      await Promise.allSettled(
        replicas
          .filter((r) => r.storage.entries[0]?.dataPointId === null)
          .map((r) => upload(r)),
      );
    }

    expect(registry.versions.size).toBe(3);
    await expectCommittedBytesMatch();
  });
});
