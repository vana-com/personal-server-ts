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
  beforeRegister?: () => Promise<void>;

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
    options: { feed?: boolean } = {},
  ) {
    return uploadOne(
      {
        storage: r.storage,
        storageAdapter: vanaAdapter(),
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

  it("leaves an unregistered different payload in place and keeps the entry unsynced", async () => {
    const occupant = await encryptWithPassword(
      new TextEncoder().encode(JSON.stringify(envelope("in flight elsewhere"))),
      scopeKeyHex,
    );
    blobs.blobs.set(blobs.keyFor(1), occupant);
    const r = await replica(envelope("mine"), 1);

    await expect(upload(r)).rejects.toThrow(
      /already holds a different payload/,
    );

    expect(blobs.blobs.get(blobs.keyFor(1))).toEqual(occupant);
    expect(registry.versions.size).toBe(0);
    expect(r.storage.entries[0]?.dataPointId).toBeNull();
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
    await first;

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
