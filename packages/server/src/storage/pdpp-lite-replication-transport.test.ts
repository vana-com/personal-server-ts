import Database from "better-sqlite3";
import { keccak256, encodeAbiParameters } from "viem";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { afterEach, expect, it } from "vitest";
import {
  createDpv2ReplicaTransport,
  replicaChainCommitment,
  type ReplicaCommitment,
  type ReplicaTransportPort,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import { createReplicaEvidenceAdapter } from "@opendatalabs/personal-server-ts-core/replication/evidence";
import {
  fragmentReplicaPayload,
  replicaDigest,
  type PreparedFragment,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  canonicalJson,
  type ReplicaEnvelope,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { binding } from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import {
  createLiteCanonicalStore,
  type LiteOperationDraft,
} from "../../../lite/src/canonical-store.js";
import { createLiteReplicaWorker } from "../../../lite/src/replication.js";
import {
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
  type CanonicalCrashPoint,
} from "../../../lite/src/test-support/canonical-persistence.js";
import type { LiteCanonicalPersistence } from "../../../lite/src/canonical-persistence.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";

const owner = "0x0000000000000000000000000000000000000001";
const registry = `0x${"2".repeat(40)}` as const;
const sourceId = "https://replica.test/source";
const at = "2026-10-20T00:00:00.000Z";
const expected = { owner, declarations: [{ sourceId, binding }] };
const context = () => ({
  ...expected,
  declarations: expected.declarations.map((d) => ({
    ...d,
    validateData: (data: Record<string, unknown>) =>
      typeof data.id === "string",
  })),
});
const base = {
  owner,
  sourceId,
  connectionId: "conn",
  methodId: "export",
  generation: 1,
};
const draft = (id: string, text: string): LiteOperationDraft => ({
  ...base,
  kind: "upsert",
  recordKey: id,
  emittedAt: at,
  declaration: binding,
  data: { id, text },
  blobs: [],
});
const cleanup: (() => void)[] = [];
let time = Date.parse(at);
afterEach(() => {
  for (const close of cleanup.splice(0)) close();
  time = Date.parse(at);
});

/** Separate Gateway and finalized slots; evidence runs through #433, not a head-only fake. */
function network(realCrypto = false) {
  const dataId = (scope: string) =>
    keccak256(
      encodeAbiParameters(
        [{ type: "address" }, { type: "string" }],
        [owner, scope],
      ),
    );
  const heads = new Map<string, ReplicaCommitment>();
  const finalized = new Map<string, ReplicaCommitment>();
  const bytes = new Map<string, Uint8Array>();
  const sent: PreparedFragment[] = [];
  const pending = new Set<string>();
  let fail: "put" | "register" | "get" | undefined;
  const fire = (where: typeof fail) => {
    if (fail === where) {
      fail = undefined;
      throw new Error(`killed:${where}`);
    }
  };
  const evidence = createReplicaEvidenceAdapter({
    owner,
    registry,
    chainId: 14800,
    gatewayUrl: "https://gateway.test",
    now: () => time,
    fetch: async (input) => {
      const url = new URL(String(input));
      const row = [...heads.values()].find((value) =>
        url.pathname.endsWith(dataId(value.scope)),
      );
      if (!row)
        return Response.json(
          { error: "Data point not found" },
          { status: 404 },
        );
      return Response.json({
        data: {
          id: dataId(row.scope),
          ownerAddress: owner,
          scope: row.scope,
          expectedVersion: row.version,
          dataHash: row.dataHash,
          metadataHash: row.metadataHash,
          state: "active",
        },
      });
    },
    rpc: {
      getChainId: async () => 14800,
      getBlock: async () => ({
        number: 1n,
        hash: `0x${"3".repeat(64)}` as const,
        timestamp: BigInt(Math.floor(time / 1000)),
      }),
      readContract: async (input) => {
        const scope = input.args[1];
        const row = finalized.get(scope);
        if (input.functionName === "currentVersion") return row ? 1n : 0n;
        if (input.functionName === "dataCommitment")
          return row
            ? replicaChainCommitment(
                row.dataHash as `0x${string}`,
                row.metadataHash as `0x${string}`,
              )
            : `0x${"0".repeat(64)}`;
        return {
          id: dataId(scope),
          owner: row ? owner : `0x${"0".repeat(40)}`,
          scope: row ? scope : "",
          status: row ? 1 : 0,
          currentVersion: row ? 1n : 0n,
          currentCommitment: row
            ? replicaChainCommitment(
                row.dataHash as `0x${string}`,
                row.metadataHash as `0x${string}`,
              )
            : `0x${"0".repeat(64)}`,
          createdAt: 0n,
          modifiedAt: 0n,
          totalAccesses: 0n,
        };
      },
    },
  });
  const storage = {
    urlForKey: (key: string) => key,
    upload: async (key: string, value: Uint8Array) => {
      bytes.set(key, value.slice());
      fire("put");
      return key;
    },
    download: async (key: string) => {
      const value = bytes.get(key);
      if (!value) throw new Error("missing bytes");
      fire("get");
      return value.slice();
    },
    delete: async () => false,
    exists: async () => true,
  };
  const port = createDpv2ReplicaTransport({
    owner,
    masterKey: new Uint8Array(32).fill(7),
    storage,
    evidence,
    signer: { signAddData: async () => "0x1234" },
    gateway: {
      registerDataPoint: async (input) => {
        if (heads.has(input.scope)) throw new Error("409 immutable version");
        const row = {
          owner,
          scope: input.scope,
          version: "1",
          dataHash: input.dataHash,
          metadataHash: input.metadataHash,
          deleted: false,
        };
        heads.set(input.scope, row);
        if (!pending.has(input.scope)) finalized.set(input.scope, row);
        fire("register");
        return { dataPointId: input.scope } as never;
      },
    },
    feed: {
      listDataPointsByOwner: async (_owner, cursor) => {
        const scopes = [...heads.keys()]
          .sort()
          .filter((scope) => cursor === null || scope > cursor);
        const chosen = scopes.slice(0, 40);
        return {
          dataPoints: chosen.map((scope) => ({ scope })) as never,
          cursor: scopes.length > chosen.length ? chosen.at(-1)! : null,
        };
      },
      getDataPoint: async () => {
        throw new Error("head-only lookup forbidden");
      },
    },
  });
  const key = randomBytes(32);
  const codec = realCrypto
    ? port
    : {
        encrypt: async (_scope: string, input: Uint8Array) => {
          const iv = randomBytes(12),
            cipher = createCipheriv("aes-256-gcm", key, iv);
          return new Uint8Array(
            Buffer.concat([
              iv,
              cipher.update(input),
              cipher.final(),
              cipher.getAuthTag(),
            ]),
          );
        },
        decrypt: async (_scope: string, input: Uint8Array) => {
          const cipher = createDecipheriv(
            "aes-256-gcm",
            key,
            input.subarray(0, 12),
          );
          cipher.setAuthTag(input.subarray(input.length - 16));
          return new Uint8Array(
            Buffer.concat([
              cipher.update(input.subarray(12, -16)),
              cipher.final(),
            ]),
          );
        },
      };
  const wrapped: ReplicaTransportPort = {
    ...port,
    encrypt: codec.encrypt,
    decrypt: codec.decrypt,
    put: async (part) => {
      sent.push(structuredClone(part));
      await port.put(part);
    },
  };
  return {
    port: wrapped,
    heads,
    finalized,
    bytes,
    sent,
    pending,
    crash: (point: typeof fail) => {
      fail = point;
    },
    async inject(envelope: ReplicaEnvelope, writer: string, sequence = 1) {
      const payload = new TextEncoder().encode(
        canonicalJson({ envelope, blobs: [] }),
      );
      const parts = await fragmentReplicaPayload({
        owner,
        writer,
        batch: envelope.batchId,
        sequence,
        previous: null,
        collectedAt: at,
        bytes: payload,
        encrypt: wrapped.encrypt,
        targetChunkBytes: 32768,
      });
      for (const part of parts) {
        await wrapped.put(part);
        await wrapped.register(part);
      }
    },
  };
}
function lite(net: ReturnType<typeof network>, transportEnabled = true) {
  const disk = fakeCanonicalDisk();
  const credential = Symbol("trusted replica");
  let native = createFakeCanonicalPersistence(disk);
  let store: ReturnType<typeof createLiteCanonicalStore>;
  let worker: ReturnType<typeof createLiteReplicaWorker>;
  let cut:
    | { prefix: string; after: boolean; test?: (value: string) => boolean }
    | undefined;
  const restart = () => {
    native = createFakeCanonicalPersistence(disk);
    const persistence: LiteCanonicalPersistence = {
      ...native.port,
      transaction: async (run) => {
        let interrupted = false;
        const result = await native.port.transaction(async (tx) => {
          const value = await run({
            ...tx,
            put: async (key, value) => {
              await tx.put(key, value);
              if (
                cut &&
                key.startsWith(cut.prefix) &&
                (!cut.test || cut.test(value))
              ) {
                interrupted = true;
                if (!cut.after) {
                  cut = undefined;
                  throw new Error("killed inside native transaction");
                }
              }
            },
          });
          return value;
        });
        if (interrupted) {
          cut = undefined;
          throw new Error("native commit acknowledgment lost");
        }
        return result;
      },
    };
    store = createLiteCanonicalStore({
      enabled: true,
      transportEnabled,
      persistence,
      context,
      authenticateReplica: (c) => (c === credential ? owner : undefined),
    });
    worker = createLiteReplicaWorker({
      enabled: true,
      persistence,
      store,
      expected: () => expected,
      credential,
      transport: net.port,
      now: () => time,
    });
  };
  restart();
  return {
    disk,
    get stagedCount() {
      return native.unpublishedStagedCount;
    },
    restart,
    get store() {
      return store;
    },
    cycle: () => worker.cycle(),
    provision: () =>
      store.provisionConnection("conn", { sourceId, methodId: "export" }),
    put: (id: string, text: string) =>
      store.commitLocal(`write-${id}-${text}`, [
        { ...base, kind: "connection-register" },
        draft(id, text),
      ]),
    read: (id: string) => store.readRecord("conn", "messages", id),
    crash: (point: CanonicalCrashPoint) => native.crashAt(point),
    cut: (prefix: string, after = false, test?: (value: string) => boolean) => {
      cut = { prefix, after, test };
    },
  };
}
function node(net: ReturnType<typeof network>) {
  const directory = mkdtempSync(join(tmpdir(), "lite-replica-node-"));
  const path = join(directory, "node.sqlite");
  let db: Database.Database;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let worker: ReturnType<typeof createReplicaTransportWorker>;
  function open() {
    db = new Database(path);
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "conn",
      sourceId,
      method: "export",
      label: "Replica",
    });
    store.replication.beginBaseline(expected);
    const receiver = createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (c) => (c === "internal" ? owner : undefined),
      declarations: () => context().declarations,
    });
    worker = createReplicaTransportWorker({
      db,
      enabled: true,
      exporter: store.replication,
      receiver,
      credential: "internal",
      expected: () => expected,
      transport: net.port,
      now: () => time,
    } as Parameters<typeof createReplicaTransportWorker>[0]);
  }
  open();
  cleanup.push(() => {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  });
  return {
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    restart: () => {
      db.close();
      open();
    },
    cycle: () => worker.cycle(),
    put: (id: string, text: string) =>
      store.ingestBatch(
        [
          {
            instance: "conn",
            stream: "messages",
            key: id,
            emitted_at: at,
            data: { id, text },
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "export", generation: 1 },
      ),
    read: (id: string) => store.getRecord("conn", "messages", id),
  };
}
async function cycles(
  a: { cycle(): Promise<void> },
  b: { cycle(): Promise<void> },
  count = 8,
) {
  for (let i = 0; i < count; i++) {
    time += 10000;
    await a.cycle();
    await b.cycle();
  }
}

it("Lite and Node exchange records in both directions across native/runtime and SQLite restarts", async () => {
  const net = network(),
    phone = lite(net),
    desktop = node(net);
  await phone.provision();
  await phone.put("phone", "from phone");
  desktop.put("node", "from Node");
  await cycles(phone, desktop);
  expect(desktop.read("phone")?.data).toEqual({
    id: "phone",
    text: "from phone",
  });
  expect((await phone.read("node"))?.data).toEqual({
    id: "node",
    text: "from Node",
  });
  const priorPhone = await phone.read("node"),
    priorNode = desktop.read("phone");
  phone.restart();
  desktop.restart();
  await cycles(phone, desktop);
  expect(await phone.read("node")).toEqual(priorPhone);
  expect(desktop.read("phone")).toEqual(priorNode);
  expect(
    [...phone.disk.rows.keys()].some(
      (key) =>
        key.startsWith("transport/content/") ||
        key.startsWith("transport/parts/") ||
        key.startsWith("transport/out/"),
    ),
  ).toBe(false);
});

it.each(["put", "register", "get"] as const)(
  "recovers a lost %s response without losing records or changing committed ciphertext",
  async (point) => {
    const net = network(),
      phone = lite(net),
      desktop = node(net);
    await phone.provision();
    await phone.put("phone", "durable");
    net.crash(point);
    await phone.cycle();
    phone.restart();
    desktop.restart();
    await cycles(phone, desktop, 10);
    expect(desktop.read("phone")?.data).toEqual({
      id: "phone",
      text: "durable",
    });
    expect(desktop.read("phone")?.version).toBe(1);
    const byScope = new Map<string, Uint8Array>();
    for (const part of net.sent) {
      if (byScope.has(part.scope))
        expect(part.encrypted).toEqual(byScope.get(part.scope));
      byScope.set(part.scope, part.encrypted);
    }
    expect(net.heads.size).toBe(byScope.size);
  },
);

it.each([
  ["transport/batches/", false],
  ["transport/out/", false],
  ["transport/batches/", true],
] as const)(
  "recovers interruption at %s (lost commit acknowledgement=%s)",
  async (prefix, after) => {
    const net = network(),
      phone = lite(net),
      desktop = node(net);
    await phone.provision();
    await phone.put("phone", "durable");
    phone.cut(prefix, after);
    await phone.cycle().catch(() => {});
    phone.restart();
    await cycles(phone, desktop, 10);
    expect(desktop.read("phone")?.data).toEqual({
      id: "phone",
      text: "durable",
    });
    expect(desktop.read("phone")?.version).toBe(1);
    expect((await phone.store.readOutboxPage()).entries).toHaveLength(0);
  },
);

it.each([false, true])(
  "canonical rows and the writer receipt recover together (lost import acknowledgement=%s)",
  async (after) => {
    const net = network(),
      phone = lite(net),
      desktop = node(net);
    await phone.provision();
    desktop.put("node", "import me");
    await desktop.cycle();
    await phone.cycle();
    await desktop.cycle();
    phone.cut("transport/imported/", after);
    await phone.cycle();
    expect((await phone.read("node"))?.data).toEqual(
      after ? { id: "node", text: "import me" } : undefined,
    );
    phone.restart();
    desktop.restart();
    await cycles(phone, desktop, 10);
    expect((await phone.read("node"))?.data).toEqual({
      id: "node",
      text: "import me",
    });
    expect((await phone.read("node"))?.version).toBe(1);
    expect((await phone.store.readOutboxPage()).entries).toHaveLength(0);
  },
);

it("rolls back a different batch reusing a writer sequence before any forked record becomes durable", async () => {
  const net = network(),
    phone = lite(net);
  await phone.provision();
  const writer = "a".repeat(32);
  const envelope = (
    batch: string,
    id: string,
    text: string,
  ): ReplicaEnvelope => ({
    format: "vana-pdpp-replica",
    version: 1,
    owner,
    batchId: batch,
    operations: [
      {
        ...base,
        kind: "connection-register",
        revision: { counter: 1, writerId: "origin", operationId: "register" },
      },
      {
        ...draft(id, text),
        revision: { counter: 2, writerId: "origin", operationId: id },
      } as ReplicaOperation,
    ],
  });
  await net.inject(envelope("b".repeat(32), "legit", "accepted"), writer);
  await phone.cycle();
  expect((await phone.read("legit"))?.data).toEqual({
    id: "legit",
    text: "accepted",
  });
  await net.inject(envelope("c".repeat(32), "fork", "must roll back"), writer);
  time += 10000;
  await phone.cycle();
  expect(await phone.read("fork")).toBeUndefined();
  expect(
    [...phone.disk.rows]
      .filter(([key]) => key.startsWith("transport/group-status/"))
      .some(([, value]) => value.includes("equivocation")),
  ).toBe(true);
});

it("uses real SDK encryption with finalized-evidence verification across Lite and Node", async () => {
  const net = network(true),
    phone = lite(net),
    desktop = node(net);
  await phone.provision();
  await phone.put("encrypted", "SDK payload");
  await cycles(phone, desktop, 5);
  expect(desktop.read("encrypted")?.data).toEqual({
    id: "encrypted",
    text: "SDK payload",
  });
}, 30000);

it("streams a blob larger than native values to Node, with no frame above 128 KiB", async () => {
  const net = network(),
    phone = lite(net),
    desktop = node(net);
  await phone.provision();
  const bytes = Uint8Array.from({ length: 512 * 1024 + 7 }, (_, i) => i % 251);
  const descriptor = {
    blobId: replicaDigest(bytes),
    sha256: replicaDigest(bytes),
    mimeType: "application/octet-stream",
    sizeBytes: bytes.length,
  };
  const stagingId = await phone.store.stageBlob(
    descriptor,
    (async function* () {
      for (let i = 0; i < bytes.length; i += 128 * 1024)
        yield bytes.subarray(i, i + 128 * 1024);
    })(),
  );
  await phone.store.commitLocal(
    "binary",
    [
      { ...base, kind: "connection-register" },
      { ...base, kind: "blob-claim", blob: descriptor },
      {
        ...base,
        kind: "upsert",
        recordKey: "binary",
        emittedAt: at,
        declaration: binding,
        blobs: [descriptor],
        data: {
          id: "binary",
          blob_ref: {
            blob_id: descriptor.blobId,
            mime_type: descriptor.mimeType,
            size_bytes: descriptor.sizeBytes,
          },
        },
      },
    ],
    [{ stagingId, descriptor }],
  );
  await cycles(phone, desktop, 12);
  expect(desktop.store.getBlobBytes(descriptor.blobId)).toEqual(bytes);
  expect(phone.stagedCount).toBe(0);
  expect(desktop.read("binary")?.data).toEqual(
    (await phone.read("binary"))?.data,
  );
  expect(net.sent.every((part) => part.encrypted.length <= 128 * 1024)).toBe(
    true,
  );
  phone.restart();
  desktop.restart();
  await cycles(phone, desktop, 4);
  expect(desktop.store.getBlobBytes(descriptor.blobId)).toEqual(bytes);
}, 30000);

it("receives default Node fragments larger than a native value without whole-batch assembly", async () => {
  const net = network(),
    phone = lite(net),
    desktop = node(net);
  await phone.provision();
  const bytes = Uint8Array.from(
    { length: 3 * 1024 * 1024 + 5 },
    (_, i) => i % 239,
  );
  const blob = desktop.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  desktop.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "large",
        emitted_at: at,
        data: {
          id: "large",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: bytes.length,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles(desktop, phone, 10);
  expect(net.sent.some((part) => part.encrypted.length > 4 * 1024 * 1024)).toBe(
    true,
  );
  const chunks: Uint8Array[] = [];
  for await (const chunk of phone.store.readBlob(blob.blobId)) {
    expect(chunk.length).toBeLessThanOrEqual(128 * 1024);
    chunks.push(chunk);
  }
  expect(Buffer.concat(chunks)).toEqual(Buffer.from(bytes));
  expect(phone.stagedCount).toBe(0);
  const row = await phone.read("large");
  expect(row?.data).toEqual(desktop.read("large")?.data);
  phone.restart();
  desktop.restart();
  await cycles(desktop, phone, 4);
  expect(await phone.read("large")).toEqual(row);
}, 60000);

it("rotates transport identity with the canonical installation writer after restore", async () => {
  const net = network(),
    phone = lite(net),
    desktop = node(net);
  await phone.provision();
  await phone.put("first", "original installation");
  await cycles(phone, desktop, 5);
  const original = JSON.parse(phone.disk.rows.get("transport/state")!).writer;
  const clock = JSON.parse(phone.disk.rows.get("clock")!);
  phone.disk.rows.set(
    "clock",
    JSON.stringify({ ...clock, writerId: crypto.randomUUID() }),
  );
  phone.restart();
  await phone.put("second", "restored installation");
  await cycles(phone, desktop, 7);
  expect(JSON.parse(phone.disk.rows.get("transport/state")!).writer).not.toBe(
    original,
  );
  expect(desktop.read("first")?.data).toEqual({
    id: "first",
    text: "original installation",
  });
  expect(desktop.read("second")?.data).toEqual({
    id: "second",
    text: "restored installation",
  });
});

it("fences a stalled old runtime after a replacement acquires its expired durable lease", async () => {
  const net = network(),
    phone = lite(net);
  await phone.provision();
  await phone.put("lease", "durable");
  let entered!: () => void, release!: () => void;
  const waiting = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const encrypt = net.port.encrypt;
  let first = true;
  net.port.encrypt = async (scope, bytes) => {
    if (first) {
      first = false;
      entered();
      await gate;
    }
    return encrypt(scope, bytes);
  };
  const old = phone.cycle();
  void old.catch(() => {});
  await waiting;
  phone.restart();
  await phone.cycle();
  expect(net.sent).toHaveLength(0);
  time += 31000;
  await phone.cycle();
  const committed = net.sent.map((part) => ({
    scope: part.scope,
    encrypted: part.encrypted.slice(),
  }));
  expect(committed.length).toBeGreaterThan(0);
  release();
  await expect(old).rejects.toThrow("Lite replica cycle incomplete");
  await phone.cycle();
  expect(
    net.sent.map((part) => ({ scope: part.scope, encrypted: part.encrypted })),
  ).toEqual(committed);
  expect(
    [...phone.disk.rows]
      .filter(([key]) => key.startsWith("transport/batches/"))
      .every(([, value]) => JSON.parse(value).prepared),
  ).toBe(true);
});

it("rejects a local record whose revision and envelope would exceed transport admission before acknowledging it", async () => {
  const net = network(),
    phone = lite(net),
    legacy = lite(net, false);
  await phone.provision();
  await legacy.provision();
  await phone.put("initial", "ok");
  await legacy.put("initial", "ok");
  const operation = {
    ...base,
    kind: "upsert" as const,
    recordKey: "oversized",
    emittedAt: at,
    declaration: binding,
    blobs: [],
    data: { id: "oversized", text: "" },
  };
  operation.data.text = "x".repeat(
    192 * 1024 -
      new TextEncoder().encode(canonicalJson([operation])).length -
      32,
  );
  const prior = (await phone.store.readOutboxPage()).entries.length;
  await expect(
    phone.store.commitLocal("oversized", [operation]),
  ).rejects.toThrow("transport admission");
  expect(await phone.read("oversized")).toBeUndefined();
  expect((await phone.store.readOutboxPage()).entries.length).toBe(prior);
  await legacy.store.commitLocal("oversized", [operation]);
  expect((await legacy.read("oversized"))?.data?.text.length).toBe(
    operation.data.text.length,
  );
  await phone.put("after", "still writable");
});

it("does not resurrect a published queue item when cleanup committed but its acknowledgement was lost", async () => {
  const net = network(),
    phone = lite(net);
  await phone.provision();
  await phone.put("published", "durable");
  phone.cut(
    "transport/send/",
    true,
    (value) => JSON.parse(value).state === "published",
  );
  await phone.cycle();
  phone.restart();
  await cycles(phone, { cycle: async () => {} }, 5);
  expect(
    (await phone.store.readRecord("conn", "messages", "published"))?.version,
  ).toBe(1);
  const status = await phone
    .cycle()
    .then(() =>
      [...phone.disk.rows]
        .filter(([key]) => key.startsWith("transport/send/"))
        .map(([, value]) => JSON.parse(value).state),
    );
  expect(status).toEqual(["published"]);
  expect(
    [...phone.disk.rows.keys()].some((key) => key.startsWith("transport/out/")),
  ).toBe(false);
});
