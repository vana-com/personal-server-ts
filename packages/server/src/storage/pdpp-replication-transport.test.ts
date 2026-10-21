import { readBinary } from "./pdpp-binary-chunks.js";
import Database from "better-sqlite3";
import { keccak256, stringToHex } from "viem";
import { afterEach, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import {
  createDpv2ReplicaTransport,
  replicaChainCommitment,
  type ReplicaFinalizedChainEvidence,
  type ReplicaCommitment,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import { REPLICA_MAX_BLOB_BYTES } from "@opendatalabs/personal-server-ts-core/replication/transport";
import type { ReplicaFragment } from "@opendatalabs/personal-server-ts-core/replication/transport";
import type { ReplicaTransportPort } from "@opendatalabs/personal-server-ts-core/replication/dpv2";

const owner = "0x0000000000000000000000000000000000000001";
const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const expected = { owner, declarations: [{ sourceId, binding }] };
const directories: string[] = [];
const devices: ReturnType<typeof device>[] = [];
let time = Date.parse(at);

/** Storage cap + DPv2 contiguous version guard, plus independent head and finalized chain stores. */
function network(realCrypto = false, cap = 8192) {
  const blobs = new Map<string, Uint8Array>();
  const head = new Map<string, ReplicaCommitment>();
  const chain = new Map<string, ReplicaFinalizedChainEvidence>();
  const chainRow = (
    scope: string,
    row?: ReplicaCommitment,
  ): ReplicaFinalizedChainEvidence => ({
    owner,
    scope,
    version: "1",
    currentVersion: row?.version ?? "0",
    status: row ? "Active" : "None",
    commitment: row
      ? replicaChainCommitment(
          row.dataHash as `0x${string}`,
          row.metadataHash as `0x${string}`,
        )
      : `0x${"0".repeat(64)}`,
    chainId: 14800,
    registry: `0x${"2".repeat(40)}`,
    blockNumber: 123n,
    blockHash: `0x${"3".repeat(64)}`,
    blockTimestamp: 1000n,
  });
  const pending = new Set<string>();
  const puts: { scope: string; bytes: Uint8Array }[] = [];
  const gets: string[] = [];
  const registrations: string[] = [];
  const failPut = new Set<string>();
  let loseRegistrationResponse = false;
  let failGetAfter = Infinity;
  let pageSize = 1000;
  let beforePut = (_scope: string, _bytes: Uint8Array) => {};
  const storage = {
    async upload(key: string, data: Uint8Array) {
      const scope = key.slice(0, -2);
      expect(key.endsWith("/1")).toBe(true);
      if (data.length > cap) throw new Error("413 storage MAX_BLOB_SIZE");
      beforePut(scope, data);
      puts.push({ scope, bytes: new Uint8Array(data) });
      if (failPut.has(scope)) throw new Error("offline");
      blobs.set(scope, new Uint8Array(data));
      return key;
    },
    urlForKey: (key: string) => key,
    async download(key: string) {
      const scope = key.slice(0, -2);
      gets.push(scope);
      if (gets.length > failGetAfter) throw new Error("download disconnected");
      const bytes = blobs.get(scope);
      if (!bytes) throw new Error("404");
      return new Uint8Array(bytes);
    },
    delete: async () => false,
    exists: async () => true,
  };
  const signAddData = vi.fn(async (msg) => {
    expect(msg.expectedVersion).toBe(1n);
    return "0x1234" as const;
  });
  const adapter = createDpv2ReplicaTransport({
    owner,
    masterKey: new Uint8Array(32).fill(5),
    storage,
    signer: { signAddData },
    gateway: {
      async registerDataPoint(input) {
        registrations.push(input.scope);
        const max = Math.max(
          Number(head.get(input.scope)?.version ?? 0),
          Number(chain.get(input.scope)?.currentVersion ?? 0),
        );
        if (Number(input.expectedVersion) <= max)
          throw new Error(
            `Gateway error: 409 Stale expectedVersion; stored value ${max}`,
          );
        if (Number(input.expectedVersion) !== max + 1)
          throw new Error(
            `Gateway error: 409 Gap in version sequence; next valid version is ${max + 1}`,
          );
        const row = {
          owner: input.ownerAddress,
          scope: input.scope,
          version: input.expectedVersion,
          dataHash: input.dataHash,
          metadataHash: input.metadataHash,
          deleted: false,
        };
        head.set(input.scope, row);
        if (!pending.has(input.scope))
          chain.set(input.scope, chainRow(input.scope, row));
        if (loseRegistrationResponse) {
          loseRegistrationResponse = false;
          throw new Error("response lost after commit");
        }
        return { dataPointId: input.scope } as never;
      },
    },
    feed: {
      async listDataPointsByOwner(_owner, cursor) {
        const keys = [...head.keys()]
          .sort()
          .filter((key) => cursor === null || key > cursor);
        const selected = keys.slice(0, pageSize);
        return {
          dataPoints: selected.map((scope) => ({ scope })) as never,
          cursor: keys.length > pageSize ? selected.at(-1)! : null,
        };
      },
      getDataPoint: async () => {
        throw new Error("head-only lookup must never be used");
      },
    },
    evidence: async (scope) => ({
      head: head.get(scope) ?? null,
      chain: chain.get(scope) ?? chainRow(scope),
      pending: pending.has(scope),
    }),
  });
  // Fast authenticated codec for high-cardinality/fault cases; one oracle below uses real SDK OpenPGP.
  const key = randomBytes(32);
  const fast = {
    async encrypt(_scope: string, bytes: Uint8Array) {
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      return new Uint8Array(
        Buffer.concat([
          iv,
          cipher.update(bytes),
          cipher.final(),
          cipher.getAuthTag(),
        ]),
      );
    },
    async decrypt(_scope: string, bytes: Uint8Array) {
      const decipher = createDecipheriv("aes-256-gcm", key, bytes.slice(0, 12));
      decipher.setAuthTag(bytes.slice(-16));
      return new Uint8Array(
        Buffer.concat([
          decipher.update(bytes.slice(12, -16)),
          decipher.final(),
        ]),
      );
    },
  };
  const port: ReplicaTransportPort = {
    ...adapter,
    ...(realCrypto ? {} : fast),
  };
  return {
    port,
    blobs,
    head,
    chainRow,
    chain,
    pending,
    puts,
    gets,
    registrations,
    signAddData,
    failPut,
    loseNextRegistrationResponse() {
      loseRegistrationResponse = true;
    },
    failDownloadsAfter(n: number) {
      failGetAfter = n;
    },
    pageSize(n: number) {
      pageSize = n;
    },
    beforePut(fn: typeof beforePut) {
      beforePut = fn;
    },
  };
}
function device(
  net: ReturnType<typeof network>,
  opts: {
    chunk?: number;
    cap?: number;
    pageSize?: number;
    enabled?: boolean;
    preexisting?: string;
  } = {},
) {
  const dir = mkdtempSync(join(tmpdir(), "replica-transport-"));
  directories.push(dir);
  const path = join(dir, "records.sqlite");
  let db = new Database(path);
  let store = createSqliteRecordStore(db);
  store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "C",
  });
  const put = (text: string, id = "a") =>
    store.ingestBatch(
      [
        {
          instance: "conn",
          stream: "messages",
          key: id,
          data: { id, text },
          emitted_at: at,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "export", generation: 1 },
    );
  if (opts.preexisting) put(opts.preexisting);
  store.replication.beginBaseline(expected);
  let declarations = expected.declarations;
  function worker() {
    const receiver = createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (c) => (c === "replica-secret" ? owner : undefined),
      declarations: () =>
        declarations.map((d) => ({
          ...d,
          validateData: (data) => typeof data.id === "string",
        })),
    });
    return createReplicaTransportWorker({
      db,
      exporter: store.replication,
      receiver,
      credential: "replica-secret",
      enabled: opts.enabled ?? true,
      expected: () => ({ owner, declarations }),
      transport: net.port,
      now: () => time,
      targetChunkBytes: opts.chunk ?? 4000,
      maxBlobBytes: opts.cap ?? 8192,
      pageSize: opts.pageSize,
    });
  }
  let engine = worker();
  const d = {
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    put,
    get(id = "a") {
      return store.getRecord("conn", "messages", id)?.data;
    },
    cycle: () => engine.cycle(),
    declarations(entries: typeof declarations) {
      declarations = entries;
    },
    reopen() {
      store.close();
      db = new Database(path);
      store = createSqliteRecordStore(db);
      engine = worker();
    },
    close() {
      if (db.open) store.close();
    },
  };
  devices.push(d);
  return d;
}
async function cycles(ds: ReturnType<typeof device>[], n = 12) {
  for (let i = 0; i < n; i++) {
    time += 10000;
    for (const d of ds) await d.cycle();
  }
}
function outbox(d: ReturnType<typeof device>) {
  return d.db
    .prepare("SELECT * FROM pdpp_transport_outbox ORDER BY rowid")
    .all() as {
    scope: string;
    state: string;
    encrypted: Buffer;
    plaintext: Buffer;
    attempts: number;
  }[];
}
function inbox(d: ReturnType<typeof device>) {
  return d.db.prepare("SELECT * FROM pdpp_transport_inbox").all() as {
    scope: string;
    state: string;
    fragment_json: string | null;
    error: string | null;
  }[];
}
afterEach(() => {
  for (const d of devices.splice(0)) d.close();
  for (const dir of directories.splice(0))
    rmSync(dir, { recursive: true, force: true });
  time = Date.parse(at);
});

it("two SQLite devices converge through real SDK OpenPGP + DPv2 signing/storage, without echo", async () => {
  const net = network(true);
  const a = device(net),
    b = device(net);
  a.put("from A");
  b.put("from B");
  const journalCount = (d: typeof a) =>
    (
      d.db
        .prepare("SELECT COUNT(*) AS n FROM pdpp_replica_operations")
        .get() as { n: number }
    ).n;
  const aCount = journalCount(a),
    bCount = journalCount(b);
  await cycles([a, b], 4);
  expect(a.get()).toEqual(b.get());
  expect(a.get()).toBeDefined();
  expect(journalCount(a)).toBe(aCount);
  expect(journalCount(b)).toBe(bCount);
  const count = net.registrations.length;
  await cycles([a, b], 2);
  expect(net.registrations).toHaveLength(count);
  expect(net.signAddData).toHaveBeenCalled();
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
}, 30000);

it("resumes uncertain publication with identical durable ciphertext, adopting only verified version 1", async () => {
  const net = network();
  const a = device(net, { preexisting: "baseline", chunk: 600 });
  net.beforePut((scope, bytes) => {
    const row = outbox(a).find((r) => r.scope === scope)!;
    expect(row.encrypted).toEqual(Buffer.from(bytes));
    expect(a.store.replication.getBaselineCheckpoint()).toBeGreaterThan(0);
  });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const original = outbox(a);
  expect(original.some((r) => r.state === "ready")).toBe(true);
  a.reopen();
  await cycles([a], 2);
  expect(outbox(a).map((r) => r.encrypted)).toEqual(
    original.map((r) => r.encrypted),
  );
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
  expect(
    net.registrations.filter((s) => s === original[0]!.scope),
  ).toHaveLength(1);
});

it("retries absence after a failed PUT at the same address with exact persisted bytes", async () => {
  const net = network();
  const a = device(net);
  let failed = false;
  net.beforePut((scope) => {
    if (!failed) {
      failed = true;
      net.failPut.add(scope);
    }
  });
  await a.cycle();
  const original = outbox(a)[0]!;
  expect(original.state).toBe("ready");
  expect(original.attempts).toBe(1);
  a.reopen();
  await a.cycle();
  expect(net.puts).toHaveLength(1); // durable backoff survives restart
  net.failPut.clear();
  await cycles([a], 2);
  const attempts = net.puts.filter((p) => p.scope === original.scope);
  expect(attempts).toHaveLength(2);
  expect(attempts[0]!.bytes).toEqual(attempts[1]!.bytes);
});

it("fragments large JSON and resumes a partial download in reverse/duplicate listing order", async () => {
  const net = network();
  const a = device(net, { preexisting: "😺".repeat(15000), chunk: 1800 });
  const b = device(net, { chunk: 1800 });
  await cycles([a], 3);
  // Reverse order + duplicates exercises index/offset assembly, not arrival order.
  const list = net.port.list;
  net.port.list = async (cursor) => {
    const page = await list(cursor);
    return {
      ...page,
      scopes: [...page.scopes].reverse().flatMap((s) => [s, s]),
    };
  };
  net.failDownloadsAfter(net.gets.length + 2);
  await b.cycle();
  expect(inbox(b).filter((r) => r.fragment_json)).toHaveLength(2);
  b.reopen();
  net.failDownloadsAfter(Infinity);
  await cycles([b], 8);
  expect(b.get()).toEqual(a.get());
  const payload = a.db
    .prepare(
      "SELECT batch FROM pdpp_transport_batches ORDER BY sequence LIMIT 1",
    )
    .get() as { batch: string };
  const payloadBytes = readBinary(a.db, "payload", payload.batch)!;
  const chunks = inbox(b)
    .filter((r) => r.fragment_json)
    .map((r) => JSON.parse(r.fragment_json!) as ReplicaFragment)
    .filter(
      (f) =>
        f.batch ===
        (
          JSON.parse(new TextDecoder().decode(payloadBytes)) as {
            envelope: { batchId: string };
          }
        ).envelope.batchId,
    )
    .sort((x, y) => x.index - y.index);
  expect(
    Buffer.concat(chunks.map((c) => Buffer.from(c.content, "base64"))),
  ).toEqual(Buffer.from(payloadBytes));
  expect(net.puts.every((p) => p.bytes.length <= 8192)).toBe(true);
});

it("rejects tampered ciphertext and imports only after the correct fragment is restored", async () => {
  const net = network();
  const a = device(net, { preexisting: "authentic", chunk: 600 });
  await cycles([a], 2);
  const b = device(net);
  const scope = outbox(a)[0]!.scope,
    original = net.blobs.get(scope)!;
  const corrupt = new Uint8Array(original);
  corrupt[20] = corrupt[20]! ^ 1;
  net.blobs.set(scope, corrupt);
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(inbox(b).find((r) => r.scope === scope)?.fragment_json).toBeNull();
  net.blobs.set(scope, original);
  await cycles([b], 5);
  expect(b.get()).toEqual(a.get());
});

it("holds false head 9 and other Gateway disagreements pending, then heals without rebase or PUT", async () => {
  const net = network();
  const a = device(net, { preexisting: "authentic" });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const scope = outbox(a)[0]!.scope;
  const authentic = net.head.get(scope)!;
  const b = device(net);
  const putCount = net.puts.filter((p) => p.scope === scope).length;
  for (const mutation of [
    { ...authentic, version: "9" },
    { ...authentic, owner: "other" },
    { ...authentic, scope: "other" },
    { ...authentic, deleted: true },
    { ...authentic, dataHash: `0x${"f".repeat(64)}` },
    { ...authentic, metadataHash: `0x${"f".repeat(64)}` },
    null,
  ]) {
    if (mutation) net.head.set(scope, mutation);
    else net.head.delete(scope);
    await cycles([a, b], 2);
    expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("ready");
    expect(b.get()).toBeUndefined();
    expect(net.puts.filter((p) => p.scope === scope)).toHaveLength(putCount);
    expect(net.registrations.filter((s) => s === scope)).toHaveLength(1);
  }
  net.head.set(scope, authentic);
  time += 3600000; // allow the bounded pending backoff to expire
  await cycles([a, b], 3);
  expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("published");
  expect(b.get()).toEqual(a.get());
  expect(net.puts.filter((p) => p.scope === scope)).toHaveLength(putCount);
});

it("quarantines a finalized currentVersion 9 without rebase, PUT or import", async () => {
  const net = network();
  const a = device(net, { preexisting: "immutable" });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const scope = outbox(a)[0]!.scope;
  net.chain.set(scope, { ...net.chain.get(scope)!, currentVersion: "9" });
  const b = device(net);
  const putCount = net.puts.filter((p) => p.scope === scope).length;
  await cycles([a, b], 2);
  expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("quarantined");
  expect(inbox(b).find((r) => r.scope === scope)?.state).toBe("quarantined");
  expect(b.get()).toBeUndefined();
  expect(net.puts.filter((p) => p.scope === scope)).toHaveLength(putCount);
  expect(net.registrations.filter((s) => s === scope)).toHaveLength(1);
});

it("pending chain settlement and Gateway deletion never trigger re-upload", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  expect(outbox(a).every((r) => r.state === "ready")).toBe(true);
  for (const scope of net.pending) {
    net.chain.set(scope, net.chainRow(scope, net.head.get(scope)!));
  }
  net.pending.clear();
  await cycles([a], 1);
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
  // A Gateway-only tombstone can roll back; hold the durable batch pending.
  a.put("next");
  net.loseNextRegistrationResponse();
  await a.cycle();
  const next = outbox(a).find((r) => r.state === "ready")!;
  net.head.set(next.scope, { ...net.head.get(next.scope)!, deleted: true });
  const n = net.puts.length;
  await cycles([a], 1);
  expect(outbox(a).find((r) => r.scope === next.scope)?.state).toBe("ready");
  expect(net.puts).toHaveLength(n);
});

it("a failing first 50 fragments cannot starve later runnable fragments", async () => {
  const net = network();
  const a = device(net, { preexisting: "x".repeat(40000), chunk: 500 });
  let blocked = 0;
  net.beforePut((scope) => {
    if (blocked++ < 50) net.failPut.add(scope);
  });
  await a.cycle();
  expect(outbox(a).length).toBeGreaterThan(50);
  time += 10000; // the oldest failures are due again, so fairness must select untouched rows
  await a.cycle();
  expect(
    outbox(a)
      .slice(50)
      .some((r) => r.state === "published"),
  ).toBe(true);
  expect(net.puts.slice(50).some((p) => !net.failPut.has(p.scope))).toBe(true);
});

it("rescans first pages to find late settled registrations behind an earlier page boundary", async () => {
  const net = network();
  const a = device(net, { preexisting: "record", chunk: 600 });
  await cycles([a], 2);
  const keys = [...net.head.keys()].sort();
  const hidden = keys[0]!,
    row = net.head.get(hidden)!;
  net.head.delete(hidden);
  net.pageSize(1);
  const b = device(net);
  await b.cycle();
  net.head.set(hidden, row); // inserted behind saved cursor
  await cycles([b], keys.length * 2 + 4);
  expect(b.get()).toEqual(a.get());
});

it("imports before checkpoint atomically and retries retained fragments after a crash", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const b = device(net);
  b.db.exec(
    "CREATE TRIGGER interrupt_import BEFORE INSERT ON pdpp_transport_imported BEGIN SELECT RAISE(ABORT,'crash before checkpoint'); END;",
  );
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(
    b.db.prepare("SELECT * FROM pdpp_replica_received").all(),
  ).toHaveLength(0);
  b.reopen();
  b.db.exec("DROP TRIGGER interrupt_import");
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
  expect(inbox(b).filter((r) => r.state === "imported").length).toBeGreaterThan(
    0,
  );
});

it("keeps unknown declarations pending and refuses wrong owner/declaration binding", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const b = device(net);
  b.declarations([]);
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(inbox(b).some((r) => r.error?.includes("declaration"))).toBe(true);
  b.declarations(expected.declarations);
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
  const c = device(net);
  const scope = outbox(a)[0]!.scope;
  net.head.set(scope, { ...net.head.get(scope)!, owner: "other-owner" });
  await c.cycle();
  expect(c.get()).toBeUndefined();
  expect(inbox(c).find((r) => r.scope === scope)?.state).toBe("ready");
});

it("is disabled by default and rejects a configured limit above the real storage cap", async () => {
  const net = network();
  const a = device(net, { enabled: false });
  await a.cycle();
  expect(net.puts).toHaveLength(0);
  expect(outbox(a)).toHaveLength(0);
  expect(() => device(net, { cap: REPLICA_MAX_BLOB_BYTES + 1 })).toThrow(
    "storage cap",
  );
});

it("reassembles binary bytes with their content digest, MIME and generation-bound claim", async () => {
  const net = network();
  const a = device(net, { chunk: 1000 });
  const b = device(net, { chunk: 1000 });
  const bytes = new Uint8Array(17000);
  for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
  const blob = a.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  a.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "binary",
        emitted_at: at,
        data: {
          id: "binary",
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
  await cycles([a, b], 6);
  expect(
    Buffer.from(b.store.getBlobBytes(blob.blobId)!).equals(Buffer.from(bytes)),
  ).toBe(true);
  expect(b.store.getBlobMeta(blob.blobId)).toEqual(
    a.store.getBlobMeta(blob.blobId),
  );
  expect(b.get("binary")).toEqual(a.get("binary"));
});

it("recovers pending imported operations after local connection authority arrives", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const b = device(net);
  // Provisioning is a separate authority. Transport must not invent a missing connection.
  b.db.prepare("DELETE FROM pdpp_instance_binding WHERE instance='conn'").run();
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(inbox(b).some((r) => r.state === "imported")).toBe(true);
  b.reopen();
  b.store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "C",
  });
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
});

it("holds a successor batch until its predecessor arrives, then imports the retained bytes", async () => {
  const net = network();
  const a = device(net);
  a.put("tail record");
  await cycles([a], 3);
  const firstBatch = (
    a.db
      .prepare(
        "SELECT batch FROM pdpp_transport_batches ORDER BY sequence LIMIT 1",
      )
      .get() as { batch: string }
  ).batch;
  const firstScopes = outbox(a)
    .filter((r) => r.scope.includes(firstBatch))
    .map((r) => r.scope);
  const list = net.port.list;
  net.port.list = async (cursor) => {
    const page = await list(cursor);
    return {
      ...page,
      scopes: page.scopes.filter((s) => !firstScopes.includes(s)),
    };
  };
  const b = device(net);
  await cycles([b], 2);
  expect(b.get()).toBeUndefined();
  net.port.list = list;
  await cycles([b], 3);
  expect(b.get()).toEqual(a.get());
});

it("a permanently failing preparation does not block publishing a later batch", async () => {
  const net = network();
  const encrypt = net.port.encrypt;
  let stuckBatch: string | undefined;
  net.port.encrypt = async (scope, bytes) => {
    stuckBatch ??= scope.split(".")[1]!;
    if (scope.split(".")[1] === stuckBatch)
      throw new Error("encryption service unavailable");
    return encrypt(scope, bytes);
  };
  const a = device(net);
  a.put("later tail");
  await a.cycle();
  a.reopen();
  await cycles([a], 3);
  expect(net.registrations.length).toBeGreaterThan(0);
  expect(
    net.registrations.every((scope) => scope.split(".")[1] !== stuckBatch),
  ).toBe(true);
  expect(
    a.db
      .prepare("SELECT error FROM pdpp_transport_batches WHERE prepared=0")
      .all().length,
  ).toBeGreaterThan(0);
});

it("rejects validly encrypted fragments whose gateway plaintext/metadata commitment differs", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const scope = outbox(a)[0]!.scope;
  const plaintext = await net.port.decrypt(scope, net.blobs.get(scope)!);
  const wrapper = JSON.parse(new TextDecoder().decode(plaintext));
  wrapper.collectedAt = "2026-10-21T00:00:00.000Z";
  wrapper.data.fragment.collectedAt = wrapper.collectedAt;
  const { canonicalJson } =
    await import("@opendatalabs/personal-server-ts-core/replication/envelope");
  net.blobs.set(
    scope,
    await net.port.encrypt(
      scope,
      new TextEncoder().encode(canonicalJson(wrapper)),
    ),
  );
  const b = device(net);
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(inbox(b).find((r) => r.scope === scope)?.fragment_json).toBeNull();
  expect(inbox(b).find((r) => r.scope === scope)?.error).not.toBeNull();
});

it("does not acknowledge or apply a different batch reusing an imported writer sequence", async () => {
  const net = network();
  const a = device(net, { preexisting: "accepted" });
  await cycles([a], 2);
  const b = device(net);
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
  const writer = (
    a.db.prepare("SELECT writer FROM pdpp_transport_state").get() as {
      writer: string;
    }
  ).writer;
  const clone = device(net, { preexisting: "conflicting clone" });
  clone.db
    .prepare(
      "INSERT INTO pdpp_transport_state (id,owner,writer) VALUES (1,?,?)",
    )
    .run(owner, writer);
  await cycles([clone, b], 2);
  expect(b.get()).toEqual(a.get());
  const cloneScope = outbox(clone)[0]!.scope;
  expect(inbox(b).find((r) => r.scope === cloneScope)?.state).toBe("ready");
  expect(inbox(b).find((r) => r.scope === cloneScope)?.error).toContain(
    "UNIQUE",
  );
});

it("the gateway oracle enforces chain-backed continuity even when the head is missing", async () => {
  const net = network();
  const scope = "pdpp_replica_v1.test.0";
  net.chain.set(
    scope,
    net.chainRow(scope, {
      owner,
      scope,
      version: "1",
      dataHash: `0x${"a".repeat(64)}`,
      metadataHash: `0x${"b".repeat(64)}`,
      deleted: false,
    }),
  );
  await expect(
    net.port.register({
      scope,
      plaintext: new Uint8Array(),
      encrypted: new Uint8Array(),
      dataHash: `0x${"a".repeat(64)}`,
      metadataHash: `0x${"b".repeat(64)}`,
    }),
  ).rejects.toThrow();
  expect(net.head.has(scope)).toBe(false);
});

it("retries durable imports while owner discovery is unavailable", async () => {
  const net = network();
  const a = device(net, { preexisting: "retained record" });
  await cycles([a], 2);
  const b = device(net);
  b.db.exec(
    "CREATE TRIGGER pause_import BEFORE INSERT ON pdpp_transport_imported BEGIN SELECT RAISE(ABORT,'pause'); END;",
  );
  await b.cycle();
  expect(b.get()).toBeUndefined();
  b.db.exec("DROP TRIGGER pause_import");
  b.reopen();
  net.port.list = async () => {
    throw new Error("gateway listing offline");
  };
  await b.cycle().catch(() => undefined);
  expect(b.get()).toEqual(a.get());
});

it("holds version-1 soft deletion pending and imports after chain status reactivation", async () => {
  const net = network();
  const a = device(net, { preexisting: "retained" });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const scope = outbox(a)[0]!.scope;
  net.chain.set(scope, { ...net.chain.get(scope)!, status: "Unavailable" });
  expect(net.head.get(scope)?.deleted).toBe(false);
  const putCount = net.puts.filter((p) => p.scope === scope).length;
  const b = device(net);
  await cycles([a, b], 2);
  expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("ready");
  expect(inbox(b).find((r) => r.scope === scope)?.state).toBe("ready");
  expect(b.get()).toBeUndefined();
  expect(net.puts.filter((p) => p.scope === scope)).toHaveLength(putCount);
  net.chain.set(scope, { ...net.chain.get(scope)!, status: "Active" });
  await cycles([a, b], 3);
  expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("published");
  expect(b.get()).toEqual(a.get());
  expect(net.puts.filter((p) => p.scope === scope)).toHaveLength(putCount);
});

it("quarantines a finalized version-1 commitment mismatch including a tombstone pair", async () => {
  for (const commitment of [
    `0x${"f".repeat(64)}` as const,
    replicaChainCommitment(
      keccak256(stringToHex("vana.data-point.tombstone.v1")),
      keccak256(stringToHex("vana.data-point.tombstone.metadata.v1")),
    ),
  ]) {
    const net = network();
    const a = device(net, { preexisting: "durable hash pair" });
    net.loseNextRegistrationResponse();
    await a.cycle();
    const scope = outbox(a)[0]!.scope;
    net.chain.set(scope, { ...net.chain.get(scope)!, commitment });
    const putCount = net.puts.length;
    await cycles([a], 2);
    expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("quarantined");
    expect(net.puts).toHaveLength(putCount);
    expect(net.registrations.filter((s) => s === scope)).toHaveLength(1);
  }
});

it("finality waits survive restart without inflating a later transient error delay", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  for (let i = 0; i < 16; i++) {
    time += 10000;
    await a.cycle();
  }
  a.reopen();
  expect(outbox(a).every((r) => r.attempts === 0)).toBe(true);
  const original = net.port.evidence;
  net.port.evidence = async () => {
    throw new Error("transient RPC");
  };
  time += 10000;
  await a.cycle();
  const rows = a.db
    .prepare("SELECT attempts,next_attempt FROM pdpp_transport_outbox")
    .all() as { attempts: number; next_attempt: number }[];
  expect(
    rows.every((r) => r.attempts === 1 && r.next_attempt <= time + 1000),
  ).toBe(true);
  net.port.evidence = original;
  for (const scope of net.pending)
    net.chain.set(scope, net.chainRow(scope, net.head.get(scope)!));
  net.pending.clear();
  time += 1000;
  await a.cycle();
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
});

it("uses advancing finalized-head hints to wake waiting rows but still verifies evidence", async () => {
  const net = network();
  let finalized = 123n;
  net.port.finality = { head: vi.fn(async () => finalized) };
  const original = net.port.evidence;
  const evidence = vi.fn(original);
  net.port.evidence = evidence;
  const a = device(net),
    b = device(net);
  a.put("head wake");
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  await b.cycle();
  time += 2000;
  await a.cycle();
  await b.cycle(); // records inclusion hints without checking unchanged finalized slots
  const count = evidence.mock.calls.length;
  for (let i = 0; i < 5; i++) {
    time += 2000;
    await a.cycle();
    await b.cycle();
  }
  expect(evidence.mock.calls.length).toBe(count);
  a.reopen();
  b.reopen();
  finalized = 140n;
  time += 2000;
  await a.cycle();
  await b.cycle();
  // A lying scheduling hint is insufficient to download, publish or import.
  expect(b.get()).toBeUndefined();
  expect(net.gets).toHaveLength(0);
  expect(outbox(a).every((r) => r.state === "ready")).toBe(true);
  for (const scope of net.pending) {
    const row = net.chainRow(scope, net.head.get(scope)!);
    net.chain.set(scope, { ...row, blockNumber: 148n });
  }
  net.pending.clear();
  finalized = 148n;
  time += 30000;
  await a.cycle();
  await b.cycle();
  expect(b.get()).toEqual({ id: "a", text: "head wake" });
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
});

it("finality hints never shorten a genuine RPC error retry", async () => {
  const net = network();
  net.port.finality = { head: async () => 1000n };
  const a = device(net);
  const evidence = vi.fn(async () => {
    throw new Error("RPC unavailable");
  });
  net.port.evidence = evidence;
  await a.cycle();
  for (let i = 0; i < 5; i++) {
    time += 100000;
    await a.cycle();
  }
  const count = evidence.mock.calls.length;
  time += 2000;
  await a.cycle();
  expect(evidence.mock.calls.length).toBe(count);
});

it("filters parked finality waits before the fifty-row budget", async () => {
  const net = network();
  net.port.finality = { head: async () => 123n };
  const a = device(net, { preexisting: "x".repeat(40000), chunk: 500 });
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  const first = net.registrations.length;
  expect(first).toBe(50);
  time += 2000;
  await a.cycle();
  expect(net.registrations.length).toBeGreaterThan(first);
  expect(
    outbox(a)
      .slice(0, 50)
      .every((r) => r.attempts === 0),
  ).toBe(true);
});

it("migrates existing delivery rows without losing immutable ciphertext", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  const bytes = outbox(a).map((r) => r.encrypted);
  for (const table of ["pdpp_transport_outbox", "pdpp_transport_inbox"])
    for (const column of ["wait_since", "checked_block"])
      a.db.exec(`ALTER TABLE ${table} DROP COLUMN ${column}`);
  a.reopen();
  expect(outbox(a).map((r) => r.encrypted)).toEqual(bytes);
  time += 2000;
  await a.cycle();
  expect(outbox(a).every((r) => r.attempts === 0)).toBe(true);
});

it("a receiver download error after many finality waits starts at one second", async () => {
  const net = network();
  const a = device(net, { preexisting: "late download" }),
    b = device(net);
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  for (let i = 0; i < 16; i++) {
    time += 2000;
    await b.cycle();
  }
  const waiting = b.db
    .prepare("SELECT attempts FROM pdpp_transport_inbox")
    .all() as { attempts: number }[];
  expect(waiting.length).toBeGreaterThan(0);
  expect(waiting.every((r) => r.attempts === 0)).toBe(true);
  for (const scope of net.pending)
    net.chain.set(scope, net.chainRow(scope, net.head.get(scope)!));
  net.pending.clear();
  net.failDownloadsAfter(0);
  time += 2000;
  await b.cycle();
  const errors = b.db
    .prepare(
      "SELECT attempts,next_attempt FROM pdpp_transport_inbox WHERE error IS NOT NULL",
    )
    .all() as { attempts: number; next_attempt: number }[];
  expect(errors.length).toBeGreaterThan(0);
  expect(
    errors.every((r) => r.attempts === 1 && r.next_attempt === time + 1000),
  ).toBe(true);
  net.failDownloadsAfter(Infinity);
  time += 1000;
  await b.cycle();
  expect(b.get()).toEqual({ id: "a", text: "late download" });
});

it("rolls staged binary and import acknowledgement back together, then retries without trusting cached bytes", async () => {
  const net = network(false, 8 * 1024 * 1024);
  const a = device(net, { cap: 8 * 1024 * 1024, chunk: 1024 * 1024 });
  const b = device(net, { cap: 8 * 1024 * 1024, chunk: 1024 * 1024 });
  const bytes = new Uint8Array(2 * 1024 * 1024).fill(31);
  const blob = a.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  a.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "binary",
        data: {
          id: "binary",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: bytes.length,
          },
        },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([a], 2);
  b.db.exec(
    "CREATE TRIGGER reject_binary BEFORE INSERT ON pdpp_records WHEN NEW.record_key='binary' BEGIN SELECT RAISE(ABORT,'fault after binary staging'); END",
  );
  await cycles([b], 3);
  expect(b.get("binary")).toBeUndefined();
  expect(b.store.getBlobBytes(blob.blobId)).toBeUndefined();
  expect(
    (
      b.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_manifests WHERE namespace IN ('received','canonical','staging')",
        )
        .get() as { n: number }
    ).n,
  ).toBe(0);
  expect(inbox(b).filter((row) => row.error !== null).length).toBeGreaterThan(
    0,
  );
  b.db.exec("DROP TRIGGER reject_binary");
  await b.cycle();
  expect(
    Buffer.from(b.store.getBlobBytes(blob.blobId)!).equals(Buffer.from(bytes)),
  ).toBe(true);
  b.db
    .prepare(
      "UPDATE pdpp_binary_chunks SET bytes=zeroblob(length(bytes)) WHERE namespace='canonical' AND blob_id=? AND position=0",
    )
    .run(blob.blobId);
  // retry rehashes current rows, detecting replacement/corruption without a verification cache.
  await expect(b.cycle()).rejects.toThrow("Replica transport cycle incomplete");
  expect(b.store.getBlobBytes(blob.blobId)).toBeUndefined();
}, 30000);

it("reclaims only hidden crash staging on restart and preserves committed payloads", async () => {
  const net = network();
  const a = device(net);
  a.put("retained");
  await a.cycle();
  const { binaryWriter } = await import("./pdpp-binary-chunks.js");
  for (const namespace of ["staging", "payload"] as const) {
    const writer = binaryWriter(a.db, namespace, "orphan");
    writer.write(new Uint8Array([1, 2, 3]));
    writer.finish();
  }
  a.db
    .prepare("INSERT INTO pdpp_transport_preparing VALUES (?,?,?,?,?,?,?)")
    .run(
      "orphan",
      "orphan",
      "orphan",
      new Uint8Array([1]),
      new Uint8Array([1]),
      "hash",
      "hash",
    );
  a.reopen();
  await a.cycle();
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_chunks WHERE blob_id='orphan'",
        )
        .get() as { n: number }
    ).n,
  ).toBe(0);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_preparing")
        .get() as { n: number }
    ).n,
  ).toBe(0);
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_manifests WHERE namespace='payload'",
        )
        .get() as { n: number }
    ).n,
  ).toBeGreaterThan(0);
});

it("bounds repeated high hints and never regresses the verified checked height", async () => {
  const net = network();
  net.port.finality = { head: async () => 1000n };
  const a = device(net, { preexisting: "pending" });
  net.beforePut((scope) => net.pending.add(scope));
  const original = net.port.evidence;
  let verified = 123n;
  const evidence = vi.fn(async (scope: string) => {
    const e = await original(scope);
    return { ...e, chain: e.chain && { ...e.chain, blockNumber: verified } };
  });
  net.port.evidence = evidence;
  await a.cycle();
  time += 2000;
  await a.cycle(); // high hint, unchanged verified head: durable cooldown
  const count = evidence.mock.calls.length;
  for (let i = 0; i < 14; i++) {
    time += 2000;
    await a.cycle();
  }
  expect(evidence.mock.calls.length).toBe(count);
  verified = 120n;
  time += 2000;
  await a.cycle();
  const rows = a.db
    .prepare(
      "SELECT checked_block,attempts,next_attempt FROM pdpp_transport_outbox",
    )
    .all() as {
    checked_block: string;
    attempts: number;
    next_attempt: number;
  }[];
  expect(
    rows.every(
      (r) =>
        r.checked_block === "123" &&
        r.attempts === 0 &&
        r.next_attempt === time + 30000,
    ),
  ).toBe(true);
  expect(net.gets).toHaveLength(0);
});
