import Database from "better-sqlite3";
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

/** Storage cap + DPv2 contiguous version guard, plus independent head/history/chain stores. */
function network(realCrypto = false, cap = 8192) {
  const blobs = new Map<string, Uint8Array>();
  const head = new Map<string, ReplicaCommitment>();
  const history = new Map<string, ReplicaCommitment>();
  const chain = new Map<string, ReplicaCommitment>();
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
          Number(history.get(input.scope)?.version ?? 0),
          Number(chain.get(input.scope)?.version ?? 0),
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
        history.set(input.scope, row);
        if (!pending.has(input.scope)) chain.set(input.scope, row);
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
      history: history.get(scope) ?? null,
      chain: chain.get(scope) ?? null,
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
    history,
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
      "SELECT payload FROM pdpp_transport_batches ORDER BY sequence LIMIT 1",
    )
    .get() as { payload: Buffer };
  const chunks = inbox(b)
    .filter((r) => r.fragment_json)
    .map((r) => JSON.parse(r.fragment_json!) as ReplicaFragment)
    .filter(
      (f) =>
        f.batch ===
        (
          JSON.parse(new TextDecoder().decode(payload.payload)) as {
            envelope: { batchId: string };
          }
        ).envelope.batchId,
    )
    .sort((x, y) => x.index - y.index);
  expect(
    Buffer.concat(chunks.map((c) => Buffer.from(c.content, "base64"))),
  ).toEqual(payload.payload);
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

it("quarantines the false head 9/history 1/chain 1 case without rebase or PUT", async () => {
  const net = network();
  const a = device(net);
  // Lose response leaves a retryable local row after authoritative remote commit.
  net.loseNextRegistrationResponse();
  await a.cycle();
  const scope = outbox(a)[0]!.scope;
  net.head.set(scope, { ...net.head.get(scope)!, version: "9" });
  const putCount = net.puts.length;
  await cycles([a], 2);
  expect(outbox(a).find((r) => r.scope === scope)?.state).toBe("quarantined");
  expect(net.puts).toHaveLength(putCount);
  expect(net.registrations.filter((s) => s === scope)).toHaveLength(1);
});

it("pending chain settlement is not publication, and deletion never resurrects a batch", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((scope) => net.pending.add(scope));
  await a.cycle();
  expect(outbox(a).every((r) => r.state === "ready")).toBe(true);
  for (const scope of net.pending) {
    net.chain.set(scope, net.history.get(scope)!);
  }
  net.pending.clear();
  await cycles([a], 1);
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
  // A different pending batch whose remote head has been tombstoned is a terminal conflict.
  a.put("next");
  net.loseNextRegistrationResponse();
  await a.cycle();
  const next = outbox(a).find((r) => r.state === "ready")!;
  net.head.set(next.scope, { ...net.head.get(next.scope)!, deleted: true });
  const n = net.puts.length;
  await cycles([a], 1);
  expect(outbox(a).find((r) => r.scope === next.scope)?.state).toBe(
    "quarantined",
  );
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
  expect(inbox(c).find((r) => r.scope === scope)?.state).toBe("quarantined");
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
  expect(b.store.getBlobBytes(blob.blobId)).toEqual(bytes);
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

it("the gateway oracle enforces chain-backed continuity even when history is missing", async () => {
  const net = network();
  const scope = "pdpp_replica_v1.test.0";
  net.chain.set(scope, {
    owner,
    scope,
    version: "1",
    dataHash: "0xaa",
    metadataHash: "0xbb",
    deleted: false,
  });
  await expect(
    net.port.register({
      scope,
      plaintext: new Uint8Array(),
      encrypted: new Uint8Array(),
      dataHash: "0xaa",
      metadataHash: "0xbb",
    }),
  ).rejects.toThrow();
  expect(net.head.has(scope)).toBe(false);
});
