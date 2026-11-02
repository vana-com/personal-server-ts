/**
 * Large-blob storage costs (host contract §6, "Memory" and "Reclaim instead of
 * a lifetime cap"), measured on what SQLite is handed and keeps, not on the
 * admission ledger:
 *
 * - Promotion: the receiver copies a verified blob into canonical storage in
 *   chunks. No value as large as the blob crosses into or out of SQLite, and
 *   canonical storage holds it once, not as a whole row plus a chunked copy.
 * - Reclaim: once a batch's registration is finalized, the sender drops its
 *   payload and fragment ciphertext. No outbound phase reads them afterwards.
 */
import { createHash } from "node:crypto";
import type Database from "better-sqlite3";
import { afterEach, expect, it } from "vitest";
import { REPLICA_MAX_BLOB_BYTES } from "@opendatalabs/personal-server-ts-core/replication/limits";
import { BINARY_CHUNK_BYTES } from "./pdpp-binary-chunks.js";
import {
  at,
  cleanupHarness,
  clock,
  network,
  slotKey,
  sourceId,
  transportDevice,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(() => cleanupHarness());

const MiB = 1024 * 1024;
/** The phone shape: 1 MiB fragments, 20 units and 8 MiB per step. */
const FRAGMENT = MiB;
const BUDGET = { units: 20, bytes: 8 * MiB };
const BLOB_BYTES = 6 * MiB;

function pattern(size: number, seed: number) {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++)
    bytes[i] = (i * 31 + seed * 7 + (i >> 13)) & 255;
  return bytes;
}

const sha256 = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");

function writeBlob(
  device: TransportDevice,
  bytes: Uint8Array,
  key: string,
  instance = "conn",
) {
  const blob = device.store.storeBlobBytesForInstance({
    instance,
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  device.store.ingestBatch(
    [
      {
        instance,
        stream: "messages",
        key,
        data: {
          id: key,
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
  return blob.blobId;
}

function sizeOf(value: unknown): number {
  if (typeof value === "string") return value.length;
  if (value instanceof Uint8Array) return value.byteLength;
  if (Array.isArray(value)) return Math.max(0, ...value.map(sizeOf));
  if (value && typeof value === "object")
    return Math.max(0, ...Object.values(value).map(sizeOf));
  return 0;
}

/** Bytes of the binary columns of one row. */
function bytesOf(row: unknown): number {
  if (!row || typeof row !== "object") return 0;
  return Object.values(row).reduce<number>(
    (sum, value) => sum + (value instanceof Uint8Array ? value.byteLength : 0),
    0,
  );
}

/** One statement call, and the rows and binary bytes it handed back. */
type Access = { sql: string; args: unknown[]; rows: number; bytes: number };

/**
 * Meter every statement the database runs from now on: its SQL and bound
 * arguments, and the largest single value bound to it or read from it.
 */
function meter(db: Database.Database) {
  const accesses: Access[] = [];
  let largest = 0;
  const prepare = db.prepare.bind(db);
  db.prepare = ((sql: string) => {
    const statement = prepare(sql);
    return new Proxy(statement, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (
          typeof value !== "function" ||
          !["get", "all", "run", "iterate"].includes(property as string)
        )
          return typeof value === "function" ? value.bind(target) : value;
        return (...args: unknown[]) => {
          const access: Access = { sql, args, rows: 0, bytes: 0 };
          accesses.push(access);
          largest = Math.max(largest, sizeOf(args));
          const result = value.apply(target, args);
          const handed = (row: unknown) => {
            access.rows++;
            access.bytes += bytesOf(row);
          };
          if (property !== "iterate") {
            largest = Math.max(largest, sizeOf(result));
            if (property === "all") (result as unknown[]).forEach(handed);
            else if (property === "get" && result !== undefined) handed(result);
            return result;
          }
          return (function* () {
            for (const row of result as Iterable<unknown>) {
              largest = Math.max(largest, sizeOf(row));
              handed(row);
              yield row;
            }
          })();
        };
      },
    });
  }) as typeof db.prepare;
  return {
    accesses,
    get largest() {
      return largest;
    },
    stop() {
      db.prepare = prepare as typeof db.prepare;
    },
  };
}

function pair() {
  const net = network({ cap: REPLICA_MAX_BLOB_BYTES });
  const options = { chunk: FRAGMENT, cap: REPLICA_MAX_BLOB_BYTES };
  return {
    net,
    from: transportDevice(net, options),
    to: transportDevice(net, options),
  };
}

async function settle(from: TransportDevice, to: TransportDevice, steps = 6) {
  for (let i = 0; i < steps; i++) {
    clock.advance(10_000);
    await from.step(BUDGET);
    await to.step(BUDGET);
  }
}

function canonicalOnDisk(device: TransportDevice, blobId: string) {
  return device.db
    .prepare(
      `SELECT
        (SELECT coalesce(sum(length(bytes)),0) FROM pdpp_blob_bytes WHERE blob_id=?) AS whole,
        (SELECT coalesce(sum(length(bytes)),0) FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id=?) AS chunked`,
    )
    .get(blobId, blobId) as { whole: number; chunked: number };
}

function arrived(device: TransportDevice, blobId: string) {
  const stored = canonicalOnDisk(device, blobId);
  return stored.whole + stored.chunked > 0;
}

/** Bulk bytes the sender keeps for its outbound batches. */
function outboundBytes(device: TransportDevice) {
  return device.db
    .prepare(
      `SELECT
        (SELECT coalesce(sum(length(bytes)),0) FROM pdpp_binary_chunks WHERE namespace='payload') AS payload,
        (SELECT coalesce(sum(length(encrypted)),0) FROM pdpp_transport_fragments_out) AS fragments,
        (SELECT coalesce(sum(length(encrypted)),0) FROM pdpp_transport_staged_fragments) AS staged`,
    )
    .get() as { payload: number; fragments: number; staged: number };
}

function largestBatch(device: TransportDevice) {
  return (
    device.db
      .prepare(
        "SELECT batch FROM pdpp_transport_batches ORDER BY total_bytes DESC LIMIT 1",
      )
      .get() as { batch: string }
  ).batch;
}

function published(device: TransportDevice, batch: string) {
  return (
    (
      device.db
        .prepare("SELECT state FROM pdpp_transport_manifests_out WHERE batch=?")
        .get(batch) as { state: string } | undefined
    )?.state === "published"
  );
}

it("promotes a large received blob in chunks, and canonical storage holds it once", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const source = pattern(BLOB_BYTES, 41);
  const id = writeBlob(from, source, "large");
  const reads = meter(to.db);
  let steps = 0;
  for (; steps < 200 && !arrived(to, id); steps++) {
    clock.advance(10_000);
    await from.step(BUDGET);
    await to.step(BUDGET);
  }
  reads.stop();
  expect(arrived(to, id)).toBe(true);
  expect(to.get("large")).toMatchObject({ id: "large" });
  // Fetch, staging and promotion handle at most about one framed fragment
  // at a time. A whole-blob promotion binds the whole blob.
  expect(reads.largest).toBeLessThanOrEqual(2 * FRAGMENT);
  expect(reads.largest).toBeLessThan(BLOB_BYTES);
  // Stored once: the canonical copy is the chunk form, with no whole row.
  expect(canonicalOnDisk(to, id)).toEqual({ whole: 0, chunked: BLOB_BYTES });
  // Canonical readers accept that form.
  const read = to.store.getBlobBytes(id);
  expect(read?.byteLength).toBe(BLOB_BYTES);
  expect(sha256(read!)).toBe(sha256(source));
}, 120_000);

it("drops a batch's payload and fragment ciphertext once its registration is final, and never reads them again", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const id = writeBlob(from, pattern(BLOB_BYTES, 42), "large");
  for (
    let i = 0;
    i < 200 && !(arrived(to, id) && published(from, largestBatch(from)));
    i++
  ) {
    clock.advance(10_000);
    await from.step(BUDGET);
    await to.step(BUDGET);
  }
  const batch = largestBatch(from);
  expect(arrived(to, id)).toBe(true);
  expect(published(from, batch)).toBe(true);
  // Hashes and lengths stay: the fragment rows and the manifest remain.
  const fragments = from.db
    .prepare(
      "SELECT count(*) AS count, coalesce(sum(length(encrypted)),0) AS bytes FROM pdpp_transport_fragments_out WHERE batch=?",
    )
    .get(batch) as { count: number; bytes: number };
  expect(fragments.count).toBeGreaterThan(1);
  expect(fragments.bytes).toBe(0);
  expect(
    from.db
      .prepare(
        "SELECT 1 FROM pdpp_binary_manifests WHERE namespace='payload' AND blob_id=?",
      )
      .get(batch),
  ).toBeUndefined();
  // Outbound scratch is back to about zero: only small batches in flight.
  const scratch = outboundBytes(from);
  expect(scratch.payload + scratch.fragments + scratch.staged).toBeLessThan(
    BINARY_CHUNK_BYTES,
  );

  // Later work on the same chain never reads the dropped bytes.
  const reads = meter(from.db);
  from.put("after the large batch", "next");
  await settle(from, to, 10);
  from.crashReopen();
  const reopened = meter(from.db);
  await settle(from, to, 4);
  reads.stop();
  reopened.stop();
  expect(to.get("next")).toMatchObject({ text: "after the large batch" });
  const bulkReads = [...reads.accesses, ...reopened.accesses].filter(
    ({ sql, args }) =>
      args.includes(batch) &&
      (/encrypted/.test(sql) ||
        (/pdpp_binary_(?:chunks|manifests)/.test(sql) &&
          args.includes("payload")) ||
        /namespace='payload'/.test(sql)),
  );
  expect(bulkReads).toEqual([]);
}, 120_000);

it("a step drops the bulk bytes of a batch that was finalized before reclaim existed", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const id = writeBlob(from, pattern(2 * MiB, 43), "large");
  for (
    let i = 0;
    i < 200 && !(arrived(to, id) && published(from, largestBatch(from)));
    i++
  ) {
    clock.advance(10_000);
    await from.step(BUDGET);
    await to.step(BUDGET);
  }
  const batch = largestBatch(from);
  expect(published(from, batch)).toBe(true);
  // Model a database finalized by an earlier build: bytes still present.
  from.db.exec(
    `UPDATE pdpp_transport_fragments_out SET encrypted=randomblob(1000) WHERE batch='${batch}';
     INSERT OR REPLACE INTO pdpp_binary_manifests VALUES ('payload','${batch}',1000);
     INSERT OR REPLACE INTO pdpp_binary_chunks VALUES ('payload','${batch}',0,randomblob(1000));`,
  );
  clock.advance(10_000);
  await from.step(BUDGET);
  const scratch = outboundBytes(from);
  expect(scratch.payload + scratch.fragments + scratch.staged).toBeLessThan(
    BINARY_CHUNK_BYTES,
  );
}, 120_000);

/** Every byte a device keeps for blobs, by where it is kept. */
function blobStorage(device: TransportDevice) {
  const sum = (sql: string) =>
    (device.db.prepare(sql).get() as { n: number | null }).n ?? 0;
  const table = (name: string) =>
    device.db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?")
      .get(name) !== undefined;
  const namespaces = Object.fromEntries(
    (
      device.db
        .prepare(
          "SELECT namespace, sum(length(bytes)) AS n FROM pdpp_binary_chunks GROUP BY namespace",
        )
        .all() as { namespace: string; n: number }[]
    ).map((row) => [row.namespace, row.n]),
  ) as Record<string, number>;
  const rows = {
    whole: sum("SELECT sum(length(bytes)) AS n FROM pdpp_blob_bytes"),
    receivedRows: table("pdpp_replica_received_bytes")
      ? sum("SELECT sum(length(bytes)) AS n FROM pdpp_replica_received_bytes")
      : 0,
    pinnedRows: table("pdpp_replica_blob_bytes")
      ? sum("SELECT sum(length(bytes)) AS n FROM pdpp_replica_blob_bytes")
      : 0,
    pendingRows: table("pdpp_replica_pending_bytes")
      ? sum("SELECT sum(length(bytes)) AS n FROM pdpp_replica_pending_bytes")
      : 0,
    inbox: sum(
      "SELECT sum(length(fragment_json)) AS n FROM pdpp_transport_fragments_in",
    ),
    outbox: sum(
      "SELECT sum(length(encrypted)) AS n FROM pdpp_transport_fragments_out",
    ),
  };
  const total =
    Object.values(namespaces).reduce((a, b) => a + b, 0) +
    Object.values(rows).reduce((a, b) => a + b, 0);
  return { namespaces, ...rows, total };
}

/** The (scope, version) slots this device registered for its own batches. */
function ownSlots(device: TransportDevice) {
  return device.db
    .prepare("SELECT scope, version FROM pdpp_transport_manifests_out")
    .all() as { scope: string; version: number }[];
}

async function exchange(a: TransportDevice, b: TransportDevice, ids: string[]) {
  const done = () =>
    ids.every((id) => arrived(a, id) && arrived(b, id)) &&
    [a, b].every(
      (device) =>
        (
          device.db
            .prepare(
              "SELECT count(*) AS n FROM pdpp_transport_manifests_out WHERE state<>'published'",
            )
            .get() as { n: number }
        ).n === 0,
    );
  for (let i = 0; i < 300 && !done(); i++) {
    clock.advance(10_000);
    await a.step(BUDGET);
    await b.step(BUDGET);
  }
  expect(done()).toBe(true);
  // A few idle steps, so any late work (sweeps, revalidation) also runs.
  await settle(a, b, 4);
}

it("a device never takes custody of its own published batch", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const reads = meter(from.db);
  const id = writeBlob(from, pattern(BLOB_BYTES, 44), "large");
  await exchange(from, to, [id]);
  reads.stop();
  const own = ownSlots(from);
  expect(own.length).toBeGreaterThan(0);
  const scopes = new Set(own.map((slot) => slot.scope));
  // Discovery never admits an own slot, so nothing downloads or imports it.
  const admitted = reads.accesses.filter(
    ({ sql, args }) =>
      /INSERT[^]*INTO pdpp_transport_manifests_in/.test(sql) &&
      scopes.has(args[1] as string),
  );
  expect(admitted).toEqual([]);
  expect(
    from.db
      .prepare(
        "SELECT count(*) AS n FROM pdpp_transport_manifests_in WHERE scope IN (SELECT scope FROM pdpp_transport_manifests_out)",
      )
      .get(),
  ).toEqual({ n: 0 });
  expect(blobStorage(from).namespaces.received ?? 0).toBe(0);
}, 120_000);

it("keeps one canonical copy of each blob after a two-way exchange, and custody only of the received one", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const sourceA = pattern(BLOB_BYTES, 45);
  const sourceB = pattern(BLOB_BYTES, 46);
  const a = writeBlob(from, sourceA, "from-a");
  const b = writeBlob(to, sourceB, "from-b");
  await exchange(from, to, [a, b]);
  for (const device of [from, to]) {
    const stored = blobStorage(device);
    // Two canonical blobs in the chunk form, and the received copy that is
    // custody for the peer's operations; no copy of its own blob.
    expect(stored).toMatchObject({
      namespaces: { canonical: 2 * BLOB_BYTES, received: BLOB_BYTES },
      whole: 0,
      receivedRows: 0,
      pinnedRows: 0,
      pendingRows: 0,
      inbox: 0,
      outbox: 0,
      total: 3 * BLOB_BYTES,
    });
    for (const [id, source] of [
      [a, sourceA],
      [b, sourceB],
    ] as const) {
      expect(sha256(device.store.getBlobBytes(id)!)).toBe(sha256(source));
      expect(
        sha256(
          device.receiver.readStore({ reader: "grant" }).getBlobBytes(id)!,
        ),
      ).toBe(sha256(source));
    }
  }
}, 120_000);

it("a step drops own-slot admissions that an earlier build kept", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const id = writeBlob(from, pattern(2 * MiB, 48), "large");
  await exchange(from, to, [id]);
  // Model a database an earlier build left: an unimported admission of an
  // own slot.
  const own = ownSlots(from)[0]!;
  from.db
    .prepare(
      "INSERT OR IGNORE INTO pdpp_transport_manifests_in (slot,scope,version,writer) VALUES (?,?,?,?)",
    )
    .run(`${own.scope}:${own.version}`, own.scope, own.version, "own");
  from.crashReopen();
  clock.advance(10_000);
  await from.step(BUDGET);
  expect(
    from.db
      .prepare(
        "SELECT count(*) AS n FROM pdpp_transport_manifests_in WHERE scope=?",
      )
      .get(own.scope),
  ).toEqual({ n: 0 });
}, 120_000);

it("a local large blob is stored once, and capture's pin references that copy", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const source = pattern(BLOB_BYTES, 49);
  const id = writeBlob(from, source, "large");
  expect(canonicalOnDisk(from, id)).toEqual({ whole: 0, chunked: BLOB_BYTES });
  expect(blobStorage(from)).toMatchObject({
    namespaces: { canonical: BLOB_BYTES },
    total: BLOB_BYTES,
  });
  // The pin serves export from the canonical copy.
  const pinned = createHash("sha256");
  for (const chunk of from.store.replication.readPinnedBlobChunks(id))
    pinned.update(chunk);
  expect(pinned.digest("hex")).toBe(sha256(source));
  await exchange(from, to, [id]);
  expect(sha256(to.store.getBlobBytes(id)!)).toBe(sha256(source));
}, 120_000);

it("a pinned blob outlives its canonical record until export no longer needs it", async () => {
  const { from } = pair();
  const source = pattern(BLOB_BYTES, 50);
  const id = writeBlob(from, source, "large");
  // Deleting the connection collects its unclaimed blobs at once.
  from.store.deleteConnection(from.instance);
  expect(from.store.getBlobBytes(id)).toBeUndefined();
  const pinned = createHash("sha256");
  let size = 0;
  for (const chunk of from.store.replication.readPinnedBlobChunks(id)) {
    pinned.update(chunk);
    size += chunk.length;
  }
  expect(size).toBe(BLOB_BYTES);
  expect(pinned.digest("hex")).toBe(sha256(source));
  // A reopen collects again; the pin still holds.
  from.reopen();
  let reopened = 0;
  for (const chunk of from.store.replication.readPinnedBlobChunks(id))
    reopened += chunk.length;
  expect(reopened).toBe(BLOB_BYTES);
}, 120_000);

it("a pinned copy becomes a reference again when its blob returns to canonical storage", async () => {
  const { from } = pair();
  const source = pattern(BLOB_BYTES, 51);
  const id = writeBlob(from, source, "large");
  // Deleting the connection moves the canonical chunks to the pin.
  from.store.deleteConnection(from.instance);
  expect(blobStorage(from)).toMatchObject({
    namespaces: { pinned: BLOB_BYTES },
    total: BLOB_BYTES,
  });
  from.store.registerConnection({
    instance: "conn2",
    sourceId,
    method: "export",
    label: "D",
  });
  expect(writeBlob(from, source, "again", "conn2")).toBe(id);
  // Capture under conn2 turns the pinned copy into a reference to canonical.
  expect(blobStorage(from)).toMatchObject({
    namespaces: { canonical: BLOB_BYTES },
    total: BLOB_BYTES,
  });
  const pinned = createHash("sha256");
  for (const chunk of from.store.replication.readPinnedBlobChunks(id))
    pinned.update(chunk);
  expect(pinned.digest("hex")).toBe(sha256(source));
}, 120_000);

it("a discover pass over a long own history reads only versions above what it has seen", async () => {
  const { net, from, to } = pair();
  await settle(from, to);
  const id = writeBlob(from, pattern(2 * MiB, 51), "large");
  await exchange(from, to, [id]);
  // Model a device with a long publishing history: thousands of published
  // own versions, registered at the Gateway.
  const slots = ownSlots(from);
  const top = Math.max(...slots.map((slot) => slot.version));
  const scope = slots.find((slot) => slot.version === top)!.scope;
  const registered = net.head.get(slotKey(scope, top))!;
  const HISTORY = 5000;
  const claim = from.db.prepare(
    "INSERT INTO pdpp_transport_manifests_out (batch,scope,version,plaintext,encrypted,data_hash,metadata_hash,state) VALUES (?,?,?,x'',x'','','','published')",
  );
  from.db.transaction(() => {
    for (let version = top + 1; version <= top + HISTORY; version++) {
      claim.run(`history-${version}`, scope, version);
      net.head.set(slotKey(scope, version), {
        ...registered,
        version: String(version),
      });
    }
  })();
  // One pass learns the history.
  clock.advance(60_000);
  await from.step(BUDGET);
  const reads = meter(from.db);
  const lists = net.calls.lists;
  for (let i = 0; i < 3; i++) {
    clock.advance(60_000);
    await from.step(BUDGET);
  }
  expect(net.calls.lists).toBeGreaterThan(lists);
  const history = reads.accesses
    .filter((access) => /pdpp_transport_manifests_(in|out)/.test(access.sql))
    .reduce((rows, access) => rows + access.rows, 0);
  expect(history).toBeLessThan(100);
  expect(
    from.db
      .prepare(
        "SELECT count(*) AS n FROM pdpp_transport_manifests_in WHERE scope=?",
      )
      .get(scope),
  ).toEqual({ n: 0 });
}, 120_000);

/** Model an earlier build's own pinned copy of a blob canonical storage holds. */
function keepPinnedCopy(device: TransportDevice, id: string) {
  device.db.exec(
    `INSERT OR IGNORE INTO pdpp_binary_chunks SELECT 'pinned', blob_id, position, bytes FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id='${id}';
     INSERT OR IGNORE INTO pdpp_binary_manifests SELECT 'pinned', blob_id, size_bytes FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id='${id}';`,
  );
}

it("compaction verifies a leftover copy across steps, within each step's byte budget", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const source = pattern(2 * MiB, 52);
  const id = writeBlob(from, source, "large");
  // Export first, so the metered steps do only compaction.
  await exchange(from, to, [id]);
  keepPinnedCopy(from, id);
  from.crashReopen();
  const small = { units: 20, bytes: MiB };
  const reads = meter(from.db);
  const chunkBytes = () =>
    reads.accesses
      .filter((access) => /pdpp_binary_chunks/.test(access.sql))
      .reduce((bytes, access) => bytes + access.bytes, 0);
  const perStep: number[] = [];
  for (
    let i = 0;
    i < 40 && (blobStorage(from).namespaces.pinned ?? 0) > 0;
    i++
  ) {
    const before = chunkBytes();
    clock.advance(10_000);
    await from.step(small);
    perStep.push(chunkBytes() - before);
  }
  expect(blobStorage(from).namespaces.pinned ?? 0).toBe(0);
  expect(perStep.length).toBeGreaterThan(1);
  expect(Math.max(...perStep)).toBeLessThanOrEqual(small.bytes);
  const pinned = createHash("sha256");
  for (const chunk of from.store.replication.readPinnedBlobChunks(id))
    pinned.update(chunk);
  expect(pinned.digest("hex")).toBe(sha256(source));
}, 120_000);

it("compaction keeps a leftover copy when canonical storage has a chunk past the blob's end", async () => {
  const { from, to } = pair();
  await settle(from, to);
  const id = writeBlob(from, pattern(2 * MiB, 53), "large");
  keepPinnedCopy(from, id);
  from.db.exec(
    `INSERT INTO pdpp_binary_chunks SELECT 'canonical', blob_id, max(position)+1, x'00' FROM pdpp_binary_chunks WHERE namespace='canonical' AND blob_id='${id}';`,
  );
  from.crashReopen();
  for (let i = 0; i < 10; i++) {
    clock.advance(10_000);
    await from.step(BUDGET);
  }
  expect(blobStorage(from).namespaces.pinned).toBe(2 * MiB);
}, 120_000);

it("a step examines a bounded number of compaction candidates", async () => {
  const { from, to } = pair();
  await settle(from, to);
  // Many leftover copies whose canonical copy is gone: each is skipped.
  const ids = Array.from({ length: 60 }, (_, i) =>
    writeBlob(to, pattern(1024, 100 + i), `small-${i}`),
  );
  // A pinned copy, and a canonical manifest that disagrees with the blob.
  const insert = to.db.prepare(
    "INSERT OR REPLACE INTO pdpp_binary_manifests (namespace, blob_id, size_bytes) VALUES ('pinned', @id, 1024), ('canonical', @id, 2048)",
  );
  const drop = to.db.prepare("DELETE FROM pdpp_blob_bytes WHERE blob_id=?");
  to.db.transaction(() => {
    for (const id of ids) {
      insert.run({ id });
      drop.run(id);
    }
  })();
  to.crashReopen();
  const reads = meter(to.db);
  const lookups = () =>
    reads.accesses.filter((access) =>
      /SELECT size_bytes AS size, sha256 FROM pdpp_blobs/.test(access.sql),
    ).length;
  const perStep: number[] = [];
  for (let i = 0; i < 12; i++) {
    const before = lookups();
    clock.advance(10_000);
    await to.step(BUDGET);
    perStep.push(lookups() - before);
  }
  expect(Math.max(...perStep)).toBeLessThanOrEqual(16);
  // Every candidate is examined once, then the compactor stops.
  expect(perStep.reduce((a, b) => a + b, 0)).toBe(ids.length);
  expect(perStep.at(-1)).toBe(0);
}, 120_000);
