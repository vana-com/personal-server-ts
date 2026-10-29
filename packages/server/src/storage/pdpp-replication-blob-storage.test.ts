/**
 * Large-blob storage costs (host contract §6, "Memory" and "Reclaim instead of
 * a lifetime cap"), measured on what SQLite is handed and keeps, not on the
 * admission ledger:
 *
 * - Promotion: the receiver moves a verified blob into canonical storage in
 *   chunks. No value as large as the blob crosses into or out of SQLite, and
 *   the blob is stored once, not as a whole row plus a chunked copy.
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

function writeBlob(device: TransportDevice, bytes: Uint8Array, key: string) {
  const blob = device.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  device.store.ingestBatch(
    [
      {
        instance: "conn",
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

type Access = { sql: string; args: unknown[] };

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
          accesses.push({ sql, args });
          largest = Math.max(largest, sizeOf(args));
          const result = value.apply(target, args);
          if (property !== "iterate") {
            largest = Math.max(largest, sizeOf(result));
            return result;
          }
          return (function* () {
            for (const row of result as Iterable<unknown>) {
              largest = Math.max(largest, sizeOf(row));
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

it("promotes a large received blob in chunks and stores it once", async () => {
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
