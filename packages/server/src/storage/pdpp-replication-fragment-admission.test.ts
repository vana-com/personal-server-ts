/**
 * Per-fragment admission (host contract §6.1 item 1): a blob bigger than the
 * step byte budget replicates fragment by fragment under that budget, and a
 * process loss inside one fragment's preparation resumes at that fragment.
 *
 * The default run scales the 200 MiB / 1 MiB / 8 MiB phone shape (and the
 * Desktop and Node shapes) down by 128 so it stays in the unit suite.
 * REPLICA_FRAGMENT_TRACE_FULL=1 runs the real sizes; put TMPDIR on disk.
 */
import { createHash } from "node:crypto";
import { afterEach, expect, it } from "vitest";
import { REPLICA_MAX_BLOB_BYTES } from "@opendatalabs/personal-server-ts-core/replication/limits";
import { readBinaryChunks } from "./pdpp-binary-chunks.js";
import {
  CrashController,
  SimulatedCrash,
  at,
  cleanupHarness,
  clock,
  network,
  transportDevice,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";

afterEach(() => cleanupHarness());

const FULL = process.env.REPLICA_FRAGMENT_TRACE_FULL === "1";
/** One "MiB" of the trace: 1 MiB at full size, 8 KiB scaled. */
const M = FULL ? 1024 * 1024 : 8 * 1024;
const BLOB_BYTES = 200 * M;

/** Crash inside the commit of the n-th prepared fragment: it rolls back. */
class FragmentCrash extends CrashController {
  private inserts = 0;
  private at: number | undefined;
  /** Count prepared fragments from now on. */
  crashAtFragment(n: number) {
    this.inserts = 0;
    this.at = n;
  }
  override point(label: string) {
    super.point(label);
    if (
      label === "after-insert:pdpp_transport_fragments_out" &&
      this.at !== undefined &&
      ++this.inserts === this.at
    ) {
      this.dead = true;
      throw new SimulatedCrash(label);
    }
  }
}

function pattern(size: number, seed: number) {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++)
    bytes[i] = (i * 31 + seed * 7 + (i >> 13)) & 255;
  return bytes;
}

function sha256(chunks: Iterable<Uint8Array>) {
  const hash = createHash("sha256");
  let length = 0;
  for (const chunk of chunks) {
    hash.update(chunk);
    length += chunk.length;
  }
  return { sha256: hash.digest("hex"), length };
}

function writeBlob(device: TransportDevice, bytes: Uint8Array) {
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
        key: "large",
        data: {
          id: "large",
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

function arrived(device: TransportDevice, blobId: string) {
  const present = device.db
    .prepare(
      "SELECT 1 FROM pdpp_binary_manifests WHERE namespace='canonical' AND blob_id=? UNION ALL SELECT 1 FROM pdpp_blob_bytes WHERE blob_id=?",
    )
    .get(blobId, blobId);
  return present
    ? sha256(readBinaryChunks(device.db, "canonical", blobId))
    : undefined;
}

/**
 * Record each committed fragment of batches prepared from now on, in commit
 * order. A rolled-back insert leaves no row.
 */
function tracePreparation(device: TransportDevice) {
  device.db
    .exec(`CREATE TABLE trace_prepared (batch TEXT NOT NULL, position INTEGER NOT NULL);
    CREATE TRIGGER trace_prepared AFTER INSERT ON pdpp_transport_fragments_out
    BEGIN INSERT INTO trace_prepared VALUES (NEW.batch, NEW.position); END`);
  return () =>
    device.db
      .prepare("SELECT batch, position FROM trace_prepared ORDER BY rowid")
      .all() as { batch: string; position: number }[];
}

const shapes = [
  { name: "phone", fragment: 1 * M, budget: { units: 20, bytes: 8 * M } },
  { name: "desktop", fragment: 4 * M, budget: { units: 50, bytes: 64 * M } },
  // Node (A9) passes no byte budget: the coordinator default applies.
  { name: "node", fragment: 4 * M, budget: { units: 50 } },
] as const;

for (const shape of shapes)
  it(`a ${BLOB_BYTES / M}-unit blob replicates under the ${shape.name} step budget across a crash inside a fragment`, async () => {
    // The payload frames blob bytes in base64, so it is about 4/3 the blob.
    const fragments = Math.ceil((4 * BLOB_BYTES) / 3 / shape.fragment);
    const crash = new FragmentCrash(3);
    const net = network({ cap: REPLICA_MAX_BLOB_BYTES });
    const options = {
      chunk: shape.fragment,
      cap: REPLICA_MAX_BLOB_BYTES,
    };
    const from = transportDevice(net, { ...options, crash });
    const to = transportDevice(net, options);
    // Settle the baseline first, so the trace holds the blob's batch only.
    for (let i = 0; i < 6; i++) {
      clock.advance(10_000);
      await from.step(shape.budget);
      await to.step(shape.budget);
    }
    const trace = tracePreparation(from);
    const prepared = () => trace().map((row) => row.position);
    const source = pattern(BLOB_BYTES, 98);
    const id = writeBlob(from, source);
    const expected = sha256([source]);
    crash.crashAtFragment(3);
    // Per-fragment admission: a fragment is charged its framed size.
    const charge = 4 * Math.ceil(shape.fragment / 3);
    const perStep =
      "bytes" in shape.budget
        ? Math.max(1, Math.floor(shape.budget.bytes / charge))
        : shape.budget.units;
    let crashed = false;
    let steps = 0;
    for (; steps < 400 && !arrived(to, id); steps++) {
      clock.advance(10_000);
      const before = prepared().length;
      await from.step(shape.budget).catch((error: unknown) => {
        if (!(error instanceof SimulatedCrash)) throw error;
      });
      if (crash.dead) {
        // Process loss in the third fragment's commit: restart both devices.
        crashed = true;
        from.crashReopen();
        to.reopen();
        expect(prepared()).toEqual([0, 1]);
      } else expect(prepared().length - before).toBeLessThanOrEqual(perStep);
      await to.step(shape.budget);
    }
    expect(crashed).toBe(true);
    expect(arrived(to, id)).toEqual(expected);
    expect(to.get("large")).toMatchObject({ id: "large" });
    // Resumed at the lost fragment: every position committed exactly once.
    expect(prepared()).toEqual([...Array(fragments).keys()]);
    expect(new Set(trace().map((row) => row.batch)).size).toBe(1);
    // More than one step, and never deferred for want of a whole-blob budget.
    expect(steps).toBeGreaterThan(1);
  }, 600_000);
