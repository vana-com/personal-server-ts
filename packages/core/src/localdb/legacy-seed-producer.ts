import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { classifyImportRow } from "./import-snapshot.js";
import { foldLayers, type FoldLayer } from "./legacy-fold.js";
import { quarantineTally, type QuarantineCounts } from "./legacy-quarantine.js";
import { ProtocolError } from "../errors/catalog.js";
import type { SeedIntake } from "./seed.js";

/** The intake refuses a connector whose connection was deleted. */
export const isConnectionDeleted = (error: unknown) =>
  error instanceof ProtocolError &&
  error.code === 410 &&
  error.errorCode === "CONNECTION_DELETED";

/**
 * Feeds a legacy store that only a host can read (a browser's IndexedDB, a
 * phone's files) into the seed intake every host already has.
 *
 * The host describes each stream it holds (`LegacySeedStream`) and how to read
 * it; the producer folds the stored versions, leaves out rows with no full
 * identity (counted by reason), and puts the rest through `SeedIntake.put`, so
 * the importer, its receipts and its fill-only rules apply unchanged. A stream
 * with a final receipt is not read: a second run adds nothing.
 *
 * Memory: one stream at a time, rows streamed as NDJSON in bounded chunks
 * (`CHUNK_BYTES`), never an array of rows. The only whole-stream structure is
 * the fold's set of key hashes.
 *
 * Limit: the seed upload has no deletion line. A deletion a layer records
 * keeps that key's older versions out of this stream's upload, and writes no
 * tombstone.
 */
export interface LegacySeedStream {
  readonly connector: string;
  readonly stream: string;
  /** The declared primary key; must match the verified artifact's. */
  readonly primaryKey: readonly string[];
  /** The artifact version the rows were collected under. */
  readonly version: string;
  /** Stored versions of the stream, newest first. */
  readonly layers: readonly FoldLayer[];
  /** Rows must carry this `$pdpp.sourceId`; other rows are counted out. */
  readonly sourceId?: string;
}

export interface LegacySeedStore {
  /** Every stream the legacy store holds. The producer reads one at a time. */
  streams(): AsyncIterable<LegacySeedStream>;
}

export interface LegacySeedStreamReport {
  readonly connector: string;
  readonly stream: string;
  /** `merged`: a final receipt already held it (before the read, or by the time
   * the upload arrived); nothing was imported here.
   * `staged`: the rows went through the importer (`rows` of them).
   * `empty`: the store had nothing importable, so no upload was made.
   * `refused`: the stream holds a fault that makes it untrustworthy (a key
   * repeated with different bodies, a store that changed under the read,
   * `reason`); nothing of it was imported and
   * the next stream goes on, as the server's import refuses one stream only. */
  readonly outcome: "merged" | "staged" | "empty" | "refused";
  /** Why the stream was refused: `invalid_record`; `source_changed` when
   * the store's content changed between the counting pass and the upload; or
   * `deleted` when the intake refused its connector as a deleted connection
   * (this stream only, the next connector goes on); or `staged_upload_pending`
   * when a host upload waits for its target and is never replaced. */
  readonly reason?:
    "invalid_record" | "source_changed" | "deleted" | "staged_upload_pending";
  /** Rows put to the intake. */
  readonly rows: number;
  /** Rows left out for want of a full identity, by reason. */
  readonly quarantine: QuarantineCounts;
  /** Lines the staging itself refused; zero when the producer did its part. */
  readonly invalid: number;
}

export interface LegacySeedReport {
  readonly streams: readonly LegacySeedStreamReport[];
  /** Totals over `streams`. */
  readonly rows: number;
  readonly quarantine: QuarantineCounts;
}

/** About one write batch of the staging, in UTF-8 bytes; a line larger than
 * this travels alone. */
const CHUNK_BYTES = 256 * 1024;

const encoder = new TextEncoder();

/** The store's content changed between the two passes. */
class SourceChanged extends Error {
  constructor() {
    super("source_changed");
  }
}

/** What a pass saw: a digest of every stored record it read (the ones the fold
 * leaves out included, not only their count per reason) and of the upload
 * lines, and the totals left out. The upload's own count check only compares
 * line counts, so a row that changed between the passes would pass it. The
 * digest compares content. */
function fingerprint(
  digest: ReturnType<typeof sha256.create>,
  quarantine: QuarantineCounts,
): string {
  return JSON.stringify([
    bytesToHex(digest.digest()),
    Object.entries(quarantine).sort(([a], [b]) => (a < b ? -1 : 1)),
  ]);
}

/** A record's text for the digest. A value with no JSON form (a cycle, a
 * BigInt) has the same stand-in each pass. */
function textOf(record: unknown): string {
  try {
    return JSON.stringify(record) ?? "undefined";
  } catch {
    return "unserializable";
  }
}

/** The layers, each stored record also fed to `digest` as it is read. */
function digesting(
  layers: readonly FoldLayer[],
  digest: ReturnType<typeof sha256.create>,
): FoldLayer[] {
  return layers.map((layer, index) => ({
    async *records() {
      for await (const record of layer.records()) {
        digest.update(encoder.encode(`${index}:r:${textOf(record)}\n`));
        yield record;
      }
    },
    ...(layer.deletions
      ? {
          async *deletions() {
            for await (const key of layer.deletions!()) {
              digest.update(encoder.encode(`${index}:d:${textOf(key)}\n`));
              yield key;
            }
          },
        }
      : {}),
  }));
}

/** The importable rows of a stream, and what was left out, in one traversal.
 * The signal is checked at every stored record, the ones the fold leaves out
 * included, so a long skip cannot outlast an abort. A pass feeds every stored
 * record it reads to `digest`. */
function importable(stream: LegacySeedStream, signal?: AbortSignal) {
  const fold = (digest: ReturnType<typeof sha256.create>) =>
    foldLayers(
      {
        source: "producer",
        owner: "",
        network: "",
        revision: "",
        target: {
          connectionId: "",
          connector: stream.connector,
          stream: stream.stream,
          primaryKey: stream.primaryKey,
          semantics: "mutable_state",
          incremental: true,
        },
        exclusions: [],
      },
      digesting(stream.layers, digest),
      stream.sourceId === undefined ? {} : { sourceId: stream.sourceId },
    );
  return async function* (
    quarantine: ReturnType<typeof quarantineTally>,
    digest: ReturnType<typeof sha256.create>,
  ) {
    for await (const record of fold(digest).records()) {
      signal?.throwIfAborted();
      const classified = await classifyImportRow(record, stream.primaryKey);
      if ("quarantine" in classified) quarantine.add(classified.quarantine);
      else yield record as Record<string, unknown>;
    }
  };
}

/** Seed every stream of a legacy store. Safe to run again: streams with a final
 * receipt are skipped, and the importer is fill-only. */
export async function seedLegacyStore(
  intake: SeedIntake,
  store: LegacySeedStore,
  options: { readonly signal?: AbortSignal } = {},
): Promise<LegacySeedReport> {
  const reports: LegacySeedStreamReport[] = [];
  const total = quarantineTally();
  let rows = 0;
  const statusOf = new Map<string, Awaited<ReturnType<SeedIntake["status"]>>>();
  const deleted = new Set<string>();
  const refuseDeleted = (connector: string, stream: string) => {
    deleted.add(connector);
    statusOf.delete(connector);
    reports.push({
      connector,
      stream,
      outcome: "refused",
      reason: "deleted",
      rows: 0,
      quarantine: {},
      invalid: 0,
    });
  };
  for await (const stream of store.streams()) {
    options.signal?.throwIfAborted();
    const { connector, stream: name } = stream;
    // The status is read per connector, and again after a stream is put: the
    // importer runs inside `put`, so a receipt appears there.
    if (deleted.has(connector)) {
      refuseDeleted(connector, name);
      continue;
    }
    let status = statusOf.get(connector);
    if (!status) {
      try {
        status = await intake.status(connector);
      } catch (error) {
        if (!isConnectionDeleted(error)) throw error;
        refuseDeleted(connector, name);
        continue;
      }
      statusOf.set(connector, status);
    }
    if (status.streams[name]?.state === "merged") {
      reports.push({
        connector,
        stream: name,
        outcome: "merged",
        rows: 0,
        quarantine: {},
        invalid: 0,
      });
      continue;
    }
    const quarantine = quarantineTally();
    const read = importable(stream, options.signal);
    // The descriptor leads the upload and states the line count, so one pass
    // counts. The second pass writes the lines. Both passes fingerprint what
    // they read (the lines, and the rows left out); the second checks its own
    // before the upload ends, so a store that changed between the passes, even
    // with the same count, stages nothing and imports nothing.
    let count = 0;
    const counted = sha256.create();
    // `for await` closes the readers when the pass ends early, by abort or fault.
    try {
      for await (const row of read(quarantine, counted)) {
        count++;
        counted.update(encoder.encode(JSON.stringify(row) + "\n"));
      }
    } catch (error) {
      // A connector deleted while its store was read refuses its streams.
      if (isConnectionDeleted(error)) {
        refuseDeleted(connector, name);
        continue;
      }
      // A conflict the fold found refuses this stream only. Anything else,
      // an abort included, stops the seed.
      if (!(error instanceof Error) || error.message !== "invalid_record")
        throw error;
      reports.push({
        connector,
        stream: name,
        outcome: "refused",
        reason: "invalid_record",
        rows: 0,
        quarantine: {},
        invalid: 0,
      });
      continue;
    }
    if (count === 0) {
      reports.push({
        connector,
        stream: name,
        outcome: "empty",
        rows: 0,
        quarantine: quarantine.counts(),
        invalid: 0,
      });
      for (const [reason, n] of Object.entries(quarantine.counts()))
        total.add(reason, n);
      continue;
    }
    const expected = fingerprint(counted, quarantine.counts());
    const descriptor = JSON.stringify({
      primaryKey: stream.primaryKey,
      profile: { key: null, version: stream.version },
      records: count,
    });
    async function* body(): AsyncIterable<Uint8Array> {
      let pending: Uint8Array[] = [encoder.encode(descriptor + "\n")];
      let bytes = pending[0]!.byteLength;
      const flush = () => {
        const chunk = new Uint8Array(bytes);
        let at = 0;
        for (const part of pending) {
          chunk.set(part, at);
          at += part.byteLength;
        }
        pending = [];
        bytes = 0;
        return chunk;
      };
      const written = sha256.create();
      const writtenQuarantine = quarantineTally();
      try {
        for await (const row of read(writtenQuarantine, written)) {
          const line = encoder.encode(JSON.stringify(row) + "\n");
          written.update(line);
          // Flush before the line that would pass the bound, so a chunk holds
          // whole lines within it; a line over the bound alone travels alone.
          if (bytes > 0 && bytes + line.byteLength > CHUNK_BYTES) yield flush();
          pending.push(line);
          bytes += line.byteLength;
        }
      } catch (error) {
        // The counting pass found no conflict, so one found now means the store
        // changed between the passes: this stream is refused as changed, and
        // the next stream goes on.
        if (error instanceof Error && error.message === "invalid_record")
          throw new SourceChanged();
        throw error;
      }
      // Before the last chunk leaves, so the staging never sees a complete
      // upload of changed content.
      if (fingerprint(written, writtenQuarantine.counts()) !== expected)
        throw new SourceChanged();
      if (bytes > 0) yield flush();
    }
    options.signal?.throwIfAborted();
    let put: Awaited<ReturnType<SeedIntake["put"]>>;
    try {
      // The intake refuses, under its own request lock, to replace an upload
      // that waits for its target.
      put = await intake.put(connector, name, body(), { keepStaged: true });
    } catch (error) {
      if (isConnectionDeleted(error)) {
        refuseDeleted(connector, name);
        continue;
      }
      if (!(error instanceof SourceChanged)) throw error;
      // Refuses this stream only; no receipt was written, so a later run reads
      // the store again.
      statusOf.delete(connector);
      reports.push({
        connector,
        stream: name,
        outcome: "refused",
        reason: "source_changed",
        rows: 0,
        quarantine: {},
        invalid: 0,
      });
      continue;
    }
    statusOf.delete(connector);
    if (put.state === "staged_upload_pending") {
      reports.push({
        connector,
        stream: name,
        outcome: "refused",
        reason: "staged_upload_pending",
        rows: 0,
        quarantine: {},
        invalid: 0,
      });
      continue;
    }
    if (put.state === "merged") {
      // A final receipt appeared after `status()`: the body was not consumed
      // and nothing was imported here. The receipt holds its own counts.
      reports.push({
        connector,
        stream: name,
        outcome: "merged",
        rows: 0,
        quarantine: {},
        invalid: 0,
      });
      continue;
    }
    reports.push({
      connector,
      stream: name,
      outcome: "staged",
      rows: count,
      quarantine: quarantine.counts(),
      invalid: put.invalid,
    });
    rows += count;
    for (const [reason, n] of Object.entries(quarantine.counts()))
      total.add(reason, n);
  }
  return { streams: reports, rows, quarantine: total.counts() };
}
