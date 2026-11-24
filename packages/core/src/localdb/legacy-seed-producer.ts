import { classifyImportRow } from "./import-snapshot.js";
import { foldLayers, type FoldLayer } from "./legacy-fold.js";
import { quarantineTally, type QuarantineCounts } from "./legacy-quarantine.js";
import type { SeedIntake } from "./seed.js";

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
 * tombstone. A tombstone needs the server runner's source (`deletions`).
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
  /** `merged`: a final receipt already held it, nothing was read.
   * `staged`: the rows went through the importer (`rows` of them).
   * `empty`: the store had nothing importable, so no upload was made. */
  readonly outcome: "merged" | "staged" | "empty";
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

/** The importable rows of a stream, and what was left out, in one traversal.
 * The signal is checked at every stored record, the ones the fold leaves out
 * included, so a long skip cannot outlast an abort. */
function importable(stream: LegacySeedStream, signal?: AbortSignal) {
  const source = foldLayers(
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
    stream.layers,
    stream.sourceId === undefined ? {} : { sourceId: stream.sourceId },
  );
  return async function* (quarantine: ReturnType<typeof quarantineTally>) {
    for await (const record of source.records()) {
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
  for await (const stream of store.streams()) {
    options.signal?.throwIfAborted();
    const { connector, stream: name } = stream;
    // The status is read per connector, and again after a stream is put: the
    // importer runs inside `put`, so a receipt appears there.
    let status = statusOf.get(connector);
    if (!status) {
      status = await intake.status(connector);
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
    // counts. The second pass writes the lines. A store that changes between
    // the two fails the upload's count check, and nothing is imported.
    let count = 0;
    // `for await` closes the readers when the pass ends early, by abort or fault.
    for await (const _row of read(quarantine)) count++;
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
      for await (const row of read(quarantineTally())) {
        const line = encoder.encode(JSON.stringify(row) + "\n");
        // Flush before the line that would pass the bound, so a chunk holds
        // whole lines within it; a line over the bound alone travels alone.
        if (bytes > 0 && bytes + line.byteLength > CHUNK_BYTES) yield flush();
        pending.push(line);
        bytes += line.byteLength;
      }
      if (bytes > 0) yield flush();
    }
    options.signal?.throwIfAborted();
    const put = await intake.put(connector, name, body());
    statusOf.delete(connector);
    reports.push({
      connector,
      stream: name,
      outcome: "staged",
      rows: count,
      quarantine: quarantine.counts(),
      invalid: put.state === "staged" ? put.invalid : 0,
    });
    rows += count;
    for (const [reason, n] of Object.entries(quarantine.counts()))
      total.add(reason, n);
  }
  return { streams: reports, rows, quarantine: total.counts() };
}
