import { selectSyncChange } from "./sync-selection.js";
import {
  compareListRows,
  listSnapshotPage,
  compareRecordIdentity,
  decodeListCursor,
} from "./list-page.js";
import { createHash } from "node:crypto";
import { randomUUID } from "node:crypto";
import type { PdppRecordStore } from "./interface.js";
import {
  planIngest,
  summarizeIngest,
  type RecordDataValidator,
} from "./ingest-plan.js";
import { decodeCursor, encodeCursor } from "./cursor.js";
import {
  BlobConflictError,
  CursorExpiredError,
  InvalidCursorError,
  type ChangesSinceOptions,
  type ChangesSincePage,
  type IngestOutcome,
  type IngestResult,
  type ListRecordsOptions,
  type ListRecordsPage,
  type PdppBlobMeta,
  type PdppRecordEnvelopeInput,
  type PdppRecordRow,
  type PdppStoredRecord,
  type PdppTombstoneRecord,
  type StreamListing,
  type StreamSemantics,
} from "./types.js";
import { InvalidCursorSyntaxError } from "./cursor.js";

function blobIdForBytes(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

type RowKey = string; // `${instance}\0${stream}\0${recordKey}`

function rowKey(instance: string, stream: string, recordKey: string): RowKey {
  return `${instance}\0${stream}\0${recordKey}`;
}

function parseOffset(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new InvalidCursorError();
  }
  return value;
}

/** A history entry: every version ever written for a row, in write order. */
interface HistoryEntry {
  instance: string;
  stream: string;
  recordKey: string;
  version: number;
  writtenAt: string; // monotonic wall-clock at write time (for changes_since horizon)
  row: PdppRecordRow;
}

/**
 * In-memory PdppRecordStore. Stands in for the Enclave runtime for this
 * lane's own tests and as a second implementation of the shared interface.
 * This is NOT a real Enclave persistence integration — that needs the
 * supplied Enclave runtime, which this lane does not have access to.
 */
export function createMemoryRecordStore(): PdppRecordStore {
  const current = new Map<RowKey, PdppRecordRow>();
  const history: HistoryEntry[] = [];
  const blobs = new Map<string, PdppBlobMeta>();
  const blobBytes = new Map<string, Uint8Array>();
  const epoch = randomUUID();
  let listSnapshot:
    | {
        key: string;
        rows: PdppStoredRecord[];
        erasureClock: number;
        erased: Set<RowKey>;
      }
    | undefined;
  let writeClock = 0; // monotonic logical clock, avoids wall-clock ties in tests

  function nextWriteTimestamp(): string {
    writeClock += 1;
    // Encode as an ISO-ish sortable string using the logical clock so
    // multiple writes within the same millisecond still order correctly.
    return new Date(writeClock).toISOString();
  }

  function cursorEpoch(): string {
    return epoch;
  }

  function assertCursorScope(
    payload: { stream?: string; epoch?: string },
    stream: string,
  ): void {
    if (payload.stream !== stream) {
      throw new CursorExpiredError();
    }
    if (payload.epoch !== cursorEpoch()) {
      throw new CursorExpiredError();
    }
  }

  function ingestBatch(
    envelopes: PdppRecordEnvelopeInput[],
    streamSemantics: (stream: string, instance: string) => StreamSemantics,
    primaryKeyFields: (stream: string, instance: string) => string[],
    _binding?: { method: string; generation: number },
    validateData?: RecordDataValidator,
  ): IngestResult {
    const results: IngestOutcome[] = [];
    // Stage writes and commit them together, so a thrown error leaves no
    // partial state (the in-memory twin of the SQLite transaction). Later
    // envelopes read the staged rows, so two envelopes for one key are
    // decided in order.
    const staged = new Map<RowKey, PdppRecordRow>();
    const stagedHistory: HistoryEntry[] = [];
    const read = (key: RowKey) => staged.get(key) ?? current.get(key);

    envelopes.forEach((envelope, index) => {
      const plan = planIngest(
        index,
        envelope,
        streamSemantics(envelope.stream, envelope.instance),
        primaryKeyFields(envelope.stream, envelope.instance),
        (recordKey) => {
          const row = read(
            rowKey(envelope.instance, envelope.stream, recordKey),
          );
          if (!row) return undefined;
          return row.deleted
            ? { deleted: true, data: null }
            : { deleted: false, data: row.data };
        },
        validateData,
      );
      results.push(plan.outcome);
      if (!plan.write) return;

      const { recordKey, data } = plan.write;
      const key = rowKey(envelope.instance, envelope.stream, recordKey);
      const version = (read(key)?.version ?? 0) + 1;
      const row: PdppRecordRow =
        data === null
          ? {
              instance: envelope.instance,
              stream: envelope.stream,
              recordKey,
              version,
              deletedAt: envelope.emitted_at,
              emittedAt: envelope.emitted_at,
              deleted: true,
            }
          : {
              instance: envelope.instance,
              stream: envelope.stream,
              recordKey,
              data,
              version,
              emittedAt: envelope.emitted_at,
              deleted: false,
            };
      staged.set(key, row);
      stagedHistory.push({
        instance: envelope.instance,
        stream: envelope.stream,
        recordKey,
        version,
        writtenAt: nextWriteTimestamp(),
        row,
      });
    });

    for (const [key, row] of staged) current.set(key, row);
    history.push(...stagedHistory);

    return summarizeIngest(results);
  }

  function getRecord(
    instance: string,
    stream: string,
    recordKey: string,
  ): PdppStoredRecord | undefined {
    const row = current.get(rowKey(instance, stream, recordKey));
    if (!row || row.deleted) return undefined;
    return row;
  }

  function listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): ListRecordsPage {
    let after: PdppStoredRecord | undefined;
    let horizon = new Date(writeClock).toISOString();
    if (options.cursor) {
      const payload = decodeListCursor(options.cursor);
      assertCursorScope(payload, stream);
      if (payload.order !== options.order) throw new InvalidCursorError();
      horizon = payload.horizon;
      after = {
        emittedAt: payload.sortValue ?? "",
        recordKey: payload.recordKey,
        instance: payload.instance,
        stream,
        data: {},
        version: 0,
        deleted: false,
      };
    }
    const snapshotKey = JSON.stringify([
      stream,
      [...new Set(options.instanceIds)].sort(),
      horizon,
    ]);
    // One bounded cache of raw row references prevents repeated sorting for a
    // page walk. It holds no disclosure decision and is rebuilt from history
    // after eviction, so concurrent traversals retain their own fixed horizons.
    if (listSnapshot?.key !== snapshotKey) {
      const snapshot = new Map<RowKey, PdppRecordRow>();
      const instances = new Set(options.instanceIds);
      for (const entry of history) {
        if (
          entry.stream === stream &&
          instances.has(entry.instance) &&
          entry.writtenAt <= horizon
        ) {
          snapshot.set(
            rowKey(entry.instance, stream, entry.recordKey),
            entry.row,
          );
        }
      }
      listSnapshot = {
        key: snapshotKey,
        erasureClock: -1,
        erased: new Set(),
        rows: Array.from(snapshot.values())
          .filter((row): row is PdppStoredRecord => !row.deleted)
          .sort(compareListRows),
      };
    }
    if (listSnapshot.erasureClock !== writeClock) {
      listSnapshot.erased = new Set(
        history
          .filter((entry) => entry.row.deleted && entry.writtenAt > horizon)
          .map((entry) =>
            rowKey(entry.instance, entry.stream, entry.recordKey),
          ),
      );
      listSnapshot.erasureClock = writeClock;
    }
    const erased = listSnapshot.erased;
    const rows = listSnapshot.rows;
    const direction = options.order === "asc" ? 1 : -1;
    let start = direction === 1 ? 0 : rows.length - 1;
    if (after) {
      let low = 0,
        high = rows.length;
      while (low < high) {
        const middle = Math.floor((low + high) / 2);
        const compared = compareListRows(rows[middle], after);
        if (compared < 0 || (direction === 1 && compared === 0))
          low = middle + 1;
        else high = middle;
      }
      start = direction === 1 ? low : low - 1;
    }
    function* orderedRows(): Generator<PdppStoredRecord> {
      for (let i = start; i >= 0 && i < rows.length; i += direction)
        yield rows[i];
    }
    return listSnapshotPage(
      orderedRows(),
      options,
      {
        stream,
        epoch: cursorEpoch(),
        horizon,
      },
      (row) => erased.has(rowKey(row.instance, row.stream, row.recordKey)),
    );
  }

  function deleteRecord(
    instance: string,
    stream: string,
    recordKey: string,
    deletedAt: string,
    streamSemantics: StreamSemantics,
  ): boolean {
    if (streamSemantics === "append_only") return false;
    const key = rowKey(instance, stream, recordKey);
    const existing = current.get(key);
    if (!existing || existing.deleted) return false;

    const version = existing.version + 1;
    const tombstone: PdppTombstoneRecord = {
      instance,
      stream,
      recordKey,
      version,
      deletedAt,
      emittedAt: deletedAt,
      deleted: true,
    };
    current.set(key, tombstone);
    history.push({
      instance,
      stream,
      recordKey,
      version,
      writtenAt: nextWriteTimestamp(),
      row: tombstone,
    });
    return true;
  }

  function changesSince(
    stream: string,
    options: ChangesSinceOptions,
  ): ChangesSincePage {
    let horizon: string;
    let sinceHorizon: string | null;
    let offset = 0;

    if (options.cursor) {
      // Continuing an already-anchored session: horizon and sinceHorizon
      // both come from the page cursor, not re-derived from changesSince.
      const payload = decodeCursor(options.cursor);
      if (payload.kind !== "changes_since") throw new InvalidCursorError();
      assertCursorScope(payload, stream);
      horizon = payload.horizon;
      sinceHorizon = payload.sinceHorizon;
      offset = parseOffset(payload.offset);
    } else if (options.changesSince) {
      let payload;
      try {
        payload = decodeCursor(options.changesSince);
      } catch (err) {
        if (err instanceof InvalidCursorSyntaxError) {
          throw new CursorExpiredError();
        }
        throw err;
      }
      if (payload.kind !== "changes_since") throw new InvalidCursorError();
      assertCursorScope(payload, stream);
      // The incoming token is the *previous* session's horizon. This
      // session's page-1 horizon is anchored fresh at "now" so writes that
      // land mid-session don't leak into this session's later pages.
      sinceHorizon = payload.horizon;
      horizon = nextWriteTimestamp();
    } else {
      // First-ever sync: no baseline, every current record is "changed".
      sinceHorizon = null;
      horizon = nextWriteTimestamp();
    }

    // Every write strictly after `horizon` is excluded from every page of
    // this session (session-horizon anchoring) — new writes surface only
    // via the next session's `changes_since`.
    const relevant = history.filter(
      (entry) =>
        entry.stream === stream &&
        options.instanceIds.includes(entry.instance) &&
        entry.writtenAt <= horizon,
    );

    const latestAsOfHorizon = new Map<string, HistoryEntry>();
    for (const entry of relevant) {
      const k = rowKey(entry.instance, entry.stream, entry.recordKey);
      const prior = latestAsOfHorizon.get(k);
      if (!prior || entry.version > prior.version) {
        latestAsOfHorizon.set(k, entry);
      }
    }

    const changed: PdppRecordRow[] = [];
    for (const entry of latestAsOfHorizon.values()) {
      if (sinceHorizon !== null) {
        const wroteSincePrior = history.some(
          (h) =>
            h.stream === entry.stream &&
            h.recordKey === entry.recordKey &&
            h.instance === entry.instance &&
            h.writtenAt > sinceHorizon &&
            h.writtenAt <= horizon,
        );
        if (!wroteSincePrior) continue;
      }

      const previous =
        sinceHorizon === null
          ? undefined
          : relevant
              .filter(
                (h) =>
                  h.instance === entry.instance &&
                  h.recordKey === entry.recordKey &&
                  h.writtenAt <= sinceHorizon,
              )
              .at(-1)?.row;
      const selected = selectSyncChange(entry.row, previous, options);
      if (selected) changed.push(selected);
    }

    changed.sort(compareRecordIdentity);

    const page = changed.slice(offset, offset + options.limit);
    const hasMore = offset + options.limit < changed.length;

    return {
      data: page,
      hasMore,
      nextCursor: hasMore
        ? encodeCursor({
            kind: "changes_since",
            stream,
            epoch: cursorEpoch(),
            horizon,
            sinceHorizon,
            offset: offset + options.limit,
          })
        : undefined,
      nextChangesSince: hasMore
        ? undefined
        : encodeCursor({
            kind: "changes_since",
            stream,
            epoch: cursorEpoch(),
            horizon,
            sinceHorizon: null,
            offset: 0,
          }),
    };
  }

  function listStreams(instanceIds: string[]): StreamListing[] {
    const byStream = new Map<
      string,
      { count: number; lastUpdated: string | null }
    >();
    for (const row of current.values()) {
      if (row.deleted) continue;
      if (!instanceIds.includes(row.instance)) continue;
      const entry = byStream.get(row.stream) ?? { count: 0, lastUpdated: null };
      entry.count += 1;
      const updated = row.emittedAt;
      if (!entry.lastUpdated || updated > entry.lastUpdated) {
        entry.lastUpdated = updated;
      }
      byStream.set(row.stream, entry);
    }
    return Array.from(byStream.entries()).map(([stream, v]) => ({
      stream,
      recordCount: v.count,
      lastUpdated: v.lastUpdated,
    }));
  }

  function findBlobReferences(blobId: string) {
    // Scanned on demand rather than maintained as a separate mutable index:
    // this store already holds every current row in memory, and a scan
    // avoids a second piece of state that could drift from `current` on
    // every ingest/delete. A record's blob reference lives at
    // `data.blob_ref.blob_id` per spec §4 "Binary data (blob_ref)". Every
    // matching non-deleted row is returned -- identical bytes can
    // legitimately be referenced by more than one record.
    const references = [];
    for (const row of current.values()) {
      if (row.deleted) continue;
      const blobRef = row.data.blob_ref as { blob_id?: unknown } | undefined;
      if (
        blobRef &&
        typeof blobRef === "object" &&
        blobRef.blob_id === blobId
      ) {
        references.push({
          instance: row.instance,
          stream: row.stream,
          recordKey: row.recordKey,
        });
      }
    }
    return references;
  }

  /** True only when the stored bytes actually hash/size-match `meta`. */
  function storedBytesVerify(meta: PdppBlobMeta): boolean {
    const bytes = blobBytes.get(meta.blobId);
    if (!bytes) return false;
    if (bytes.byteLength !== meta.sizeBytes) return false;
    return createHash("sha256").update(bytes).digest("hex") === meta.sha256;
  }

  function storeBlobBytes(bytes: Uint8Array, mimeType: string): PdppBlobMeta {
    const blobId = blobIdForBytes(bytes);
    const existing = blobs.get(blobId);

    if (existing) {
      const sha256 = blobId.slice("sha256:".length);
      if (
        existing.mimeType !== mimeType ||
        existing.sha256 !== sha256 ||
        existing.sizeBytes !== bytes.byteLength
      ) {
        throw new BlobConflictError(blobId, existing);
      }
      if (!blobBytes.has(existing.blobId)) {
        // Metadata-only row (legacy/test fixture via putBlobMeta, or a prior
        // write that never got this far): complete it with real bytes now,
        // rather than reporting a false "already stored" no-op.
        blobBytes.set(blobId, bytes.slice());
        return existing;
      }
      if (!storedBytesVerify(existing)) {
        // Bytes are present but corrupt relative to their own metadata.
        // Reporting success here would hand back an existing-looking
        // success while the underlying content stays broken; refuse
        // instead of silently repairing or silently succeeding.
        throw new BlobConflictError(blobId, existing);
      }
      // Verified idempotent no-op: content and mimeType both match.
      return existing;
    }

    const sha256 = blobId.slice("sha256:".length);
    const meta: PdppBlobMeta = {
      blobId,
      mimeType,
      sizeBytes: bytes.byteLength,
      sha256,
    };
    // Bytes and metadata become visible together: no reader can observe one
    // without the other.
    blobBytes.set(blobId, bytes.slice());
    blobs.set(blobId, meta);
    return meta;
  }

  function getBlobBytes(blobId: string): Uint8Array<ArrayBuffer> | undefined {
    const meta = blobs.get(blobId);
    const bytes = blobBytes.get(blobId);
    if (!meta || !bytes) return undefined;
    if (bytes.byteLength !== meta.sizeBytes) return undefined;
    const actualHash = createHash("sha256").update(bytes).digest("hex");
    if (actualHash !== meta.sha256) return undefined;
    return bytes.slice() as Uint8Array<ArrayBuffer>;
  }

  return {
    ingestBatch,
    getRecord,
    listRecords,
    deleteRecord,
    changesSince,
    listStreams,
    putBlobMeta: (meta: PdppBlobMeta) => blobs.set(meta.blobId, meta),
    getBlobMeta: (blobId: string) => blobs.get(blobId),
    storeBlobBytes,
    getBlobBytes,
    findBlobReferences,
    close: () => {
      current.clear();
      history.length = 0;
      blobs.clear();
      blobBytes.clear();
    },
  };
}
