import {
  compareListRows,
  listSnapshotPage,
  compareRecordIdentity,
  decodeListCursor,
  assertListCursorBinding,
} from "./list-page.js";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { timeSortKey } from "../../pdpp/time.js";
import { createMemorySyncStateStore } from "./sync-state.js";
import type { PdppRecordStore } from "./interface.js";
import {
  planIngest,
  summarizeIngest,
  type RecordDataValidator,
} from "./ingest-plan.js";
import {
  BlobConflictError,
  CursorExpiredError,
  InvalidCursorError,
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
  type SyncBudget,
  type SyncPreparationRequest,
  type SyncPreparationResult,
  type SyncWindow,
  type RecordIdentity,
  type SyncWindowChange,
  type SyncWindowRequest,
} from "./types.js";

function blobIdForBytes(bytes: Uint8Array): string {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

type RowKey = string; // `${instance}\0${stream}\0${recordKey}`

function rowKey(instance: string, stream: string, recordKey: string): RowKey {
  return `${instance}\0${stream}\0${recordKey}`;
}

/** This store's horizons are the ISO form of its logical write clock. */
function parseHorizon(value: unknown): string {
  if (
    typeof value !== "string" ||
    Number.isNaN(Date.parse(value)) ||
    new Date(value).toISOString() !== value
  ) {
    throw new InvalidCursorError();
  }
  return value;
}

/** One session's prepared candidate set. */
interface MemoryPreparation {
  owner: string;
  high: string;
  rows: number;
  done: boolean;
  expiresAt: number;
  seq: number;
  /** Next history position to read; kept with the candidates. */
  next?: number;
  /** In `compareRecordIdentity` order. */
  candidates: RecordIdentity[];
}

/** First index whose identity is not before `id`. */
function lowerBound(ids: RecordIdentity[], id: RecordIdentity): number {
  let lo = 0,
    hi = ids.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (compareRecordIdentity(ids[mid]!, id) < 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** First index whose identity is after `id`. */
function upperBound(ids: RecordIdentity[], id: RecordIdentity): number {
  let lo = 0,
    hi = ids.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (compareRecordIdentity(ids[mid]!, id) <= 0) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** First index whose key is after `value`, for a list sorted by key. */
function upperBoundBy<T>(
  list: T[],
  value: string,
  key: (item: T) => string,
): number {
  let lo = 0,
    hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (key(list[mid]!) <= value) lo = mid + 1;
    else hi = mid;
  }
  return lo;
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
  const syncTokenKey = new Uint8Array(randomBytes(32));
  const syncStates = createMemorySyncStateStore();
  // Indexes kept on write so a sync request only seeks: versions per key in
  // write order and deletion times per key.
  const versionsByKey = new Map<RowKey, HistoryEntry[]>();
  const deletionsByKey = new Map<RowKey, string[]>();
  const preparations = new Map<string, MemoryPreparation>();
  /** Candidate rows each owner's live preparations hold. */
  const ownerRows = new Map<string, number>();
  let preparationSeq = 0;
  function dropPreparation(id: string): void {
    const p = preparations.get(id);
    if (!p) return;
    preparations.delete(id);
    ownerRows.set(p.owner, (ownerRows.get(p.owner) ?? 0) - p.rows);
  }
  function record(entry: HistoryEntry): void {
    history.push(entry);
    const key = rowKey(entry.instance, entry.stream, entry.recordKey);
    const versions = versionsByKey.get(key);
    if (versions) versions.push(entry);
    else versionsByKey.set(key, [entry]);
    if (entry.row.deleted) {
      const deletions = deletionsByKey.get(key) ?? [];
      deletions.push(entry.writtenAt);
      deletionsByKey.set(key, deletions);
    }
  }
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
    let stagedClock = writeClock;

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
        writtenAt: new Date(++stagedClock).toISOString(),
        row,
      });
    });

    // Publish only after every envelope is decided, without argument
    // spreading: nothing below can throw, so current state, history and the
    // write clock move together or not at all.
    for (const [key, row] of staged) current.set(key, row);
    for (const entry of stagedHistory) record(entry);
    writeClock = stagedClock;

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
      assertListCursorBinding(payload, options);
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
      (instance, recordKey) =>
        history
          .filter(
            (entry) =>
              entry.stream === stream &&
              entry.instance === instance &&
              entry.recordKey === recordKey &&
              entry.writtenAt <= horizon,
          )
          .at(-1)?.row,
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
    record({
      instance,
      stream,
      recordKey,
      version,
      writtenAt: nextWriteTimestamp(),
      row: tombstone,
    });
    return true;
  }

  function readSyncWindow<T>(
    stream: string,
    request: SyncWindowRequest,
    read: (window: SyncWindow) => T,
  ): T {
    const clock = new Date(writeClock).toISOString();
    const high =
      request.high === undefined ? clock : parseHorizon(request.high);
    const low = request.low === null ? null : parseHorizon(request.low);
    // A horizon past this store's clock was never issued by it.
    if (high > clock || (low !== null && low > high)) {
      throw new CursorExpiredError();
    }
    const preparation = preparations.get(request.preparation);
    if (!preparation?.done || preparation.expiresAt <= request.now) {
      throw new CursorExpiredError();
    }
    const versionAt = (
      instance: string,
      recordKey: string,
      horizon: string,
    ): PdppRecordRow | undefined => {
      const versions = versionsByKey.get(rowKey(instance, stream, recordKey));
      if (!versions) return undefined;
      const at = upperBoundBy(versions, horizon, (e) => e.writtenAt) - 1;
      return at >= 0 ? versions[at]!.row : undefined;
    };

    function next(
      direction: "asc" | "desc",
      after: RecordIdentity | undefined,
      budget: SyncBudget,
    ): RecordIdentity | undefined | null {
      if (!budget.spend()) return null;
      const ids = preparation!.candidates;
      const i =
        direction === "asc"
          ? after
            ? upperBound(ids, after)
            : 0
          : (after ? lowerBound(ids, after) : ids.length) - 1;
      return i >= 0 && i < ids.length ? ids[i]! : undefined;
    }

    function change({
      recordKey,
      instance,
    }: RecordIdentity): SyncWindowChange | undefined {
      const after = versionAt(instance, recordKey, high);
      if (!after) return undefined;
      return {
        after,
        before: () =>
          low === null ? undefined : versionAt(instance, recordKey, low),
        deletedAfterHigh: () => {
          const deletions = deletionsByKey.get(
            rowKey(instance, stream, recordKey),
          );
          return (
            deletions !== undefined &&
            upperBoundBy(deletions, high, (d) => d) < deletions.length
          );
        },
      };
    }

    return read({
      high,
      next,
      change,
      versionAtHigh: (instance, recordKey) =>
        versionAt(instance, recordKey, high),
    });
  }

  /** Drops expired preparations; the memory store frees them at once. */
  function sweepPreparations(now: number): void {
    for (const [id, p] of preparations)
      if (p.expiresAt <= now) dropPreparation(id);
  }

  function prepareSyncWindow(
    stream: string,
    request: SyncPreparationRequest,
  ): SyncPreparationResult {
    sweepPreparations(request.now);
    let preparation = preparations.get(request.id);
    if (!preparation) {
      // A session that already started has lost its preparation: expired,
      // evicted or swept.
      if (request.high !== undefined) throw new CursorExpiredError();
      preparation = {
        owner: request.owner,
        high: new Date(writeClock).toISOString(),
        rows: 0,
        done: false,
        expiresAt: request.expiresAt,
        seq: ++preparationSeq,
        candidates: [],
      };
      preparations.set(request.id, preparation);
      const own = [...preparations.entries()]
        .filter(([, p]) => p.owner === request.owner)
        .sort(([, a], [, b]) => b.seq - a.seq);
      for (const [id] of own.slice(request.maxPerOwner)) dropPreparation(id);
    }
    preparation.expiresAt = request.expiresAt;
    const high = preparation.high;
    const instances = new Set(request.instanceIds);
    // History is in write order, so the window is one slice of it. Every
    // entry read is paid from the budget, whatever its stream.
    let n =
      preparation.next ??
      (request.low === null
        ? 0
        : upperBoundBy(history, parseHorizon(request.low), (e) => e.writtenAt));
    for (; !preparation.done; n++) {
      const entry = history[n];
      if (!entry || entry.writtenAt > high) {
        preparation.done = true;
        break;
      }
      if (!request.budget.spend()) break;
      if (entry.stream === stream && instances.has(entry.instance)) {
        const id = { recordKey: entry.recordKey, instance: entry.instance };
        const at = lowerBound(preparation.candidates, id);
        const existing = preparation.candidates[at];
        if (!existing || compareRecordIdentity(existing, id) !== 0) {
          preparation.candidates.splice(at, 0, id);
          preparation.rows += 1;
          const rows = (ownerRows.get(request.owner) ?? 0) + 1;
          ownerRows.set(request.owner, rows);
          if (rows > request.maxRowsPerOwner) {
            dropPreparation(request.id);
            throw new CursorExpiredError();
          }
        }
      }
      request.budget.progressed();
    }
    preparation.next = n;
    return { high, done: preparation.done };
  }

  function touchSyncPreparation(
    id: string,
    expiresAt: number,
    now: number,
  ): void {
    sweepPreparations(now);
    const preparation = preparations.get(id);
    if (!preparation) return;
    if (expiresAt <= now) dropPreparation(id);
    else preparation.expiresAt = expiresAt;
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
      if (
        !entry.lastUpdated ||
        timeSortKey(updated) > timeSortKey(entry.lastUpdated)
      ) {
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
    readSyncWindow,
    syncTokenScope: () => ({ epoch, key: syncTokenKey }),
    syncStates: () => syncStates,
    prepareSyncWindow,
    touchSyncPreparation,
    sweepSyncPreparations: sweepPreparations,
    inspectSyncState: () => ({
      states: syncStates.size(),
      preparations: preparations.size,
      candidates: [...preparations.values()].reduce(
        (sum, p) => sum + p.candidates.length,
        0,
      ),
    }),
    listStreams,
    putBlobMeta: (meta: PdppBlobMeta) => blobs.set(meta.blobId, meta),
    getBlobMeta: (blobId: string) => blobs.get(blobId),
    storeBlobBytes,
    getBlobBytes,
    findBlobReferences,
    close: () => {
      current.clear();
      history.length = 0;
      versionsByKey.clear();
      deletionsByKey.clear();
      preparations.clear();
      ownerRows.clear();
      blobs.clear();
      blobBytes.clear();
    },
  };
}
