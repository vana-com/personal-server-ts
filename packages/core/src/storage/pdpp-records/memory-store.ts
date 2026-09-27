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

  function projectFields(
    data: Record<string, unknown>,
    fields: string[] | undefined,
  ): Record<string, unknown> {
    if (!fields) return data;
    const projected: Record<string, unknown> = {};
    for (const field of fields) {
      if (field in data) projected[field] = data[field];
    }
    return projected;
  }

  function sortKey(row: PdppStoredRecord): [string, string] {
    // cursor_field is modeled here as emittedAt (stand-in for the declared
    // cursor_field — the ingest path only knows emitted_at, per-stream
    // declared cursor fields are a SourceDeclaration concern the RS route
    // layer resolves before calling into the store).
    return [row.emittedAt, row.recordKey];
  }

  function listRecords(
    stream: string,
    options: ListRecordsOptions,
  ): ListRecordsPage {
    let startAfter: [string, string] | null = null;
    if (options.cursor) {
      const payload = decodeCursor(options.cursor);
      if (payload.kind !== "list") throw new InvalidCursorError();
      assertCursorScope(payload, stream);
      if (payload.order !== options.order) throw new InvalidCursorError();
      startAfter = [payload.sortValue ?? "", payload.recordKey];
    }

    const rows = Array.from(current.values()).filter(
      (row): row is PdppStoredRecord =>
        !row.deleted &&
        row.stream === stream &&
        options.instanceIds.includes(row.instance),
    );

    rows.sort((a, b) => {
      const [aVal, aKey] = sortKey(a);
      const [bVal, bKey] = sortKey(b);
      const cmp =
        aVal === bVal ? aKey.localeCompare(bKey) : aVal < bVal ? -1 : 1;
      return options.order === "asc" ? cmp : -cmp;
    });

    let filtered = rows;
    if (startAfter) {
      const [afterVal, afterKey] = startAfter;
      filtered = rows.filter((row) => {
        const [val, key] = sortKey(row);
        const cmp =
          val === afterVal
            ? key.localeCompare(afterKey)
            : val < afterVal
              ? -1
              : 1;
        return options.order === "asc" ? cmp > 0 : cmp < 0;
      });
    }

    const page = filtered.slice(0, options.limit);
    const hasMore = filtered.length > options.limit;
    const last = page[page.length - 1];

    return {
      data: page.map((row) => ({
        ...row,
        data: projectFields(row.data, options.fields),
      })),
      hasMore,
      nextCursor:
        hasMore && last
          ? encodeCursor({
              kind: "list",
              stream,
              epoch: cursorEpoch(),
              order: options.order,
              sortValue: sortKey(last)[0],
              recordKey: last.recordKey,
            })
          : undefined,
    };
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

      if (entry.row.deleted) {
        changed.push(entry.row);
        continue;
      }

      const projectedNow = projectFields(entry.row.data, options.fields);

      if (sinceHorizon !== null && options.fields) {
        // Eligibility MUST be computed on the grant-authorized projection
        // (spec §4): if only unauthorized fields changed since the prior
        // session horizon, this record must not appear as "changed".
        const priorEntry = [...history]
          .filter(
            (h) =>
              h.stream === entry.stream &&
              h.recordKey === entry.recordKey &&
              h.instance === entry.instance &&
              h.writtenAt <= sinceHorizon,
          )
          .sort((a, b) => b.version - a.version)[0];
        if (priorEntry && !priorEntry.row.deleted) {
          const priorProjected = projectFields(
            priorEntry.row.data,
            options.fields,
          );
          if (JSON.stringify(priorProjected) === JSON.stringify(projectedNow)) {
            continue;
          }
        }
      }

      // Return the RAW (unprojected) row here, not `projectedNow`. Eligibility
      // above legitimately needs the grant-authorized projection to decide
      // "did the authorized fields change" without leaking a hidden-field
      // change. But a caller enforcing time_constraint against `row.data`
      // (packages/server/src/routes/pdpp-records.ts) needs the real field
      // value, not one already stripped to the grant's fields — projecting
      // here would silently break that filter for any grant whose fields
      // don't happen to include the time_constraint field. Field projection
      // for the response is the caller's job, applied AFTER any filtering
      // that reads real field values.
      changed.push(entry.row);
    }

    changed.sort((a, b) => a.recordKey.localeCompare(b.recordKey));

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
