import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  ANTHROPIC_CONNECTOR_ID,
  CLAUDE_SOURCE_ID,
} from "../legacy-projection/bindings.js";
import {
  hasAlternateLegacyProfile,
  LEGACY_SCOPE_BINDINGS,
  legacyBindingsForProfile,
  legacyScopeToPdppSelection,
  projectPdppRecordsToLegacyPayload,
  type LegacyScopeBinding,
  type LegacyScopeLookupError,
  type ProjectionError,
} from "../legacy-projection/index.js";
import type {
  ProjectionDiagnostic,
  ProjectionOmission,
} from "../legacy-projection/types.js";
import {
  declaredBlobField,
  declaredBlobReference,
  decodeDeclaredBlob,
  decodeDeclaredRecordsForProjection,
  DeclaredTextError,
  type StreamSchemas,
} from "../legacy-projection/declared-text.js";
import type { StreamDeclarationRegistry } from "./pdpp-records/stream-declaration.js";
import {
  claudeBlobReference,
  ClaudeSourceRecordError,
  decodeClaudeSourceRecord,
  mergeClaudeSourceRecords,
  type ClaudeBlobContents,
} from "../legacy-projection/claude-source-record.js";
import {
  CursorExpiredError,
  InvalidCursorError,
  type PdppRecordStore,
  type PdppStoredRecord,
  type StreamListing,
} from "./pdpp-records/portable.js";

/**
 * Read-time legacy view over canonical PDPP records.
 *
 * Reads ONE legacy scope from exactly one selected connection and returns the
 * legacy `DataFileEnvelope`. Nothing is stored: every call recomputes the body
 * from the live rows, so a repaired source is visible on the next read. The
 * reader only calls read methods on the store.
 *
 * Out of scope here: manual/unbound scope files (no binding => `unbound_scope`),
 * auth/grants, and the sync `DataStoragePort` listing surface.
 */

/** Bump when a change to this module (or the pure projector) can change bytes. */
export const CANONICAL_LEGACY_VIEW_CONTRACT = "canonical-legacy-view/8";

const DEFAULT_PAGE_SIZE = 500;
const MAX_BLOB_READ_BYTES = 64 * 1024 * 1024;
const SOURCE_ID_PREFIX = "https://registry.pdpp.dev/sources/";
const CONNECTOR_ID_PREFIX = "https://registry.pdpp.dev/connectors/";

export interface CanonicalConnectionBinding {
  instance: string;
  sourceId: string | null;
  method: string | null;
  deletedAt: string | null;
  generation: number;
  resetClock: number;
}

/**
 * Evidence that one full replace delivered the stream's current live set.
 * The store writes it only inside a successful P7 replace that named
 * `sourceCollectedAt`, and deletes it on any other write to the stream and on
 * reset or delete of the connection.
 */
export interface CanonicalStreamCompletion {
  stream: string;
  method: string;
  generation: number;
  /** Producer collection time (RFC 3339), never the store clock. */
  sourceCollectedAt: string;
  /** Store write sequence when the replace committed. */
  writeSeq: number;
  /** Live rows the replace left. */
  liveCount: number;
}

/**
 * The slice of the SQLite record store this reader needs. Read methods only.
 * The calls are synchronous.
 */
export interface CanonicalLegacyReadStore extends Pick<
  PdppRecordStore,
  "listRecords" | "listStreams"
> {
  /** Optional for non-blob stores. Byte reads are synchronous inside readSnapshot. */
  getBlobMeta?: PdppRecordStore["getBlobMeta"];
  getBlobBytes?: PdppRecordStore["getBlobBytes"];
  getInstanceBinding(instance: string): CanonicalConnectionBinding;
  listConnections(sourceId: string): CanonicalConnectionBinding[];
  /** Completion receipts stored for one instance. */
  listStreamCompletions(instance: string): CanonicalStreamCompletion[];
  /**
   * Live record keys of one stream in the order each last arrived in the
   * connection's current generation. A key the store holds no arrival for
   * is absent. Read only for a binding with `rowOrder: "arrival"`.
   */
  listArrivalOrder(instance: string, stream: string): string[];
  /**
   * Run `read` against one point-in-time snapshot of the store: a write that
   * commits meanwhile, from any connection, is invisible to every call made
   * inside it. The reader relies on this instead of guessing from counts or
   * timestamps, which an update at an older `emittedAt` does not move.
   */
  readSnapshot<T>(read: () => T): T;
}

/**
 * The one connection a read may use. It must come from a trusted resolver
 * (`resolveCanonicalConnection`, or a grant/bridge that already named the
 * instance); the reader re-checks it against the store binding.
 */
export interface CanonicalConnectionSelection {
  instance: string;
  /** Store source id, e.g. `https://registry.pdpp.dev/sources/oura`. */
  sourceId: string;
  method: string;
}

export interface CanonicalReadDiagnostics {
  /** Live source rows read per bound stream. Counts only, no row content. */
  sourceRowCounts: Record<string, number>;
  /**
   * Source rows the projector left out of a still-deliverable payload, one
   * entry per (stream, reason) the projector reported. Counts are distinct
   * source rows.
   */
  omissions: { stream: string; count: number; reasons: string[] }[];
  /** Rows delivered although their source says detail is missing. */
  partialRows: { stream: string; count: number; reasons: string[] }[];
  /**
   * Properties of the legacy body the canonical rows cannot show. Today one:
   * a stream of two or more rows served in arrival order whose rows the
   * store holds no arrival for (rows stored before it kept one). Those rows
   * are all delivered, in primary-key order. Present only when not empty,
   * so no other scope's result changes shape.
   */
  unproven?: {
    stream: string;
    aspect: "record_order";
    reason: string;
  }[];
}

export interface CanonicalLegacyReadOk {
  ok: true;
  envelope: DataFileEnvelope;
  projectionOmissions?: ProjectionOmission[];
  /** Conservative collection horizon for each input stream in this snapshot. */
  streamCollectionTimes?: Record<string, string | null>;
  /** Current accepted P7 completion time for each input stream, if any. */
  streamCompletionTimes?: Record<string, string | null>;
  /**
   * Opaque view revision: a hash of the contract version, connection,
   * method, generation, declaration, per-stream row horizons in served
   * order, order gaps, and the completion receipts the read used. It does
   * not depend on the wall clock or on writes to other connections, so an
   * unchanged source reads back the same value.
   */
  revision: string;
  /**
   * False when `diagnostics.omissions`, `diagnostics.partialRows` or
   * `diagnostics.unproven` is not empty.
   */
  complete: boolean;
  diagnostics: CanonicalReadDiagnostics;
}

export type CanonicalLegacyReadFailure =
  | {
      status: "unavailable";
      reason: "unbound_scope";
      lookup: LegacyScopeLookupError;
    }
  | { status: "unavailable"; reason: "scope_source_mismatch"; scope: string }
  | {
      status: "unavailable";
      reason: "connection_unavailable";
      detail:
        "not_registered" | "deleted" | "source_mismatch" | "method_mismatch";
    }
  | { status: "unavailable"; reason: "no_synced_data" }
  | {
      /**
       * A bound stream has no live rows and no completion receipt from the
       * connection's current method and generation, so it cannot be told
       * apart from a stream never collected. Another stream having data, or
       * another stream's receipt, is not evidence.
       */
      status: "unavailable";
      reason: "stream_completion_unknown";
      streams: string[];
    }
  | { status: "unavailable"; reason: "invalid_collected_at" }
  | { status: "unavailable"; reason: "store_inconsistent_read"; detail: string }
  | {
      status: "unavailable";
      reason: "blob_backed_records_unsupported";
      stream: string;
      recordCount: number;
      blocker: string;
    }
  | {
      status: "unavailable";
      reason: "blob_read_budget_exceeded";
      requiredBytes?: number;
      maxBytes: number;
    }
  | {
      status: "unavailable";
      reason: "blob_backed_record_invalid";
      detail: string;
    }
  | {
      status: "unavailable";
      reason: "missing_raw_blob";
      recordCount: number;
    }
  | {
      status: "incomplete";
      reason: "projection_rejected";
      error: ProjectionError;
      sourceRowCounts: Record<string, number>;
    }
  | {
      status: "incomplete";
      reason: "all_rows_rejected";
      stream: string;
      sourceRows: number;
      dropped: number;
      reasons: string[];
      sourceRowCounts: Record<string, number>;
    };

export type CanonicalLegacyReadResult =
  CanonicalLegacyReadOk | ({ ok: false } & CanonicalLegacyReadFailure);

export interface ReadCanonicalLegacyScopeInput {
  store: CanonicalLegacyReadStore;
  /** Trusted declarations governing this instance, read inside the record snapshot. */
  declarations?: Pick<StreamDeclarationRegistry, "forInstance">;
  scope: string;
  selection: CanonicalConnectionSelection;
  /**
   * How the selected connection's declaration profile is found.
   * `"source"` (default): from the last segment of the source id.
   * `"method"`: the method id is the profile key, as in Desktop's trusted
   * method configuration, where one public source has several methods
   * (`oura` and `oura-browser` both collect `sources/oura`). The binding
   * must then belong to that method; the source id is not derived from it.
   */
  profileBy?: "source" | "method";
  /**
   * Runs first inside the read snapshot. False means the caller's selection
   * no longer holds in the state the rows come from, and the read is
   * refused as `store_inconsistent_read`.
   */
  confirmSelection?: () => boolean;
  /** Require a matching completion receipt for every stream in the row snapshot. */
  requireCompletionReceipts?: boolean;
  /** A parity caller can compare an unproven empty stream with the actual legacy body. */
  allowUnprovenEmptyStreams?: boolean;
  /** Include the per-stream time evidence used by the parity takeover caller. */
  includeStreamTimes?: boolean;
  /** Require raw Claude envelopes when deciding whether a legacy head is covered. */
  requireClaudeRawBlobs?: boolean;
  /** Rows per store page. Tests lower it to force several pages. */
  pageSize?: number;
  /** @internal Tests may lower the blob budget; never raises the 64 MiB limit. */
  blobByteBudget?: number;
}

export type ResolveCanonicalConnectionResult =
  | { ok: true; selection: CanonicalConnectionSelection }
  | {
      ok: false;
      status: "unavailable";
      reason: "no_connection" | "ambiguous_connection";
      candidates: number;
    };

/**
 * Pick the single connection for a source. Several matches is an error, never
 * a union: a legacy body is one account's data.
 */
export function resolveCanonicalConnection(
  store: Pick<CanonicalLegacyReadStore, "listConnections">,
  query: { sourceId: string; method?: string; instance?: string },
): ResolveCanonicalConnectionResult {
  const matches = store
    .listConnections(query.sourceId)
    .filter(
      (binding) =>
        binding.deletedAt === null &&
        binding.method !== null &&
        (query.method === undefined || binding.method === query.method) &&
        (query.instance === undefined || binding.instance === query.instance),
    );
  const [only] = matches;
  if (matches.length === 1 && only?.method) {
    return {
      ok: true,
      selection: {
        instance: only.instance,
        sourceId: query.sourceId,
        method: only.method,
      },
    };
  }
  return {
    ok: false,
    status: "unavailable",
    reason: matches.length === 0 ? "no_connection" : "ambiguous_connection",
    candidates: matches.length,
  };
}

export async function readCanonicalLegacyScope(
  input: ReadCanonicalLegacyScopeInput,
): Promise<CanonicalLegacyReadResult> {
  const { store, scope, selection } = input;
  const pageSize = Math.max(1, Math.floor(input.pageSize ?? DEFAULT_PAGE_SIZE));

  const byMethod = input.profileBy === "method";
  const profileKey = byMethod
    ? profileKeyForMethod(selection.method)
    : profileKeyForSource(selection.sourceId);
  const lookup = legacyScopeToPdppSelection(scope, { profileKey });
  const binding = bindingFor(scope, profileKey);
  if (!lookup.ok || !binding) {
    return unavailable({
      reason: "unbound_scope",
      lookup: lookup.ok ? { kind: "unknown_scope", scope } : lookup.error,
    });
  }
  if (
    (binding.pdppSource === ANTHROPIC_CONNECTOR_ID &&
      selection.sourceId !== CLAUDE_SOURCE_ID) ||
    (byMethod
      ? legacyConnectorKey(binding.pdppSource) !== selection.method
      : canonicalSourceId(binding.pdppSource) !== selection.sourceId)
  ) {
    return unavailable({ reason: "scope_source_mismatch", scope });
  }
  const streams = lookup.selection.streams;

  const snapshot = store.readSnapshot(() =>
    input.confirmSelection && !input.confirmSelection()
      ? {
          ok: false as const,
          result: inconsistent("the connection selection changed"),
        }
      : collectSnapshot(
          store,
          selection,
          streams,
          binding.rowOrder === "arrival",
          pageSize,
          Number.isSafeInteger(input.blobByteBudget) &&
            (input.blobByteBudget ?? -1) >= 0
            ? Math.min(MAX_BLOB_READ_BYTES, input.blobByteBudget!)
            : MAX_BLOB_READ_BYTES,
          input.requireCompletionReceipts === true,
          input.allowUnprovenEmptyStreams === true,
          input.declarations,
        ),
  );
  if (!snapshot.ok) return snapshot.result;

  return projectSnapshot({
    scope,
    selection,
    streams,
    binding,
    profileKey,
    includeStreamTimes: input.includeStreamTimes === true,
    requireClaudeRawBlobs: input.requireClaudeRawBlobs === true,
    ...snapshot,
  });
}

interface Snapshot {
  ok: true;
  generation: number;
  listing: StreamListing[];
  /** In arrival order for an arrival-ordered binding, unless a gap says not. */
  rowsByStream: Map<string, PdppStoredRecord[]>;
  /** Streams of an arrival-ordered binding whose order the store cannot prove. */
  orderGaps: string[];
  /**
   * Valid receipts of the bound streams: current method and generation, and
   * a live count equal to the rows read in this snapshot.
   */
  completions: Map<string, CanonicalStreamCompletion>;
  blobContents: Map<string, ClaudeBlobContents>;
  streamSchemas: StreamSchemas;
}

/** Everything the view needs from the store, read inside one snapshot. */
function collectSnapshot(
  store: CanonicalLegacyReadStore,
  selection: CanonicalConnectionSelection,
  streams: string[],
  arrivalOrder: boolean,
  pageSize: number,
  blobByteBudget: number,
  requireCompletionReceipts: boolean,
  allowUnprovenEmptyStreams: boolean,
  declarations?: Pick<StreamDeclarationRegistry, "forInstance">,
): Snapshot | { ok: false; result: CanonicalLegacyReadResult } {
  const { instance } = selection;
  const binding = store.getInstanceBinding(instance);
  const rejected = checkConnection(binding, selection);
  if (rejected) return { ok: false, result: unavailable(rejected) };
  const listing = store.listStreams([instance]);
  const streamSchemas: Record<string, Record<string, unknown>> = {};
  for (const stream of streams) {
    const schema = declarations?.forInstance(instance, stream)?.schema;
    if (schema) streamSchemas[stream] = structuredClone(schema);
  }

  const rowsByStream = new Map<string, PdppStoredRecord[]>();
  const orderGaps: string[] = [];
  try {
    for (const stream of streams) {
      const rows = readAllRows(store, instance, stream, pageSize);
      if (typeof rows === "string") {
        return { ok: false, result: inconsistent(rows) };
      }
      // Inside one snapshot the listing and the pages must agree.
      if (rows.length !== countFor(listing, stream)) {
        return {
          ok: false,
          result: inconsistent(`${stream} pages disagree with the listing`),
        };
      }
      const ordered = arrivalOrder
        ? inArrivalOrder(rows, store.listArrivalOrder(instance, stream))
        : rows;
      if (!ordered) orderGaps.push(stream);
      rowsByStream.set(stream, ordered ?? rows);
    }
  } catch (error) {
    if (
      error instanceof CursorExpiredError ||
      error instanceof InvalidCursorError
    ) {
      return { ok: false, result: inconsistent("store cursor rejected") };
    }
    throw error;
  }
  const completions = new Map<string, CanonicalStreamCompletion>();
  for (const receipt of store.listStreamCompletions(instance)) {
    if (
      streams.includes(receipt.stream) &&
      receipt.method === binding.method &&
      receipt.generation === binding.generation &&
      receipt.liveCount === rowsByStream.get(receipt.stream)?.length
    ) {
      completions.set(receipt.stream, receipt);
    }
  }

  // Refuse missing source evidence before reading even one blob body.
  // Binding, rows, receipts, metadata and the later copies share this snapshot.
  if (
    completions.size === 0 &&
    listing.every((entry) => entry.recordCount === 0)
  ) {
    return { ok: false, result: unavailable({ reason: "no_synced_data" }) };
  }
  const unprovenStreams = streams.filter(
    (stream) =>
      !completions.has(stream) &&
      (requireCompletionReceipts ||
        (!allowUnprovenEmptyStreams &&
          (rowsByStream.get(stream)?.length ?? 0) === 0)),
  );
  if (unprovenStreams.length > 0) {
    return {
      ok: false,
      result: unavailable({
        reason: "stream_completion_unknown",
        streams: unprovenStreams,
      }),
    };
  }

  // Preflight all unique references/metadata before copying ANY body. A legal
  // per-blob size does not bound fan-in; excluded raw fields still cost bytes.
  const blobContents = new Map<string, ClaudeBlobContents>();
  let requiredBytes = 0;
  const declaredBlobIds = new Set<string>();
  for (const stream of streams) {
    const blobBacked = (rowsByStream.get(stream) ?? []).filter(hasBlobRef);
    if (blobBacked.length === 0) continue;
    const projectedField = declaredBlobField(streamSchemas[stream]);
    if (
      !projectedField &&
      (selection.sourceId !== CLAUDE_SOURCE_ID ||
        (stream !== "conversations" && stream !== "projects"))
    ) {
      return {
        ok: false,
        result: unavailable({
          reason: "blob_backed_records_unsupported",
          stream,
          recordCount: blobBacked.length,
          blocker:
            "This scope/stream has no verified mapping from blob bytes to its legacy fields.",
        }),
      };
    }
    for (const row of blobBacked) {
      let ref;
      try {
        ref = projectedField
          ? declaredBlobReference(row.data, projectedField)
          : claudeBlobReference(row.data);
      } catch (error) {
        if (!projectedField && !(error instanceof ClaudeSourceRecordError))
          throw error;
        return {
          ok: false,
          result: unavailable({
            reason: "blob_backed_record_invalid",
            detail: projectedField
              ? "invalid_blob_reference"
              : (error as ClaudeSourceRecordError).message,
          }),
        };
      }
      if (projectedField) declaredBlobIds.add(ref.blobId);
      const prior = blobContents.get(ref.blobId);
      let meta;
      try {
        meta = prior?.meta ?? store.getBlobMeta?.(ref.blobId);
      } catch (error) {
        if (!projectedField) throw error;
        return {
          ok: false,
          result: unavailable({ reason: "missing_raw_blob", recordCount: 1 }),
        };
      }
      if (!meta && projectedField) {
        return {
          ok: false,
          result: unavailable({ reason: "missing_raw_blob", recordCount: 1 }),
        };
      }
      if (!meta)
        return {
          ok: false,
          result: unavailable({
            reason: "blob_backed_record_invalid",
            detail: "blob_missing_or_corrupt",
          }),
        };
      if (
        meta.blobId !== ref.blobId ||
        meta.mimeType !== "application/json" ||
        meta.sizeBytes !== ref.size ||
        meta.sha256 !== ref.sha256
      ) {
        return {
          ok: false,
          result: unavailable({
            reason: "blob_backed_record_invalid",
            detail: "blob_metadata_mismatch",
          }),
        };
      }
      if (prior) continue;
      const sum = requiredBytes + ref.size;
      // Never accumulate an inexact integer, even for a refused request.
      if (!Number.isSafeInteger(sum)) {
        return {
          ok: false,
          result: unavailable({
            reason: "blob_read_budget_exceeded",
            maxBytes: blobByteBudget,
          }),
        };
      }
      requiredBytes = sum;
      blobContents.set(ref.blobId, { meta: { ...meta }, bytes: undefined });
    }
  }
  if (requiredBytes > blobByteBudget) {
    return {
      ok: false,
      result: unavailable({
        reason: "blob_read_budget_exceeded",
        requiredBytes,
        maxBytes: blobByteBudget,
      }),
    };
  }
  for (const [blobId, contents] of blobContents) {
    let bytes;
    try {
      bytes = store.getBlobBytes?.(blobId);
    } catch (error) {
      if (!declaredBlobIds.has(blobId)) throw error;
      return {
        ok: false,
        result: unavailable({ reason: "missing_raw_blob", recordCount: 1 }),
      };
    }
    if (!bytes && declaredBlobIds.has(blobId)) {
      return {
        ok: false,
        result: unavailable({ reason: "missing_raw_blob", recordCount: 1 }),
      };
    }
    if (!bytes)
      return {
        ok: false,
        result: unavailable({
          reason: "blob_backed_record_invalid",
          detail: "blob_missing_or_corrupt",
        }),
      };
    if (bytes.byteLength !== contents.meta?.sizeBytes) {
      return {
        ok: false,
        result: unavailable({
          reason: "blob_backed_record_invalid",
          detail: "blob_metadata_mismatch",
        }),
      };
    }
    contents.bytes = bytes.slice();
  }
  return {
    ok: true,
    generation: binding.generation,
    listing,
    rowsByStream,
    orderGaps,
    completions,
    blobContents,
    streamSchemas,
  };
}

/**
 * `rows` in the order their keys last arrived, or null when a row has no
 * arrival to place it by. Zero or one row has only one order.
 */
function inArrivalOrder(
  rows: PdppStoredRecord[],
  arrival: string[],
): PdppStoredRecord[] | null {
  if (rows.length < 2) return rows;
  const position = new Map(arrival.map((key, index) => [key, index]));
  const placed = rows.map((row) => ({ row, at: position.get(row.recordKey) }));
  if (placed.some(({ at }) => at === undefined)) return null;
  return placed.sort((a, b) => (a.at ?? 0) - (b.at ?? 0)).map(({ row }) => row);
}

interface ProjectInput extends Snapshot {
  scope: string;
  selection: CanonicalConnectionSelection;
  streams: string[];
  binding: LegacyScopeBinding;
  profileKey: string | undefined;
  includeStreamTimes: boolean;
  requireClaudeRawBlobs: boolean;
}

async function projectSnapshot(
  input: ProjectInput,
): Promise<CanonicalLegacyReadResult> {
  const {
    scope,
    selection,
    streams,
    binding,
    profileKey,
    rowsByStream,
    orderGaps,
    completions,
  } = input;
  const listingBefore = input.listing;
  const sourceRowCounts = Object.fromEntries(
    streams.map((stream) => [stream, rowsByStream.get(stream)?.length ?? 0]),
  );

  const expanded = [];
  const canExpandClaude =
    selection.sourceId === CLAUDE_SOURCE_ID &&
    (scope === "claude.conversations" || scope === "claude.projects");
  if (canExpandClaude && input.requireClaudeRawBlobs) {
    const parentStream =
      scope === "claude.conversations" ? "conversations" : "projects";
    const missingRawBlobCount = (rowsByStream.get(parentStream) ?? []).filter(
      (row) => !hasBlobRef(row),
    ).length;
    if (missingRawBlobCount > 0) {
      return unavailable({
        reason: "missing_raw_blob",
        recordCount: missingRawBlobCount,
      });
    }
  }
  for (const stream of streams) {
    const blobBacked = (rowsByStream.get(stream) ?? []).filter(hasBlobRef);
    if (
      canExpandClaude &&
      !declaredBlobField(input.streamSchemas[stream]) &&
      (stream === "conversations" || stream === "projects")
    ) {
      try {
        for (const row of blobBacked) {
          const ref = claudeBlobReference(row.data);
          expanded.push(
            ...(await decodeClaudeSourceRecord(
              row,
              input.blobContents.get(ref.blobId) ?? {
                meta: undefined,
                bytes: undefined,
              },
            )),
          );
        }
      } catch (error) {
        if (!(error instanceof ClaudeSourceRecordError)) throw error;
        return unavailable({
          reason: "blob_backed_record_invalid",
          detail: error.message,
        });
      }
      continue;
    }
    if (
      blobBacked.length > 0 &&
      !declaredBlobField(input.streamSchemas[stream])
    ) {
      return unavailable({
        reason: "blob_backed_records_unsupported",
        stream,
        recordCount: blobBacked.length,
        blocker:
          "This scope/stream has no verified mapping from blob bytes to its legacy fields.",
      });
    }
  }

  const collectedAt = latestCollectedAt(
    rowsByStream,
    completions,
    listingBefore,
  );
  if (collectedAt === null)
    return unavailable({ reason: "invalid_collected_at" });

  let records = streams.flatMap((stream) =>
    (rowsByStream.get(stream) ?? []).map((row) => ({ stream, data: row.data })),
  );
  // Decode inline fields before inserting raw blob text; a JSON-string blob
  // is already source text and must never be decoded a second time.
  let decodeDiagnostics: ProjectionDiagnostic[] = [];
  try {
    const decoded = decodeDeclaredRecordsForProjection(
      records,
      input.streamSchemas,
      scope,
      true,
    );
    records = decoded.records;
    decodeDiagnostics = decoded.diagnostics;
  } catch (error) {
    if (!(error instanceof DeclaredTextError)) throw error;
    return rejection(error.projectionError(scope), sourceRowCounts);
  }
  for (let i = 0; i < records.length; i++) {
    const record = records[i]!;
    const field = declaredBlobField(input.streamSchemas[record.stream]);
    if (!field || !Object.hasOwn(record.data, "blob_ref")) continue;
    try {
      const ref = declaredBlobReference(record.data, field);
      records[i] = {
        ...record,
        data: await decodeDeclaredBlob(
          record.data,
          field,
          input.blobContents.get(ref.blobId) ?? {
            meta: undefined,
            bytes: undefined,
          },
        ),
      };
    } catch {
      return unavailable({
        reason: "blob_backed_record_invalid",
        detail: "invalid_declared_blob",
      });
    }
  }
  if (expanded.length > 0) {
    try {
      records = mergeClaudeSourceRecords(
        records.filter((record) => !Object.hasOwn(record.data, "blob_ref")),
        expanded,
      );
    } catch (error) {
      if (!(error instanceof ClaudeSourceRecordError)) throw error;
      return unavailable({
        reason: "blob_backed_record_invalid",
        detail: error.message,
      });
    }
  }
  const projected = projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams: streams,
    ...(profileKey ? { profileKey } : {}),
    now: collectedAt,
    // Rows of an arrival-ordered scope go in as read. Without proof of that
    // order the view falls back to key order and reports the gap below.
    orderByPrimaryKey: binding.rowOrder !== "arrival" || orderGaps.length > 0,
  });
  if (!projected.ok) {
    return rejection(projected.error, sourceRowCounts);
  }

  const omissions: CanonicalReadDiagnostics["omissions"] = [];
  const partialRows: CanonicalReadDiagnostics["partialRows"] = [];
  const unproven: NonNullable<CanonicalReadDiagnostics["unproven"]> =
    orderGaps.map((stream) => ({
      stream,
      aspect: "record_order",
      reason:
        "some rows were stored before the store kept arrival order; they are served in primary-key order",
    }));
  for (const diagnostic of [
    ...decodeDiagnostics,
    ...(projected.diagnostics ?? []),
  ]) {
    if (
      diagnostic.kind === "records_dropped" ||
      diagnostic.kind === "records_partial"
    ) {
      (diagnostic.kind === "records_dropped" ? omissions : partialRows).push({
        stream: diagnostic.stream,
        count: diagnostic.count,
        reasons: diagnostic.reasons,
      });
    }
  }
  // Valid peers may deliver with omissions. If NOTHING of the item stream
  // survived, a "successful empty" would read as an empty history.
  const itemStream = streams[0];
  const sourceRows = itemStream ? (sourceRowCounts[itemStream] ?? 0) : 0;
  const itemOmissions = omissions.filter(
    (entry) => entry.stream === itemStream,
  );
  const itemDropped = itemOmissions.reduce(
    (sum, entry) => sum + entry.count,
    0,
  );
  if (itemStream && sourceRows > 0 && itemDropped >= sourceRows) {
    return {
      ok: false,
      status: "incomplete",
      reason: "all_rows_rejected",
      stream: itemStream,
      sourceRows,
      dropped: itemDropped,
      reasons: [...new Set(itemOmissions.flatMap((entry) => entry.reasons))],
      sourceRowCounts,
    };
  }

  const revision = await viewRevision({
    scope,
    selection,
    binding,
    profileKey,
    generation: input.generation,
    streams,
    rowsByStream,
    orderGaps,
    completions,
    listing: listingBefore,
    streamSchemas: input.streamSchemas,
  });

  return {
    ok: true,
    ...(projected.projectionOmissions
      ? { projectionOmissions: projected.projectionOmissions }
      : {}),
    envelope: {
      version: "1.0",
      scope,
      collectedAt,
      data: projected.payload,
    },
    ...(input.includeStreamTimes
      ? {
          streamCollectionTimes: Object.fromEntries(
            streams.map((stream) => {
              const receipt = completions.get(stream);
              if (receipt) return [stream, receipt.sourceCollectedAt];
              const rows = rowsByStream.get(stream) ?? [];
              const times = rows.map((row) => Date.parse(row.emittedAt));
              if (
                times.length === 0 ||
                times.some((time) => !Number.isFinite(time))
              ) {
                return [stream, null];
              }
              return [
                stream,
                new Date(
                  times.reduce(
                    (oldest, time) => Math.min(oldest, time),
                    Number.POSITIVE_INFINITY,
                  ),
                ).toISOString(),
              ];
            }),
          ),
          streamCompletionTimes: Object.fromEntries(
            streams.map((stream) => [
              stream,
              completions.get(stream)?.sourceCollectedAt ?? null,
            ]),
          ),
        }
      : {}),
    revision,
    complete:
      omissions.length === 0 &&
      partialRows.length === 0 &&
      unproven.length === 0,
    diagnostics: {
      sourceRowCounts,
      omissions,
      partialRows,
      ...(unproven.length > 0 ? { unproven } : {}),
    },
  };
}

function inconsistent(detail: string): CanonicalLegacyReadResult {
  return unavailable({ reason: "store_inconsistent_read", detail });
}

/** All live rows of one stream, or a detail string if the pages are not one clean listing. */
function readAllRows(
  store: CanonicalLegacyReadStore,
  instance: string,
  stream: string,
  limit: number,
): PdppStoredRecord[] | string {
  const rows: PdppStoredRecord[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  let horizon: string | undefined;
  let first = true;
  for (;;) {
    const page = store.listRecords(stream, {
      instanceIds: [instance],
      limit,
      cursor,
      order: "asc",
    });
    if (first) horizon = page.horizon;
    else if (page.horizon !== horizon) return `${stream} page horizon moved`;
    first = false;
    for (const row of page.data) {
      const identity = `${row.instance}\u0000${row.recordKey}`;
      if (
        row.instance !== instance ||
        row.stream !== stream ||
        seen.has(identity)
      ) {
        return `${stream} returned a foreign or repeated row`;
      }
      seen.add(identity);
      rows.push(row);
    }
    if (!page.hasMore) return rows;
    if (!page.nextCursor || page.nextCursor === cursor) {
      return `${stream} cursor did not advance`;
    }
    cursor = page.nextCursor;
  }
}

function checkConnection(
  binding: CanonicalConnectionBinding,
  selection: CanonicalConnectionSelection,
): Omit<
  Extract<CanonicalLegacyReadFailure, { reason: "connection_unavailable" }>,
  "status"
> | null {
  const detail = (
    value: "not_registered" | "deleted" | "source_mismatch" | "method_mismatch",
  ) => ({ reason: "connection_unavailable" as const, detail: value });
  if (binding.sourceId === null) return detail("not_registered");
  if (binding.deletedAt !== null) return detail("deleted");
  if (binding.sourceId !== selection.sourceId) return detail("source_mismatch");
  if (binding.method !== selection.method) return detail("method_mismatch");
  return null;
}

function rejection(
  error: ProjectionError,
  sourceRowCounts: Record<string, number>,
): CanonicalLegacyReadResult {
  if (
    error.kind === "unknown_scope" ||
    error.kind === "unsupported_profile" ||
    error.kind === "gap"
  ) {
    return unavailable({
      reason: "unbound_scope",
      lookup:
        error.kind === "gap"
          ? {
              kind: "gap",
              scope: error.scope,
              reason: error.reason,
              provenanceChecked: [],
            }
          : error,
    });
  }
  return {
    ok: false,
    status: "incomplete",
    reason: "projection_rejected",
    error,
    sourceRowCounts,
  };
}

type UnavailableFailure = Extract<
  CanonicalLegacyReadFailure,
  { status: "unavailable" }
>;
type WithoutStatus<T> = T extends unknown ? Omit<T, "status"> : never;

function unavailable(
  failure: WithoutStatus<UnavailableFailure>,
): CanonicalLegacyReadResult {
  return {
    ok: false,
    status: "unavailable",
    ...failure,
  } as CanonicalLegacyReadResult;
}

function hasBlobRef(row: PdppStoredRecord): boolean {
  return Object.hasOwn(row.data, "blob_ref");
}

function countFor(listing: StreamListing[], stream: string): number {
  return listing.find((entry) => entry.stream === stream)?.recordCount ?? 0;
}

/**
 * Newest collection time over the bound streams. A stream with a valid
 * receipt was collected at its producer `sourceCollectedAt`, even when an
 * unchanged replace left older rows. A stream without one falls back to its
 * rows' `emittedAt` (the importer stamps it from the original envelope
 * `collectedAt`). With neither, the newest stream horizon of the connection.
 * Never the wall clock.
 */
function latestCollectedAt(
  rowsByStream: Map<string, PdppStoredRecord[]>,
  completions: Map<string, CanonicalStreamCompletion>,
  listing: StreamListing[],
): string | null {
  const stamps: string[] = [];
  for (const [stream, rows] of rowsByStream) {
    const receipt = completions.get(stream);
    if (receipt) stamps.push(receipt.sourceCollectedAt);
    else for (const row of rows) stamps.push(row.emittedAt);
  }
  if (stamps.length === 0) {
    for (const entry of listing) {
      if (entry.lastUpdated !== null) stamps.push(entry.lastUpdated);
    }
  }
  let newest = Number.NEGATIVE_INFINITY;
  for (const stamp of stamps) {
    const ms = Date.parse(stamp);
    if (Number.isNaN(ms)) return null;
    newest = Math.max(newest, ms);
  }
  return Number.isFinite(newest) ? new Date(newest).toISOString() : null;
}

async function viewRevision(input: {
  scope: string;
  selection: CanonicalConnectionSelection;
  binding: LegacyScopeBinding;
  profileKey: string | undefined;
  generation: number;
  streams: string[];
  rowsByStream: Map<string, PdppStoredRecord[]>;
  orderGaps: string[];
  completions: Map<string, CanonicalStreamCompletion>;
  listing: StreamListing[];
  streamSchemas: StreamSchemas;
}): Promise<string> {
  const horizons = [];
  for (const stream of input.streams) {
    const rows = input.rowsByStream.get(stream) ?? [];
    horizons.push({
      stream,
      count: rows.length,
      lastUpdated:
        input.listing.find((entry) => entry.stream === stream)?.lastUpdated ??
        null,
      rows: await sha256Hex(
        rows
          .map(
            (row) =>
              `${row.recordKey}\u0000${row.version}\u0000${row.emittedAt}`,
          )
          .join("\n"),
      ),
    });
  }
  const digest = await sha256Hex(
    JSON.stringify({
      contract: CANONICAL_LEGACY_VIEW_CONTRACT,
      streamSchemas: input.streamSchemas,
      scope: input.scope,
      instance: input.selection.instance,
      sourceId: input.selection.sourceId,
      method: input.selection.method,
      generation: input.generation,
      profileKey: input.profileKey ?? null,
      declaration: {
        pdppSource: input.binding.pdppSource,
        streams: input.binding.pdppStreams,
        primaryKey: input.binding.primaryKey,
        fieldsRead: input.binding.fieldsRead,
        provenance: input.binding.provenance,
      },
      // Rows hash in served order, so a re-delivery that moves a key moves
      // the revision even though no row version changed.
      horizons,
      orderGaps: input.orderGaps,
      // Not `writeSeq`: the write clock is shared by all connections, so an
      // unchanged replay after another account's write would move it.
      completions: input.streams.flatMap((stream) => {
        const receipt = input.completions.get(stream);
        return receipt
          ? [
              {
                stream,
                method: receipt.method,
                generation: receipt.generation,
                sourceCollectedAt: receipt.sourceCollectedAt,
                liveCount: receipt.liveCount,
              },
            ]
          : [];
      }),
    }),
  );
  return `v1:${digest}`;
}

async function sha256Hex(text: string): Promise<string> {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(bytes), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

function bindingFor(
  scope: string,
  profileKey: string | undefined,
): LegacyScopeBinding | undefined {
  return profileKey
    ? legacyBindingsForProfile(profileKey).get(scope)
    : LEGACY_SCOPE_BINDINGS.get(scope);
}

/** Alternate declaration profiles are keyed by the source's last segment. */
function profileKeyForSource(sourceId: string): string | undefined {
  const key = sourceId.slice(sourceId.lastIndexOf("/") + 1);
  return hasAlternateLegacyProfile(key) ? key : undefined;
}

/** A method id names its alternate profile directly; others use the default. */
function profileKeyForMethod(method: string): string | undefined {
  return hasAlternateLegacyProfile(method) ? method : undefined;
}

/**
 * The connector key a binding was reviewed for: the last segment of its
 * `pdppSource`. It is a profile name, not a store source id.
 */
export function legacyConnectorKey(pdppSource: string): string {
  return pdppSource.slice(pdppSource.lastIndexOf("/") + 1);
}

/** Most connector keys match their public source; Anthropic collects Claude. */
function canonicalSourceId(pdppSource: string): string {
  if (pdppSource === ANTHROPIC_CONNECTOR_ID) return CLAUDE_SOURCE_ID;
  return pdppSource.startsWith(CONNECTOR_ID_PREFIX)
    ? SOURCE_ID_PREFIX + pdppSource.slice(CONNECTOR_ID_PREFIX.length)
    : pdppSource;
}
