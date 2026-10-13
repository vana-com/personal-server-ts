import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
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
import {
  CursorExpiredError,
  InvalidCursorError,
  type PdppRecordStore,
  type PdppStoredRecord,
  type StreamListing,
} from "./pdpp-records/index.js";

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
export const CANONICAL_LEGACY_VIEW_CONTRACT = "canonical-legacy-view/3";

const DEFAULT_PAGE_SIZE = 500;
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
  getInstanceBinding(instance: string): CanonicalConnectionBinding;
  listConnections(sourceId: string): CanonicalConnectionBinding[];
  /** Completion receipts stored for one instance. */
  listStreamCompletions(instance: string): CanonicalStreamCompletion[];
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
   * Properties of the legacy body the canonical rows cannot show, such as
   * the order the legacy export gave. The rows are all delivered.
   */
  unproven: {
    stream: string;
    aspect: "record_order" | "collection_coverage";
    reason: string;
  }[];
}

export interface CanonicalLegacyReadOk {
  ok: true;
  envelope: DataFileEnvelope;
  /**
   * Opaque view revision: a hash of the contract version, connection,
   * method, generation, declaration, per-stream row horizons, and the
   * completion receipts the read used. It does not depend on the
   * wall clock or on writes to other connections, so an unchanged source
   * reads back the same value.
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
        | "not_registered"
        | "deleted"
        | "source_mismatch"
        | "method_mismatch";
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
  | CanonicalLegacyReadOk
  | ({ ok: false } & CanonicalLegacyReadFailure);

export interface ReadCanonicalLegacyScopeInput {
  store: CanonicalLegacyReadStore;
  scope: string;
  selection: CanonicalConnectionSelection;
  /** Rows per store page. Tests lower it to force several pages. */
  pageSize?: number;
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

  const profileKey = profileKeyForSource(selection.sourceId);
  const lookup = legacyScopeToPdppSelection(scope, { profileKey });
  const binding = bindingFor(scope, profileKey);
  if (!lookup.ok || !binding) {
    return unavailable({
      reason: "unbound_scope",
      lookup: lookup.ok ? { kind: "unknown_scope", scope } : lookup.error,
    });
  }
  if (canonicalSourceId(binding.pdppSource) !== selection.sourceId) {
    return unavailable({ reason: "scope_source_mismatch", scope });
  }
  const streams = lookup.selection.streams;

  const snapshot = store.readSnapshot(() =>
    collectSnapshot(store, selection, streams, pageSize),
  );
  if (!snapshot.ok) return snapshot.result;

  return projectSnapshot({
    scope,
    selection,
    streams,
    binding,
    profileKey,
    ...snapshot,
  });
}

interface Snapshot {
  ok: true;
  generation: number;
  listing: StreamListing[];
  rowsByStream: Map<string, PdppStoredRecord[]>;
  /**
   * Valid receipts of the bound streams: current method and generation, and
   * a live count equal to the rows read in this snapshot.
   */
  completions: Map<string, CanonicalStreamCompletion>;
}

/** Everything the view needs from the store, read inside one snapshot. */
function collectSnapshot(
  store: CanonicalLegacyReadStore,
  selection: CanonicalConnectionSelection,
  streams: string[],
  pageSize: number,
): Snapshot | { ok: false; result: CanonicalLegacyReadResult } {
  const { instance } = selection;
  const binding = store.getInstanceBinding(instance);
  const rejected = checkConnection(binding, selection);
  if (rejected) return { ok: false, result: unavailable(rejected) };
  const listing = store.listStreams([instance]);

  const rowsByStream = new Map<string, PdppStoredRecord[]>();
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
      rowsByStream.set(stream, rows);
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
  return {
    ok: true,
    generation: binding.generation,
    listing,
    rowsByStream,
    completions,
  };
}

interface ProjectInput extends Snapshot {
  scope: string;
  selection: CanonicalConnectionSelection;
  streams: string[];
  binding: LegacyScopeBinding;
  profileKey: string | undefined;
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
    completions,
  } = input;
  const listingBefore = input.listing;
  const sourceRowCounts = Object.fromEntries(
    streams.map((stream) => [stream, rowsByStream.get(stream)?.length ?? 0]),
  );

  if (
    completions.size === 0 &&
    listingBefore.every((entry) => entry.recordCount === 0)
  ) {
    return unavailable({ reason: "no_synced_data" });
  }
  const unprovenEmpty = streams.filter(
    (stream) =>
      (rowsByStream.get(stream)?.length ?? 0) === 0 && !completions.has(stream),
  );
  if (unprovenEmpty.length > 0) {
    return unavailable({
      reason: "stream_completion_unknown",
      streams: unprovenEmpty,
    });
  }

  for (const stream of streams) {
    const blobBacked = (rowsByStream.get(stream) ?? []).filter(hasBlobRef);
    if (blobBacked.length > 0) {
      return unavailable({
        reason: "blob_backed_records_unsupported",
        stream,
        recordCount: blobBacked.length,
        blocker:
          "Blob bytes are an anthropic-source-record-v1 envelope (see evidence/claude-blob-contract.md). Hydrating them needs the connector parsers ported, blob byte access in this reader, and tests; until then a row served without its blob would fabricate an empty body.",
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

  const records = streams.flatMap((stream) =>
    (rowsByStream.get(stream) ?? []).map((row) => ({ stream, data: row.data })),
  );
  const projected = projectPdppRecordsToLegacyPayload(scope, records, {
    fetchedStreams: streams,
    ...(profileKey ? { profileKey } : {}),
    now: collectedAt,
    orderByPrimaryKey: true,
  });
  if (!projected.ok) {
    return rejection(projected.error, sourceRowCounts);
  }

  const omissions: CanonicalReadDiagnostics["omissions"] = [];
  const partialRows: CanonicalReadDiagnostics["partialRows"] = [];
  const unproven: CanonicalReadDiagnostics["unproven"] = [];
  for (const diagnostic of projected.diagnostics ?? []) {
    if (diagnostic.kind === "unproven") {
      unproven.push({
        stream: diagnostic.stream,
        aspect: diagnostic.aspect,
        reason: diagnostic.reason,
      });
    }
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
    completions,
    listing: listingBefore,
  });

  return {
    ok: true,
    envelope: {
      version: "1.0",
      scope,
      collectedAt,
      data: projected.payload,
    },
    revision,
    complete:
      omissions.length === 0 &&
      partialRows.length === 0 &&
      unproven.length === 0,
    diagnostics: { sourceRowCounts, omissions, partialRows, unproven },
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
      if (row.instance !== instance || seen.has(identity)) {
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
  const ref = row.data.blob_ref;
  return typeof ref === "object" && ref !== null;
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
  completions: Map<string, CanonicalStreamCompletion>;
  listing: StreamListing[];
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
      horizons,
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

/** Binding sources are `connectors/<name>`; the store registers `sources/<name>`. */
function canonicalSourceId(pdppSource: string): string {
  return pdppSource.startsWith(CONNECTOR_ID_PREFIX)
    ? SOURCE_ID_PREFIX + pdppSource.slice(CONNECTOR_ID_PREFIX.length)
    : pdppSource;
}
