import {
  decodeBase64UrlUtf8,
  encodeBase64UrlUtf8,
} from "../encoding/base64url.js";
import { PDPP_VERSION } from "../pdpp-version.js";
import { grantIsCandidate } from "../pdpp/types.js";
import type { OwnedAccountStorageMode } from "./account-storage-mode.js";
import { PdppError } from "../errors/pdpp-catalog.js";
import {
  listCursor,
  type RecordQuery,
  type StoredRecord,
} from "../localdb/query.js";
import type { PdppTokenContext, StreamGrant } from "../ports/pdpp-auth.js";
import {
  recordKeyWithinGrantResources,
  recordWithinGrantTimeConstraint,
  resolveReadScope,
} from "../storage/pdpp-records/enforcement.js";
import type {
  ChangesSinceOptions,
  ChangesSincePage,
} from "../storage/pdpp-records/types.js";
import type {
  StreamDeclaration,
  StreamDeclarationRegistry,
} from "../storage/pdpp-records/stream-declaration.js";
import { parseRecordQuery, requestedCountGrade } from "./pdpp-record-query.js";

export interface LocalRecord {
  readonly instance: string;
  readonly recordKey: string;
  readonly data: Record<string, unknown>;
  readonly emittedAt: string | null;
  readonly deleted?: boolean;
}

export function localRecord(
  instance: string,
  record: StoredRecord,
): LocalRecord {
  const data: unknown = JSON.parse(record.body);
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("Local record data is not an object");
  }
  return {
    instance,
    recordKey: record.recordKey,
    data: data as Record<string, unknown>,
    emittedAt: new Date(record.emittedAt).toISOString(),
  };
}

export function localRecordJson(
  stream: string,
  row: LocalRecord,
  fields: string[] | undefined,
  candidate: boolean,
) {
  const identity = {
    object: "record",
    id: row.recordKey,
    ...(candidate && { instance_id: row.instance }),
    stream,
  };
  if (row.deleted) {
    // RecordQuery exposes the removal sequence, not a deletion timestamp.
    return candidate
      ? { ...identity, deleted: true }
      : { ...identity, deleted: true, deleted_at: null, emitted_at: null };
  }
  return {
    ...identity,
    data: projectFields(row.data, fields),
    emitted_at: row.emittedAt,
  };
}

/** Multi-connection continuation keeps a key per connection, including ties. */
export function localListCursors(
  cursor: string | undefined,
  stream: string,
  instances: string[],
): (string | undefined)[] {
  if (instances.length === 1) return [cursor];
  if (cursor === undefined) return instances.map(() => undefined);
  try {
    const value = JSON.parse(decodeBase64UrlUtf8(cursor));
    if (
      value.kind !== "local-records" ||
      value.stream !== stream ||
      JSON.stringify(value.instances) !== JSON.stringify(instances) ||
      !Array.isArray(value.after) ||
      value.after.length !== instances.length ||
      !value.after.every(
        (key: unknown) => key === null || typeof key === "string",
      )
    ) {
      throw new Error("invalid cursor");
    }
    return value.after.map((key: string | null) => key ?? undefined);
  } catch {
    throw new PdppError("invalid_cursor", "Cursor does not match this stream");
  }
}

function localSequence(value: string): number {
  const number = value === "beginning" ? 0 : Number(value);
  if (
    (value !== "beginning" && !/^(0|[1-9][0-9]*)$/.test(value)) ||
    !Number.isSafeInteger(number)
  ) {
    throw new PdppError("invalid_cursor", "Change cursor must be a sequence");
  }
  return number;
}

/** Only authorized connection ids enter the query; projection follows filtering. */
export async function localRecordPage(
  query: RecordQuery,
  stream: string,
  instanceIds: string[],
  input: ReturnType<typeof parseRecordQuery>,
  streamGrant: StreamGrant | undefined,
  owner: boolean,
  history: RecordHistory | undefined,
  candidate: boolean,
  eligibilityFields: string[] | undefined,
  /**
   * Also state the whole stream's record count across the instances, read with
   * each instance's page. Only the owner's plain listing has one.
   */
  withTotal = false,
): Promise<{
  data: LocalRecord[];
  hasMore: boolean;
  nextCursor: string | null;
  nextChangesSince?: string;
  total?: number;
}> {
  const instances = [...new Set(instanceIds)].sort();
  const visible = (row: LocalRecord) =>
    recordKeyWithinGrantResources(row.recordKey, streamGrant) &&
    (row.deleted || recordWithinGrantTimeConstraint(row.data, streamGrant));
  if (input.changesSince !== undefined) {
    if (!owner) {
      if (!history)
        throw new PdppError(
          "STREAM_HISTORY_UNAVAILABLE",
          "Grant-safe stream change history is unavailable",
        );
      const page = await history(stream, {
        instanceIds: instances,
        changesSince:
          candidate && input.changesSince === "beginning"
            ? undefined
            : input.changesSince,
        cursor: input.cursor,
        limit: input.limit,
        fields: eligibilityFields,
        expireOnErasure: candidate,
        isVisible: (row) =>
          recordKeyWithinGrantResources(row.recordKey, streamGrant) &&
          recordWithinGrantTimeConstraint(row.data, streamGrant),
      });
      return {
        data: page.data.map((row) => ({
          instance: row.instance,
          recordKey: row.recordKey,
          data: row.deleted ? {} : row.data,
          emittedAt: row.emittedAt,
          deleted: row.deleted,
        })),
        hasMore: page.hasMore,
        nextCursor: page.nextCursor ?? null,
        nextChangesSince: page.nextChangesSince,
      };
    }
    const since = localSequence(input.changesSince);
    const after =
      input.cursor === undefined ? since : localSequence(input.cursor);
    if (after < since) {
      throw new PdppError(
        "invalid_cursor",
        "Change cursor precedes changes_since",
      );
    }
    const changes: {
      seq: number;
      row: LocalRecord | null;
    }[] = [];
    let more = false;
    for (const instance of instances) {
      const page = await query.changesSince({
        connectionId: instance,
        stream,
        cursor: after,
        limit: input.limit,
      });
      if (page === "gone") {
        throw new PdppError(
          "cursor_expired",
          "changes_since cursor has expired",
        );
      }
      more ||= page.nextCursor !== null;
      for (const change of page.changes) {
        changes.push({
          seq: change.seq,
          row:
            change.op === "remove"
              ? {
                  instance,
                  recordKey: change.recordKey,
                  data: {},
                  emittedAt: null,
                  deleted: true,
                }
              : change.record === null
                ? null
                : localRecord(instance, change.record),
        });
      }
    }
    changes.sort((a, b) => a.seq - b.seq);
    const page = changes.slice(0, input.limit);
    const hasMore = more || changes.length > input.limit;
    const last = page.at(-1)?.seq ?? after;
    return {
      data: page.flatMap(({ row }) => (row && visible(row) ? [row] : [])),
      hasMore,
      nextCursor: hasMore ? String(last) : null,
      nextChangesSince: String(last),
    };
  }

  if (!owner) {
    if (!history)
      throw new PdppError(
        "STREAM_HISTORY_UNAVAILABLE",
        "Grant-safe stream snapshots are unavailable",
      );
    // Reuse the query module's frozen, visibility-filtered initial snapshot.
    // Hidden identities never consume a page or escape in a list cursor.
    const page = await history(stream, {
      purpose: "listing",
      instanceIds: instances,
      cursor: input.cursor,
      limit: input.limit,
      fields: eligibilityFields,
      isVisible: (row) =>
        visible({
          instance: row.instance,
          recordKey: row.recordKey,
          data: row.data,
          emittedAt: row.emittedAt,
          deleted: false,
        }),
    });
    return {
      data: page.data.map((row) => ({
        instance: row.instance,
        recordKey: row.recordKey,
        data: row.deleted ? {} : row.data,
        emittedAt: row.emittedAt,
        deleted: row.deleted,
      })),
      hasMore: page.hasMore,
      nextCursor: page.nextCursor ?? null,
    };
  }

  const after = localListCursors(input.cursor, stream, instances);
  const records: { index: number; record: StoredRecord }[] = [];
  let more = false;
  let total = 0;
  for (const [index, instance] of instances.entries()) {
    const page = await query.listRecords({
      connectionId: instance,
      stream,
      cursor: after[index],
      limit: input.limit,
      ...(withTotal && { withTotal }),
    });
    more ||= page.nextCursor !== null;
    total += page.total ?? 0;
    for (const record of page.records) records.push({ index, record });
  }
  // SQLite record_key order is binary UTF-8, independent of locale or stamp_o.
  records.sort(
    (a, b) =>
      compareBytes(
        new TextEncoder().encode(a.record.recordKey),
        new TextEncoder().encode(b.record.recordKey),
      ) || a.index - b.index,
  );
  const page = records.slice(0, input.limit);
  const hasMore = more || records.length > input.limit;
  for (const entry of page)
    after[entry.index] = listCursor(
      entry.record.recordKey,
      entry.record.pkHash,
    );
  const nextCursor = !hasMore
    ? null
    : instances.length === 1
      ? after[0]!
      : encodeBase64UrlUtf8(
          JSON.stringify({
            kind: "local-records",
            stream,
            instances,
            after: after.map((key) => key ?? null),
          }),
        );
  return {
    data: page
      .map(({ index, record }) => localRecord(instances[index]!, record))
      .filter(visible),
    hasMore,
    nextCursor,
    ...(withTotal && { total }),
  };
}

/**
 * Applies the grant's field projection to a record's data for the response
 * body. Callers MUST filter by time_constraint against the record's
 * unprojected data BEFORE calling this — projecting first would strip the
 * time_constraint field before it can be compared, silently breaking the
 * filter for any grant whose fields don't happen to include that field.
 */
export function projectFields(
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

/** Query-backed frozen history for grant listing and changes. */
export type RecordHistory = (
  stream: string,
  options: ChangesSinceOptions,
) => Promise<ChangesSincePage>;

/** What a validated list request resolved to, before any rows are read. */
export interface RecordListPlan {
  readonly query: ReturnType<typeof parseRecordQuery>;
  readonly stream: string;
  readonly context: PdppTokenContext;
  readonly scope: ReturnType<typeof resolveReadScope>;
  /** Connections this read may touch: authorized, owned and declaring the stream. */
  readonly instanceIds: string[];
}

/**
 * Everything a host supplies to serve a PDPP record listing. The handler
 * never learns which host it runs on: the host resolves the credential
 * (before the call) and the owner's source scope (through `ownerInstances`).
 */
export interface PdppRecordListPorts {
  /** Absent reads as unknown, which refuses every read. */
  accountMode?: Pick<OwnedAccountStorageMode, "read">;
  /** The linked query a switched account reads through. */
  recordQuery?: RecordQuery;
  recordHistory?: RecordHistory;
  declarations: StreamDeclarationRegistry;
  /**
   * The connections an owner context may read, with the request's optional
   * `source` already applied: narrowing only, never widening. Throws a
   * PdppError to refuse a `source` the context does not cover.
   */
  ownerInstances(
    context: PdppTokenContext,
    source: string | undefined,
  ): string[];
  /** Refuse a client read when one of its connections is unavailable. */
  requireRegisteredConnections?(instanceIds: string[]): void;
  /** The unswitched account's reader. Absent where no legacy store exists. */
  legacy?(plan: RecordListPlan): Promise<Record<string, unknown>>;
}

export interface RecordListResult {
  readonly body: Record<string, unknown>;
  /** True when the read belongs in the client access feed. */
  readonly feed: boolean;
}

/**
 * The single read behind `GET /v1/streams/:stream/records`.
 *
 * Throws a PdppError for every refusal; the host frames it. The context must
 * already be authenticated and active.
 */
export async function listPdppRecords(
  ports: PdppRecordListPorts,
  input: {
    readonly url: string;
    readonly stream: string;
    readonly context: PdppTokenContext;
    /** The request's `Prefer` header, where it may ask for a `count`. */
    readonly prefer?: string | null;
  },
): Promise<RecordListResult> {
  const { context, stream } = input;
  const owner = context.tokenKind === "owner";
  const query = parseRecordQuery(input.url, "listRecords", context.tokenKind);
  if (!owner && query.source !== undefined) {
    throw new PdppError(
      "invalid_request",
      "Parameter 'source' applies to owner reads only",
      { param: "source" },
    );
  }
  const localQuery = localRecordsFor(ports);

  const { declaration, ownerInstanceIds } = readDeclaration(
    ports,
    context,
    stream,
    query.source,
  );
  const scope = resolveReadScope(context, stream, declaration, query.fields);
  const instanceIds = owner ? ownerInstanceIds : scope.instanceIds;
  if (!owner) ports.requireRegisteredConnections?.(instanceIds);
  if (owner && instanceIds.length === 0) {
    throw new PdppError(
      "grant_stream_not_allowed",
      "Owner token is not scoped to a currently owned instance",
    );
  }

  const candidate = grantIsCandidate(context.grant);
  const warnings: { code: string; message: string; param?: string }[] = [];
  if (query.clamped)
    warnings.push({ code: "limit_clamped", message: "limit clamped to 100" });

  if (localQuery) {
    // A count is the whole stream across the read's connections, never the
    // page. Only the owner's plain listing has that one filter to count over;
    // a grant's visibility and a change feed have no such total.
    const wantsCount = requestedCountGrade(input.prefer) !== "none";
    const countable = owner && query.changesSince === undefined;
    if (wantsCount && !countable) {
      warnings.push({
        code: "count_downgraded",
        message: "No exact count is available for this read",
        param: "count",
      });
    }
    const page = await localRecordPage(
      localQuery,
      stream,
      instanceIds,
      query,
      scope.streamGrant,
      owner,
      ports.recordHistory,
      candidate,
      candidate ? scope.streamGrant?.fields : scope.fields,
      wantsCount && countable,
    );
    const count =
      page.total === undefined
        ? undefined
        : ({ kind: "exact", value: page.total } as const);
    return {
      feed: true,
      body: {
        object: "list",
        has_more: page.hasMore,
        ...(page.nextCursor !== null && { next_cursor: page.nextCursor }),
        ...(page.nextChangesSince !== undefined && {
          next_changes_since: page.nextChangesSince,
        }),
        data: page.data.map((row) =>
          localRecordJson(stream, row, scope.fields, candidate),
        ),
        ...((count || warnings.length > 0) && {
          meta: {
            ...(count && { count }),
            ...(warnings.length > 0 && { warnings }),
          },
        }),
      },
    };
  }

  if (!ports.legacy) {
    throw new PdppError(
      "STREAM_READ_UNAVAILABLE",
      "No legacy reader is available for this account",
    );
  }
  return {
    feed: query.changesSince === undefined,
    body: await ports.legacy({ query, stream, context, scope, instanceIds }),
  };
}

/** Read the mode once per request. A switched read never uses legacy rows. */
function localRecordsFor(ports: PdppRecordListPorts): RecordQuery | undefined {
  const mode = ports.accountMode?.read() ?? "unknown";
  if (mode === "unknown")
    throw new PdppError(
      "ACCOUNT_MODE_UNKNOWN",
      "The account mode is not known yet",
    );
  if (mode === "unswitched") return undefined;
  if (!ports.recordQuery) {
    throw new PdppError(
      "STREAM_READ_UNAVAILABLE",
      "Local record query is unavailable for a switched account",
    );
  }
  return ports.recordQuery;
}

/**
 * The declaration a read of `stream` is measured against.
 *
 * A client reads under its grant, which names one source. An owner reads
 * only the context's currently owned connections whose source declares the
 * stream. The declaration only answers whether that stream exists; records
 * carry their own shape.
 */
function readDeclaration(
  ports: PdppRecordListPorts,
  context: PdppTokenContext,
  stream: string,
  source: string | undefined,
): {
  declaration: StreamDeclaration | undefined;
  ownerInstanceIds: string[];
} {
  if (context.tokenKind !== "owner") {
    return {
      declaration: ports.declarations.get(stream, context.grant?.source.id),
      ownerInstanceIds: [],
    };
  }
  const ownerInstanceIds = ports
    .ownerInstances(context, source)
    .filter((instance) => ports.declarations.forInstance(instance, stream));
  const declaration =
    ownerInstanceIds.length > 0
      ? ports.declarations.forInstance(ownerInstanceIds[0]!, stream)
      : ports.declarations.get(stream);
  return { declaration, ownerInstanceIds };
}

/**
 * Version negotiation for every PDPP request: only `PDPP_VERSION` is
 * supported. Both hosts call it before authentication or any query. An
 * absent or empty header is accepted.
 */
export function assertSupportedPdppVersion(
  requested: string | null | undefined,
): void {
  if (requested && requested !== PDPP_VERSION) {
    throw new PdppError(
      "unsupported_version",
      `Unsupported PDPP-Version '${requested}'`,
    );
  }
}

/** The connector a registered source id names: its last path segment. */
export function connectorOfSourceId(sourceId: string): string | undefined {
  return sourceId.split("/").filter(Boolean).at(-1);
}

/** What a host knows about the sources it serves. */
export interface SourceLookup {
  /** The source id a connector id stands for; absent when none is held. */
  sourceIdForConnector(connector: string): string | undefined;
}

/**
 * The source a request's `source` names: a connector id the host maps to its
 * source id, or any other string as given. A source id is never derived from
 * another string by its shape, so a string no host mapping accepts names no
 * source and the read refuses it like a source the caller may not read.
 */
export function resolveOwnerSource(
  source: string,
  lookup: SourceLookup,
): string {
  return lookup.sourceIdForConnector(source) ?? source;
}

/** SQLite BINARY collation compares unsigned UTF-8 bytes, then length. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}
