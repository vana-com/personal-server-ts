import { createHash, createHmac, randomBytes } from "node:crypto";
import {
  decodeCursor,
  encodeCursor,
  InvalidCursorSyntaxError,
} from "./cursor.js";
import { canonicalJson } from "./ingest-plan.js";
import type { PdppRecordStore } from "./interface.js";
import {
  CursorExpiredError,
  InvalidCursorError,
  RecordIdentityConflictError,
  SyncRetryLaterError,
  type ChangesSincePage,
  type PdppRecordRow,
  type PdppStoredRecord,
  type RecordIdentity,
  type SyncStateStore,
  type SyncTokenScope,
  type SyncWindow,
  type SyncWindowChange,
} from "./types.js";

/** What a grant lets one sync session disclose. Absent for an owner read. */
export interface SyncAccess {
  /** Resource restriction on a key, the only test a current-profile tombstone gets. */
  canSeeKey(recordKey: string): boolean;
  /** Every grant restriction on one record version. */
  canSeeRecord(row: PdppStoredRecord): boolean;
}

export interface SyncRequest {
  stream: string;
  /**
   * Whose session state this is: the grant subject, or the owner. Stored
   * state is capped per owner.
   */
  owner?: string;
  instanceIds: string[];
  /**
   * The `changes_since` value. Current profile: empty or absent begins.
   * Candidate profile: `beginning` or absent begins.
   */
  changesSince?: string;
  cursor?: string;
  limit: number;
  /**
   * Fields whose change makes a record visible at both horizons a change.
   * Absent: the current profile compares nothing, the candidate whole data.
   */
  eligibilityFields?: string[];
  access?: SyncAccess;
  /**
   * The wire names a record by key alone. When set, a session that would
   * disclose a key another read instance holds visibly at the horizon throws
   * `RecordIdentityConflictError` rather than send two records as one.
   */
  oneRecordPerKey?: boolean;
  /**
   * Selects the candidate profile. `binding` is the caller's query context
   * (grant identity and restrictions, response fields) that every token of
   * the session is bound to, in addition to what this service reads itself.
   */
  candidate?: { binding: unknown; order: "asc" | "desc" };
}

export interface SyncSessionOptions {
  /**
   * Changes one request may examine. A candidate request that reaches it
   * before it has a page saves its scan and answers `SyncRetryLaterError`; a
   * current-profile page ends early with a page cursor past the last change
   * it examined.
   */
  maxExaminedPerRequest?: number;
  /** Wall-clock budget of one candidate scan, in milliseconds. */
  maxScanMillis?: number;
  /** Clock for budgets and expiry. */
  now?: () => number;
  /** How long a page cursor stays usable. */
  pageTtlMs?: number;
  /** How long a candidate checkpoint stays usable. */
  checkpointTtlMs?: number;
  /** How long a paused scan waits for its retry. */
  scanTtlMs?: number;
  /** Stored session states per owner; the oldest are expired beyond it. */
  maxStatesPerOwner?: number;
  /** UTF-8 bytes one session state may hold; beyond it the session expires. */
  maxStateBytes?: number;
}

/** Matches the stream summary's scan budget in the HTTP route. */
export const DEFAULT_SYNC_EXAMINED_PER_REQUEST = 10_000;
export const DEFAULT_SYNC_SCAN_MILLIS = 2_000;
const HOUR = 3_600_000;
export const DEFAULT_SYNC_PAGE_TTL_MS = HOUR;
export const DEFAULT_SYNC_CHECKPOINT_TTL_MS = 30 * 24 * HOUR;
export const DEFAULT_SYNC_SCAN_TTL_MS = 10 * 60_000;
export const DEFAULT_SYNC_STATES_PER_OWNER = 1_000;
export const DEFAULT_SYNC_STATE_BYTES = 256 * 1024;

/**
 * The single owner of PDPP `changes_since` sessions: horizons, the
 * authorized change set, its pagination, the work one request may do, and
 * every token a session issues. Stores only supply raw history
 * (`readSyncWindow`) and opaque state storage (`syncStates`); HTTP only maps
 * the page.
 *
 * Profiles differ only in policy, never in path:
 * - current: one-horizon visibility, current-state grant filter, readable
 *   checkpoints that existing clients store;
 * - candidate: visibility at both horizons with removals, key order in the
 *   requested direction, checkpoints bound to grant and query context.
 *
 * Every page cursor, and every candidate checkpoint, is a fixed-length
 * handle: a random id with a MAC, naming state this service keeps on the
 * server. A token's length therefore says nothing about keys, positions or
 * how much a session carries, and its size never limits a session.
 *
 * A candidate request scans until it has a page of authorized results, one
 * more to prove `has_more`, or the end of the window. Hidden changes never
 * shape a page. When the request's work or time budget runs out first, it
 * saves the scan and throws `SyncRetryLaterError`; the same request then
 * resumes where the scan stopped, so nothing is examined twice. The answer
 * is the same whatever exhausted the budget.
 *
 * Only the candidate refuses to serve a record deleted after the session's
 * fixed horizon. It withholds that record and keeps its identity in the
 * session state, and the next session returns it as of its own horizon even
 * when its projection did not change. That is the candidate's rule for a
 * reference redacted on a later page, applied to the record itself: comparing
 * projections alone would lose a record deleted and recreated unchanged.
 */
export function createPdppSyncSessionService(
  store: Pick<
    PdppRecordStore,
    "readSyncWindow" | "syncTokenScope" | "syncStates"
  >,
  options: SyncSessionOptions = {},
) {
  const budget =
    options.maxExaminedPerRequest ?? DEFAULT_SYNC_EXAMINED_PER_REQUEST;
  if (!Number.isSafeInteger(budget) || budget < 1) {
    throw new RangeError("sync request budget must be a positive integer");
  }
  const policy: StatePolicy = {
    now: options.now ?? Date.now,
    ttl: {
      page: options.pageTtlMs ?? DEFAULT_SYNC_PAGE_TTL_MS,
      checkpoint: options.checkpointTtlMs ?? DEFAULT_SYNC_CHECKPOINT_TTL_MS,
      scan: options.scanTtlMs ?? DEFAULT_SYNC_SCAN_TTL_MS,
    },
    maxPerOwner: options.maxStatesPerOwner ?? DEFAULT_SYNC_STATES_PER_OWNER,
    maxBytes: options.maxStateBytes ?? DEFAULT_SYNC_STATE_BYTES,
  };
  const scanMillis = options.maxScanMillis ?? DEFAULT_SYNC_SCAN_MILLIS;

  function read(request: SyncRequest): ChangesSincePage {
    if (!Number.isSafeInteger(request.limit) || request.limit < 1) {
      throw new RangeError("sync page limit must be a positive integer");
    }
    const tokens = sessionTokens(
      store.syncTokenScope(),
      store.syncStates(),
      policy,
      request,
    );
    const position = tokens.open(request);
    const paused = request.candidate ? tokens.resumeScan() : undefined;
    const carried = new Set(position.carried.map(identityKey));
    const result = store.readSyncWindow(
      request.stream,
      {
        instanceIds: request.instanceIds,
        low: position.low,
        ...((paused?.high ?? position.high) !== undefined && {
          high: paused?.high ?? position.high,
        }),
      },
      (window): ChangesSincePage | { paused: PausedScan } => {
        const direction = request.candidate?.order === "desc" ? "desc" : "asc";
        const deadline = policy.now() + scanMillis;
        const withheld = [...(paused?.withheld ?? position.withheld)];
        const rows: PdppRecordRow[] = [];
        // Accepts one disclosed change, or withholds it; false if neither.
        const take = (change: SyncWindowChange): boolean => {
          const row = disclose(
            change,
            position.low,
            request,
            carried.has(identityKey(change.after)),
          );
          if (!row) return false;
          if (request.oneRecordPerKey) assertOnlyHolder(row, window, request);
          // Candidate deletion exception: never serve a record deleted after
          // the session's first page. The next session returns it.
          if (request.candidate && !row.deleted && change.deletedAfterHigh()) {
            withheld.push({ recordKey: row.recordKey, instance: row.instance });
            return false;
          }
          rows.push(row);
          return true;
        };
        // Changes an earlier request already disclosed, read again at the
        // same horizon so a deletion since then still withholds them.
        for (const id of paused?.found ?? position.found) {
          const change = window.change(id);
          if (change) take(change);
        }
        const need = request.limit + 1;
        let examined = 0;
        let scanned: RecordIdentity | undefined =
          paused?.after ?? position.after;
        let exhausted = false;
        if (rows.length < need) {
          const changes = window.changes(direction, scanned)[Symbol.iterator]();
          try {
            for (;;) {
              // Checked before the next change is read, so a resumed scan
              // starts at the first change no request has examined.
              // The time budget applies once this request has examined a
              // new change, so every retry makes progress.
              if (
                examined === budget ||
                (request.candidate && examined > 0 && policy.now() >= deadline)
              ) {
                exhausted = true;
                break;
              }
              const next = changes.next();
              if (next.done) break;
              examined += 1;
              scanned = identity(next.value.after);
              if (take(next.value) && rows.length === need) break;
            }
          } finally {
            // A store may hold a cursor open while changes are read.
            changes.return?.();
          }
        }
        if (exhausted && request.candidate) {
          // Saved after the store's read ends, so a store that reads in a
          // transaction does not roll the saved scan back.
          return {
            paused: {
              high: window.high,
              after: scanned,
              found: rows.map(identity),
              withheld,
            },
          };
        }
        if (rows.length === need || exhausted) {
          // The extra row is kept for the next page, which starts after the
          // last change this request examined.
          const data = rows.slice(0, request.limit);
          return {
            data,
            hasMore: true,
            nextCursor: tokens.page({
              low: position.low,
              high: window.high,
              after: scanned!,
              found: rows.slice(request.limit).map(identity),
              carried: position.carried,
              withheld,
            }),
          };
        }
        return {
          data: rows,
          hasMore: false,
          nextChangesSince: tokens.checkpoint(window.high, withheld),
        };
      },
    );
    // State is written after the store's read ends, so a read snapshot never
    // turns into a write and a store that reads in a transaction never rolls
    // a write back.
    if ("paused" in result) {
      tokens.pauseScan(result.paused);
      throw new SyncRetryLaterError();
    }
    tokens.flush();
    if (paused) tokens.endScan();
    return result;
  }

  return { read };
}

export type PdppSyncSessionService = ReturnType<
  typeof createPdppSyncSessionService
>;

function identity(row: { recordKey: string; instance: string }) {
  return { recordKey: row.recordKey, instance: row.instance };
}

/**
 * The record a session discloses for one changed key, if any. `carried`
 * marks a record the previous session withheld: it is returned even when its
 * projection is the same at both horizons.
 */
function disclose(
  change: SyncWindowChange,
  low: string | null,
  request: SyncRequest,
  carried: boolean,
): PdppRecordRow | undefined {
  const { after } = change;
  const { access, eligibilityFields: fields } = request;
  if (request.candidate) {
    const before = low === null ? undefined : change.before();
    const wasVisible = visible(before, access);
    if (!visible(after, access)) {
      return wasVisible ? removal(after) : undefined;
    }
    if (!carried && wasVisible && sameProjection(before!, after, fields)) {
      return undefined;
    }
    return after;
  }
  if (after.deleted) {
    return !access || access.canSeeKey(after.recordKey) ? after : undefined;
  }
  if (access && !access.canSeeRecord(after)) return undefined;
  const before = low === null ? undefined : change.before();
  if (fields && before && sameProjection(before, after, fields)) {
    return undefined;
  }
  // The current contract fixes every page at the session horizon, with no
  // deletion exception: the next session carries the tombstone.
  return after;
}

function visible(
  row: PdppRecordRow | undefined,
  access: SyncAccess | undefined,
): row is PdppStoredRecord {
  return (
    row !== undefined && !row.deleted && (!access || access.canSeeRecord(row))
  );
}

/**
 * A disclosed record or removal names its key alone. If another read
 * instance holds that key visibly at the horizon, the client cannot tell the
 * two apart, so the session refuses instead of conflating them. A same-key
 * record the grant hides is no conflict and is not revealed.
 */
function assertOnlyHolder(
  row: PdppRecordRow,
  window: SyncWindow,
  request: SyncRequest,
): void {
  for (const instance of request.instanceIds) {
    if (instance === row.instance) continue;
    if (
      visible(window.versionAtHigh(instance, row.recordKey), request.access)
    ) {
      throw new RecordIdentityConflictError(row.recordKey);
    }
  }
}

/** A minimal removal: never the now-hidden payload. */
function removal(row: PdppRecordRow): PdppRecordRow {
  if (row.deleted) return row;
  return {
    instance: row.instance,
    stream: row.stream,
    recordKey: row.recordKey,
    version: row.version,
    emittedAt: row.emittedAt,
    deletedAt: row.emittedAt,
    deleted: true,
  };
}

function sameProjection(
  before: PdppRecordRow,
  after: PdppRecordRow,
  fields: string[] | undefined,
): boolean {
  if (before.deleted || after.deleted) return false;
  const project = (data: Record<string, unknown>) =>
    fields
      ? Object.fromEntries(
          fields.filter((f) => Object.hasOwn(data, f)).map((f) => [f, data[f]]),
        )
      : data;
  return (
    canonicalJson(project(before.data)) === canonicalJson(project(after.data))
  );
}

interface Position {
  low: string | null;
  high?: string;
  /** The last change an earlier page examined. */
  after?: RecordIdentity;
  /** Changes an earlier page disclosed but did not serve. */
  found: RecordIdentity[];
  /** Candidate: records the previous session withheld, returned in this one. */
  carried: RecordIdentity[];
  /** Candidate: records this session has withheld so far. */
  withheld: RecordIdentity[];
}

interface PausedScan {
  high: string;
  after?: RecordIdentity;
  found: RecordIdentity[];
  withheld: RecordIdentity[];
}

interface StatePolicy {
  now: () => number;
  ttl: { page: number; checkpoint: number; scan: number };
  maxPerOwner: number;
  maxBytes: number;
}

interface SessionTokens {
  open(request: SyncRequest): Position;
  page(position: Required<Omit<Position, "high">> & { high: string }): string;
  checkpoint(high: string, withheld: RecordIdentity[]): string;
  /** A scan this same request paused earlier, if any. */
  resumeScan(): PausedScan | undefined;
  /** Saves the scan unless another request moved it since it was resumed. */
  pauseScan(scan: PausedScan): void;
  /** Ends the resumed scan unless another request moved it. */
  endScan(): void;
  /** Writes the handles this request minted. */
  flush(): void;
}

function identityKey(id: RecordIdentity): string {
  return JSON.stringify([id.recordKey, id.instance]);
}

type Pair = [string, string];
const toPairs = (ids: RecordIdentity[]): Pair[] =>
  ids.map((id): Pair => [id.recordKey, id.instance]);
const fromPairs = (pairs: Pair[] | undefined): RecordIdentity[] =>
  (pairs ?? []).map(([recordKey, instance]) => ({ recordKey, instance }));

/** What the server keeps behind one handle. */
interface StoredState {
  /** Role: a page cursor, a completed-session checkpoint, or a paused scan. */
  r: "page" | "checkpoint" | "scan";
  /** Digest of the context the state is bound to. */
  b: string;
  /** Page and scan: digest of the session's `changes_since` input. */
  s?: string;
  l?: string | null;
  h: string;
  a?: Pair;
  f?: Pair[];
  c?: Pair[];
  w?: Pair[];
}

const HANDLE_VERSION = 2;
const KEY_ID_BYTES = 4;
const ID_BYTES = 16;
const MAC_BYTES = 16;
const HANDLE_BYTES = 1 + KEY_ID_BYTES + ID_BYTES + MAC_BYTES;

/**
 * Handles name server-side state. Each is the same length: version, store
 * key id, random id and a MAC over them under the store's token key. A
 * handle reveals nothing; altering one fails its MAC (400), one from another
 * or a rebuilt store names another key (410), and one whose state expired or
 * was evicted is gone (410).
 *
 * Bindings: a candidate state is bound to its role and to the grant and query
 * context, and a candidate page also to its session's input checkpoint. A
 * current-profile page is bound to its role, stream and instances only, as
 * the current contract leaves the rest of the query free. Current-profile
 * checkpoints keep the readable format existing clients store; the store
 * validates the horizons they carry.
 */
function sessionTokens(
  scope: SyncTokenScope,
  states: SyncStateStore,
  policy: StatePolicy,
  request: SyncRequest,
): SessionTokens {
  const instances = [...new Set(request.instanceIds)].sort();
  const context = digest(
    canonicalJson(
      request.candidate
        ? {
            binding: request.candidate.binding,
            stream: request.stream,
            instances,
            fields: request.eligibilityFields
              ? [...new Set(request.eligibilityFields)].sort()
              : null,
            order: request.candidate.order,
          }
        : { profile: "current", stream: request.stream, instances },
    ),
  );
  const baseline = digest(request.changesSince ?? "beginning");
  const owner = request.owner ?? "";
  const keyId = createHash("sha256")
    .update(scope.key)
    .digest()
    .subarray(0, KEY_ID_BYTES);
  const mac = (body: Buffer) =>
    createHmac("sha256", scope.key)
      .update(body)
      .digest()
      .subarray(0, MAC_BYTES);
  // A paused scan is found again by the request that paused it: the same
  // context, input tokens and limit.
  const scanId = `scan:${digest(
    canonicalJson([context, request.cursor ?? null, baseline, request.limit]),
  )}`;

  function serialize(state: StoredState): string {
    const json = JSON.stringify(state);
    if (Buffer.byteLength(json, "utf8") > policy.maxBytes) {
      throw new CursorExpiredError();
    }
    return json;
  }

  function write(
    id: string,
    json: string,
    role: keyof StatePolicy["ttl"],
    expect?: string | null,
  ): boolean {
    const now = policy.now();
    return states.put({
      id,
      owner,
      state: json,
      expiresAt: now + policy.ttl[role],
      now,
      maxPerOwner: policy.maxPerOwner,
      ...(expect !== undefined && { expect }),
    });
  }

  const minted: { id: string; json: string; role: "page" | "checkpoint" }[] =
    [];
  function mint(state: StoredState): string {
    const id = randomBytes(ID_BYTES);
    const body = Buffer.concat([Buffer.from([HANDLE_VERSION]), keyId, id]);
    minted.push({
      id: id.toString("base64url"),
      json: serialize(state),
      role: state.r === "page" ? "page" : "checkpoint",
    });
    return Buffer.concat([body, mac(body)]).toString("base64url");
  }

  function isHandle(token: string): boolean {
    return Buffer.from(token, "base64url")[0] === HANDLE_VERSION;
  }

  function load(token: string, role: StoredState["r"]): StoredState {
    const bytes = Buffer.from(token, "base64url");
    if (
      bytes.length !== HANDLE_BYTES ||
      bytes.toString("base64url") !== token ||
      bytes[0] !== HANDLE_VERSION
    ) {
      throw new InvalidCursorError();
    }
    // Minted by another store or a rebuilt one: its history is gone here.
    if (!bytes.subarray(1, 1 + KEY_ID_BYTES).equals(keyId)) {
      throw new CursorExpiredError();
    }
    const body = bytes.subarray(0, HANDLE_BYTES - MAC_BYTES);
    if (!mac(body).equals(bytes.subarray(HANDLE_BYTES - MAC_BYTES))) {
      throw new InvalidCursorError();
    }
    const id = body.subarray(1 + KEY_ID_BYTES).toString("base64url");
    const json = states.get(id, policy.now());
    if (json === undefined) throw new CursorExpiredError();
    const state = JSON.parse(json) as StoredState;
    if (state.r !== role || state.b !== context) {
      throw new InvalidCursorError();
    }
    return state;
  }

  function openPage(cursor: string): Position {
    const state = load(cursor, "page");
    if (state.s !== baseline) throw new InvalidCursorError();
    return {
      low: state.l ?? null,
      high: state.h,
      ...(state.a && {
        after: { recordKey: state.a[0], instance: state.a[1] },
      }),
      found: fromPairs(state.f),
      carried: fromPairs(state.c),
      withheld: fromPairs(state.w),
    };
  }

  /** A readable current-profile token, checked against this store and stream. */
  function decodeCurrent(token: string) {
    const payload = decodeCursor(token);
    if (payload.kind !== "changes_since") throw new InvalidCursorError();
    if (payload.stream !== request.stream || payload.epoch !== scope.epoch) {
      throw new CursorExpiredError();
    }
    return payload;
  }

  const fresh = (low: string | null): Position => ({
    low,
    found: [],
    carried: [],
    withheld: [],
  });

  const page: SessionTokens["page"] = (position) =>
    mint({
      r: "page",
      b: context,
      s: baseline,
      l: position.low,
      h: position.high,
      a: [position.after.recordKey, position.after.instance],
      f: toPairs(position.found),
      c: toPairs(position.carried),
      w: toPairs(position.withheld),
    });

  // The paused state this request resumed, compared on every later write.
  let resumed: string | undefined;
  const scans = {
    flush(): void {
      for (const { id, json, role } of minted.splice(0)) write(id, json, role);
    },
    resumeScan(): PausedScan | undefined {
      const json = states.get(scanId, policy.now());
      if (json === undefined) return undefined;
      resumed = json;
      const state = JSON.parse(json) as StoredState;
      if (state.r !== "scan" || state.b !== context) return undefined;
      return {
        high: state.h,
        ...(state.a && {
          after: { recordKey: state.a[0], instance: state.a[1] },
        }),
        found: fromPairs(state.f),
        withheld: fromPairs(state.w),
      };
    },
    pauseScan(scan: PausedScan): void {
      write(
        scanId,
        serialize({
          r: "scan",
          b: context,
          h: scan.high,
          ...(scan.after && { a: [scan.after.recordKey, scan.after.instance] }),
          f: toPairs(scan.found),
          w: toPairs(scan.withheld),
        }),
        "scan",
        resumed ?? null,
      );
    },
    endScan(): void {
      if (resumed !== undefined) states.delete(scanId, resumed);
    },
  };

  if (request.candidate) {
    return {
      open(request) {
        if (request.cursor) return openPage(request.cursor);
        if (
          request.changesSince === undefined ||
          request.changesSince === "beginning"
        ) {
          return fresh(null);
        }
        const state = load(request.changesSince, "checkpoint");
        return { ...fresh(state.h), carried: fromPairs(state.w) };
      },
      page,
      checkpoint: (high, withheld) =>
        mint({ r: "checkpoint", b: context, h: high, w: toPairs(withheld) }),
      ...scans,
    };
  }

  return {
    open(request) {
      if (request.cursor) {
        if (isHandle(request.cursor)) return openPage(request.cursor);
        // A readable page cursor predates server-side sessions. Its position
        // counted rows the grant hides, so it cannot be resumed.
        decodeCurrent(request.cursor);
        throw new CursorExpiredError();
      }
      if (!request.changesSince) return fresh(null);
      try {
        return fresh(decodeCurrent(request.changesSince).horizon);
      } catch (err) {
        if (err instanceof InvalidCursorSyntaxError) {
          throw new CursorExpiredError();
        }
        throw err;
      }
    },
    page,
    checkpoint: (high) =>
      encodeCursor({
        kind: "changes_since",
        stream: request.stream,
        epoch: scope.epoch,
        horizon: high,
        sinceHorizon: null,
        offset: 0,
      }),
    ...scans,
  };
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}
