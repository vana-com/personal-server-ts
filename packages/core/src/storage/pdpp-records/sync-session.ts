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
  type SyncBudget,
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
  /** Query direction applies to every profile's session pages. */
  order?: "asc" | "desc";
  /** Caller-owned authorization/query facts bound into every cursor. */
  queryBinding?: unknown;
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
  /**
   * Candidate rows one owner's prepared sessions may hold. A window over it
   * expires (410); the client restarts from `beginning`, which prepares the
   * first-sync candidate set too.
   */
  maxPreparedRowsPerOwner?: number;
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
export const DEFAULT_SYNC_PREPARED_ROWS_PER_OWNER = 10_000_000;
/** The largest page one sync request serves. */
export const MAX_SYNC_PAGE_LIMIT = 100;
/** The most instances one sync request reads. */
export const MAX_SYNC_INSTANCES = 64;

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
    | "readSyncWindow"
    | "syncTokenScope"
    | "syncStates"
    | "prepareSyncWindow"
    | "touchSyncPreparation"
    | "sweepSyncPreparations"
  >,
  options: SyncSessionOptions = {},
) {
  const budgetUnits =
    options.maxExaminedPerRequest ?? DEFAULT_SYNC_EXAMINED_PER_REQUEST;
  if (!Number.isSafeInteger(budgetUnits) || budgetUnits < 1) {
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
  const preparedRows =
    options.maxPreparedRowsPerOwner ?? DEFAULT_SYNC_PREPARED_ROWS_PER_OWNER;

  function read(input: SyncRequest): ChangesSincePage {
    // One normalized scope for every consumer: the instance cap, the sibling
    // check, the token binding and every store query see each instance once.
    const request: SyncRequest = {
      ...input,
      instanceIds: [...new Set(input.instanceIds)],
    };
    // The HTTP route clamps `limit` to the same maximum. It also bounds the
    // rows a resumed request reads again (`found`), which the budget charges
    // but never cuts short.
    if (
      !Number.isSafeInteger(request.limit) ||
      request.limit < 1 ||
      request.limit > MAX_SYNC_PAGE_LIMIT
    ) {
      throw new RangeError(
        `sync page limit must be an integer from 1 to ${MAX_SYNC_PAGE_LIMIT}`,
      );
    }
    // A finite scope bounds the one-record-per-key check, which reads every
    // other instance for one identity at once.
    if (request.instanceIds.length > MAX_SYNC_INSTANCES) {
      throw new RangeError(
        `one sync request reads at most ${MAX_SYNC_INSTANCES} instances`,
      );
    }
    // Candidate records carry instance_id: the check is the current wire's.
    if (request.candidate && request.oneRecordPerKey) {
      throw new RangeError(
        "oneRecordPerKey applies to the current profile only",
      );
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
    const now = policy.now();
    const budget = requestBudget(
      budgetUnits,
      request.candidate ? now + scanMillis : undefined,
      policy.now,
    );
    const owner = request.owner ?? "";
    const withheld0 = paused?.withheld ?? position.withheld;
    let high = paused?.high ?? position.high;
    let preparation = paused?.preparation ?? position.preparation;
    // State is written after the store's read ends, so a read snapshot never
    // turns into a write and a store that reads in a transaction never rolls
    // a write back.
    const finish = <T>(result: T): T => {
      tokens.flush();
      if (paused) tokens.endScan();
      store.sweepSyncPreparations(policy.now());
      return result;
    };

    try {
      return walk();
    } catch (err) {
      // A paused scan whose preparation is gone (expired, evicted, over the
      // row cap) would fail every identical retry. Retire it, unless another
      // request moved it, so the next request starts afresh.
      if (paused && err instanceof CursorExpiredError) tokens.endScan();
      throw err;
    }

    function walk(): ChangesSincePage {
      // Every session first prepares its candidate set, in budgeted steps and
      // possibly over several requests: the keys written in its window, or for
      // a first sync every key held at its horizon.
      if (!preparation?.done) {
        preparation ??= {
          id: `prep:${randomBytes(16).toString("base64url")}`,
          done: false,
        };
        const prepared = store.prepareSyncWindow(request.stream, {
          id: preparation.id,
          owner,
          instanceIds: request.instanceIds,
          low: position.low,
          ...(high !== undefined && { high }),
          budget,
          now,
          expiresAt: now + policy.ttl.page,
          maxPerOwner: policy.maxPerOwner,
          maxRowsPerOwner: preparedRows,
        });
        high = prepared.high;
        preparation = { id: preparation.id, done: prepared.done };
        if (!prepared.done) {
          const scan: PausedScan = {
            high,
            ...(paused?.after && { after: paused.after }),
            found: paused?.found ?? position.found,
            withheld: withheld0,
            preparation,
          };
          if (request.candidate) {
            tokens.pauseScan(scan);
            store.sweepSyncPreparations(policy.now());
            throw new SyncRetryLaterError();
          }
          // The current profile keeps its early, possibly empty page.
          return finish({
            data: [],
            hasMore: true,
            nextCursor: tokens.page({
              low: position.low,
              high,
              ...(position.after && { after: position.after }),
              found: position.found,
              carried: position.carried,
              withheld: withheld0,
              preparation,
            }),
          });
        }
      }

      const result = store.readSyncWindow(
        request.stream,
        {
          instanceIds: request.instanceIds,
          low: position.low,
          ...(high !== undefined && { high }),
          preparation: preparation.id,
          now: policy.now(),
        },
        (window): ChangesSincePage | { paused: PausedScan } => {
          const direction = request.order ?? request.candidate?.order ?? "asc";
          const withheld = [...withheld0];
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
            if (
              request.candidate &&
              !row.deleted &&
              change.deletedAfterHigh()
            ) {
              withheld.push({
                recordKey: row.recordKey,
                instance: row.instance,
              });
              return false;
            }
            rows.push(row);
            return true;
          };
          // Changes an earlier request already disclosed, read again at the
          // same horizon so a deletion since then still withholds them. Charged,
          // but never cut short: there are at most one page plus one, and a
          // resumed request that stopped among them would read them again.
          for (const id of paused?.found ?? position.found) {
            budget.spend(
              1 +
                (request.oneRecordPerKey ? request.instanceIds.length - 1 : 0),
            );
            const change = window.change(id);
            if (change) take(change);
          }
          // Re-reading is not progress: the first new identity below is always
          // granted, so a session whose found rows exceed the budget still moves.
          const need = request.limit + 1;
          let scanned: RecordIdentity | undefined =
            paused?.after ?? position.after;
          let exhausted = false;
          // One seek per identity, each paid from the budget.
          while (rows.length < need) {
            const id = window.next(direction, scanned, budget);
            if (id === null) {
              exhausted = true;
              break;
            }
            if (id === undefined) break;
            // The other instances this row's key is checked against, paid
            // before the row is read so a spent budget stops here.
            if (
              request.oneRecordPerKey &&
              !budget.spend(request.instanceIds.length - 1)
            ) {
              exhausted = true;
              break;
            }
            scanned = id;
            const change = window.change(id);
            if (change) take(change);
            budget.progressed();
          }
          if (exhausted && request.candidate) {
            return {
              paused: {
                high: window.high,
                ...(scanned && { after: scanned }),
                found: rows.map(identity),
                withheld,
                preparation: preparation!,
              },
            };
          }
          if (rows.length === need || exhausted) {
            // The extra row is kept for the next page, which starts after the
            // last change this request examined.
            return {
              data: rows.slice(0, request.limit),
              hasMore: true,
              nextCursor: tokens.page({
                low: position.low,
                high: window.high,
                ...(scanned && { after: scanned }),
                found: rows.slice(request.limit).map(identity),
                carried: position.carried,
                withheld,
                preparation: preparation!,
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
      if ("paused" in result) {
        tokens.pauseScan(result.paused);
        store.touchSyncPreparation(
          preparation.id,
          policy.now() + policy.ttl.page,
          policy.now(),
        );
        throw new SyncRetryLaterError();
      }
      // The preparation lives as long as a page cursor that can replay it,
      // including a retry of the session's last page.
      store.touchSyncPreparation(
        preparation.id,
        policy.now() + policy.ttl.page,
        policy.now(),
      );
      return finish(result);
    }
  }

  return { read };
}

export type PdppSyncSessionService = ReturnType<
  typeof createPdppSyncSessionService
>;

/**
 * One request's budget: `units` of store work, and for a candidate request a
 * deadline. The first logical unit is always granted, so every request makes
 * progress. A session can finish when its data is within the supported
 * envelope, its state remains retained, and retries arrive before expiry or
 * eviction.
 */
function requestBudget(
  units: number,
  deadline: number | undefined,
  now: () => number,
): SyncBudget {
  let left = units;
  let progress = false;
  return {
    spend(n = 1) {
      // Until one unit of work is done, spend always grants.
      if (
        progress &&
        (left < n || (deadline !== undefined && now() >= deadline))
      ) {
        return false;
      }
      left -= n;
      return true;
    },
    progressed() {
      progress = true;
    },
  };
}

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
    // A key-only tombstone is still identity/activity metadata. The prior
    // version must have been visible under the same grant before its deletion.
    return visible(change.before(), access) ? after : undefined;
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

/** A session's prepared candidate set; the store keeps its progress. */
interface Preparation {
  id: string;
  done: boolean;
}

interface Position {
  low: string | null;
  high?: string;
  /** Incremental sessions: their prepared candidate set. */
  preparation?: Preparation;
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
  preparation?: Preparation;
}

interface StatePolicy {
  now: () => number;
  ttl: { page: number; checkpoint: number; scan: number };
  maxPerOwner: number;
  maxBytes: number;
}

interface SessionTokens {
  open(request: SyncRequest): Position;
  page(
    position: Omit<Position, "high"> &
      Pick<Required<Position>, "found" | "carried" | "withheld"> & {
        high: string;
      },
  ): string;
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

const toStored = (p: Preparation): NonNullable<StoredState["p"]> => ({
  i: p.id,
  d: p.done,
});
const fromStored = (p: NonNullable<StoredState["p"]>): Preparation => ({
  id: p.i,
  done: p.d,
});

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
  /** The session's preparation id and whether it is done. */
  p?: { i: string; d: boolean };
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
    canonicalJson({
      profile: request.candidate ? "candidate" : "current",
      binding: request.queryBinding ?? request.candidate?.binding ?? null,
      stream: request.stream,
      instances,
      fields: request.eligibilityFields
        ? [...new Set(request.eligibilityFields)].sort()
        : null,
      order: request.order ?? request.candidate?.order ?? "asc",
      oneRecordPerKey: request.oneRecordPerKey ?? false,
    }),
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
  // persistent context, input tokens and page size. Page size stays out of
  // persistent cursor identity so callers may resize between pages.
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
      ...(state.p && { preparation: fromStored(state.p) }),
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
      ...(position.after && {
        a: [position.after.recordKey, position.after.instance] as Pair,
      }),
      f: toPairs(position.found),
      c: toPairs(position.carried),
      w: toPairs(position.withheld),
      ...(position.preparation && { p: toStored(position.preparation) }),
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
        ...(state.p && { preparation: fromStored(state.p) }),
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
          ...(scan.preparation && { p: toStored(scan.preparation) }),
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
