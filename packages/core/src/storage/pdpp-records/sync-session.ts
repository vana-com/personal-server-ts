import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
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
  type ChangesSincePage,
  type PdppRecordRow,
  type PdppStoredRecord,
  type RecordIdentity,
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
   * Changes one page may examine. A page that reaches it ends early with a
   * page cursor past the last change it examined, so one request never walks
   * an unbounded window of changes the grant does not disclose.
   */
  maxExaminedPerPage?: number;
}

/** Matches the stream summary's scan budget in the HTTP route. */
export const DEFAULT_SYNC_EXAMINED_PER_PAGE = 10_000;

/**
 * The single owner of PDPP `changes_since` sessions: horizons, the
 * authorized change set, its pagination, the work one page may do, and every
 * token a session issues. Stores only supply raw history
 * (`readSyncWindow`); HTTP only maps the page.
 *
 * Profiles differ only in policy, never in path:
 * - current: one-horizon visibility, current-state grant filter, readable
 *   checkpoints that existing clients store;
 * - candidate: visibility at both horizons with removals, key order in the
 *   requested direction, sealed checkpoints bound to grant and query context.
 *
 * Both profiles paginate over the authorized result only and seal every page
 * cursor, because a page that ends on its work budget resumes after a change
 * it may not disclose. Only the candidate refuses to serve a record deleted
 * after the session's fixed horizon. It withholds that record, carries its
 * identity in the session's sealed tokens, and the next session returns it
 * as of its own horizon even when its projection did not change. That is the
 * candidate's rule for a reference redacted on a later page, applied to the
 * record itself: comparing projections alone would lose a record deleted and
 * recreated unchanged. A session that withholds more than a token can carry
 * expires instead.
 */
export function createPdppSyncSessionService(
  store: Pick<PdppRecordStore, "readSyncWindow" | "syncTokenScope">,
  options: SyncSessionOptions = {},
) {
  const budget = options.maxExaminedPerPage ?? DEFAULT_SYNC_EXAMINED_PER_PAGE;
  if (!Number.isSafeInteger(budget) || budget < 1) {
    throw new RangeError("sync page budget must be a positive integer");
  }

  function read(request: SyncRequest): ChangesSincePage {
    if (!Number.isSafeInteger(request.limit) || request.limit < 1) {
      throw new RangeError("sync page limit must be a positive integer");
    }
    const tokens = sessionTokens(store.syncTokenScope(), request);
    const position = tokens.open(request);
    const carried = new Set(position.carried.map(identityKey));
    const withheld = [...position.withheld];
    return store.readSyncWindow(
      request.stream,
      {
        instanceIds: request.instanceIds,
        low: position.low,
        ...(position.high !== undefined && { high: position.high }),
      },
      (window) => {
        const direction = request.candidate?.order === "desc" ? "desc" : "asc";
        const data: PdppRecordRow[] = [];
        let examined = 0;
        let last: RecordIdentity | undefined;
        let resumeAfter: RecordIdentity | undefined;
        for (const change of window.changes(direction, position.after)) {
          if (examined === budget) {
            // Another change exists past the budget: end this page there.
            resumeAfter = last;
            break;
          }
          examined += 1;
          last = change.after;
          const row = disclose(
            change,
            position.low,
            request,
            carried.has(identityKey(change.after)),
          );
          if (!row) continue;
          if (data.length === request.limit) {
            resumeAfter = data[data.length - 1];
            break;
          }
          if (request.oneRecordPerKey) assertOnlyHolder(row, window, request);
          // Candidate deletion exception: never serve a record deleted after
          // the session's first page. The next session returns it.
          if (request.candidate && !row.deleted && change.deletedAfterHigh()) {
            withheld.push({ recordKey: row.recordKey, instance: row.instance });
            continue;
          }
          data.push(row);
        }
        if (!resumeAfter) {
          return {
            data,
            hasMore: false,
            nextChangesSince: tokens.checkpoint(window.high, withheld),
          };
        }
        return {
          data,
          hasMore: true,
          nextCursor: tokens.page({
            low: position.low,
            high: window.high,
            after: {
              recordKey: resumeAfter.recordKey,
              instance: resumeAfter.instance,
            },
            carried: position.carried,
            withheld,
          }),
        };
      },
    );
  }

  return { read };
}

export type PdppSyncSessionService = ReturnType<
  typeof createPdppSyncSessionService
>;

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
  after?: RecordIdentity;
  /** Candidate: records the previous session withheld, returned in this one. */
  carried: RecordIdentity[];
  /** Candidate: records this session has withheld so far. */
  withheld: RecordIdentity[];
}

interface SessionTokens {
  open(request: SyncRequest): Position;
  page(position: Required<Position>): string;
  checkpoint(high: string, withheld: RecordIdentity[]): string;
}

function identityKey(id: RecordIdentity): string {
  return JSON.stringify([id.recordKey, id.instance]);
}

/**
 * The most identity text one token carries for each of `carried` and
 * `withheld`. Beyond it the session expires, so a token stays a usable query
 * parameter. Reaching it needs that many visible records deleted between
 * pages of one session.
 */
export const MAX_SYNC_CARRY_BYTES = 2048;

const SEALED_VERSION = 1;
const KEY_ID_BYTES = 4;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const HEADER_BYTES = 1 + KEY_ID_BYTES + IV_BYTES + TAG_BYTES;
/** Horizons are padded so a token's size never tracks the store clock. */
const HORIZON_WIDTH = 32;
const PLAINTEXT_BLOCK = 64;

interface SealedPayload {
  /** Role: a page cursor or a completed-session checkpoint. */
  r: "page" | "checkpoint";
  /** Digest of the context the token is bound to. */
  b: string;
  /** Candidate page only: digest of the session's `changes_since` input. */
  s?: string;
  l?: string;
  h: string;
  a?: [string, string];
  /** Candidate: carried and withheld identities, as [recordKey, instance]. */
  c?: [string, string][];
  w?: [string, string][];
}

/**
 * Every page cursor, in both profiles, and every candidate checkpoint is
 * AES-256-GCM over its position with fresh randomness, so it reveals no
 * position, time or key, and token equality signals nothing. A
 * current-profile checkpoint keeps the readable format existing clients
 * store; the store validates the horizons it carries.
 *
 * Bindings: a candidate token is bound to its role and to the grant and
 * query context, and a candidate page cursor also to its session's input
 * checkpoint. A current-profile page cursor is bound to its role, stream and
 * instances only, as the current contract leaves the rest of the query free.
 */
function sessionTokens(
  scope: SyncTokenScope,
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
  const baseline = request.candidate
    ? digest(request.changesSince ?? "beginning")
    : undefined;
  const keyId = createHash("sha256")
    .update(scope.key)
    .digest()
    .subarray(0, KEY_ID_BYTES);

  function seal(payload: SealedPayload): string {
    let json = JSON.stringify(payload);
    json += " ".repeat(
      (PLAINTEXT_BLOCK - (json.length % PLAINTEXT_BLOCK)) % PLAINTEXT_BLOCK,
    );
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv("aes-256-gcm", scope.key, iv);
    const body = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
    return Buffer.concat([
      Buffer.from([SEALED_VERSION]),
      keyId,
      iv,
      cipher.getAuthTag(),
      body,
    ]).toString("base64url");
  }

  function isSealed(token: string): boolean {
    return Buffer.from(token, "base64url")[0] === SEALED_VERSION;
  }

  function unseal(token: string, role: SealedPayload["r"]): SealedPayload {
    const bytes = Buffer.from(token, "base64url");
    if (
      bytes.length <= HEADER_BYTES ||
      bytes.toString("base64url") !== token ||
      bytes[0] !== SEALED_VERSION
    ) {
      throw new InvalidCursorError();
    }
    // Sealed by another store or a rebuilt one: its history is gone here.
    if (!bytes.subarray(1, 1 + KEY_ID_BYTES).equals(keyId)) {
      throw new CursorExpiredError();
    }
    let payload: SealedPayload;
    try {
      const ivStart = 1 + KEY_ID_BYTES;
      const decipher = createDecipheriv(
        "aes-256-gcm",
        scope.key,
        bytes.subarray(ivStart, ivStart + IV_BYTES),
      );
      decipher.setAuthTag(bytes.subarray(ivStart + IV_BYTES, HEADER_BYTES));
      payload = JSON.parse(
        Buffer.concat([
          decipher.update(bytes.subarray(HEADER_BYTES)),
          decipher.final(),
        ]).toString("utf8"),
      ) as SealedPayload;
    } catch {
      throw new InvalidCursorError();
    }
    if (payload.r !== role || payload.b !== context) {
      throw new InvalidCursorError();
    }
    return payload;
  }

  function openPage(cursor: string): Position {
    const payload = unseal(cursor, "page");
    if (payload.s !== baseline) throw new InvalidCursorError();
    return {
      low: payload.l?.trim() ?? null,
      high: payload.h.trim(),
      ...(payload.a && {
        after: { recordKey: payload.a[0], instance: payload.a[1] },
      }),
      carried: fromPairs(payload.c),
      withheld: fromPairs(payload.w),
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

  const page = ({ low, high, after, carried, withheld }: Required<Position>) =>
    seal({
      r: "page",
      b: context,
      ...(baseline && { s: baseline }),
      ...(low !== null && { l: low.padStart(HORIZON_WIDTH) }),
      h: high.padStart(HORIZON_WIDTH),
      a: [after.recordKey, after.instance],
      ...(carried.length > 0 && { c: toPairs(carried) }),
      ...(withheld.length > 0 && { w: toPairs(withheld) }),
    });

  if (request.candidate) {
    return {
      open(request) {
        if (request.cursor) return openPage(request.cursor);
        if (
          request.changesSince === undefined ||
          request.changesSince === "beginning"
        ) {
          return { low: null, carried: [], withheld: [] };
        }
        const payload = unseal(request.changesSince, "checkpoint");
        return {
          low: payload.h.trim(),
          carried: fromPairs(payload.w),
          withheld: [],
        };
      },
      page,
      checkpoint: (high, withheld) =>
        seal({
          r: "checkpoint",
          b: context,
          h: high.padStart(HORIZON_WIDTH),
          ...(withheld.length > 0 && { w: toPairs(withheld) }),
        }),
    };
  }

  return {
    open(request) {
      if (request.cursor) {
        if (isSealed(request.cursor)) return openPage(request.cursor);
        // A readable page cursor predates sealed cursors. Its position
        // counted rows the grant hides, so it cannot be resumed.
        decodeCurrent(request.cursor);
        throw new CursorExpiredError();
      }
      if (!request.changesSince)
        return { low: null, carried: [], withheld: [] };
      try {
        return {
          low: decodeCurrent(request.changesSince).horizon,
          carried: [],
          withheld: [],
        };
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
  };
}

function toPairs(ids: RecordIdentity[]): [string, string][] {
  const pairs = ids.map((id): [string, string] => [id.recordKey, id.instance]);
  if (JSON.stringify(pairs).length > MAX_SYNC_CARRY_BYTES) {
    throw new CursorExpiredError();
  }
  return pairs;
}

function fromPairs(pairs: [string, string][] | undefined): RecordIdentity[] {
  return (pairs ?? []).map(([recordKey, instance]) => ({
    recordKey,
    instance,
  }));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}
