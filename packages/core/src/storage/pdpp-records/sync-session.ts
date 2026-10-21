import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { decodeCursor, InvalidCursorSyntaxError } from "./cursor.js";
import { encodeCursor } from "./cursor.js";
import { canonicalJson } from "./ingest-plan.js";
import type { PdppRecordStore } from "./interface.js";
import { compareRecordIdentity } from "./list-page.js";
import {
  CursorExpiredError,
  InvalidCursorError,
  type ChangesSincePage,
  type PdppRecordRow,
  type PdppStoredRecord,
  type SyncTokenScope,
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
   * Selects the candidate profile. `binding` is the caller's query context
   * (grant identity and restrictions, response fields) that every token of
   * the session is bound to, in addition to what this service reads itself.
   */
  candidate?: { binding: unknown; order: "asc" | "desc" };
}

/**
 * The single owner of PDPP `changes_since` sessions: horizons, the
 * authorized change set, its pagination and every token a session issues.
 * Stores only supply raw history (`readSyncWindow`); HTTP only maps the page.
 *
 * Profiles differ only in policy, never in path:
 * - current: one-horizon visibility, current-state grant filter, readable
 *   tokens that existing clients store;
 * - candidate: visibility at both horizons with removals, key order in the
 *   requested direction, sealed tokens bound to grant and query context.
 *
 * Both profiles paginate over the authorized result only, so hidden records
 * never shape a page, and neither serves a record deleted after the session's
 * fixed horizon; the next session reports that deletion.
 */
export function createPdppSyncSessionService(
  store: Pick<PdppRecordStore, "readSyncWindow" | "syncTokenScope">,
) {
  function read(request: SyncRequest): ChangesSincePage {
    if (!Number.isSafeInteger(request.limit) || request.limit < 1) {
      throw new RangeError("sync page limit must be a positive integer");
    }
    const tokens = request.candidate
      ? candidateTokens(store.syncTokenScope(), request)
      : currentTokens(store.syncTokenScope(), request.stream);
    const position = tokens.open(request);
    const descending = request.candidate?.order === "desc";
    return store.readSyncWindow(
      request.stream,
      {
        instanceIds: request.instanceIds,
        low: position.low,
        ...(position.high !== undefined && { high: position.high }),
      },
      (window) => {
        const { changes } = window;
        const step = descending ? -1 : 1;
        let index = descending ? changes.length - 1 : 0;
        if (position.after) {
          const boundary = position.after;
          const firstNotBefore = searchChanges(
            changes,
            (row) => compareRecordIdentity(row, boundary) < 0,
          );
          index = descending
            ? firstNotBefore - 1
            : searchChanges(
                changes,
                (row) => compareRecordIdentity(row, boundary) <= 0,
              );
        }
        const data: PdppRecordRow[] = [];
        let hasMore = false;
        for (; index >= 0 && index < changes.length; index += step) {
          const row = disclose(changes[index], position.low, request);
          if (!row) continue;
          if (data.length === request.limit) {
            hasMore = true;
            break;
          }
          data.push(row);
        }
        if (!hasMore) {
          return {
            data,
            hasMore,
            nextChangesSince: tokens.checkpoint(window.high),
          };
        }
        const last = data[data.length - 1];
        return {
          data,
          hasMore,
          nextCursor: tokens.page({
            low: position.low,
            high: window.high,
            after: { recordKey: last.recordKey, instance: last.instance },
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

/** The record a session discloses for one changed key, if any. */
function disclose(
  change: SyncWindowChange,
  low: string | null,
  request: SyncRequest,
): PdppRecordRow | undefined {
  const { after } = change;
  const { access, eligibilityFields: fields } = request;
  if (request.candidate) {
    const visible = (row: PdppRecordRow | undefined) =>
      row !== undefined &&
      !row.deleted &&
      (!access || access.canSeeRecord(row));
    const before = low === null ? undefined : change.before();
    const wasVisible = visible(before);
    if (!visible(after)) return wasVisible ? removal(after) : undefined;
    if (wasVisible && sameProjection(before!, after, fields)) return undefined;
    return change.deletedLater() ? undefined : after;
  }
  if (after.deleted) {
    return !access || access.canSeeKey(after.recordKey) ? after : undefined;
  }
  if (access && !access.canSeeRecord(after)) return undefined;
  const before = low === null ? undefined : change.before();
  if (fields && before && sameProjection(before, after, fields)) {
    return undefined;
  }
  return change.deletedLater() ? undefined : after;
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

/** First index whose row fails `isBefore`; `changes` is identity-ordered. */
function searchChanges(
  changes: SyncWindowChange[],
  isBefore: (row: PdppRecordRow) => boolean,
): number {
  let low = 0;
  let high = changes.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (isBefore(changes[middle].after)) low = middle + 1;
    else high = middle;
  }
  return low;
}

interface Position {
  low: string | null;
  high?: string;
  after?: { recordKey: string; instance: string };
}

interface SessionTokens {
  open(request: SyncRequest): Position;
  page(position: Required<Position>): string;
  checkpoint(high: string): string;
}

/**
 * Current-profile tokens: the readable format existing clients already
 * store. The store validates the horizons they carry.
 */
function currentTokens(scope: SyncTokenScope, stream: string): SessionTokens {
  function decodeScoped(token: string) {
    const payload = decodeCursor(token);
    if (payload.kind !== "changes_since") throw new InvalidCursorError();
    if (payload.stream !== stream || payload.epoch !== scope.epoch) {
      throw new CursorExpiredError();
    }
    return payload;
  }
  return {
    open(request) {
      if (request.cursor) {
        const payload = decodeScoped(request.cursor);
        const { offset, after } = payload;
        if (!Number.isSafeInteger(offset) || offset < 0) {
          throw new InvalidCursorError();
        }
        if (after === undefined) {
          // A pre-boundary cursor counted hidden rows; it cannot be resumed.
          if (offset !== 0) throw new CursorExpiredError();
          return { low: payload.sinceHorizon, high: payload.horizon };
        }
        if (
          typeof after?.recordKey !== "string" ||
          typeof after.instance !== "string"
        ) {
          throw new InvalidCursorError();
        }
        return { low: payload.sinceHorizon, high: payload.horizon, after };
      }
      if (!request.changesSince) return { low: null };
      try {
        return { low: decodeScoped(request.changesSince).horizon };
      } catch (err) {
        if (err instanceof InvalidCursorSyntaxError) {
          throw new CursorExpiredError();
        }
        throw err;
      }
    },
    page: ({ low, high, after }) =>
      encodeCursor({
        kind: "changes_since",
        stream,
        epoch: scope.epoch,
        horizon: high,
        sinceHorizon: low,
        offset: 0,
        after,
      }),
    checkpoint: (high) =>
      encodeCursor({
        kind: "changes_since",
        stream,
        epoch: scope.epoch,
        horizon: high,
        sinceHorizon: null,
        offset: 0,
      }),
  };
}

const SEALED_VERSION = 1;
const KEY_ID_BYTES = 4;
const IV_BYTES = 12;
const TAG_BYTES = 16;
/** Horizons are padded so a token's size never tracks the store clock. */
const HORIZON_WIDTH = 32;
const PLAINTEXT_BLOCK = 64;

interface SealedPayload {
  /** Role: a page cursor or a completed-session checkpoint. */
  r: "page" | "checkpoint";
  /** Digest of the grant and query context. */
  b: string;
  /** Page only: digest of the session's `changes_since` input. */
  s?: string;
  l?: string;
  h: string;
  a?: [string, string];
}

/**
 * Candidate-profile tokens: AES-256-GCM over the position, with fresh
 * randomness per issue, so no token reveals a position or time and token
 * equality signals nothing. Each token is bound to its role, its grant and
 * query context, and (for a page) its session's input checkpoint.
 */
function candidateTokens(
  scope: SyncTokenScope,
  request: SyncRequest,
): SessionTokens {
  const { binding, order } = request.candidate!;
  const context = digest(
    canonicalJson({
      binding,
      stream: request.stream,
      instances: [...new Set(request.instanceIds)].sort(),
      fields: request.eligibilityFields
        ? [...new Set(request.eligibilityFields)].sort()
        : null,
      order,
    }),
  );
  const baseline = digest(request.changesSince ?? "beginning");
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

  function unseal(token: string, role: SealedPayload["r"]): SealedPayload {
    const bytes = Buffer.from(token, "base64url");
    const header = 1 + KEY_ID_BYTES + IV_BYTES + TAG_BYTES;
    if (
      bytes.length <= header ||
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
      decipher.setAuthTag(bytes.subarray(ivStart + IV_BYTES, header));
      payload = JSON.parse(
        Buffer.concat([
          decipher.update(bytes.subarray(header)),
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

  return {
    open(request) {
      if (request.cursor) {
        const payload = unseal(request.cursor, "page");
        if (payload.s !== baseline) throw new InvalidCursorError();
        return {
          low: payload.l?.trim() ?? null,
          high: payload.h.trim(),
          ...(payload.a && {
            after: { recordKey: payload.a[0], instance: payload.a[1] },
          }),
        };
      }
      if (
        request.changesSince === undefined ||
        request.changesSince === "beginning"
      ) {
        return { low: null };
      }
      return { low: unseal(request.changesSince, "checkpoint").h.trim() };
    },
    page: ({ low, high, after }) =>
      seal({
        r: "page",
        b: context,
        s: baseline,
        ...(low !== null && { l: low.padStart(HORIZON_WIDTH) }),
        h: high.padStart(HORIZON_WIDTH),
        a: [after.recordKey, after.instance],
      }),
    checkpoint: (high) =>
      seal({ r: "checkpoint", b: context, h: high.padStart(HORIZON_WIDTH) }),
  };
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("base64url");
}
