/**
 * The PDPP held-data lifecycle at the Authorization Server (spec-core §7
 * "Held data after a grant ends" L1532 to "Lifecycle durability" L1830; §9
 * AS items 39-47; held-data cases P1-P9, C1-C9, D1-D5).
 *
 *   - `handleLifecycleRequest`: the grant lifecycle operation (L1686-L1801,
 *     AS item 39): queries, `received`/`completed`/`retained` reports and
 *     client-conveyed `pdpp_disposition=delete`.
 *   - owner ending paths (L1560-L1578, AS item 41): every owner action that
 *     ends grants requires an explicit disposition per grant, lists the
 *     complete affected set, and applies no default.
 *   - erasure requests, advance elections, security revocation and
 *     decommission (AS items 42, 43, 46).
 *   - lifecycle recovery (L1802-L1808, AS item 47).
 *   - owner actions while the history is unavailable, and re-establishing
 *     it (L1827, AS item 44).
 *
 * This AS has public clients only: it performs no client authentication at
 * the token endpoint, so the confidential-client paths (several `grant_id`
 * values, assertions) do not apply, and it issues no DPoP-bound token.
 */

import { createHash, randomBytes } from "node:crypto";
import { verifyCodeVerifier } from "./pkce.js";
import {
  hashToken,
  newOpaqueToken,
  type PdppAuthStore,
  type StoredGrant,
} from "./store.js";
import {
  DELETION_BOUND_MS,
  RETRY_INTERVAL_MS,
  STOP_USE_BOUND_MS,
  type ErasureInstructionRecord,
} from "./lifecycle-store.js";
import {
  deleteStatements,
  keepStatement,
  narrowingStatements,
  PENDING_HISTORY_STATEMENT,
  RECOVERY_STATEMENT,
  stageSummary,
} from "./held-data-statements.js";
import type { AnchoredErasure, PendingOwnerAction } from "./history.js";

export {
  DELETION_BOUND_MS,
  RECONCILIATION_INTERVAL_MS,
  RETRY_INTERVAL_MS,
  STOP_USE_BOUND_MS,
} from "./lifecycle-store.js";

/** L1802: the lifecycle recovery authorization-details type (AS items 33, 47). */
export const PDPP_GRANT_LIFECYCLE_TYPE = "https://pdpp.dev/grant-lifecycle";

/** Rate-limit windows kept in memory at most (one per client and grant). */
export const MAX_RATE_WINDOWS = 10_000;

/** Seconds a client should wait after a 503 from an unavailable history. */
export const HISTORY_RETRY_AFTER_SECONDS = 300;

export type ReadState = "active" | "window_closed" | "expired" | "revoked";

export interface LifecycleAnswer {
  grant_id: string;
  assessed_at: string;
  read_state: ReadState;
  ended_at?: string;
  held_data: "permitted" | "erase";
  erasure?: {
    instruction_id: string;
    accepted_at: string;
    effective_at: string;
    stop_use_by: string;
  };
}

export type LifecycleEntry =
  | LifecycleAnswer
  | {
      grant_id: string;
      error:
        | "invalid_grant"
        | "current_authentication_required"
        | "invalid_instruction";
    };

export type LifecycleHttpResult =
  | { status: 200; body: { grants: LifecycleEntry[] } }
  | {
      status: 400 | 401 | 429 | 503;
      body: { error: string; error_description: string };
      retryAfterSeconds?: number;
    };

const RFC3339 =
  /^\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(\.\d+)?([zZ]|[+-]\d{2}:\d{2})$/;

export function isRfc3339(value: string): boolean {
  return RFC3339.test(value) && !Number.isNaN(Date.parse(value));
}

/** L1704: the three forms of `retained_until`. */
export function parseRetainedUntil(
  value: string,
):
  | { kind: "date"; value: string }
  | { kind: "event"; value: string }
  | { kind: "unknown" }
  | null {
  if (value === "unknown") return { kind: "unknown" };
  if (value.startsWith("event:")) {
    const text = value.slice("event:".length);
    return /\S/.test(text) ? { kind: "event", value: text } : null;
  }
  if (isRfc3339(value)) return { kind: "date", value };
  return null;
}

function iso(ms: number): string {
  return new Date(ms).toISOString();
}

function stopUseBy(effectiveAt: string): string {
  return iso(Date.parse(effectiveAt) + STOP_USE_BOUND_MS);
}

/** A credential presented to the lifecycle operation (L1712-L1720). */
interface LifecycleCredential {
  kind: "access_token" | "refresh_token" | "recovery_token";
  digest: string;
  clientId: string;
  /** Grants the token covers (L1713: "covers the grant"). */
  covers: string[];
  /** L1714: current client authentication for a write. */
  currentFor(grantId: string, now: Date): boolean;
}

export type OwnerEndingAction =
  "revoke" | "disconnect_client" | "narrowing" | "decommission";

/** One grant in an owner action's affected set (L1566, AS item 41). */
export interface AffectedGrant {
  grant_id: string;
  client_id: string;
  source_id: string;
  purpose_code: string;
  issued_at: string;
  access_mode: "single_use" | "continuous";
  read_state: ReadState;
  ended_at?: string;
  /** "end": the action ends this grant; "record": it only records a disposition. */
  effect: "end" | "record";
  /** An effective erasure instruction already applies; the choice is locked. */
  disposition_locked?: "delete";
  disposition_required: boolean;
  /** L1576: neither option is preselected. */
  preselected: null;
  options: {
    keep: { surviving_use: string; retention_limit: string };
    delete: { statements: string[] };
  };
}

export interface OwnerActionResult {
  complete: boolean;
  /** L1828: per grant, recorded or pending. */
  grants: Array<{
    grant_id: string;
    state: "recorded" | "pending";
    ended?: boolean;
    disposition?: "keep" | "delete";
  }>;
  statement?: string;
}

/** The owner view of one grant's erasure instruction (AS items 42, 43). */
export interface ErasureOwnerView {
  instruction_id: string;
  advance: boolean;
  requested_at: string;
  effective_at?: string;
  stop_use_by?: string;
  latest_stage:
    | "requested"
    | "sent"
    | "receipt_reported"
    | "exception_reported"
    | "completion_reported";
  stages: {
    requested_at: string;
    sent_at?: string;
    receipt_reported?: { reported_at: string; recorded_at: string };
    completion_reported?: { reported_at: string; recorded_at: string };
    exceptions?: Array<{
      reported_at: string;
      received_at: string;
      retained_until:
        | { kind: "date"; value: string }
        | { kind: "event"; value: string }
        | { kind: "unknown" };
      retention_basis?: string;
      retention_scope?: string;
    }>;
  };
  /**
   * L1661: only from a reported receipt time, never from acceptance or first
   * return. Absent until a receipt is reported.
   */
  deletion_due_by?: string;
  summary: string;
  statements: string[];
}

export interface OwnerGrantLifecycleView {
  /**
   * R1 / L1829: "recorded" once every terminal event shown here is durable
   * with its evidence; "pending" while an evidence write is owed.
   */
  evidence: "recorded" | "pending";
  read_state: ReadState;
  ended_at?: string;
  ending?: { reason: string; detail?: string };
  held_data_may_remain: boolean;
  /** L1572: an ended grant without a disposition shows the choice as offered. */
  disposition: "offered" | "keep" | "delete" | "not_applicable";
  erasure?: ErasureOwnerView;
  /** Grants the owner can still ask to erase (L1586, AS item 46). */
  erasure_request_available: boolean;
}

interface RecoverySession {
  session_id: string;
  subject_id: string;
  client_id: string;
  grant_ids: string[];
  redirect_uri: string;
  state_param?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  expires_at: string;
  status: "pending" | "approved" | "denied";
  review_digest: string;
}

export interface GrantLifecycleServiceOptions {
  clock?: () => Date;
  /**
   * Queries admitted per (client, grant) per retry interval. L1738: "MUST
   * admit at least one query per grant per retry interval from each client".
   */
  queriesPerRetryInterval?: number;
}

export class GrantLifecycleService {
  readonly clock: () => Date;
  private readonly queryLimit: number;
  private readonly windows = new Map<
    string,
    { start: number; count: number }
  >();
  private readonly recoverySessions = new Map<string, RecoverySession>();
  private readonly journaledFirstReturns = new Set<string>();

  constructor(
    private readonly store: PdppAuthStore,
    options: GrantLifecycleServiceOptions = {},
  ) {
    this.clock = options.clock ?? (() => new Date());
    this.queryLimit = Math.max(1, options.queriesPerRetryInterval ?? 60);
  }

  // ======================================================================
  // Grant lifecycle operation (L1686-L1801)
  // ======================================================================

  /**
   * One lifecycle request. `params` holds every value of every form field,
   * in order, so a repeated `grant_id` is visible.
   */
  handleLifecycleRequest(params: Map<string, string[]>): LifecycleHttpResult {
    const now = this.clock();
    const bad = (description: string): LifecycleHttpResult => ({
      status: 400,
      body: { error: "invalid_request", error_description: description },
    });

    const grantIds = params.get("grant_id") ?? [];
    if (grantIds.length === 0 || grantIds.some((g) => g.length === 0)) {
      return bad("grant_id is required");
    }
    const single: Record<string, string | undefined> = {};
    for (const name of [
      "token",
      "token_type_hint",
      "report",
      "instruction_id",
      "reported_at",
      "retained_until",
      "retention_basis",
      "retention_scope",
      "pdpp_disposition",
      "client_id",
    ]) {
      const values = params.get(name);
      if (values && values.length > 1) return bad(`${name} must not repeat`);
      single[name] = values?.[0];
    }
    const {
      token,
      token_type_hint: hint,
      report,
      instruction_id: instructionId,
      reported_at: reportedAt,
      retained_until: retainedUntil,
      retention_basis: retentionBasis,
      retention_scope: retentionScope,
      pdpp_disposition: disposition,
      client_id: clientIdParam,
    } = single;

    // L1709: unknown values, missing required parameters, both writes.
    if (
      hint !== undefined &&
      hint !== "access_token" &&
      hint !== "refresh_token"
    )
      return bad("token_type_hint must be access_token or refresh_token");
    if (
      report !== undefined &&
      report !== "received" &&
      report !== "completed" &&
      report !== "retained"
    )
      return bad("report must be received, completed or retained");
    if (disposition !== undefined && disposition !== "delete")
      return bad("pdpp_disposition must be delete on the lifecycle operation");
    if (report !== undefined && disposition !== undefined)
      return bad("a request carries report or pdpp_disposition, not both");
    const write = report !== undefined || disposition !== undefined;
    if (write && grantIds.length !== 1)
      return bad("a write names exactly one grant");
    if (report !== undefined && (!instructionId || !reportedAt))
      return bad("report requires instruction_id and reported_at");
    if (report === undefined && instructionId !== undefined)
      return bad("instruction_id is accepted only with report");
    if (!write && reportedAt !== undefined)
      return bad("reported_at is accepted only with a write");
    if (report === "retained" && retainedUntil === undefined)
      return bad("report=retained requires retained_until");
    if (
      report !== "retained" &&
      (retainedUntil !== undefined ||
        retentionBasis !== undefined ||
        retentionScope !== undefined)
    )
      return bad(
        "retained_until, retention_basis and retention_scope go with report=retained",
      );
    // L1748: reported_at later than the request is invalid.
    if (reportedAt !== undefined) {
      if (!isRfc3339(reportedAt))
        return bad("reported_at must be an RFC 3339 date-time");
      if (Date.parse(reportedAt) > now.getTime())
        return bad("reported_at is later than the request");
    }
    let retainedForm: ReturnType<typeof parseRetainedUntil> = null;
    if (retainedUntil !== undefined) {
      retainedForm = parseRetainedUntil(retainedUntil);
      if (!retainedForm)
        return bad(
          "retained_until must be a date-time, event:<text>, or unknown",
        );
      if (
        retainedForm.kind === "date" &&
        reportedAt !== undefined &&
        Date.parse(retainedForm.value) < Date.parse(reportedAt)
      )
        return bad("retained_until is earlier than reported_at");
    }

    // L1712: a public client authenticates with `token`. This AS has no
    // confidential clients, so a request without one cannot authenticate.
    if (!token) {
      return {
        status: 401,
        body: {
          error: "invalid_client",
          error_description: "a public client authenticates with token",
        },
      };
    }
    const credential = this.lookupCredential(token, hint);
    const digest = hashToken(token);
    const disabled =
      this.store.lifecycle.isDigestDisabled(digest) ||
      // While not current, disablings the stale store lost still hold (F4).
      (!this.store.history.isCurrent() &&
        this.store.history.anchoredDisabledDigests().includes(digest));
    // F5: a grant a restore lost. Its anchored instruction still reaches the
    // client through a token whose digest the evidence carries.
    if (!credential && !disabled && grantIds.length === 1) {
      const evidence = this.evidenceErasureFor(grantIds[0]!);
      if (
        evidence?.token_digests?.includes(digest) &&
        (clientIdParam === undefined || clientIdParam === evidence.client_id)
      ) {
        if (write) {
          return {
            status: 200,
            body: {
              grants: [
                {
                  grant_id: evidence.grant_id,
                  error: "current_authentication_required",
                },
              ],
            },
          };
        }
        try {
          return {
            status: 200,
            body: { grants: [this.evidenceAnswer(evidence, now)] },
          };
        } catch {
          return {
            status: 503,
            body: {
              error: "temporarily_unavailable",
              error_description: "the lifecycle state could not be recorded",
            },
            retryAfterSeconds: 5,
          };
        }
      }
    }
    // L1736: unknown, malformed, another client's, or disabled → invalid_token.
    if (
      !credential ||
      disabled ||
      (clientIdParam !== undefined && clientIdParam !== credential.clientId)
    ) {
      return {
        status: 401,
        body: {
          error: "invalid_token",
          error_description: "the token cannot authenticate this operation",
        },
      };
    }
    // L1698: a public client sends grant_id once.
    if (grantIds.length !== 1)
      return bad("a public client sends grant_id once");
    const grantId = grantIds[0]!;

    // L1738: admit at least one query per grant per retry interval.
    if (!write) {
      const limited = this.rateLimit(credential.clientId, grantId, now);
      if (limited) return limited;
    }

    const covered = this.covers(credential, grantId);

    // L1820, L1825: a history that is not current yields no positive
    // assessment and authenticates no write. An anchored, complete erasure
    // instruction MAY still be returned (case D1, D4).
    if (!this.store.history.isCurrent()) {
      if (!write && covered) {
        const anchored = this.store.history.anchoredErasure(grantId);
        if (anchored && anchored.client_id === credential.clientId) {
          return {
            status: 200,
            body: { grants: [this.evidenceAnswer(anchored, now)] },
          };
        }
      }
      return {
        status: 503,
        body: {
          error: "temporarily_unavailable",
          error_description:
            "the authorization history cannot be established as current",
        },
        retryAfterSeconds: HISTORY_RETRY_AFTER_SECONDS,
      };
    }

    // L1734: unknown, foreign and uncovered grants are indistinguishable.
    if (!covered) {
      return {
        status: 200,
        body: { grants: [{ grant_id: grantId, error: "invalid_grant" }] },
      };
    }

    try {
      if (!write) {
        return {
          status: 200,
          body: { grants: [this.assess(grantId, now)] },
        };
      }
      // L1714: writes need current client authentication.
      if (!credential.currentFor(grantId, now)) {
        return {
          status: 200,
          body: {
            grants: [
              { grant_id: grantId, error: "current_authentication_required" },
            ],
          },
        };
      }
      if (disposition === "delete") {
        const stored = this.store.getGrant(grantId)!;
        this.store.commit(() => {
          this.store.requestErasureInTx({
            grantId,
            clientId: stored.clientId,
            origin: "client",
            now,
            ending: { reason: "client_erasure" },
            ...(reportedAt !== undefined && { receiptReportedAt: reportedAt }),
          });
        }, now);
        return { status: 200, body: { grants: [this.assess(grantId, now)] } };
      }
      const instruction = this.store.lifecycle.getInstruction(grantId);
      if (!instruction || instruction.instructionId !== instructionId) {
        return {
          status: 200,
          body: {
            grants: [{ grant_id: grantId, error: "invalid_instruction" }],
          },
        };
      }
      const at = now.toISOString();
      this.store.commit(() => {
        if (report === "received") {
          this.store.lifecycle.recordReceipt(
            instruction.instructionId,
            reportedAt!,
            at,
          );
        } else if (report === "completed") {
          this.store.lifecycle.recordCompleted(
            instruction.instructionId,
            reportedAt!,
            at,
          );
        } else {
          this.store.lifecycle.addRetained(
            instruction.instructionId,
            {
              reportedAt: reportedAt!,
              retainedUntil: retainedUntil!,
              retentionBasis: retentionBasis ?? null,
              retentionScope: retentionScope ?? null,
            },
            at,
          );
        }
      }, now);
      return { status: 200, body: { grants: [this.assess(grantId, now)] } };
    } catch (err) {
      // L1816 / L2787: nothing is acknowledged unless it is durable.
      return {
        status: 503,
        body: {
          error: "temporarily_unavailable",
          error_description: `the lifecycle state could not be recorded: ${
            err instanceof Error ? err.message : String(err)
          }`,
        },
        retryAfterSeconds: 5,
      };
    }
  }

  /**
   * The evidence-held instruction for a grant: the anchor while the history
   * is not current; after re-establishment, the orphan record for a grant
   * the restored store lacks.
   */
  private evidenceErasureFor(grantId: string): AnchoredErasure | null {
    if (!this.store.history.isCurrent())
      return this.store.history.anchoredErasure(grantId);
    if (this.store.getGrant(grantId)) return null;
    return this.store.lifecycle.getOrphanErasure(grantId);
  }

  /** An `erase` answer from evidence (L1820); its first return is recorded. */
  private evidenceAnswer(e: AnchoredErasure, now: Date): LifecycleAnswer {
    if (!this.store.history.isCurrent()) {
      this.journalFirstReturn(e.instruction_id, e.grant_id, now);
    } else {
      // An orphan record's first return is recorded before the answer
      // leaves (L1660); a failed evidence write throws to the caller (503).
      this.store.commit(
        () =>
          this.store.lifecycle.recordOrphanFirstReturn(
            e.grant_id,
            now.toISOString(),
          ),
        now,
      );
    }
    return {
      grant_id: e.grant_id,
      assessed_at: now.toISOString(),
      read_state: e.read_state,
      ended_at: e.ended_at,
      held_data: "erase",
      erasure: {
        instruction_id: e.instruction_id,
        accepted_at: e.accepted_at,
        effective_at: e.effective_at,
        stop_use_by: e.stop_use_by,
      },
    };
  }

  /**
   * The lifecycle answer for one grant, from current ordered state (AS item
   * 40, L1593). Records the instruction's first return before the answer
   * leaves (L1660, L1824).
   */
  assess(grantId: string, now: Date = this.clock()): LifecycleAnswer {
    return this.store.commit(() => {
      const instruction = this.store.settleAdvanceInTx(grantId, now);
      const stored = this.store.getGrant(grantId)!;
      const answer: LifecycleAnswer = {
        grant_id: grantId,
        assessed_at: now.toISOString(),
        ...this.readStateOf(stored, now),
        held_data: "permitted",
      };
      // An instruction is effective once `effective_at` is recorded; it is
      // recorded only at or after that time, so a clock that later moves
      // backwards never makes it look pending again (L1556, case C5a).
      if (instruction?.effectiveAt) {
        answer.held_data = "erase";
        answer.erasure = {
          instruction_id: instruction.instructionId,
          accepted_at: instruction.acceptedAt,
          effective_at: instruction.effectiveAt,
          stop_use_by: stopUseBy(instruction.effectiveAt),
        };
        this.store.lifecycle.recordFirstReturn(
          instruction.instructionId,
          now.toISOString(),
        );
      }
      return answer;
    }, now);
  }

  /** L1726-L1735: read state and the grant's one ending. */
  readStateOf(
    stored: StoredGrant,
    now: Date,
  ): { read_state: ReadState; ended_at?: string } {
    const ending = this.store.endingOf(stored, now);
    if (ending)
      return { read_state: ending.readState, ended_at: ending.endedAt };
    if (
      stored.grant.access_mode === "single_use" &&
      stored.consumedAt &&
      !this.store.lifecycle.hasLiveAccessToken(
        stored.grant.grant_id,
        now.toISOString(),
      )
    ) {
      return { read_state: "window_closed" };
    }
    return { read_state: "active" };
  }

  private lookupCredential(
    token: string,
    hint?: string,
  ): LifecycleCredential | null {
    const digest = hashToken(token);
    const order =
      hint === "refresh_token"
        ? (["refresh", "access", "recovery"] as const)
        : (["access", "refresh", "recovery"] as const);
    for (const kind of order) {
      if (kind === "access") {
        const record = this.store.getAccessToken(token);
        if (
          !record ||
          record.tokenKind !== "client" ||
          !record.grantId ||
          !record.clientId
        )
          continue;
        const grantId = record.grantId;
        const clientId = record.clientId;
        return {
          kind: "access_token",
          digest,
          clientId,
          covers: [grantId],
          currentFor: (g, now) => {
            if (g !== grantId) return false;
            const live = this.store.getAccessToken(token);
            if (!live || live.revokedAt) return false;
            if (live.expiresAt && Date.parse(live.expiresAt) <= now.getTime())
              return false;
            if (live.familyId && this.store.isFamilyRevoked(live.familyId))
              return false;
            const stored = this.store.getGrant(grantId);
            return (
              !!stored && !this.store.endingOf(stored, now) && !stored.revokedAt
            );
          },
        };
      }
      if (kind === "refresh") {
        const refresh = this.store.inspectRefreshToken(token);
        if (!refresh) continue;
        const stored = this.store.getGrant(refresh.grantId);
        if (!stored) continue;
        const grantId = refresh.grantId;
        return {
          kind: "refresh_token",
          digest,
          clientId: stored.clientId,
          covers: [grantId],
          currentFor: (g, now) => {
            if (g !== grantId) return false;
            const live = this.store.inspectRefreshToken(token);
            const grant = this.store.getGrant(grantId);
            return (
              !!live &&
              !live.superseded &&
              !live.familyRevoked &&
              !!grant &&
              !grant.revokedAt &&
              !this.store.endingOf(grant, now)
            );
          },
        };
      }
      const recovery = this.store.lifecycle.getRecoveryToken(digest);
      if (!recovery) continue;
      return {
        kind: "recovery_token",
        digest,
        clientId: recovery.clientId,
        covers: recovery.grantIds,
        currentFor: (g, now) => {
          const live = this.store.lifecycle.getRecoveryToken(digest);
          if (!live || live.revokedAt || !live.grantIds.includes(g))
            return false;
          return (
            now.getTime() <
            this.recoveryWriteDeadline(live.grantIds, live.issuedAt)
          );
        },
      };
    }
    return null;
  }

  /**
   * L1806: a recovery token stays valid for writes until at least the
   * deletion bound after the client's first receipt of each covered
   * instruction, or after issuance when no receipt is recorded.
   */
  recoveryWriteDeadline(grantIds: string[], issuedAt: string): number {
    let start = Date.parse(issuedAt);
    for (const g of grantIds) {
      const receipt = this.store.lifecycle.getInstruction(g)?.receiptReportedAt;
      if (receipt) start = Math.max(start, Date.parse(receipt));
    }
    return start + DELETION_BOUND_MS;
  }

  private covers(credential: LifecycleCredential, grantId: string): boolean {
    if (!credential.covers.includes(grantId)) return false;
    const stored = this.store.getGrant(grantId);
    return !!stored && stored.clientId === credential.clientId;
  }

  private rateLimit(
    clientId: string,
    grantId: string,
    now: Date,
  ): LifecycleHttpResult | null {
    const key = `${clientId}\u0000${grantId}`;
    const t = now.getTime();
    // Bound the map: drop expired windows, then the oldest, past the cap.
    if (this.windows.size >= MAX_RATE_WINDOWS && !this.windows.has(key)) {
      for (const [k, w] of this.windows) {
        if (t - w.start >= RETRY_INTERVAL_MS || t < w.start)
          this.windows.delete(k);
      }
      while (this.windows.size >= MAX_RATE_WINDOWS) {
        const oldest = this.windows.keys().next().value;
        if (oldest === undefined) break;
        this.windows.delete(oldest);
      }
    }
    const window = this.windows.get(key);
    if (!window || t - window.start >= RETRY_INTERVAL_MS || t < window.start) {
      this.windows.set(key, { start: t, count: 1 });
      return null;
    }
    if (window.count < this.queryLimit) {
      window.count += 1;
      return null;
    }
    return {
      status: 429,
      body: {
        error: "slow_down",
        error_description: "too many lifecycle queries for this grant",
      },
      retryAfterSeconds: Math.max(
        1,
        Math.ceil((window.start + RETRY_INTERVAL_MS - t) / 1000),
      ),
    };
  }

  private journalFirstReturn(
    instructionId: string,
    grantId: string,
    now: Date,
  ) {
    // L1820: "The AS still records its first return of an instruction". The
    // stale store cannot be written, so the fact waits in the journal, once.
    if (this.journaledFirstReturns.has(instructionId)) return;
    if (
      this.store.pendingActions
        .list()
        .some((a) => a.kind === "first_return" && a.action === instructionId)
    ) {
      this.journaledFirstReturns.add(instructionId);
      return;
    }
    try {
      this.store.pendingActions.append({
        action_id: `fr_${instructionId}`,
        subject_id: "",
        recorded_at: now.toISOString(),
        kind: "first_return",
        action: instructionId,
        grant_ids: [grantId],
        dispositions: {},
      });
      this.journaledFirstReturns.add(instructionId);
    } catch {
      // Best effort: without the journal the AS cannot record the first
      // return; the answer is still the durable instruction.
    }
  }

  // ======================================================================
  // Disabling tokens for lifecycle use (L1716, AS item 39, case D3)
  // ======================================================================

  /**
   * Disable tokens for lifecycle use, by digest or by (client, grants).
   * Ends no grant, records no disposition, changes nothing else.
   */
  disableForLifecycle(input: {
    tokenDigests?: string[];
    clientId?: string;
    grantIds?: string[];
    now?: Date;
  }): number {
    const now = input.now ?? this.clock();
    const digests = [
      ...(input.tokenDigests ?? []),
      ...(input.clientId && input.grantIds
        ? this.store.lifecycle.tokenDigestsFor(input.clientId, input.grantIds)
        : []),
    ];
    return this.store.commit(
      () =>
        digests.filter((d) =>
          this.store.lifecycle.disableDigest(d, now.toISOString()),
        ).length,
      now,
    );
  }

  // ======================================================================
  // Owner ending paths (L1560-L1578, AS item 41)
  // ======================================================================

  /** Held data may remain once a client token was issued and no completion is reported. */
  heldDataMayRemain(grantId: string): boolean {
    if (!this.store.lifecycle.everIssuedClientToken(grantId)) return false;
    return !this.store.lifecycle.getInstruction(grantId)?.completedReportedAt;
  }

  /**
   * The complete affected set of an owner action, before its final step
   * (L1566): grants it will end, and ended or consumed grants whose held-data
   * disposition it will record.
   */
  affectedSet(input: {
    subjectId: string;
    action: OwnerEndingAction;
    clientId?: string;
    grantIds?: string[];
    /** The owner token's ceiling; grants outside it are not in scope. */
    inScope: (stored: StoredGrant) => boolean;
    now?: Date;
  }): { ok: true; grants: AffectedGrant[] } | { ok: false; message: string } {
    const now = input.now ?? this.clock();
    let candidates: StoredGrant[];
    if (
      input.action === "disconnect_client" ||
      input.action === "decommission"
    ) {
      if (input.action === "disconnect_client" && !input.clientId)
        return {
          ok: false,
          message: "client_id is required to disconnect a client",
        };
      candidates = this.store
        .listGrantsForSubject(input.subjectId)
        .filter(
          (g) =>
            (input.action === "decommission" ||
              g.clientId === input.clientId) &&
            input.inScope(g),
        )
        .filter(
          (g) =>
            this.readStateOf(g, now).read_state === "active" ||
            this.heldDataMayRemain(g.grant.grant_id),
        );
    } else {
      const ids = input.grantIds ?? [];
      if (ids.length === 0)
        return { ok: false, message: "grant_id is required" };
      if (input.action === "narrowing" && ids.length !== 1)
        return { ok: false, message: "narrowing revokes exactly one grant" };
      candidates = [];
      for (const id of ids) {
        const stored = this.store.getGrant(id);
        if (
          !stored ||
          stored.subjectId !== input.subjectId ||
          !input.inScope(stored)
        )
          return { ok: false, message: "grant not found" };
        candidates.push(stored);
      }
    }
    return {
      ok: true,
      grants: candidates.map((stored) =>
        this.affectedEntry(stored, input.action, now),
      ),
    };
  }

  private affectedEntry(
    stored: StoredGrant,
    action: OwnerEndingAction,
    now: Date,
  ): AffectedGrant {
    const state = this.readStateOf(stored, now);
    const instruction = this.store.lifecycle.getInstruction(
      stored.grant.grant_id,
    );
    const locked = !!instruction?.effectiveAt;
    const terms = {
      ...(stored.grant.retention && { retention: stored.grant.retention }),
    };
    const keep = keepStatement(terms);
    const del = deleteStatements(terms);
    const narrowing =
      action === "narrowing" ? narrowingStatements() : undefined;
    return {
      grant_id: stored.grant.grant_id,
      client_id: stored.clientId,
      source_id: stored.grant.source.id,
      purpose_code: stored.grant.purpose_code,
      issued_at: stored.grant.issued_at,
      access_mode: stored.grant.access_mode,
      ...state,
      effect:
        state.read_state === "active" || state.read_state === "window_closed"
          ? "end"
          : "record",
      ...(locked && { disposition_locked: "delete" as const }),
      disposition_required: !locked,
      preselected: null,
      options: {
        keep: narrowing
          ? {
              ...keep,
              surviving_use: `${narrowing.keep} ${keep.surviving_use}`,
            }
          : keep,
        delete: { statements: narrowing ? [narrowing.delete, ...del] : del },
      },
    };
  }

  /**
   * Apply an owner action that ends grants (AS item 41). Every grant in the
   * affected set needs an explicit `keep` or `delete`; a request missing one
   * is rejected and no default is applied (L1576). Each grant is recorded
   * in its own durable unit, so a failure leaves a per-grant result (L1828).
   * A retry with the same `actionId` skips grants already recorded and never
   * restarts a clock.
   */
  endGrantsForOwner(input: {
    subjectId: string;
    action: OwnerEndingAction;
    clientId?: string;
    grantIds?: string[];
    dispositions: Record<string, "keep" | "delete">;
    actionId: string;
    inScope: (stored: StoredGrant) => boolean;
    now?: Date;
  }):
    | { ok: true; result: OwnerActionResult }
    | {
        ok: false;
        code: "invalid_request" | "disposition_required" | "not_found";
        message: string;
        missing?: string[];
      } {
    const now = input.now ?? this.clock();
    for (const value of Object.values(input.dispositions)) {
      if (value !== "keep" && value !== "delete")
        return {
          ok: false,
          code: "invalid_request",
          message: "a disposition is keep or delete",
        };
    }
    if (!this.store.history.isCurrent()) {
      return this.acceptPending({
        subjectId: input.subjectId,
        kind: "end",
        action: input.action,
        grantIds:
          input.grantIds && input.grantIds.length > 0
            ? input.grantIds
            : Object.keys(input.dispositions),
        dispositions: input.dispositions,
        actionId: input.actionId,
        now,
        requireAll: true,
        inScope: input.inScope,
      });
    }
    const affected = this.affectedSet({ ...input, now });
    if (!affected.ok)
      return {
        ok: false,
        code:
          affected.message === "grant not found"
            ? "not_found"
            : "invalid_request",
        message: affected.message,
      };
    const scope = new Set(affected.grants.map((g) => g.grant_id));
    const outside = Object.keys(input.dispositions).filter(
      (g) => !scope.has(g),
    );
    if (outside.length > 0)
      return {
        ok: false,
        code: "invalid_request",
        message: "a disposition names a grant outside the action's scope",
      };
    const missing = affected.grants
      .filter((g) => g.disposition_required && !input.dispositions[g.grant_id])
      .map((g) => g.grant_id);
    if (missing.length > 0) {
      return {
        ok: false,
        code: "disposition_required",
        message:
          "an explicit keep or delete disposition is required for every grant in scope",
        missing,
      };
    }
    const results: OwnerActionResult["grants"] = [];
    for (const entry of affected.grants) {
      const grantId = entry.grant_id;
      const disposition = input.dispositions[grantId] ?? "delete";
      try {
        let ended = false;
        if (
          !this.store.lifecycle.hasOwnerDisposition(grantId, input.actionId)
        ) {
          this.store.commit(() => {
            this.store.lifecycle.insertOwnerDisposition({
              grantId,
              disposition,
              path: input.action,
              actionId: input.actionId,
              at: now.toISOString(),
            });
            if (disposition === "delete") {
              ended = this.store.requestErasureInTx({
                grantId,
                clientId: entry.client_id,
                origin: "owner",
                now,
                ending: { reason: "owner_withdrawal", detail: input.action },
              }).ended;
            } else {
              ended = this.store.endGrantInTx(grantId, now, {
                reason: "owner_withdrawal",
                detail: input.action,
              });
            }
          }, now);
        } else {
          // F1: a retry of a recorded action is acknowledged only once the
          // evidence for it is written: flush any owed advance (it throws,
          // and the grant stays pending, if the anchor still cannot be
          // written).
          this.store.commit(() => undefined, now);
        }
        results.push({
          grant_id: grantId,
          state: "recorded",
          ended,
          disposition,
        });
      } catch {
        results.push({ grant_id: grantId, state: "pending", disposition });
      }
    }
    return {
      ok: true,
      result: {
        complete: results.every((r) => r.state === "recorded"),
        grants: results,
      },
    };
  }

  /**
   * Owner erasure request for one grant (L1586, AS item 46): immediate
   * (ends an active grant, or applies to an ended one while held data may
   * remain) or an election in advance, which takes effect at grant end and
   * neither revokes the grant nor prohibits use before then.
   */
  requestErasureForOwner(input: {
    subjectId: string;
    grantId: string;
    advance: boolean;
    actionId: string;
    inScope: (stored: StoredGrant) => boolean;
    now?: Date;
  }):
    | { ok: true; result: OwnerActionResult; erasure?: ErasureOwnerView }
    | { ok: false; code: "not_found" | "invalid_request"; message: string } {
    const now = input.now ?? this.clock();
    if (!this.store.history.isCurrent()) {
      const pending = this.acceptPending({
        subjectId: input.subjectId,
        kind: "erasure",
        action: input.advance ? "advance" : "immediate",
        grantIds: [input.grantId],
        dispositions: { [input.grantId]: "delete" },
        actionId: input.actionId,
        now,
        requireAll: false,
        inScope: input.inScope,
      });
      return pending.ok
        ? pending
        : {
            ok: false,
            code:
              pending.code === "not_found" ? "not_found" : "invalid_request",
            message: pending.message,
          };
    }
    const stored = this.store.getGrant(input.grantId);
    if (
      !stored ||
      stored.subjectId !== input.subjectId ||
      !input.inScope(stored)
    )
      return { ok: false, code: "not_found", message: "grant not found" };
    const state = this.readStateOf(stored, now);
    const active =
      state.read_state === "active" || state.read_state === "window_closed";
    if (
      !active &&
      !this.heldDataMayRemain(input.grantId) &&
      !this.store.lifecycle.getInstruction(input.grantId)
    )
      return {
        ok: false,
        code: "invalid_request",
        message: "no held data of this grant may remain",
      };
    try {
      let ended = false;
      this.store.commit(() => {
        if (
          !this.store.lifecycle.hasOwnerDisposition(
            input.grantId,
            input.actionId,
          )
        ) {
          this.store.lifecycle.insertOwnerDisposition({
            grantId: input.grantId,
            disposition: "delete",
            path:
              input.advance && active ? "advance_election" : "erasure_request",
            actionId: input.actionId,
            at: now.toISOString(),
          });
        }
        if (input.advance && active) {
          if (!this.store.lifecycle.getInstruction(input.grantId)) {
            this.store.lifecycle.insertInstruction({
              grantId: input.grantId,
              clientId: stored.clientId,
              origin: "owner",
              advance: true,
              at: now.toISOString(),
              effectiveAt: null,
            });
          }
        } else {
          ended = this.store.requestErasureInTx({
            grantId: input.grantId,
            clientId: stored.clientId,
            origin: "owner",
            now,
            ending: { reason: "erasure_request" },
          }).ended;
        }
      }, now);
      return {
        ok: true,
        result: {
          complete: true,
          grants: [
            {
              grant_id: input.grantId,
              state: "recorded",
              ended,
              disposition: "delete",
            },
          ],
        },
        erasure: this.ownerView(this.store.getGrant(input.grantId)!, now)
          .erasure,
      };
    } catch {
      return {
        ok: true,
        result: {
          complete: false,
          grants: [
            {
              grant_id: input.grantId,
              state: "pending",
              disposition: "delete",
            },
          ],
        },
      };
    }
  }

  /**
   * Security revocation by the AS (L1572, AS item 46, case P7): ends grants
   * the owner did not ask to end. Creates no erasure instruction; the owner
   * surface then shows the ending, its reason, and offers the disposition.
   */
  securityRevoke(input: {
    grantIds: string[];
    reason: string;
    now?: Date;
  }): string[] {
    const now = input.now ?? this.clock();
    return this.store.commit(
      () =>
        input.grantIds.filter((g) =>
          this.store.getGrant(g)
            ? this.store.endGrantInTx(g, now, {
                reason: "security",
                detail: input.reason,
              })
            : false,
        ),
      now,
    );
  }

  /** Owner view of one grant's lifecycle (AS items 42, 43, 46). */
  ownerView(
    stored: StoredGrant,
    now: Date = this.clock(),
  ): OwnerGrantLifecycleView {
    const grantId = stored.grant.grant_id;
    const state = this.readStateOf(stored, now);
    const ending = this.store.lifecycle.getEnding(grantId);
    const instruction = this.store.lifecycle.getInstruction(grantId);
    const mayRemain = this.heldDataMayRemain(grantId);
    const disposition = this.store.lifecycle.latestDisposition(grantId);
    const active =
      state.read_state === "active" || state.read_state === "window_closed";
    // R1: a terminal event is shown as recorded only once its evidence is
    // written; otherwise the whole view is marked pending.
    const evidence: "recorded" | "pending" = this.flushEvidence(now)
      ? "recorded"
      : "pending";
    return {
      evidence,
      ...state,
      ...(ending &&
        (state.read_state === "revoked" || ending.reason === "security") && {
          ending: {
            reason: ending.reason,
            ...(ending.detail && { detail: ending.detail }),
          },
        }),
      held_data_may_remain: mayRemain,
      disposition: instruction
        ? "delete"
        : disposition
          ? disposition
          : !active && mayRemain
            ? "offered"
            : "not_applicable",
      ...(instruction && {
        erasure: this.erasureView(stored, instruction, now),
      }),
      erasure_request_available:
        !instruction?.effectiveAt && (active || mayRemain),
    };
  }

  /** AS items 42, 43: stages recorded separately; no receipt-based date before a receipt. */
  erasureView(
    stored: StoredGrant,
    instruction: ErasureInstructionRecord,
    now: Date,
  ): ErasureOwnerView {
    const retained = this.store.lifecycle.listRetained(
      instruction.instructionId,
    );
    const latest: ErasureOwnerView["latest_stage"] =
      instruction.completedReportedAt
        ? "completion_reported"
        : retained.length > 0
          ? "exception_reported"
          : instruction.receiptReportedAt
            ? "receipt_reported"
            : instruction.firstReturnedAt
              ? "sent"
              : "requested";
    const effective = instruction.effectiveAt ?? undefined;
    const terms = {
      ...(stored.grant.retention && { retention: stored.grant.retention }),
    };
    return {
      instruction_id: instruction.instructionId,
      advance: instruction.advance,
      requested_at: instruction.acceptedAt,
      ...(effective && {
        effective_at: effective,
        stop_use_by: stopUseBy(effective),
      }),
      latest_stage: latest,
      stages: {
        requested_at: instruction.acceptedAt,
        ...(instruction.firstReturnedAt && {
          sent_at: instruction.firstReturnedAt,
        }),
        ...(instruction.receiptReportedAt && {
          receipt_reported: {
            reported_at: instruction.receiptReportedAt,
            recorded_at: instruction.receiptRecordedAt!,
          },
        }),
        ...(instruction.completedReportedAt && {
          completion_reported: {
            reported_at: instruction.completedReportedAt,
            recorded_at: instruction.completedRecordedAt!,
          },
        }),
        ...(retained.length > 0 && {
          exceptions: retained.map((r) => ({
            reported_at: r.reportedAt,
            received_at: r.receivedAt,
            retained_until: parseRetainedUntil(r.retainedUntil) ?? {
              kind: "unknown" as const,
            },
            ...(r.retentionBasis && { retention_basis: r.retentionBasis }),
            ...(r.retentionScope && { retention_scope: r.retentionScope }),
          })),
        }),
      },
      // L1661: a date only from a reported receipt time.
      ...(instruction.receiptReportedAt && {
        deletion_due_by: iso(
          Date.parse(instruction.receiptReportedAt) + DELETION_BOUND_MS,
        ),
      }),
      summary: stageSummary({
        latest,
        acceptedAt: instruction.acceptedAt,
        firstReturnedAt: instruction.firstReturnedAt,
        receiptReportedAt: instruction.receiptReportedAt,
        completedReportedAt: instruction.completedReportedAt,
        retainedReported: retained.length > 0,
      }),
      statements: deleteStatements({
        ...terms,
        ...(effective
          ? { stopUseBy: stopUseBy(effective) }
          : {
              advanceEvent: stored.expiresAt
                ? `the grant ends (at the latest ${stored.expiresAt})`
                : "the grant ends",
            }),
      }),
    };
  }

  // ======================================================================
  // Decommission (L1574, AS item 46, case P9)
  // ======================================================================

  decommissionView(input: {
    subjectId: string;
    inScope: (stored: StoredGrant) => boolean;
    now?: Date;
  }): {
    confirmed_at?: string;
    grants: Array<{
      grant_id: string;
      client_id: string;
      read_state: ReadState;
      ended_at?: string;
      stage: "offered" | "recorded" | "sent" | "receipt_reported";
      disposition?: "keep" | "delete";
      warning?: string;
      options: AffectedGrant["options"];
      preselected: null;
    }>;
  } {
    const now = input.now ?? this.clock();
    const grants = this.store
      .listGrantsForSubject(input.subjectId)
      .filter(input.inScope)
      .filter(
        (g) =>
          this.heldDataMayRemain(g.grant.grant_id) ||
          this.readStateOf(g, now).read_state === "active",
      )
      .map((g) => {
        const grantId = g.grant.grant_id;
        const instruction = this.store.lifecycle.getInstruction(grantId);
        const disposition = instruction
          ? "delete"
          : this.store.lifecycle.latestDisposition(grantId);
        const stage: "offered" | "recorded" | "sent" | "receipt_reported" =
          !disposition
            ? "offered"
            : disposition === "keep"
              ? "recorded"
              : instruction?.receiptReportedAt
                ? "receipt_reported"
                : instruction?.firstReturnedAt
                  ? "sent"
                  : "recorded";
        const warning =
          disposition === "delete" && stage === "recorded"
            ? "No app has received this deletion request yet. Once your server stops answering, the app cannot learn of it."
            : disposition === "delete" && stage === "sent"
              ? "This deletion request was sent, but the app has not reported receiving it. Once your server stops answering, an app that did not receive it cannot learn of it."
              : undefined;
        const entry = this.affectedEntry(g, "decommission", now);
        return {
          grant_id: grantId,
          client_id: g.clientId,
          ...this.readStateOf(g, now),
          stage,
          ...(disposition && { disposition }),
          ...(warning && { warning }),
          options: entry.options,
          preselected: null,
        };
      });
    const confirmed = this.store.lifecycle.decommissionConfirmedAt();
    return { ...(confirmed && { confirmed_at: confirmed }), grants };
  }

  /**
   * Confirm decommission: records a disposition for every grant still at
   * `offered` (each needs an explicit one), ends the remaining active grants,
   * and records the confirmation. Stopping the server stays the operator's
   * act; this only makes sure nothing was left undecided first.
   */
  confirmDecommission(input: {
    subjectId: string;
    dispositions: Record<string, "keep" | "delete">;
    actionId: string;
    inScope: (stored: StoredGrant) => boolean;
    now?: Date;
  }):
    | {
        ok: true;
        view: ReturnType<GrantLifecycleService["decommissionView"]>;
        result: OwnerActionResult;
      }
    | {
        ok: false;
        code: "disposition_required" | "invalid_request" | "not_found";
        message: string;
        missing?: string[];
      } {
    const now = input.now ?? this.clock();
    const view = this.decommissionView({ ...input, now });
    const offered = view.grants.filter(
      (g) => g.stage === "offered" || g.read_state === "active",
    );
    const missing = offered
      .filter((g) => !g.disposition && !input.dispositions[g.grant_id])
      .map((g) => g.grant_id);
    if (missing.length > 0)
      return {
        ok: false,
        code: "disposition_required",
        message:
          "an explicit disposition is required for every grant whose held data may remain",
        missing,
      };
    const ended = this.endGrantsForOwner({
      subjectId: input.subjectId,
      action: "decommission",
      dispositions: Object.fromEntries(
        offered
          .filter((g) => input.dispositions[g.grant_id] || g.disposition)
          .map((g) => [
            g.grant_id,
            input.dispositions[g.grant_id] ?? g.disposition!,
          ]),
      ),
      actionId: input.actionId,
      inScope: (s) =>
        input.inScope(s) &&
        offered.some((g) => g.grant_id === s.grant.grant_id),
      now,
    });
    if (!ended.ok) return ended;
    if (ended.result.complete) {
      this.store.commit(
        () => this.store.lifecycle.confirmDecommission(now.toISOString()),
        now,
      );
    }
    return {
      ok: true,
      view: this.decommissionView({ ...input, now }),
      result: ended.result,
    };
  }

  // ======================================================================
  // History unavailable: accept, record, later apply (L1827, case D4)
  // ======================================================================

  private acceptPending(input: {
    subjectId: string;
    kind: "end" | "erasure";
    action: string;
    grantIds: string[];
    dispositions: Record<string, "keep" | "delete">;
    actionId: string;
    now: Date;
    requireAll: boolean;
    inScope: (stored: StoredGrant) => boolean;
  }):
    | { ok: true; result: OwnerActionResult }
    | {
        ok: false;
        code: "disposition_required" | "invalid_request" | "not_found";
        message: string;
        missing?: string[];
      } {
    if (input.grantIds.length === 0)
      return {
        ok: false,
        code: "invalid_request",
        message: "grant_id is required",
      };
    // The owner's ceiling still applies: a grant must be the owner's and in
    // the token's scope as far as the readable (possibly stale) store shows.
    // This rejects for scope, never for the unavailable history (L1827).
    // F5: a grant the stale store lacks (issued after the restored backup)
    // is still accepted and journaled; only one that the store or the
    // evidence shows belongs to another owner, or lies outside the token's
    // scope, is refused.
    for (const g of input.grantIds) {
      const stored = this.store.getGrant(g);
      if (stored) {
        if (stored.subjectId !== input.subjectId || !input.inScope(stored))
          return { ok: false, code: "not_found", message: "grant not found" };
        continue;
      }
      const evidence = this.store.history.anchoredErasure(g);
      if (evidence?.subject_id && evidence.subject_id !== input.subjectId)
        return { ok: false, code: "not_found", message: "grant not found" };
    }
    // The scope of a whole-client action cannot be listed from a history that
    // may be stale, so the owner names each grant; each still needs its own
    // explicit disposition (L1576).
    const missing = input.grantIds.filter((g) => !input.dispositions[g]);
    if (input.requireAll && missing.length > 0)
      return {
        ok: false,
        code: "disposition_required",
        message:
          "an explicit keep or delete disposition is required for every grant",
        missing,
      };
    const action: PendingOwnerAction = {
      action_id: input.actionId,
      subject_id: input.subjectId,
      recorded_at: input.now.toISOString(),
      kind: input.kind,
      action: input.action,
      grant_ids: input.grantIds,
      dispositions: input.dispositions,
    };
    try {
      this.store.pendingActions.append(action);
    } catch {
      return {
        ok: true,
        result: {
          complete: false,
          grants: input.grantIds.map((g) => ({
            grant_id: g,
            state: "pending" as const,
          })),
        },
      };
    }
    return {
      ok: true,
      result: {
        complete: false,
        grants: input.grantIds.map((g) => ({
          grant_id: g,
          state: "pending" as const,
          ...(input.dispositions[g] && { disposition: input.dispositions[g] }),
        })),
        statement: PENDING_HISTORY_STATEMENT,
      },
    };
  }

  /** Owner actions recorded while the history was unavailable, for the owner surface. */
  pendingOwnerActions(subjectId: string): PendingOwnerAction[] {
    return this.store.pendingActions
      .list()
      .filter((a) => a.kind !== "first_return" && a.subject_id === subjectId);
  }

  /**
   * The grants re-establishment would end: active in the (possibly stale)
   * store, with no anchored erasure and no pending owner ending. Each needs
   * an explicit disposition (AS item 41), except a grant with an anchored or
   * recorded advance election: its choice is locked to `delete` (F2, L1622
   * "A later `keep` [...] MUST NOT cancel it"). `inScope` filters what a
   * caller sees (F7); re-establishment itself always covers every grant.
   */
  reestablishAffected(
    now: Date = this.clock(),
    inScope: (stored: StoredGrant) => boolean = () => true,
  ): AffectedGrant[] {
    const anchored = new Set(
      this.store.history.anchoredErasures().map((e) => e.grant_id),
    );
    const elected = new Set(
      this.store.history.anchoredElections().map((e) => e.grant_id),
    );
    const pending = new Set(
      this.store.pendingActions
        .list()
        .filter((a) => a.kind !== "first_return")
        .flatMap((a) => a.grant_ids.filter((g) => a.dispositions[g])),
    );
    return this.store
      .listAllGrants()
      .filter((g) => !this.store.endingOf(g, now) && !g.revokedAt)
      .filter(
        (g) =>
          !anchored.has(g.grant.grant_id) && !pending.has(g.grant.grant_id),
      )
      .filter(inScope)
      .map((g) => {
        const entry = this.affectedEntry(g, "revoke", now);
        const locked =
          elected.has(g.grant.grant_id) ||
          !!this.store.lifecycle.getInstruction(g.grant.grant_id);
        return locked
          ? {
              ...entry,
              disposition_locked: "delete" as const,
              disposition_required: false,
            }
          : entry;
      });
  }

  /**
   * The owner of an anchored election's grant: the election's own
   * `subject_id` (anchored since round 3). For an anchor written before
   * elections carried it, fall back to any anchored erasure's subject, then
   * to the first grant's subject; on a single-owner server that is the
   * owner.
   */
  private anchoredSubject(grantId: string): string | undefined {
    const election = this.store.history.anchoredElection(grantId);
    return (
      election?.subject_id ??
      this.store.history.anchoredErasures().find((x) => x.subject_id)
        ?.subject_id ??
      this.store.listAllGrants()[0]?.subjectId
    );
  }

  /**
   * R1: before the owner surface renders a terminal event, write any owed
   * evidence. Returns false when it is still owed: the caller then shows
   * the events as pending or refuses the read.
   */
  flushEvidence(now: Date = this.clock()): boolean {
    if (!this.store.history.isCurrent()) return true;
    if (!this.store.history.evidenceOwed()) return true;
    try {
      this.store.commit(() => undefined, now);
      return true;
    } catch {
      return false;
    }
  }

  /** Pending actions the re-established store could not apply (F5). */
  unappliedOwnerActions(subjectId: string) {
    return this.store.lifecycle.listUnappliedActions(subjectId);
  }

  /**
   * Re-establish the history after the declared mechanism found it not
   * current (L1823, L1827). In one transaction:
   *
   *   1. restore every anchored erasure instruction and advance election the
   *      database lacks, with its original identifier and clocks (F2); for a
   *      grant the database lacks, keep the anchored instruction as an
   *      orphan record so the client can still receive it (F5);
   *   2. re-disable every token digest the anchor shows disabled, and revoke
   *      and disable every lifecycle recovery token (F4);
   *   3. apply every pending owner action in order; one naming a grant the
   *      store lacks is kept as unapplied, for the owner to see (F5);
   *   4. end every grant that is still active, because its terminal events
   *      may be missing (L1823), each with the owner's explicit disposition,
   *      or `delete` where an advance election locks it.
   *
   * Only then does the store become current under a new epoch.
   */
  reestablishHistory(input: {
    dispositions: Record<string, "keep" | "delete">;
    actionId: string;
    now?: Date;
  }):
    | {
        ok: true;
        restoredInstructions: number;
        appliedActions: number;
        invalidatedGrants: string[];
        orphanedInstructions: string[];
        unappliedActions: number;
        disabledTokens: number;
      }
    | {
        ok: false;
        code: "disposition_required";
        missing: string[];
        message: string;
      } {
    const now = input.now ?? this.clock();
    if (this.store.history.isCurrent()) {
      return {
        ok: true,
        restoredInstructions: 0,
        appliedActions: 0,
        invalidatedGrants: [],
        orphanedInstructions: [],
        unappliedActions: 0,
        disabledTokens: 0,
      };
    }
    const toEnd = this.reestablishAffected(now);
    const missing = toEnd
      .filter((g) => g.disposition_required)
      .map((g) => g.grant_id)
      .filter(
        (g) =>
          input.dispositions[g] !== "keep" &&
          input.dispositions[g] !== "delete",
      );
    if (missing.length > 0) {
      return {
        ok: false,
        code: "disposition_required",
        missing,
        message:
          "re-establishing the history ends every still-active grant; each needs an explicit keep or delete",
      };
    }
    let restored = 0;
    let applied = 0;
    let unapplied = 0;
    let disabledTokens = 0;
    const orphaned: string[] = [];
    const invalidated: string[] = [];
    const at = now.toISOString();
    const actions = this.store.pendingActions.list();
    this.store.reestablishHistory(() => {
      // 1. instructions and elections
      for (const e of this.store.history.anchoredErasures()) {
        if (!this.store.getGrant(e.grant_id)) {
          if (!this.store.lifecycle.getOrphanErasure(e.grant_id)) {
            this.store.lifecycle.insertOrphanErasure(e, at);
            orphaned.push(e.grant_id);
          }
          continue;
        }
        if (this.store.restoreAnchoredInstructionInTx(e, now)) restored += 1;
      }
      for (const e of this.store.history.anchoredElections()) {
        if (!this.store.getGrant(e.grant_id)) {
          // R2: an election cannot be promoted from stale state (L1820),
          // and its grant is gone, so it cannot take effect. Keep a record
          // the owner sees instead of dropping it.
          this.store.lifecycle.insertUnappliedAction({
            actionId: e.instruction_id,
            grantId: e.grant_id,
            subjectId: this.anchoredSubject(e.grant_id) ?? "",
            kind: "advance_election",
            action: "advance",
            disposition: "delete",
            recordedAt: e.accepted_at,
            outcome: "advance_election_grant_not_in_restored_store",
            at,
          });
          unapplied += 1;
          continue;
        }
        if (
          this.store.lifecycle.restoreInstruction(
            { ...e, effective_at: null, advance: true },
            at,
          )
        )
          restored += 1;
      }
      // 2. lifecycle-disabled digests and recovery tokens
      for (const d of this.store.history.anchoredDisabledDigests()) {
        if (this.store.lifecycle.disableDigest(d, at)) disabledTokens += 1;
      }
      for (const d of this.store.lifecycle.listRecoveryTokenDigests()) {
        this.store.lifecycle.revokeRecoveryToken(d, at);
        if (this.store.lifecycle.disableDigest(d, at)) disabledTokens += 1;
      }
      // 3. pending owner actions
      for (const a of actions) {
        if (a.kind === "first_return") {
          const instruction = this.store.lifecycle.getInstruction(
            a.grant_ids[0] ?? "",
          );
          if (instruction?.instructionId === a.action)
            this.store.lifecycle.recordFirstReturn(a.action, a.recorded_at);
          else if (
            this.store.lifecycle.getOrphanErasure(a.grant_ids[0] ?? "")
              ?.instruction_id === a.action
          )
            this.store.lifecycle.recordOrphanFirstReturn(
              a.grant_ids[0]!,
              a.recorded_at,
            );
          continue;
        }
        for (const grantId of a.grant_ids) {
          const stored = this.store.getGrant(grantId);
          const d = a.dispositions[grantId];
          if (!stored) {
            this.store.lifecycle.insertUnappliedAction({
              actionId: a.action_id,
              grantId,
              subjectId: a.subject_id,
              kind: a.kind,
              action: a.action,
              disposition: d ?? null,
              recordedAt: a.recorded_at,
              outcome: this.store.lifecycle.getOrphanErasure(grantId)
                ? "grant_not_in_restored_store_instruction_delivered_from_evidence"
                : "grant_not_in_restored_store",
              at,
            });
            unapplied += 1;
            continue;
          }
          if (stored.subjectId !== a.subject_id || !d) continue;
          this.store.lifecycle.insertOwnerDisposition({
            grantId,
            disposition: d,
            path: a.kind === "erasure" ? "erasure_request" : a.action,
            actionId: a.action_id,
            at: a.recorded_at,
          });
          const actedAt = new Date(a.recorded_at);
          if (
            a.kind === "erasure" &&
            a.action === "advance" &&
            !this.store.endingOf(stored, actedAt) &&
            !this.store.lifecycle.getInstruction(grantId)
          ) {
            this.store.lifecycle.insertInstruction({
              grantId,
              clientId: stored.clientId,
              origin: "owner",
              advance: true,
              at: a.recorded_at,
              effectiveAt: null,
            });
          } else if (d === "delete") {
            this.store.requestErasureInTx({
              grantId,
              clientId: stored.clientId,
              origin: "owner",
              now: actedAt,
              ending: {
                reason:
                  a.kind === "erasure" ? "erasure_request" : "owner_withdrawal",
                detail: a.action,
              },
            });
          } else {
            this.store.endGrantInTx(grantId, actedAt, {
              reason: "owner_withdrawal",
              detail: a.action,
            });
          }
        }
        applied += 1;
      }
      // 4. end what is still active
      const ending = {
        reason: "history_restore" as const,
        detail:
          "the server could not confirm its authorization history was complete",
      };
      for (const entry of toEnd) {
        const grantId = entry.grant_id;
        const d = entry.disposition_locked ?? input.dispositions[grantId]!;
        this.store.lifecycle.insertOwnerDisposition({
          grantId,
          disposition: d,
          path: "history_restore",
          actionId: input.actionId,
          at,
        });
        const ended =
          d === "delete"
            ? this.store.requestErasureInTx({
                grantId,
                clientId: entry.client_id,
                origin: "owner",
                now,
                ending,
              }).ended
            : this.store.endGrantInTx(grantId, now, ending);
        if (ended) invalidated.push(grantId);
      }
      // No grant may leave this transaction active, and an advance election
      // on any grant ends with it (settled inside endGrantInTx).
      for (const g of this.store.listAllGrants()) {
        if (this.store.endGrantInTx(g.grant.grant_id, now, ending))
          invalidated.push(g.grant.grant_id);
      }
    }, now);
    this.store.pendingActions.clear();
    return {
      ok: true,
      restoredInstructions: restored,
      appliedActions: applied,
      invalidatedGrants: invalidated,
      orphanedInstructions: orphaned,
      unappliedActions: unapplied,
      disabledTokens,
    };
  }

  // ======================================================================
  // Lifecycle recovery (L1802-L1808, AS item 47, case D3)
  // ======================================================================

  /** Validate a recovery detail: `type` and a non-empty, distinct `grant_ids` only. */
  static parseRecoveryDetail(
    detail: unknown,
  ): { ok: true; grantIds: string[] } | { ok: false; message: string } {
    if (!detail || typeof detail !== "object" || Array.isArray(detail))
      return { ok: false, message: "a lifecycle recovery detail is an object" };
    const d = detail as Record<string, unknown>;
    if (d.type !== PDPP_GRANT_LIFECYCLE_TYPE)
      return { ok: false, message: "not a lifecycle recovery detail" };
    const extra = Object.keys(d).filter(
      (k) => k !== "type" && k !== "grant_ids",
    );
    if (extra.length > 0)
      return {
        ok: false,
        message: "a lifecycle recovery detail carries only type and grant_ids",
      };
    const ids = d.grant_ids;
    if (
      !Array.isArray(ids) ||
      ids.length === 0 ||
      ids.some((g) => typeof g !== "string" || g.length === 0) ||
      new Set(ids).size !== ids.length
    )
      return {
        ok: false,
        message:
          "grant_ids must be a non-empty array of distinct, non-empty strings",
      };
    return { ok: true, grantIds: ids as string[] };
  }

  /**
   * Open a recovery session after the owner is authenticated (L1804). Every
   * named grant must have been issued to this client for this owner, ended
   * or not; a failure does not say which grant failed.
   */
  openRecoverySession(input: {
    subjectId: string;
    clientId: string;
    grantIds: string[];
    redirectUri: string;
    stateParam?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    inScope: (stored: StoredGrant) => boolean;
    now?: Date;
  }):
    | { ok: true; session_id: string; expires_at: string }
    | { ok: false; message: string } {
    const now = input.now ?? this.clock();
    for (const g of input.grantIds) {
      const stored = this.store.getGrant(g);
      if (
        !stored ||
        stored.clientId !== input.clientId ||
        stored.subjectId !== input.subjectId ||
        !input.inScope(stored)
      )
        return {
          ok: false,
          message:
            "the lifecycle recovery request names a grant that cannot be recovered",
        };
    }
    const sessionId = `lrs_${randomBytes(16).toString("hex")}`;
    const expiresAt = iso(now.getTime() + 10 * 60 * 1000);
    const session: RecoverySession = {
      session_id: sessionId,
      subject_id: input.subjectId,
      client_id: input.clientId,
      grant_ids: input.grantIds,
      redirect_uri: input.redirectUri,
      ...(input.stateParam && { state_param: input.stateParam }),
      ...(input.codeChallenge && { code_challenge: input.codeChallenge }),
      ...(input.codeChallengeMethod && {
        code_challenge_method: input.codeChallengeMethod,
      }),
      expires_at: expiresAt,
      status: "pending",
      review_digest: createHash("sha256")
        .update(
          JSON.stringify([
            input.subjectId,
            input.clientId,
            input.grantIds,
            RECOVERY_STATEMENT,
          ]),
        )
        .digest("hex"),
    };
    this.recoverySessions.set(sessionId, session);
    return { ok: true, session_id: sessionId, expires_at: expiresAt };
  }

  hasRecoverySession(sessionId: string): boolean {
    return this.recoverySessions.has(sessionId);
  }

  recoverySessionSubject(sessionId: string): string | undefined {
    return this.recoverySessions.get(sessionId)?.subject_id;
  }

  /** L1804: before approval, show each grant's client, source, purpose and issue date. */
  recoveryReview(
    sessionId: string,
    subjectId: string,
  ):
    | {
        ok: true;
        review: {
          type: typeof PDPP_GRANT_LIFECYCLE_TYPE;
          client_id: string;
          grants: Array<{
            grant_id: string;
            client: { client_id: string; display_name?: string };
            source_id: string;
            purpose_code: string;
            purpose_description?: string;
            issued_at: string;
          }>;
          statement: string;
          review_digest: string;
        };
        expires_at: string;
      }
    | { ok: false; code: "session_not_found" } {
    const session = this.liveRecoverySession(sessionId, subjectId);
    if (!session) return { ok: false, code: "session_not_found" };
    return {
      ok: true,
      expires_at: session.expires_at,
      review: {
        type: PDPP_GRANT_LIFECYCLE_TYPE,
        client_id: session.client_id,
        grants: session.grant_ids.map((g) => {
          const stored = this.store.getGrant(g)!;
          return {
            grant_id: g,
            client: {
              client_id: stored.clientId,
              ...(stored.grant.client.client_display?.name && {
                display_name: stored.grant.client.client_display.name,
              }),
            },
            source_id: stored.grant.source.id,
            purpose_code: stored.grant.purpose_code,
            ...(stored.grant.purpose_description && {
              purpose_description: stored.grant.purpose_description,
            }),
            issued_at: stored.grant.issued_at,
          };
        }),
        statement: RECOVERY_STATEMENT,
        review_digest: session.review_digest,
      },
    };
  }

  private liveRecoverySession(
    sessionId: string,
    subjectId: string,
  ): RecoverySession | null {
    const session = this.recoverySessions.get(sessionId);
    if (!session || session.subject_id !== subjectId) return null;
    if (
      session.status !== "pending" ||
      Date.parse(session.expires_at) <= this.clock().getTime()
    )
      return null;
    return session;
  }

  /** Approve: fixes the grant set and client binding in durable evidence (L1804). */
  approveRecovery(input: {
    sessionId: string;
    subjectId: string;
    reviewDigest: string;
    now?: Date;
  }):
    | { ok: true; redirect_uri: string }
    | {
        ok: false;
        code: "session_not_found" | "stale_review" | "temporarily_unavailable";
      } {
    const now = input.now ?? this.clock();
    const session = this.liveRecoverySession(input.sessionId, input.subjectId);
    if (!session) return { ok: false, code: "session_not_found" };
    if (input.reviewDigest !== session.review_digest)
      return { ok: false, code: "stale_review" };
    if (!this.store.history.isCurrent())
      return { ok: false, code: "temporarily_unavailable" };
    const code = `pdpp_lrc_${randomBytes(24).toString("hex")}`;
    try {
      this.store.commit(() => {
        this.store.lifecycle.insertRecoveryApproval({
          approvalId: `lra_${randomBytes(16).toString("hex")}`,
          subjectId: session.subject_id,
          clientId: session.client_id,
          grantIds: session.grant_ids,
          reviewDigest: session.review_digest,
          statement: RECOVERY_STATEMENT,
          at: now.toISOString(),
          codeHash: hashToken(code),
          redirectUri: session.redirect_uri,
          codeChallenge: session.code_challenge ?? null,
          codeChallengeMethod: session.code_challenge_method ?? null,
          codeExpiresAt: iso(now.getTime() + 60_000),
        });
      }, now);
    } catch {
      return { ok: false, code: "temporarily_unavailable" };
    }
    session.status = "approved";
    const redirect = new URL(session.redirect_uri);
    redirect.searchParams.set("code", code);
    if (session.state_param)
      redirect.searchParams.set("state", session.state_param);
    return { ok: true, redirect_uri: redirect.toString() };
  }

  denyRecovery(
    sessionId: string,
    subjectId: string,
  ): { ok: true; redirect_uri: string } | { ok: false } {
    const session = this.liveRecoverySession(sessionId, subjectId);
    if (!session) return { ok: false };
    session.status = "denied";
    const redirect = new URL(session.redirect_uri);
    redirect.searchParams.set("error", "access_denied");
    if (session.state_param)
      redirect.searchParams.set("state", session.state_param);
    return { ok: true, redirect_uri: redirect.toString() };
  }

  isRecoveryCode(code: string): boolean {
    return this.store.lifecycle.hasRecoveryCode(hashToken(code));
  }

  /**
   * Redeem a recovery code (L1806): a lifecycle-only access token for exactly
   * the approved grants, the approved element in `authorization_details`,
   * and no refresh token. Issuance creates or reopens no data grant, read
   * window or processing authority, and is not a positive assessment.
   */
  redeemRecoveryCode(input: {
    code: string;
    clientId: string;
    redirectUri: string;
    codeVerifier?: string;
    now?: Date;
  }):
    | {
        ok: true;
        issued: {
          access_token: string;
          token_type: "Bearer";
          authorization_details: Array<{
            type: typeof PDPP_GRANT_LIFECYCLE_TYPE;
            grant_ids: string[];
          }>;
        };
      }
    | {
        ok: false;
        code: "invalid_grant" | "temporarily_unavailable";
        message: string;
      } {
    const now = input.now ?? this.clock();
    if (!this.store.history.isCurrent())
      return {
        ok: false,
        code: "temporarily_unavailable",
        message: "history is not current",
      };
    const invalid = {
      ok: false as const,
      code: "invalid_grant" as const,
      message: "authorization code is invalid, expired, or already redeemed",
    };
    const token = newOpaqueToken("pdpp_lt");
    let result:
      ReturnType<typeof this.store.lifecycle.consumeRecoveryCode> | "mismatch";
    try {
      result = this.store.commit(() => {
        const record = this.store.lifecycle.consumeRecoveryCode(
          hashToken(input.code),
          now.toISOString(),
        );
        if (!record) return null;
        if (
          record.clientId !== input.clientId ||
          record.redirectUri !== input.redirectUri
        )
          return "mismatch" as const;
        if (
          verifyCodeVerifier(
            input.codeVerifier,
            record.codeChallenge,
            record.codeChallengeMethod,
          )
        )
          return "mismatch" as const;
        this.store.lifecycle.insertRecoveryToken({
          tokenHash: hashToken(token),
          approvalId: record.approvalId,
          clientId: record.clientId,
          subjectId: record.subjectId,
          grantIds: record.grantIds,
          at: now.toISOString(),
        });
        return record;
      }, now);
    } catch {
      return {
        ok: false,
        code: "temporarily_unavailable",
        message: "the recovery token could not be recorded",
      };
    }
    if (!result || result === "mismatch") return invalid;
    return {
      ok: true,
      issued: {
        access_token: token,
        token_type: "Bearer",
        authorization_details: [
          { type: PDPP_GRANT_LIFECYCLE_TYPE, grant_ids: result.grantIds },
        ],
      },
    };
  }
}
