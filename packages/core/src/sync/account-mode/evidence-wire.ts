/**
 * The wire shape hosts use to give the module an Account answer
 * (POST /v1/account-mode/evidence), and the decision it returns. Host-neutral
 * JSON: Desktop and phone post it, Web builds it in process.
 */

import type { ModeEvidenceInput } from "./authority.js";
import type { ModeDecision } from "./record.js";

export interface EvidenceBody extends ModeEvidenceInput {
  owner: string;
}

export interface DecisionBody {
  decision: ModeDecision["kind"];
  code?: string;
  status?: 503 | 426;
}

/** What a host saw when it asked the Account for the stream-sync switch. */
export interface AccountAnswerSeen {
  /** The HTTP status; null or absent when no response arrived. */
  rawStatus?: number | null;
  /** The `streamSync` field of the response body, as the host decoded it. */
  streamSync?: unknown;
  /** The `generation` field of the response body, as the host decoded it. */
  generation?: unknown;
}

/**
 * The one reading of the Account's `GET /api/v1/me/stream-sync` answer. Only a
 * 2xx answer (a whole-number HTTP status) with a boolean `streamSync` and a
 * safe integer `generation` of 0 or more is on or off. Anything else (no response, another status, a missing
 * or malformed field, the Account's own failure body, which has no generation)
 * is `unknown`: a failed read is never an Off.
 */
export function parseAccountAnswer(
  seen: AccountAnswerSeen,
): Pick<ModeEvidenceInput, "state" | "generation"> {
  const status = seen.rawStatus;
  const answered =
    typeof status === "number" &&
    Number.isInteger(status) &&
    status >= 200 &&
    status < 300;
  const generation = seen.generation;
  if (
    answered &&
    typeof seen.streamSync === "boolean" &&
    typeof generation === "number" &&
    Number.isSafeInteger(generation) &&
    generation >= 0
  ) {
    return { state: seen.streamSync ? "on" : "off", generation };
  }
  return { state: "unknown" };
}

/**
 * Either `{owner, state: "on"|"off"|"unknown", generation?}` (the host read the
 * Account itself), or `{owner, rawStatus, streamSync?, generation?}` (the host
 * says what it saw and `parseAccountAnswer` reads it, so no host holds that
 * rule). When both name a state, the stated state wins. Other fields hosts send
 * (fetchStartedAt) are accepted and ignored. Null when the value is not a body.
 */
export function parseEvidenceBody(value: unknown): EvidenceBody | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.owner !== "string") return null;
  if (v.state === undefined) {
    if (
      !("rawStatus" in v) ||
      !(v.rawStatus === null || typeof v.rawStatus === "number")
    ) {
      return null;
    }
    return {
      owner: v.owner,
      ...parseAccountAnswer({
        rawStatus: v.rawStatus,
        streamSync: v.streamSync,
        generation: v.generation,
      }),
    };
  }
  if (v.state !== "on" && v.state !== "off" && v.state !== "unknown") {
    return null;
  }
  if (
    v.generation !== undefined &&
    !(Number.isSafeInteger(v.generation) && (v.generation as number) >= 0)
  ) {
    return null;
  }
  return {
    owner: v.owner,
    state: v.state,
    ...(v.generation === undefined
      ? {}
      : { generation: v.generation as number }),
  };
}

export function decisionBody(decision: ModeDecision): DecisionBody {
  return decision.kind === "refuse"
    ? { decision: "refuse", code: decision.code, status: decision.status }
    : { decision: decision.kind };
}
