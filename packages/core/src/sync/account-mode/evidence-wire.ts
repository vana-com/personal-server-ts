/**
 * The wire shape hosts use to give the module an Account answer, and the shape
 * of the decision it returns. Host-neutral JSON: the same body is posted by the
 * Desktop and phone hosts and built in-process by Web.
 */

import type { ModeDecision, ModeState } from "./mode-machine.js";

export interface EvidenceBody {
  owner: string;
  state: ModeState;
  /** Epoch milliseconds, host clock, when the Account request started. */
  fetchStartedAt: number;
  /** HTTP status of the Account response, or null when there was none. */
  rawStatus: number | null;
}

export interface DecisionBody {
  decision: ModeDecision["kind"];
  importRequired: boolean;
  /** Present when the decision is a refusal. */
  code?: "ACCOUNT_MODE_UNKNOWN" | "LEGACY_REFUSED_SWITCHED";
  status?: 503 | 426;
}

/**
 * A body that does not parse is rejected by the route (400). A body that
 * parses but carries nothing usable becomes `state: "unknown"` so it changes
 * no state.
 */
export function parseEvidenceBody(value: unknown): EvidenceBody | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.owner !== "string") return null;
  if (v.state !== "on" && v.state !== "off" && v.state !== "unknown") {
    return null;
  }
  const rawStatus =
    typeof v.rawStatus === "number" && Number.isInteger(v.rawStatus)
      ? v.rawStatus
      : v.rawStatus === null || v.rawStatus === undefined
        ? null
        : Number.NaN;
  if (Number.isNaN(rawStatus)) return null;
  const fetchStartedAt =
    typeof v.fetchStartedAt === "number" ? v.fetchStartedAt : Number.NaN;
  return {
    owner: v.owner,
    state: v.state,
    fetchStartedAt,
    rawStatus,
  };
}

export function decisionBody(decision: ModeDecision): DecisionBody {
  switch (decision.kind) {
    case "streams":
      return { decision: "streams", importRequired: decision.importRequired };
    case "legacy":
      return { decision: "legacy", importRequired: false };
    case "refuse":
      return {
        decision: "refuse",
        importRequired: false,
        code: decision.code,
        status: decision.status,
      };
  }
}
