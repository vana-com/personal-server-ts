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

/**
 * `{owner, state: "on"|"off"|"unknown", generation?}`. Other fields hosts
 * already send (fetchStartedAt, rawStatus) are accepted and ignored. Null when
 * the value is not a body.
 */
export function parseEvidenceBody(value: unknown): EvidenceBody | null {
  if (typeof value !== "object" || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.owner !== "string") return null;
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
