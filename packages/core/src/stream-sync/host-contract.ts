/**
 * The facts of this server that a host with a writer of its own must agree
 * with: the run-intake refusals, what `end` can answer, when an `end` answer
 * means the run's work is saved, and the shape of the database name.
 *
 * A native host (Rust, Dart) cannot import this module. It reads
 * `contracts/host-contract.json`, which `hostContract()` generates and a test
 * here keeps equal to it. When this module changes and the file does not,
 * that test fails; when a host's own list differs from the file, the host's
 * test fails. Nothing is copied by hand.
 */
import { LOCAL_DATABASE_NAME_PATTERN } from "../localdb/name.js";
import { RUN_INTAKE_ERROR_STATUS } from "./intake.js";

/** What `end` can answer (V2 §2.3). */
export const END_RESULTS = [
  "queued",
  "checkpoint_only",
  "no_checkpoint",
  "discarded",
  "aborted",
] as const;
export type EndResult = (typeof END_RESULTS)[number];

/** What a run says when it ends. `failed` and `cancelled` always answer `aborted`. */
export const END_OUTCOMES = [
  "succeeded",
  "partial",
  "retry_pending",
  "failed",
  "cancelled",
] as const;
export type EndOutcome = (typeof END_OUTCOMES)[number];

export interface EndAcceptanceRule {
  readonly result: EndResult;
  readonly outcomes: readonly EndOutcome[];
  /**
   * `any`: whether the run sent records does not matter. `none`: the rule
   * holds only for a run that sent no records.
   */
  readonly recordsSent: "any" | "none";
}

/**
 * When an `end` answer means the run's work is saved.
 *
 * `queued`: records were merged. `checkpoint_only` and `no_checkpoint`: no
 * record was merged, so a run that sent records and gets either has lost them.
 * Only a `retry_pending` run expects that (it stops early and retries), and a
 * `succeeded` run that sent nothing has nothing to lose. Everything else,
 * including `discarded`, `aborted` and an answer this list does not know, is
 * not saved.
 */
export const END_ACCEPTANCE: readonly EndAcceptanceRule[] = [
  {
    result: "queued",
    outcomes: ["succeeded", "partial", "retry_pending"],
    recordsSent: "any",
  },
  {
    result: "checkpoint_only",
    outcomes: ["retry_pending"],
    recordsSent: "any",
  },
  { result: "checkpoint_only", outcomes: ["succeeded"], recordsSent: "none" },
  { result: "no_checkpoint", outcomes: ["retry_pending"], recordsSent: "any" },
  { result: "no_checkpoint", outcomes: ["succeeded"], recordsSent: "none" },
];

/**
 * Whether an `end` answer means the run's work is saved. Fails closed: an
 * unknown result or outcome is not saved.
 */
export function endResultIsAccepted(
  result: unknown,
  outcome: unknown,
  recordsSent: boolean,
): boolean {
  return END_ACCEPTANCE.some(
    (rule) =>
      rule.result === result &&
      (rule.outcomes as readonly unknown[]).includes(outcome) &&
      (rule.recordsSent === "any" || !recordsSent),
  );
}

export const HOST_CONTRACT_FORMAT = 1;

/** The JSON a non-TypeScript host reads (`contracts/host-contract.json`). */
export interface HostContract {
  readonly format: typeof HOST_CONTRACT_FORMAT;
  readonly runIntake: {
    readonly errors: readonly {
      readonly name: string;
      readonly status: number;
    }[];
    readonly endResults: readonly string[];
    readonly endOutcomes: readonly string[];
    readonly endAcceptance: readonly EndAcceptanceRule[];
  };
  readonly localDatabase: { readonly namePattern: string };
}

export function hostContract(): HostContract {
  return {
    format: HOST_CONTRACT_FORMAT,
    runIntake: {
      errors: Object.entries(RUN_INTAKE_ERROR_STATUS).map(([name, status]) => ({
        name,
        status,
      })),
      endResults: END_RESULTS,
      endOutcomes: END_OUTCOMES,
      endAcceptance: END_ACCEPTANCE,
    },
    localDatabase: { namePattern: LOCAL_DATABASE_NAME_PATTERN.source },
  };
}
