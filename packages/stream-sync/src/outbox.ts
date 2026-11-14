/**
 * §2.8 outbox entry. One entry per run, stored by the host on its durable
 * spool (filesystem + SQLite, native files, OPFS or IndexedDB). The host
 * resumes each stream from its `state`. Failures are visible and retried;
 * no attempt cap drops data.
 *
 * Stream states:
 *   planned            nothing durable yet; redo from "read control"
 *   request_persisted  head ciphertext and signed request persisted; on an
 *                      ambiguous reply, resend the request byte-for-byte
 *   committed          the head POST succeeded at `generation`
 *   noop               every part and `complete` unchanged; nothing posted
 *   discarded          `decide` discarded this run
 */

import type { StreamRunResult } from "./decide.js";
import type { StartSnapshot } from "./decide.js";
import { InvalidArgumentError } from "./errors.js";
import type { JsonValue } from "./json.js";
import { runMustBeFull, type NeedsFull } from "./needs-full.js";

export type OutboxStreamState =
  "planned" | "request_persisted" | "committed" | "noop" | "discarded";

/** The visible reason a stream has not committed yet. */
export type OutboxProblem =
  | "key_mismatch"
  | "registry_inconsistent"
  | "bucket_too_large"
  | "connector_update_required";

export interface OutboxStream {
  readonly state: OutboxStreamState;
  readonly requestRef?: string;
  readonly headCipherRef?: string;
  /** Set with `committed` and `noop`. */
  readonly generation?: number;
  /** `complete` of the committed or unchanged head. */
  readonly complete?: boolean;
  readonly problem?: OutboxProblem;
}

export interface OutboxEntry {
  readonly runId: string;
  readonly connector: string;
  /** `null` until the run's account identity is known. */
  readonly ns: string | null;
  /** Control states for the connector at run start, by ns; `null` = no listing yet. */
  readonly start: StartSnapshot;
  readonly userConnect: boolean;
  /** The run used no checkpoint. */
  readonly full: boolean;
  /** Run start, in milliseconds since the epoch; the `o` of every run line. */
  readonly observedAt: number;
  readonly spoolRef: string;
  readonly checkpointCandidate: JsonValue | null;
  readonly streams: Readonly<Record<string, OutboxStream>>;
}

/**
 * Build the entry at run start. Refuses a non-full run while the connector
 * has any `needsFull` (§2.4: any `needsFull` for c forces `full`).
 */
export function createOutboxEntry(input: {
  readonly runId: string;
  readonly connector: string;
  readonly start: StartSnapshot;
  readonly userConnect: boolean;
  readonly full: boolean;
  readonly observedAt: number;
  readonly spoolRef: string;
  readonly checkpointCandidate: JsonValue | null;
  readonly needsFull: NeedsFull;
}): OutboxEntry {
  if (input.runId === "") throw new InvalidArgumentError("runId is empty");
  if (!Number.isSafeInteger(input.observedAt) || input.observedAt < 0) {
    throw new InvalidArgumentError("observedAt must be a non-negative integer");
  }
  if (!input.full && runMustBeFull(input.needsFull, input.connector)) {
    throw new InvalidArgumentError(
      `connector ${input.connector} has needsFull: the run must be full`,
    );
  }
  return {
    runId: input.runId,
    connector: input.connector,
    ns: null,
    start: input.start === null ? null : { ...input.start },
    userConnect: input.userConnect,
    full: input.full,
    observedAt: input.observedAt,
    spoolRef: input.spoolRef,
    checkpointCandidate: input.checkpointCandidate,
    streams: {},
  };
}

/** The checkpoint view of one outbox stream (`checkpointDecision` input). */
export function streamRunResult(stream: OutboxStream): StreamRunResult {
  if (stream.state === "committed" || stream.state === "noop") {
    if (stream.generation === undefined || stream.complete === undefined) {
      throw new InvalidArgumentError(
        `${stream.state} stream needs generation and complete`,
      );
    }
    return {
      state: stream.state,
      generation: stream.generation,
      complete: stream.complete,
    };
  }
  return { state: stream.state === "discarded" ? "discarded" : "pending" };
}
