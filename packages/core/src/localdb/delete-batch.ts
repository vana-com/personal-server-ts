/**
 * The first landing of a connection delete as batch requests: the control
 * fences of its namespaces in one `POST /v1/data/batch`, then every stream
 * tombstone in the next (each split above the gateway's row limit).
 *
 * Each participant (a fence, or a stream) submits at most one signed row, or
 * leaves without one. When every participant has done one or the other the
 * rows go out. No timer: a participant is never waited for past its own work.
 *
 * Why two requests and not one:
 * - A stream row of namespace N must land only if N's fence landed. The only
 *   way to say so is a condition on N's control row, and the gateway refuses a
 *   condition on a row the same request writes (HTTP 400). Rows of one request
 *   also commit independently, so a fence that lost its compare-and-set would
 *   not hold back the stream rows beside it.
 * - So the fences go first, alone, each guarded by its own compare-and-set (the
 *   next version, and the active head's data hash). The stream rows go next,
 *   each namespace's rows resting on the condition "control is the tombstone at
 *   pin + 1". No stream row lands unless its fence is already committed.
 * - A fence that does not land, a failed condition, a missing batch route, or a
 *   request the gateway refuses, all answer `fallback`: nothing is guessed and
 *   the caller runs the per-stream path, which re-reads and re-checks
 *   everything itself. A refusal of the request's shape is a defect of this
 *   code, so it is reported through `onRefused`, never as a quiet limit.
 */
import type { ControlHashes } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  AmbiguousRegistryReplyError,
  RegistryRefusedError,
  type RegistryRequirement,
  type SignedBatchRow,
  type StreamSyncRegistry,
} from "../stream-sync/ports.js";
import { GATEWAY_MAX_BATCH_ROWS } from "./batch-commit.js";

/** `committed`: the row is written. `fallback`: it is not; use the per-stream path. */
export type BatchTurn = "committed" | "fallback";

export interface DeleteBatcher {
  /** Park a signed row of namespace `ns` (a fence, or a stream under it) for the request. */
  submit(
    row: SignedBatchRow,
    part: { readonly ns: string; readonly fence: boolean },
  ): Promise<BatchTurn>;
  /** This participant has no row to send. */
  leave(): void;
}

interface Parked {
  readonly row: SignedBatchRow;
  readonly ns: string;
  readonly fence: boolean;
  readonly settle: (turn: BatchTurn) => void;
  readonly fail: (error: unknown) => void;
}

export function createDeleteBatcher(options: {
  readonly registry: StreamSyncRegistry;
  readonly ownerAddress: string;
  readonly controlScopeOf: (ns: string) => string;
  /** The version each namespace's control row held when the delete was planned. */
  readonly pins: ReadonlyMap<string, number>;
  readonly hashes: Pick<ControlHashes, "activeData" | "tombstoneData">;
  /** Fences plus streams: each calls `submit` or `leave` once. */
  readonly participants: number;
  /** The registry answered that it has no batch route. */
  readonly onUnusable: () => void;
  /** The registry refused the request (HTTP 4xx other than 409): a defect to surface. */
  readonly onRefused: (error: RegistryRefusedError) => void;
}): DeleteBatcher {
  let outstanding = options.participants;
  const parked: Parked[] = [];

  /**
   * The fence rows carry their own compare-and-set. The stream rows of a
   * namespace rest on that namespace's fence having landed.
   */
  const requiresFor = (chunk: readonly Parked[]): RegistryRequirement[] => {
    const requires: RegistryRequirement[] = [];
    const seen = new Set<string>();
    for (const part of chunk) {
      if (part.fence || seen.has(part.ns)) continue;
      seen.add(part.ns);
      requires.push({
        scope: options.controlScopeOf(part.ns),
        expectedVersion: String(options.pins.get(part.ns)! + 1),
        notDeleted: false,
        expectedDataHash: options.hashes.tombstoneData,
      });
    }
    return requires;
  };

  /** True when the request went through and every fence row of the chunk is written. */
  async function send(chunk: readonly Parked[]): Promise<boolean> {
    const request = {
      ownerAddress: options.ownerAddress,
      rows: chunk.map((p) => p.row),
      requires: requiresFor(chunk),
    };
    const fallbackAll = () => {
      for (const p of chunk) p.settle("fallback");
      return false;
    };
    try {
      let answer;
      try {
        answer = await options.registry.postBatch!(request);
      } catch (error) {
        if (!(error instanceof AmbiguousRegistryReplyError)) throw error;
        // The first send may have landed. The same request again answers a
        // row it holds as a conflict and fails its conditions: both fall back.
        answer = await options.registry.postBatch!(request);
      }
      if (answer.kind === "unsupported") {
        options.onUnusable();
        return fallbackAll();
      }
      if (answer.kind === "precondition_failed") return fallbackAll();
      let all = true;
      for (const [i, p] of chunk.entries()) {
        if (answer.rows[i]!.kind === "committed") {
          p.settle("committed");
        } else {
          p.settle("fallback");
          if (p.fence) all = false;
        }
      }
      return all;
    } catch (error) {
      if (error instanceof RegistryRefusedError && error.status !== 409) {
        // The delete still ends, by the per-stream path. The refusal is
        // reported: the gateway judged the request wrong, and a caller that
        // swallowed that would never be fixed.
        options.onRefused(error);
        return fallbackAll();
      }
      for (const p of chunk) p.fail(error);
      return false;
    }
  }

  async function flush() {
    const byScope = (a: Parked, b: Parked) =>
      a.row.scope < b.row.scope ? -1 : a.row.scope > b.row.scope ? 1 : 0;
    const rows = parked.splice(0);
    const split = (list: Parked[]) => {
      const chunks: Parked[][] = [];
      for (let i = 0; i < list.length; i += GATEWAY_MAX_BATCH_ROWS)
        chunks.push(list.slice(i, i + GATEWAY_MAX_BATCH_ROWS));
      return chunks;
    };
    const fences = split(rows.filter((p) => p.fence).sort(byScope));
    const streams = split(rows.filter((p) => !p.fence).sort(byScope));
    let healthy = true;
    for (const chunk of fences) {
      if (!healthy) {
        for (const p of chunk) p.settle("fallback");
        continue;
      }
      healthy = await send(chunk);
    }
    if (!healthy) {
      for (const chunk of streams) for (const p of chunk) p.settle("fallback");
      return;
    }
    await Promise.all(streams.map(send));
  }

  const arrived = () => {
    outstanding--;
    if (outstanding === 0 && parked.length > 0) void flush();
  };
  return {
    submit: (row, part) =>
      new Promise<BatchTurn>((settle, fail) => {
        parked.push({ row, ...part, settle, fail });
        arrived();
      }),
    leave: arrived,
  };
}
