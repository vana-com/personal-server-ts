/**
 * The first landing of a connection delete as batch requests: the control
 * fence and the stream tombstones of its namespaces in ONE `POST
 * /v1/data/batch` (split above the gateway's row limit).
 *
 * Each participant (a fence, or a stream) submits at most one signed row, or
 * leaves without one. When every participant has done one or the other the
 * rows go out. No timer: a participant is never waited for past its own work.
 *
 * Why the fence still comes first:
 * - A stream row of namespace N is sent only with a condition on N's control
 *   row. The gateway judges conditions on the state before the batch's writes,
 *   in the transaction of those writes. In the chunk that holds N's fence row
 *   the condition is "control is active at the pin" (so the fence write, a CAS
 *   at pin + 1, cannot lose and no later lifetime exists). In a later chunk it
 *   is "control is the tombstone at pin + 1" (the fence landed earlier).
 *   Either way no stream row lands unless the fence is in its commit or an
 *   earlier one.
 * - Rows are ordered fences first, then streams, and chunks are sent in that
 *   order up to the last chunk that holds a fence. Only the chunks after it
 *   (streams only, their fences already committed) go out together.
 * - A row that loses its CAS, a failed condition, a missing or refusing batch
 *   route, all answer `fallback`: nothing is guessed and the caller runs the
 *   per-stream path, which re-reads and re-checks everything itself.
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
  /** The registry answered that it has no batch route, or refused the request shape. */
  readonly onUnusable: () => void;
}): DeleteBatcher {
  let outstanding = options.participants;
  const parked: Parked[] = [];
  const landedFences = new Set<string>();

  const requiresFor = (chunk: readonly Parked[]): RegistryRequirement[] => {
    const requires: RegistryRequirement[] = [];
    const seen = new Set<string>();
    for (const part of chunk) {
      if (part.fence || seen.has(part.ns)) continue;
      seen.add(part.ns);
      const pin = options.pins.get(part.ns)!;
      const scope = options.controlScopeOf(part.ns);
      requires.push(
        chunk.some((q) => q.fence && q.ns === part.ns)
          ? {
              scope,
              expectedVersion: String(pin),
              notDeleted: true,
              expectedDataHash: options.hashes.activeData,
            }
          : {
              scope,
              expectedVersion: String(pin + 1),
              notDeleted: false,
              expectedDataHash: options.hashes.tombstoneData,
            },
      );
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
          if (p.fence) landedFences.add(p.ns);
          p.settle("committed");
        } else {
          p.settle("fallback");
          if (p.fence) all = false;
        }
      }
      return all;
    } catch (error) {
      if (error instanceof RegistryRefusedError && error.status !== 409) {
        // A gateway that refuses this request's shape (a limit it has and we
        // do not know) is no worse off than one without the route.
        options.onUnusable();
        return fallbackAll();
      }
      for (const p of chunk) p.fail(error);
      return false;
    }
  }

  async function flush() {
    const rows = parked
      .splice(0)
      .sort(
        (a, b) =>
          Number(b.fence) - Number(a.fence) ||
          (a.row.scope < b.row.scope ? -1 : a.row.scope > b.row.scope ? 1 : 0),
      );
    const chunks: Parked[][] = [];
    for (let i = 0; i < rows.length; i += GATEWAY_MAX_BATCH_ROWS)
      chunks.push(rows.slice(i, i + GATEWAY_MAX_BATCH_ROWS));
    // Fences sort first, so the chunks that hold one are a prefix.
    const lastFence = chunks.reduce(
      (last, chunk, i) => (chunk.some((p) => p.fence) ? i : last),
      -1,
    );
    let healthy = true;
    for (const [i, chunk] of chunks.entries()) {
      if (i > lastFence) break;
      if (!healthy) {
        for (const p of chunk) p.settle("fallback");
        continue;
      }
      healthy = await send(chunk);
    }
    const rest = chunks.slice(lastFence + 1);
    if (!healthy) {
      for (const chunk of rest) for (const p of chunk) p.settle("fallback");
      return;
    }
    await Promise.all(rest.map(send));
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
