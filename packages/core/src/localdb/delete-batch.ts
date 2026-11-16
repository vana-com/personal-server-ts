/**
 * The fences of a connection delete (one control tombstone per namespace) as
 * batch requests on `POST /v1/data/batch`, within the bounds the gateway
 * advertises. Each request is one all-or-nothing transaction: every row lands,
 * or none does. A gateway that serves no batch contract fails the delete
 * (`RegistryBatchRouteMissingError`): there is no per-row path for it.
 *
 * - A request the gateway refuses writes nothing. A row the gateway already
 *   held (a replay: the same tombstone, written by this delete before or by
 *   another device's delete) answers `committed`. A row that lost its
 *   compare-and-set answers `not_written`, and the other rows go again at once
 *   without it: each refusal drops at least one row, since the gateway names
 *   the row that lost.
 * - A request with no answer (no reply twice, or a failure that says nothing
 *   of the rows) answers `not_written` for its rows: they may have landed.
 * - The caller reads each row that is not `committed` again and writes it
 *   alone (delete.ts `landFence`), as a resumed delete does.
 * - A refusal of the request itself (no batch contract, a request the gateway
 *   judged malformed) throws: it is not a race to recover from.
 */
import {
  AmbiguousRegistryReplyError,
  RegistryBatchRouteMissingError,
  RegistryRefusedError,
  type SignedBatchRow,
  type StreamSyncRegistry,
} from "../stream-sync/ports.js";
import { requireBatchPolicy } from "./batch-commit.js";

export type FenceTurn = "committed" | "not_written";

/** One turn per row, in the order of `rows`. */
export async function commitFences(options: {
  readonly registry: StreamSyncRegistry;
  readonly ownerAddress: string;
  readonly rows: readonly SignedBatchRow[];
}): Promise<readonly FenceTurn[]> {
  const { rows: bound } = await requireBatchPolicy(options.registry);
  const turns: FenceTurn[] = options.rows.map(() => "not_written");
  const indexes = options.rows.map((_, i) => i);
  const chunks: number[][] = [];
  for (let at = 0; at < indexes.length; at += bound)
    chunks.push(indexes.slice(at, at + bound));
  // Each fence is a compare-and-set on its own row, so the requests go
  // together.
  await Promise.all(chunks.map((chunk) => send(chunk)));
  return turns;

  async function send(chunk: readonly number[]) {
    let pending = chunk;
    try {
      while (pending.length > 0) {
        const request = {
          ownerAddress: options.ownerAddress,
          rows: pending.map((i) => options.rows[i]!),
          requires: [],
        };
        let answer;
        try {
          answer = await options.registry.postBatch!(request);
        } catch (error) {
          if (!(error instanceof AmbiguousRegistryReplyError)) throw error;
          // The first send may have landed. The same request again answers
          // the rows it holds as replays.
          answer = await options.registry.postBatch!(request);
        }
        if (answer.kind === "committed") {
          for (const i of pending) turns[i] = "committed";
          return;
        }
        // A request with no conditions fails none; the per-row pass decides.
        if (answer.kind === "precondition_failed") return;
        // Refused: nothing of the request was written. A replay is stored all
        // the same; the rows that lost leave; the rest go again.
        const rest: number[] = [];
        for (const [at, i] of pending.entries()) {
          const row = answer.rows[at]!;
          if (row.kind === "committed") turns[i] = "committed";
          else if (row.kind === "not_written") rest.push(i);
        }
        pending = rest;
      }
    } catch (error) {
      if (
        error instanceof RegistryBatchRouteMissingError ||
        error instanceof RegistryRefusedError
      )
        throw error;
      // No answer: the per-row pass reads each row.
    }
  }
}
