import type { EndRequest, EndResult } from "../stream-sync/intake.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * Run end and abort, in the connection queue (C.1 "end"). Order: fence;
 * `planStreamStep` per stream on local state (refused = drop the stream's
 * `run_rows`; deferred or publish/noop = merge, store the decision, advance
 * the floor); then the checkpoint and retry rule in the SAME batch
 * (`retry_pending` merges what was received and saves the cursor of every
 * candidate stream); then the EndResult table. The result of `end` is
 * `EndResult`; `stuck` stays false until publish says otherwise.
 */
export interface RunEndStore {
  end(runId: string, req: EndRequest): Promise<{ readonly result: EndResult }>;
  abort(runId: string, reason: "failed" | "cancelled"): Promise<void>;
}

export function createRunEndStore(deps: LocalSyncDeps): RunEndStore {
  void deps;
  throw new Error("PS-2: not built");
}
