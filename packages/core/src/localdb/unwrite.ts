import type { LocalSyncDeps } from "./deps.js";

/**
 * C.2 step 3: a run accepted at `end` but now refused is un-written in ONE
 * batch with origin `purge`: delete the stream's rows whose stamp is the
 * run's stamp AND delete the stream's `head_parts`. The caller then applies
 * at once (even at the same version), so rows the refused run overwrote come
 * back. DELETES USER DATA. Spec: C.2 step 3 (must-fix 2).
 */
export async function unwriteRefusedRun(
  deps: LocalSyncDeps,
  input: {
    readonly connectionId: string;
    readonly stream: string;
    readonly runId: string;
    readonly reason: "connector_update_required" | "out_of_order";
  },
): Promise<void> {
  void deps;
  void input;
  throw new Error("PS-2: not built");
}
