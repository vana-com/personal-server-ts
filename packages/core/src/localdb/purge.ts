import type { LocalSyncDeps } from "./deps.js";

/**
 * F.5 step 1: the local purge of one connection, in the connection queue
 * (kind "purge"), in ONE batch with origin `purge`: delete the connection's
 * `records`, `run_rows`, `head_parts`, `blob_refs` and unreferenced `blobs`;
 * set `control_state='deleted'`; set `last_delete_version`; clear
 * `connections.checkpoint`. DELETES USER DATA. Spec: F.5, C.0 step 1.
 */
export async function purgeConnection(
  deps: LocalSyncDeps,
  connectionId: string,
  deleted: { readonly controlVersion: number },
): Promise<void> {
  void deps;
  void connectionId;
  void deleted;
  throw new Error("PS-2: not built");
}
