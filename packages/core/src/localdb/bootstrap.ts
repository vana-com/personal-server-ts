import type { ConnectionRow, LocalSyncDeps } from "./deps.js";

/**
 * C.0 step 1: list the registry's control rows and upsert one `connections`
 * row per control scope (classification is `classifyControl`). A deleted
 * control row whose connection still has rows runs the local purge (F.5).
 * Returns the connections now known. Spec: C.0.
 */
export async function bootstrapConnections(
  deps: LocalSyncDeps,
): Promise<readonly ConnectionRow[]> {
  void deps;
  throw new Error("PS-2: not built");
}

/**
 * C.0 step 2, inside the connection queue and before any row is staged:
 * read the control row and the stream rows, then apply every stream whose
 * registry version differs from `head_version` or whose `head_parts` is empty
 * while `head_version > 0`. `unreachable` = the registry did not answer (C.0
 * step 3); the caller then stages the run `generation_unbound` or answers
 * `ok:false` in the embed frame.
 */
export async function syncBeforeBegin(
  deps: LocalSyncDeps,
  connector: string,
): Promise<{
  readonly connection: ConnectionRow | null;
  readonly unreachable: boolean;
}> {
  void deps;
  void connector;
  throw new Error("PS-2: not built");
}
