import { publishLog } from "./log-publish.js";
import { ELIGIBLE_CHANGE } from "./publication-work.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * A read may attest the accepted log only while none of its input streams
 * has unpublished edits. Apply preserves such edits over remote rows; a
 * stream's installed head counter alone therefore cannot prove coverage.
 *
 * Publication advances publish_watermark and log_state in the acceptance
 * transaction. Remote applies run under the connection queue. Call this
 * while holding that queue when deciding a body; its existing row epoch pin
 * keeps a later write from leaking into a paged body.
 */
export async function registeredReadPosition(
  deps: Pick<LocalSyncDeps, "db">,
  connectionId: string,
  streams: readonly string[],
): Promise<number | null> {
  if (streams.length === 0) return null;
  const [row] = await deps.db.query<{ position: number }>(
    `SELECT l.position FROM log_state l WHERE l.connection_id=? AND l.position>0
       AND NOT EXISTS (SELECT 1 FROM log_keyed_pending k WHERE k.connection_id=l.connection_id)
       AND NOT EXISTS (
         SELECT 1 FROM record_changes JOIN stream_state s
           ON s.connection_id=record_changes.connection_id AND s.stream=record_changes.stream
         WHERE record_changes.connection_id=l.connection_id AND record_changes.stream IN (${streams.map(() => "?").join(",")})
           AND seq>s.publish_watermark AND ${ELIGIBLE_CHANGE})`,
    [connectionId, ...streams],
  );
  return row?.position ?? null;
}

/** Try the existing publisher once; the caller reselects its body afterwards. */
export async function ensureRegisteredRead(
  deps: LocalSyncDeps,
  connectionId: string,
  streams: readonly string[],
  signal?: AbortSignal,
): Promise<boolean> {
  if (signal?.aborted) return false;
  if ((await registeredReadPosition(deps, connectionId, streams)) !== null)
    return true;
  try {
    signal?.throwIfAborted();
    // publishLog owns its queue slots. A request ending stops its wait, not
    // the shared publication's registration/reconciliation obligation.
    const publication = publishLog(deps, connectionId);
    if (!signal) await publication;
    else {
      let abort: () => void = () => {};
      try {
        await Promise.race([
          publication,
          new Promise<never>((_, reject) => {
            abort = () => reject(signal.reason);
            signal.addEventListener("abort", abort, { once: true });
            if (signal.aborted) abort();
          }),
        ]);
      } finally {
        signal.removeEventListener("abort", abort);
      }
    }
  } catch (error) {
    deps.logger.warn(
      { error: String(error) },
      "paid read publication did not complete",
    );
  }
  return (
    !signal?.aborted &&
    (await registeredReadPosition(deps, connectionId, streams)) !== null
  );
}
