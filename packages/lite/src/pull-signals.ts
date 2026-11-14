/**
 * Page signals that say remote state may have changed: the page became
 * visible, the window gained focus, the network came back. Each starts a pull
 * (`SyncManager.requestPull`): a registry probe, then a cycle if it moved.
 *
 * Prior art: TanStack Query refetches stale queries on `visibilitychange` and
 * on reconnect (`refetchOnWindowFocus`, `refetchOnReconnect`); Replicache pulls
 * on focus and when the connection returns. A burst (`visibilitychange`, then
 * `focus`) costs one pull: the manager coalesces requests.
 */

type Listenable = Pick<EventTarget, "addEventListener" | "removeEventListener">;

export interface PullSignalSources {
  /** Default: the global `document`, if there is one. */
  document?: Listenable & { visibilityState?: string };
  /** Default: the global `window`, if there is one. */
  window?: Listenable;
}

/** Starts the listeners; the returned function removes them. */
export function startPullSignals(
  onSignal: () => void,
  sources: PullSignalSources = {
    document: (globalThis as { document?: PullSignalSources["document"] })
      .document,
    window: (globalThis as { window?: PullSignalSources["window"] }).window,
  },
): () => void {
  // An event handler that throws would surface as an uncaught page error.
  const signal = () => {
    try {
      onSignal();
    } catch {
      // A failed request for a pull is not the page's problem.
    }
  };
  const doc = sources.document;
  const onVisibility = () => {
    if (doc?.visibilityState === "visible") signal();
  };
  doc?.addEventListener("visibilitychange", onVisibility);
  sources.window?.addEventListener("focus", signal);
  sources.window?.addEventListener("online", signal);
  return () => {
    doc?.removeEventListener("visibilitychange", onVisibility);
    sources.window?.removeEventListener("focus", signal);
    sources.window?.removeEventListener("online", signal);
  };
}
