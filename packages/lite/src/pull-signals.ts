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

export interface VisibilityPausable {
  pause?: () => void;
  resume?: () => void;
}

/**
 * Hides stop the sync manager's requests and timers; shows start them again
 * (`SyncManager.pause` and `resume`). A hidden tab has no one to show a change
 * to, so it holds no push request and runs no timer, and `startPullSignals`
 * pulls once when it is shown. Start this before `startPullSignals`: both
 * listen to `visibilitychange`, and the manager must be running again before
 * the pull asks it for a probe. A page that starts hidden pauses at once.
 * Where there is no page (a worker, Node), nothing is paused. The returned
 * function removes the listener.
 */
export function startVisibilityPause(
  manager: VisibilityPausable,
  sources: Pick<PullSignalSources, "document"> = {
    document: (globalThis as { document?: PullSignalSources["document"] })
      .document,
  },
): () => void {
  const doc = sources.document;
  if (!doc) return () => {};
  const apply = () => {
    try {
      if (doc.visibilityState === "hidden") manager.pause?.();
      else manager.resume?.();
    } catch {
      // A manager that refuses is not the page's problem.
    }
  };
  doc.addEventListener("visibilitychange", apply);
  if (doc.visibilityState === "hidden") apply();
  return () => doc.removeEventListener("visibilitychange", apply);
}
