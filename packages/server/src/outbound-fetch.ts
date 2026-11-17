import { Agent } from "undici";

/**
 * The Node host's outbound `fetch` for the data gateway and storage.
 *
 * Node's built-in `fetch` closes an idle connection after 4 seconds, and the
 * gateway and storage send no `Keep-Alive` hint that would raise that. A save
 * comes seconds to minutes after the last request, so with the default every
 * request opens a new TCP and TLS connection first. This transport keeps an
 * idle connection for
 * {@link KEEP_ALIVE_IDLE_MS}, and `undici` opens a fresh one when the peer has
 * closed an idle connection before the next request.
 */

/**
 * How long an idle connection stays open: 300 s.
 *
 * The number covers the save gaps measured from a Desktop host, 15 s to 252 s
 * between requests. We could not measure the server side: the gateway and the
 * storage each held an idle connection open for the full 480 s of the
 * measurement, 3 connections per host, and none closed. So no server idle
 * timeout is known to be shorter than this value. If one is, `undici` opens a
 * new connection when it sees the close, and a request that meets the close
 * mid-flight is sent again (see `createKeepAliveFetch`).
 *
 * Separately, `undici` turns on TCP keepalive probes after 60 s of idle, so a
 * home router's connection table does not drop a quiet connection earlier.
 */
export const KEEP_ALIVE_IDLE_MS = 300_000;

/** Methods that are safe to send again: no body, and no effect on the peer. */
const RESENDABLE = new Set(["GET", "HEAD"]);

function methodOf(input: Parameters<typeof fetch>[0], init?: RequestInit) {
  const method =
    init?.method ?? (input instanceof Request ? input.method : "GET");
  return method.toUpperCase();
}

/**
 * The peer closed a connection as this request went out, after the connection
 * had received bytes: `undici` fails the request with `UND_ERR_SOCKET` and does
 * not retry. `bytesRead > 0` is what the check can see. It holds for a reused
 * connection, and it also holds when the peer sent part of a reply to this
 * request, or (over TLS) only its handshake. It does not prove the request
 * never reached the peer. That is safe because only GET and HEAD are resent,
 * and only once.
 */
function resetReusedSocket(error: unknown): boolean {
  const cause = (error as { cause?: { code?: string; socket?: SocketInfo } })
    ?.cause;
  return cause?.code === "UND_ERR_SOCKET" && (cause.socket?.bytesRead ?? 0) > 0;
}
interface SocketInfo {
  bytesRead?: number;
}

/** The default for {@link KeepAliveFetchOptions.closeGraceMs}. */
export const CLOSE_GRACE_MS = 5_000;

export interface KeepAliveFetch {
  readonly fetch: typeof fetch;
  /**
   * Waits for requests in flight to finish, then closes every connection. A
   * request still running when the grace time ends is aborted, and so is a
   * response body its caller has not finished reading. For shutdown, after the
   * callers that matter have drained. Calling it again returns when the first
   * call has finished.
   */
  close(): Promise<void>;
}

export interface KeepAliveFetchOptions {
  /** How long `close` waits for requests in flight. Default: 5 s. */
  closeGraceMs?: number;
}

/**
 * A `fetch` that sends through one shared connection pool with
 * {@link KEEP_ALIVE_IDLE_MS} of idle keep-alive. It wraps `send`, which is the
 * `globalThis.fetch` of the moment it is created, as the clients that default
 * to `globalThis.fetch` capture it. The pool belongs to the caller, which
 * closes it with `close`.
 *
 * A GET or HEAD that fails because the peer reset a reused connection is sent
 * once more, on another connection. Nothing else is resent: a write that failed
 * this way may have reached the peer, and its caller decides.
 */
export function createKeepAliveFetch(
  send: typeof fetch = globalThis.fetch,
  { closeGraceMs = CLOSE_GRACE_MS }: KeepAliveFetchOptions = {},
): KeepAliveFetch {
  const dispatcher = new Agent({
    // Used when the peer sends no `Keep-Alive` hint; `keepAliveMaxTimeout` is
    // the cap on a peer's hint and defaults to 600 s, so it is lowered with the
    // idle timeout.
    keepAliveTimeout: KEEP_ALIVE_IDLE_MS,
    keepAliveMaxTimeout: KEEP_ALIVE_IDLE_MS,
  });
  const pastGrace = new AbortController();
  const through = (input: Parameters<typeof fetch>[0], init?: RequestInit) => {
    // `fetch` takes the signal of `init` over the one of a `Request`.
    const own =
      init?.signal ?? (input instanceof Request ? input.signal : undefined);
    return send(input, {
      ...init,
      signal: own ? AbortSignal.any([own, pastGrace.signal]) : pastGrace.signal,
      dispatcher,
    } as RequestInit);
  };
  const keepAliveFetch: typeof fetch = async (input, init) => {
    try {
      return await through(input, init);
    } catch (error) {
      if (!RESENDABLE.has(methodOf(input, init)) || !resetReusedSocket(error))
        throw error;
      return through(input, init);
    }
  };
  const close = async () => {
    // `Agent.close` destroys the agent when it is done, and `close` on a
    // destroyed agent rejects. A close that runs while another is open joins it.
    if (dispatcher.destroyed) return;
    // The end of the grace time aborts what is still running through its
    // signal. `Agent.destroy` cannot: `Agent.close` empties the agent's table
    // of pools as it starts, so a `destroy` after it reaches no pool. Measured
    // on undici 7.30 with Node 22 and 24: after `close` then `destroy`, a
    // request without headers and a body not yet read both stay pending, and
    // `close` never settles.
    const timer = setTimeout(() => pastGrace.abort(), closeGraceMs);
    try {
      await dispatcher.close();
    } finally {
      clearTimeout(timer);
    }
  };
  return { fetch: keepAliveFetch, close };
}
