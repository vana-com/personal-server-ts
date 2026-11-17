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
 * The peer closed a connection that had already answered a request, as this
 * request went out: undici fails the request with `UND_ERR_SOCKET` and does
 * not retry. The socket has read bytes only when an earlier request used it, so
 * a connection that failed on its first request is not this case.
 */
function resetReusedSocket(error: unknown): boolean {
  const cause = (error as { cause?: { code?: string; socket?: SocketInfo } })
    ?.cause;
  return cause?.code === "UND_ERR_SOCKET" && (cause.socket?.bytesRead ?? 0) > 0;
}
interface SocketInfo {
  bytesRead?: number;
}

export interface KeepAliveFetch {
  readonly fetch: typeof fetch;
  /**
   * Closes every connection and fails any request still in flight. For server
   * shutdown, after the callers that send through `fetch` have stopped.
   */
  close(): Promise<void>;
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
): KeepAliveFetch {
  const dispatcher = new Agent({
    // Used when the peer sends no `Keep-Alive` hint; `keepAliveMaxTimeout` is
    // the cap on a peer's hint and defaults to 600 s, so it is lowered with the
    // idle timeout.
    keepAliveTimeout: KEEP_ALIVE_IDLE_MS,
    keepAliveMaxTimeout: KEEP_ALIVE_IDLE_MS,
  });
  const through = (input: Parameters<typeof fetch>[0], init?: RequestInit) =>
    send(input, { ...init, dispatcher } as RequestInit);
  const keepAliveFetch: typeof fetch = async (input, init) => {
    try {
      return await through(input, init);
    } catch (error) {
      if (!RESENDABLE.has(methodOf(input, init)) || !resetReusedSocket(error))
        throw error;
      return through(input, init);
    }
  };
  return { fetch: keepAliveFetch, close: () => dispatcher.destroy() };
}
