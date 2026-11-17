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

/** AWS NAT gateways drop a connection that has carried no packet for 350 s. */
const NAT_IDLE_DROP_MS = 350_000;
/** Close our side before the NAT drops it, so no request meets a dead socket. */
const NAT_MARGIN_MS = 50_000;
/** How long an idle connection stays open: 300 s. */
export const KEEP_ALIVE_IDLE_MS = NAT_IDLE_DROP_MS - NAT_MARGIN_MS;

/**
 * A `fetch` that sends through one shared connection pool with
 * {@link KEEP_ALIVE_IDLE_MS} of idle keep-alive. It wraps `send`, which is the
 * `globalThis.fetch` of the moment it is created, as the clients that default
 * to `globalThis.fetch` capture it. The pool belongs to the caller, not to the
 * process.
 */
export function createKeepAliveFetch(send: typeof fetch = globalThis.fetch) {
  const dispatcher = new Agent({
    // Used when the peer sends no `Keep-Alive` hint; `keepAliveMaxTimeout` is
    // the cap on a peer's hint and defaults to 600 s, which is above the NAT's
    // drop, so it is lowered with the idle timeout.
    keepAliveTimeout: KEEP_ALIVE_IDLE_MS,
    keepAliveMaxTimeout: KEEP_ALIVE_IDLE_MS,
  });
  const keepAliveFetch: typeof fetch = (input, init) =>
    send(input, { ...init, dispatcher } as RequestInit);
  return keepAliveFetch;
}
