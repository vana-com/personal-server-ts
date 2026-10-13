import type { Context, MiddlewareHandler } from "hono";

export interface LoopbackListenerDeps {
  /**
   * Port of the loopback-only auth listener (see `index.ts`). The dev UI is
   * served ONLY to connections that arrived on this listener. `undefined`
   * (cloud mode, or not yet bound) means the UI is never served.
   */
  localApprovalPort: number | undefined;
  /**
   * The main (tunneled) server port. If the loopback port collides with it
   * the loopback bind fails but the port value survives, and every tunneled
   * request would match — so a collision disables the UI outright.
   */
  serverPort?: number;
}

const LOOPBACK_V4 = /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

/** Socket-level check: is this IP address (not a hostname) loopback? */
export function isLoopbackIp(address: string | undefined): boolean {
  if (!address) return false;
  return (
    address === "::1" ||
    address === "::ffff:127.0.0.1" ||
    LOOPBACK_V4.test(address)
  );
}

/**
 * Host-header check (DNS-rebinding defense). A hostile page can point a
 * name it controls at 127.0.0.1 and then fetch
 * `http://attacker.example:<port>/ui`; the browser sends that name as both
 * `Host` and `Origin`, so origin equality alone would pass and the browser
 * would treat the response as same-origin. Only loopback literals and the
 * exact name `localhost` may address this listener. (`URL.hostname` keeps
 * IPv6 brackets.)
 */
function isLoopbackRequestHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname === "::1" ||
    LOOPBACK_V4.test(hostname)
  );
}

function getSocket(
  c: Context,
): { localPort?: unknown; localAddress?: unknown } | undefined {
  // Access the Node.js socket via Hono's env bindings when running on the
  // real server (@hono/node-server sets `c.env.incoming`).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return (c.env as any)?.incoming?.socket;
}

/**
 * Browser check. A cross-origin fetch always carries an `Origin` header
 * naming the requesting site; same-origin navigations carry none, and the
 * page's own fetches (if the browser adds one) carry the page's origin,
 * which is this listener's origin. Anything else is another page in the
 * user's browser probing the loopback listener — the app's global CORS is
 * `*`, and not every browser enforces Private Network Access.
 *
 * Exact equality against the request's own origin, deliberately: hostname
 * heuristics are bypassable (`127.attacker.example` is a public name), and
 * another *local* origin such as `http://localhost:12345` must not read
 * this page either. Combined with the Host allowlist above, the request
 * origin itself is guaranteed to be a loopback origin.
 */
function hasForeignOrigin(c: Context, requestOrigin: string): boolean {
  const origin = c.req.header("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin !== requestOrigin;
  } catch {
    return true;
  }
}

/**
 * Fetch Metadata check. Browsers that send `Sec-Fetch-Site` label every
 * request with its initiator; only the page itself (`same-origin`) and a
 * user-typed or externally opened URL (`none`) may act on the loopback
 * listener.
 */
function hasCrossSiteFetchMetadata(c: Context): boolean {
  const site = c.req.header("sec-fetch-site");
  if (site === undefined) return false;
  return site !== "same-origin" && site !== "none";
}

/**
 * Request-level half of the loopback gate, for routes that cannot 404 the
 * whole subtree: the request addressed this server by a loopback name and
 * was not issued by another browser origin. Socket checks (listener port,
 * peer address) are the caller's job.
 */
/**
 * The raw Host header names the same host as the request URL. Node builds
 * `c.req.url` from an absolute-form request line (`POST http://localhost/...`)
 * and ignores Host, so a forwarder that passes the request line through could
 * pair a loopback URL with a public Host. Require both to agree. A request
 * with no Host never reaches a handler on the real server (node-server answers
 * 400), so an absent header only occurs in-process and has nothing to disagree
 * with; the socket checks still apply.
 */
function hostHeaderMatchesUrl(c: Context, requestUrl: URL): boolean {
  const host = c.req.header("host");
  if (!host) return true;
  try {
    return new URL(`${requestUrl.protocol}//${host}`).host === requestUrl.host;
  } catch {
    return false;
  }
}

export function isSameOriginLoopbackRequest(c: Context): boolean {
  let requestUrl: URL;
  try {
    requestUrl = new URL(c.req.url);
  } catch {
    return false;
  }
  return (
    isLoopbackRequestHost(requestUrl.hostname) &&
    hostHeaderMatchesUrl(c, requestUrl) &&
    !hasForeignOrigin(c, requestUrl.origin) &&
    !hasCrossSiteFetchMetadata(c)
  );
}

/**
 * Socket-level half of the loopback gate: the connection was accepted by the
 * loopback auth listener (its port, on a loopback address). This is the one
 * fact a remote caller cannot influence — the tunnel forwards the main port
 * only, and `Host` is just a header. Fails closed when the listener is not
 * configured, collides with the main port, or there is no socket info.
 */
export function arrivedOnLoopbackListener(
  c: Context,
  deps: LoopbackListenerDeps,
): boolean {
  const port = deps.localApprovalPort;
  if (port === undefined || port === deps.serverPort) return false;
  const socket = getSocket(c);
  return (
    !!socket &&
    socket.localPort === port &&
    isLoopbackIp(
      typeof socket.localAddress === "string" ? socket.localAddress : undefined,
    )
  );
}

/**
 * Restrict a route subtree to requests that physically arrived on the
 * loopback auth listener, addressed it by a loopback name, and did not come
 * from another browser origin.
 *
 * Why the listener port and not the peer address: the tunnel client (frpc)
 * runs on the same host and connects to the MAIN server port from
 * 127.0.0.1, so every tunneled request already looks local by
 * `remoteAddress`. The one thing a remote caller can never influence is
 * which listening socket accepted the connection — the tunnel forwards to
 * `config.server.port` only, never to the loopback auth port.
 *
 * Fails closed: no socket information (tests, non-Node runtimes), no
 * loopback listener configured, a port collision, or an unparseable URL →
 * 404, so the subtree is invisible.
 */
export function requireLoopbackListener(
  deps: LoopbackListenerDeps,
): MiddlewareHandler {
  return async (c, next) => {
    if (!arrivedOnLoopbackListener(c, deps)) {
      return c.notFound();
    }
    let requestUrl: URL;
    try {
      requestUrl = new URL(c.req.url);
    } catch {
      return c.notFound();
    }
    if (!isLoopbackRequestHost(requestUrl.hostname)) {
      return c.notFound();
    }
    if (hasForeignOrigin(c, requestUrl.origin)) {
      return c.notFound();
    }
    await next();
  };
}
