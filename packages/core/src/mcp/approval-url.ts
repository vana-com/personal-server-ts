/**
 * Where the owner answers an MCP client's scope request.
 *
 * `request_scope_access` only records a pending request; the owner decides it
 * on Vana Web (the same approval surface as app data connection requests).
 * The page loads the request from this server and posts the decision back to
 * `POST /v1/mcp/connections/:id/scope-request/{approve,deny}` with a
 * Web3Signed owner request, so the link has to name both the connection and
 * the server's public origin:
 *
 *   https://app.vana.org/mcp/requests/<connectionId>?ps_origin=<server origin>#t=<read token>
 *
 * `ps_origin` is the same param the MCP OAuth approval link carries. The page
 * treats it as a claim, never as proof: before it calls the server it checks
 * that the Gateway lists an active server registered by the signed-in owner
 * at exactly that origin.
 *
 * `t` is the request's read token. It lets the page load the request without
 * an owner signature (`GET /v1/mcp/connections/:id/scope-request` with the
 * `X-Vana-Scope-Request-Token` header), so the owner signs only to answer.
 * It sits in the fragment, which browsers never send to the web server or in
 * a Referer, and the page strips it from the address bar once read.
 */

/** Production Vana Web. */
export const VANA_WEB_ORIGIN = "https://app.vana.org";

/** Vana Web route that renders one MCP scope request. */
export const MCP_SCOPE_REQUEST_APPROVAL_PATH = "/mcp/requests";

/** Query param naming the server that holds the request. */
export const MCP_APPROVAL_PS_ORIGIN_PARAM = "ps_origin";

/** Fragment param carrying the request's read token. */
export const MCP_SCOPE_REQUEST_TOKEN_FRAGMENT_PARAM = "t";

/** What a host knows when the agent asks for a link. */
export interface McpScopeRequestApprovalUrlContext {
  /**
   * This server's current public origin (the Web3Signed audience): the
   * tunnel URL once it is up, otherwise the configured origin.
   */
  serverOrigin?: string;
  /**
   * Read token for the request just recorded. Put it in the link's fragment
   * (see {@link buildMcpScopeRequestApprovalUrl}); never in the query or path.
   */
  readToken?: string;
}

/**
 * Host hook: returns the page for one connection's pending request, or
 * undefined to keep pointing the owner at Vana without a link.
 */
export type McpScopeRequestApprovalUrlHook = (
  connectionId: string,
  context: McpScopeRequestApprovalUrlContext,
) => string | undefined;

function parseOrigin(value: string | undefined): URL | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:"
      ? url
      : undefined;
  } catch {
    return undefined;
  }
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "[::1]" ||
    hostname.endsWith(".localhost")
  );
}

/**
 * A page on `webOrigin` can only call a server it can reach: an https server
 * from anywhere, a loopback http server only from a loopback dev web origin
 * (a public https page cannot fetch http, and a phone cannot reach the
 * laptop's loopback at all).
 */
function isReachableFromWeb(web: URL, server: URL): boolean {
  if (server.protocol === "https:") return true;
  return isLoopbackHost(server.hostname) && isLoopbackHost(web.hostname);
}

/**
 * The approval link for one connection, or undefined when this server cannot
 * be reached from that web origin (no public origin yet, local-only http).
 */
export function buildMcpScopeRequestApprovalUrl(input: {
  connectionId: string;
  serverOrigin: string | undefined;
  webOrigin?: string;
  readToken?: string;
}): string | undefined {
  const web = parseOrigin(input.webOrigin ?? VANA_WEB_ORIGIN);
  const server = parseOrigin(input.serverOrigin);
  if (!web || !server || !input.connectionId) return undefined;
  if (!isReachableFromWeb(web, server)) return undefined;
  const url = new URL(
    `${MCP_SCOPE_REQUEST_APPROVAL_PATH}/${encodeURIComponent(input.connectionId)}`,
    web.origin,
  );
  url.searchParams.set(MCP_APPROVAL_PS_ORIGIN_PARAM, server.origin);
  if (input.readToken) {
    url.hash = new URLSearchParams({
      [MCP_SCOPE_REQUEST_TOKEN_FRAGMENT_PARAM]: input.readToken,
    }).toString();
  }
  return url.toString();
}

/**
 * Default hook for hosts that let Vana Web answer scope requests: builds the
 * link from the server's current public origin at the moment the agent asks.
 * Pass `webOrigin` for app-dev or a local web dev server.
 */
export function vanaWebMcpScopeRequestApprovalUrl(
  options: { webOrigin?: string } = {},
): McpScopeRequestApprovalUrlHook {
  return (connectionId, context) =>
    buildMcpScopeRequestApprovalUrl({
      connectionId,
      serverOrigin: context.serverOrigin,
      webOrigin: options.webOrigin,
      readToken: context.readToken,
    });
}
