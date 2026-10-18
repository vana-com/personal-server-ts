/**
 * Validation for OAuth `redirect_uri` values accepted by the MCP OAuth
 * endpoints (authorize, error redirects, dynamic client registration).
 *
 * Rules:
 * - must parse as an absolute URL and carry no fragment (RFC 6749 3.1.2);
 * - `https:` is allowed;
 * - `http:` is allowed only for loopback hosts (RFC 8252 7.3);
 * - other (private-use) schemes are allowed so native MCP clients keep
 *   working (RFC 8252 7.1), except schemes that browsers execute or resolve
 *   locally instead of handing to an application.
 */

const DENIED_REDIRECT_SCHEMES = new Set([
  "javascript:",
  "data:",
  "file:",
  "vbscript:",
  "blob:",
  "about:",
  "filesystem:",
]);

function isLoopbackHost(hostname: string): boolean {
  if (hostname === "localhost") return true;
  if (hostname === "[::1]") return true;
  // WHATWG URL parsing canonicalizes IPv4 hosts to dotted-decimal.
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

export function isAllowedOAuthRedirectUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0) return false;
  if (value.includes("#")) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  const protocol = url.protocol.toLowerCase();
  if (DENIED_REDIRECT_SCHEMES.has(protocol)) return false;
  if (protocol === "https:") return url.hostname.length > 0;
  if (protocol === "http:") return isLoopbackHost(url.hostname);
  return true;
}
