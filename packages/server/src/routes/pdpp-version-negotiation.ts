import type { Context, MiddlewareHandler } from "hono";
import { assertSupportedPdppVersion } from "@opendatalabs/personal-server-ts-core/api";
import { PdppError } from "@opendatalabs/personal-server-ts-core/errors/pdpp";

/**
 * `PDPP-Version` negotiation shared by the Core RS routers (records, blobs).
 *
 * spec-core §8 "API versioning":
 * - the RS selects a contract or rejects with 400 (`invalid_request` for a
 *   malformed field, `unsupported_version` otherwise);
 * - "These rules do not override … the authentication requirements of this
 *   section: an inactive token still produces the required HTTP 401";
 * - "No request with an invalid or unsupported version may disclose protected
 *   data or perform the requested operation";
 * - "When version validation fails without selecting a contract, the RS MUST
 *   omit that response field."
 *
 * So the middleware only records the outcome. The route's authentication step
 * reports the version error once the token is known to be active
 * (`pdppVersionFailure`). As a safety net, a request whose negotiation failed
 * can never leave with a success status, and never with a `PDPP-Version`
 * field.
 */
const failures = new WeakMap<Request, PdppError>();

export function pdppVersionFailure(c: Context): PdppError | undefined {
  return failures.get(c.req.raw);
}

export function pdppVersionMiddleware(
  requestId: () => string,
): MiddlewareHandler {
  // Register it only on a router's own Core paths (see pdppRecordsRoutes):
  // a "*" registration on a router mounted under a shared prefix also wraps
  // sibling routers mounted later under that prefix.
  return async (c, next) => {
    try {
      assertSupportedPdppVersion(c.req.header("PDPP-Version"));
    } catch (error) {
      if (!(error instanceof PdppError)) throw error;
      failures.set(c.req.raw, error);
    }
    await next();
    const failure = failures.get(c.req.raw);
    if (!failure) return;
    if (c.res.status < 400) {
      // A route served the request without passing through authentication
      // (or ignored the failure). Refuse rather than disclose. The refusal is
      // a fresh Response: `c.json` would carry the route's pending headers
      // (a redirect's Location), and the `c.res` setter copies the refused
      // response's headers onto its replacement unless `c.res` is cleared.
      c.res = undefined as unknown as Response;
      c.res = new Response(JSON.stringify(failure.toJSON(requestId())), {
        status: failure.status,
        headers: {
          "Content-Type": "application/json",
          "Cache-Control": "private, no-store",
          "Request-Id": requestId(),
        },
      });
    }
    c.res.headers.delete("PDPP-Version");
  };
}

/** Response headers for an RS response: `PDPP-Version` only when a contract was selected. */
export function versionedHeaders(
  c: Context,
  headers: Record<string, string>,
  selected: string,
): Record<string, string> {
  if (pdppVersionFailure(c)) {
    const { "PDPP-Version": _omitted, ...rest } = headers;
    return rest;
  }
  return { ...headers, "PDPP-Version": selected };
}
