/**
 * CORS for browser-based clients (allow all origins).
 *
 * A browser preflight only passes when every non-safelisted request header is
 * listed in Access-Control-Allow-Headers, and a browser can only read a
 * non-safelisted response header that is listed in
 * Access-Control-Expose-Headers. Both lists therefore have to track every
 * custom header the API reads or writes on a browser-reachable route; the
 * Write API (delegated ingest) is the first path a builder app calls straight
 * from the browser. Header names are case-insensitive (Fetch).
 */

import { cors } from "hono/cors";
import { WRITE_SIGNATURE_HEADER } from "@opendatalabs/personal-server-ts-core/write";

/** Request headers the API reads that are not CORS-safelisted. */
export const CORS_ALLOW_HEADERS: readonly string[] = [
  "Content-Type",
  "Authorization",
  // Write API: builder-signed payload proof on delegated ingest
  // (api-auth authorizeWrite -> verifyWriterAttribution).
  WRITE_SIGNATURE_HEADER,
  // Ingest hints (core handlePersonalServerDataRequest).
  "X-Vana-Metadata",
  "X-Filename",
  "Content-Disposition",
  // Granted / paid reads.
  "X-PS-Grant-Id",
  "X-PAYMENT",
];

/** Response headers a browser client must be able to read back. */
export const CORS_EXPOSE_HEADERS: readonly string[] = [
  "X-Vana-Metadata",
  "X-PAYMENT-RESPONSE",
  "Content-Disposition",
];

export const CORS_ALLOW_METHODS: readonly string[] = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "OPTIONS",
];

export function corsMiddleware() {
  return cors({
    origin: "*",
    allowHeaders: [...CORS_ALLOW_HEADERS],
    exposeHeaders: [...CORS_EXPOSE_HEADERS],
    allowMethods: [...CORS_ALLOW_METHODS],
    maxAge: 86400,
  });
}
