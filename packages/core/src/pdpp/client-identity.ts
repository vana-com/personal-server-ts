/**
 * Resolving a URL-hosted client identity, under a bounded fetch policy.
 *
 * §6 says a conforming AS MUST NOT reject a valid client ID metadata document
 * solely because the client is not preregistered, and MUST accept a valid
 * URL-hosted client identity unless local policy denies authorization. Before
 * this, the AS validated `redirect_uri` only against a config-supplied
 * registration, so an unregistered-but-valid client was refused for the one
 * reason the spec names as insufficient.
 *
 * ── Why this is not just "fetch the client_id" ──────────────────────────────
 *
 * The AS is being handed a URL by an untrusted caller and asked to fetch it.
 * That is a server-side request forgery primitive: without bounds, a client_id
 * of `http://169.254.169.254/...` turns the AS into a proxy for whatever the
 * deployment can reach. So this reuses `checkDeclarationUrl`, the same guard
 * the declaration retrieval path already applies — https-only, no private or
 * loopback literals, and the deployment's host allowlist unless it has
 * explicitly opted into any HTTPS host.
 *
 * The response is size-capped and redirect-bounded for the same reason: an
 * unbounded body is a memory exhaustion vector, and unbounded redirects defeat
 * the host check by hopping somewhere it would have refused.
 *
 * ── Registration still wins ────────────────────────────────────────────────
 *
 * A locally registered client is resolved from config without any fetch at
 * all. This path exists only for clients the deployment has NOT registered,
 * and a deployment that wants registration-only behavior gets it by leaving
 * the fetcher unset — in which case nothing here runs and the previous
 * behavior is preserved exactly.
 */

import {
  checkDeclarationUrl,
  type DeclarationTrustPolicy,
} from "./declaration.js";
import { verifyClientIdDocument } from "./client-metadata.js";
import type { RegisteredRedirectPolicy } from "./redirect.js";

/** Bodies larger than this are refused rather than buffered. */
export const MAX_CLIENT_DOCUMENT_BYTES = 64 * 1024;

export type ClientIdentityFailureCode =
  | "untrusted_client_url"
  | "fetch_failed"
  | "invalid_document"
  | "client_id_mismatch"
  | "too_large";

export interface ClientIdentityFailure {
  code: ClientIdentityFailureCode;
  message: string;
}

/**
 * Retrieves a client ID metadata document. Injected so the deployment owns
 * the transport, and so that leaving it unset disables this path entirely.
 */
export type ClientDocumentFetcher = (
  url: string,
) => Promise<{ status: number; body: string; finalUrl: string } | null>;

export interface ResolveClientIdentityOptions {
  clientId: string;
  fetcher: ClientDocumentFetcher;
  /** Reuses the declaration trust policy; same bounds, same allowlist. */
  policy: DeclarationTrustPolicy;
}

export type ClientIdentityResult =
  | { ok: true; policy: RegisteredRedirectPolicy; verifiedDomain: string }
  | { ok: false; failure: ClientIdentityFailure };

/**
 * Resolve a `client_id` URL into a redirect policy the AS can enforce.
 *
 * Returns the same `RegisteredRedirectPolicy` shape a config registration
 * produces, so the caller's redirect validation is unchanged — a URL-hosted
 * client is subject to exactly the same exact-match redirect rule as a
 * registered one, rather than a looser path.
 */
export async function resolveUrlHostedClientIdentity(
  options: ResolveClientIdentityOptions,
): Promise<ClientIdentityResult> {
  const { clientId, fetcher, policy } = options;

  // A non-URL client_id is not a URL-hosted identity. Not an error here —
  // the caller falls back to registration-only behavior.
  let parsed: URL;
  try {
    parsed = new URL(clientId);
  } catch {
    return {
      ok: false,
      failure: {
        code: "untrusted_client_url",
        message: "client_id is not a URL-hosted identity",
      },
    };
  }

  // The SSRF gate, before any network call.
  const urlProblem = checkDeclarationUrl(parsed.toString(), policy);
  if (urlProblem) {
    return {
      ok: false,
      failure: {
        code: "untrusted_client_url",
        message: urlProblem.message,
      },
    };
  }

  let retrieved: Awaited<ReturnType<ClientDocumentFetcher>>;
  try {
    retrieved = await fetcher(parsed.toString());
  } catch (err) {
    return {
      ok: false,
      failure: {
        code: "fetch_failed",
        message: err instanceof Error ? err.message : String(err),
      },
    };
  }

  if (!retrieved || retrieved.status !== 200) {
    return {
      ok: false,
      failure: {
        code: "fetch_failed",
        message: `client_id document returned ${retrieved?.status ?? "no response"}`,
      },
    };
  }

  if (retrieved.body.length > MAX_CLIENT_DOCUMENT_BYTES) {
    return {
      ok: false,
      failure: {
        code: "too_large",
        message: `client_id document exceeds ${MAX_CLIENT_DOCUMENT_BYTES} bytes`,
      },
    };
  }

  // A redirect may not escape the gate: re-check where we actually landed.
  const finalProblem = checkDeclarationUrl(retrieved.finalUrl, policy);
  if (finalProblem) {
    return {
      ok: false,
      failure: {
        code: "untrusted_client_url",
        message: `client_id document redirected to an untrusted location: ${finalProblem.message}`,
      },
    };
  }

  let document: {
    client_id?: unknown;
    client_name?: unknown;
    redirect_uris?: unknown;
  };
  try {
    document = JSON.parse(retrieved.body) as typeof document;
  } catch {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "client_id document is not valid JSON",
      },
    };
  }

  if (!Array.isArray(document.redirect_uris)) {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "client_id document declares no redirect_uris",
      },
    };
  }

  // The identity check: the document must assert the URL it came from.
  // Without this, any host could publish a document claiming to be someone
  // else's client_id.
  const verified = verifyClientIdDocument({
    client_id: String(document.client_id ?? ""),
    display: { name: String(document.client_name ?? "") },
    https: true,
    retrieved_from: retrieved.finalUrl,
  });
  if (!verified) {
    return {
      ok: false,
      failure: {
        code: "client_id_mismatch",
        message:
          "client_id document does not assert the URL it was retrieved from",
      },
    };
  }

  const redirectUris = document.redirect_uris.filter(
    (uri): uri is string => typeof uri === "string" && uri.length > 0,
  );
  if (redirectUris.length === 0) {
    return {
      ok: false,
      failure: {
        code: "invalid_document",
        message: "client_id document declares no usable redirect_uris",
      },
    };
  }

  return {
    ok: true,
    policy: { client_id: clientId, redirect_uris: redirectUris },
    verifiedDomain: verified.verifiedDomain,
  };
}
