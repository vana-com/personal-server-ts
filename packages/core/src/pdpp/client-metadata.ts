/**
 * PDPP Core §6 requester-identity resolution.
 *
 * Two things the spec insists on keeping apart, and which are easy to conflate:
 *
 *   - **Verified domain control** means the AS retrieved this client's metadata
 *     from the client_id URL over HTTPS and the document identified the same
 *     client. It says the operator of that domain published this metadata. It
 *     says nothing about the client's conduct or data practices.
 *   - **App approval** means a local registration or trust-registry admission
 *     decision — someone actually vetted the client.
 *
 * §6 obligation 5 requires the first to be rendered as a *named domain*
 * ("Verified domain: example.com"), never as an unqualified "Verified app".
 * `RequesterIdentity` therefore carries them as two separate fields, so a
 * consent surface cannot render one as the other by accident.
 */

import type { RequesterIdentity } from "./review.js";
import type { ClientDisplay } from "./types.js";

/** Metadata the deployment holds locally, or a trust registry supplied. */
export interface RegisteredClientMetadata {
  client_id: string;
  display: ClientDisplay;
  /** True only when an admission decision was actually made. */
  approved: boolean;
}

/**
 * A client ID metadata document retrieved from the client_id URL.
 *
 * §6: the document is *valid* only when it was retrieved over HTTPS from the
 * client_id URL itself and the `client_id` inside it is identical to that URL.
 * That last check is what stops a document claiming to be a different client.
 */
export interface ClientIdMetadataDocument {
  /** The URL the document was retrieved from. */
  retrieved_from: string;
  /** The client_id the document asserts. */
  client_id: string;
  /**
   * Optional: a document may validly declare redirect_uris and no name. An
   * absent name must stay absent rather than become `{ name: "" }`, which
   * would outrank inline metadata in §6 precedence and render a blank
   * requester on the consent surface.
   */
  display?: ClientDisplay;
  /** Whether retrieval used HTTPS. */
  https: boolean;
}

export interface ResolveRequesterInput {
  client_id: string;
  /** Highest precedence: local registration or trust registry. */
  registered?: RegisteredClientMetadata;
  /** Validated binding metadata, when the binding supplied one. */
  document?: ClientIdMetadataDocument;
  /** Lowest precedence: the client's own inline assertion. */
  inline?: ClientDisplay;
}

/**
 * Validate a client ID metadata document per §6.
 *
 * Returns the verified domain when all three conditions hold, otherwise null.
 * A null result is not a rejection of the client — §6's interoperability
 * obligation forbids rejecting a valid document merely for being
 * unpreregistered, and a document that fails validation just means we fall
 * through to a lower-precedence metadata source.
 */
export function verifyClientIdDocument(
  doc: ClientIdMetadataDocument,
): { verifiedDomain: string } | null {
  if (!doc.https) return null;

  let retrievedUrl: URL;
  try {
    retrievedUrl = new URL(doc.retrieved_from);
  } catch {
    return null;
  }
  if (retrievedUrl.protocol !== "https:") return null;

  // The identity check: the document's client_id must be the URL it came from.
  // Compared as URLs so a trailing-slash difference is not a false negative.
  let assertedUrl: URL;
  try {
    assertedUrl = new URL(doc.client_id);
  } catch {
    return null;
  }
  if (assertedUrl.toString() !== retrievedUrl.toString()) return null;

  return { verifiedDomain: retrievedUrl.hostname };
}

/**
 * Resolve requester identity under §6's precedence:
 *
 *   local registration / trust registry
 *     > validated software statement (not supported in this build)
 *     > validated binding metadata (the client ID metadata document)
 *     > inline `client_display`
 *     > `client_id` fallback
 *
 * The display name always resolves to something: §6 obligation 2 requires the
 * AS to display `client_id` when no name is available, so the consent surface
 * is never left with nothing to render.
 */
export function resolveRequesterIdentity(
  input: ResolveRequesterInput,
): RequesterIdentity {
  const verification = input.document
    ? verifyClientIdDocument(input.document)
    : null;

  // Precedence order, highest first.
  const display: ClientDisplay | undefined =
    input.registered?.display ??
    (verification ? input.document?.display : undefined) ??
    input.inline;

  return {
    client_id: input.client_id,
    display_name: display?.name ?? input.client_id,
    ...(display && { display }),
    // Named, not asserted as blanket verification.
    ...(verification && { verified_domain: verification.verifiedDomain }),
    // Only a real admission decision counts. Domain control is not approval.
    app_approved: input.registered?.approved ?? false,
  };
}

/**
 * Whether a client-supplied remote logo may be rendered directly.
 *
 * §6 obligation 6: `logo_uri` is untrusted content. An unverified client's
 * remote logo must not be fetched into the consent UI — the surface generates
 * a monogram from the display name instead. Proxied-and-approved assets are a
 * deployment concern the caller signals explicitly.
 */
export function mayRenderRemoteLogo(
  identity: RequesterIdentity,
  options: { assetProxiedAndApproved?: boolean } = {},
): boolean {
  if (options.assetProxiedAndApproved === true) return true;
  return identity.app_approved || identity.verified_domain !== undefined;
}
