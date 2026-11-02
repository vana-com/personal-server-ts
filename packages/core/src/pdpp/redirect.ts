/**
 * Redirect URI validation (RFC 6749 §3.1.2, §10.6; RFC 8252 §7.3).
 *
 * The authorization code travels to the client in this redirect. If the AS
 * honours whatever `redirect_uri` a caller supplies, the attack is direct: an
 * attacker opens an authorization session pointing at their own host, the
 * owner sees a consent screen that looks entirely legitimate (it is — the AS
 * generated it), approves, and the code is delivered to the attacker.
 *
 * **PKCE does not mitigate this.** PKCE binds the code to whoever chose the
 * challenge, and in this attack that is the attacker. They hold the matching
 * verifier, so they redeem the stolen code and receive a grant-bound token
 * over the owner's personal data. Code interception and code *misdelivery* are
 * different problems; §10.6 is the one that covers misdelivery.
 *
 * Validation is by exact match against the client's registered redirect URIs.
 * RFC 6749 §3.1.2.2 requires registration, and §3.1.2.3 allows fuzzier
 * matching only for clients that registered a full URI — we do not take that
 * latitude. Prefix or subdomain matching is where open-redirect bugs live: a
 * registered `https://app.example.com/cb` "matching"
 * `https://app.example.com.evil.test/cb` or `https://app.example.com/cb/../x`
 * is the classic failure. Exact string equality after normalization has no
 * such edge, and the cost is that a client registers each callback it uses.
 */

/** Loopback hosts, where RFC 8252 §7.3 permits plain http for native apps. */
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "[::1]", "::1", "localhost"]);

export type RedirectFailureCode =
  | "unregistered_redirect_uri"
  | "insecure_redirect_uri"
  | "malformed_redirect_uri"
  | "no_registered_redirect_uris";

export interface RedirectFailure {
  code: RedirectFailureCode;
  message: string;
}

/**
 * Registered metadata for a client, as the deployment holds it.
 *
 * `redirect_uris` is required and non-empty for the code flow: a client with
 * no registered callback cannot safely receive a code, and defaulting to
 * "accept anything" would reintroduce exactly the hole this module closes.
 */
export interface RegisteredRedirectPolicy {
  client_id: string;
  redirect_uris: string[];
}

/**
 * Normalize for comparison without loosening the match.
 *
 * `URL` resolves dot-segments and lowercases scheme and host, so
 * `https://App.Example.com/cb/../cb` and `https://app.example.com/cb` compare
 * equal — that is canonicalization, not fuzzy matching. Query and fragment are
 * preserved, because a registered URI that carries a query is a different
 * endpoint from one that does not.
 */
function normalize(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

/**
 * Validate a requested redirect URI against the client's registered set.
 *
 * Returns null when the URI is acceptable. Every rejection is deliberately
 * the same shape, so a caller probing for registered URIs learns only that
 * theirs was not one.
 */
export function validateRedirectUri(
  requested: string | undefined,
  policy: RegisteredRedirectPolicy | null,
): RedirectFailure | null {
  if (!requested || requested.length === 0) {
    return {
      code: "malformed_redirect_uri",
      message: "redirect_uri is required",
    };
  }

  const url = normalize(requested);
  if (!url) {
    return {
      code: "malformed_redirect_uri",
      message: "redirect_uri is not a valid absolute URI",
    };
  }

  // RFC 6749 §3.1.2: the endpoint URI MUST NOT include a fragment. A fragment
  // is also how a target gets smuggled past a naive prefix check.
  if (url.hash.length > 0) {
    return {
      code: "malformed_redirect_uri",
      message: "redirect_uri must not include a fragment component",
    };
  }

  // Scheme gate before anything else. `javascript:` and `data:` are the
  // XSS-on-redirect shapes; everything non-http(s) is refused outright rather
  // than enumerated, so a scheme nobody thought of is refused by default.
  const isLoopback = LOOPBACK_HOSTS.has(url.hostname);
  if (url.protocol === "http:") {
    // RFC 8252 §7.3: loopback http is the native-app redirect, and is fine.
    if (!isLoopback) {
      return {
        code: "insecure_redirect_uri",
        message: "redirect_uri must use https except for loopback addresses",
      };
    }
  } else if (url.protocol !== "https:") {
    return {
      code: "insecure_redirect_uri",
      message: `redirect_uri scheme '${url.protocol}' is not permitted`,
    };
  }

  if (!policy || policy.redirect_uris.length === 0) {
    // No registration means no safe target. Failing closed here is the whole
    // point: an AS that falls back to "trust the request" when it has no
    // policy has no policy.
    return {
      code: "no_registered_redirect_uris",
      message:
        "client has no registered redirect URIs; register one before requesting authorization",
    };
  }

  // Exact match after canonicalization. No prefix, no subdomain, no wildcard.
  const matched = policy.redirect_uris.some((candidate) => {
    const registered = normalize(candidate);
    return registered !== null && registered.toString() === url.toString();
  });

  if (!matched) {
    return {
      code: "unregistered_redirect_uri",
      message: "redirect_uri does not exactly match a registered redirect URI",
    };
  }

  return null;
}

/**
 * Whether a redirect failure may be reported *by redirecting*.
 *
 * RFC 6749 §4.1.2.1 is explicit: when the redirect URI is invalid or
 * unregistered, the AS MUST NOT automatically redirect the user-agent to it.
 * Doing so would turn the authorization endpoint into an open redirector and
 * would hand the attacker the error response they were fishing for. Every
 * failure from `validateRedirectUri` is therefore reported directly to the
 * caller and never as a redirect.
 */
export const REDIRECT_FAILURES_ARE_NEVER_REDIRECTED = true as const;
