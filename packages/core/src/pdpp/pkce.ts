/**
 * PKCE (RFC 7636) for the PDPP authorization-code flow.
 *
 * PDPP clients are public clients: a browser app or a desktop tool holds no
 * client secret, so `client_id` + `redirect_uri` alone do not prove that the
 * party redeeming a code is the party that requested it. An attacker who
 * intercepts the code — a malicious app registered on the same custom URI
 * scheme, a leaked Referer, a shoulder-surfed loopback redirect — can redeem
 * it and receive a grant-bound token. RFC 7636 §1 describes exactly this.
 *
 * PKCE closes it: the client sends a challenge up front and must present the
 * verifier at redemption. The AS binds the two. An intercepted code is useless
 * without the verifier, which never leaves the requesting client.
 *
 * Only S256 is supported. `plain` is in RFC 7636 for constrained clients that
 * cannot compute SHA-256, and it defeats the purpose here: an attacker who
 * sees the challenge in the authorization request has the verifier. RFC 7636
 * §4.2 says a server MUST support S256 and clients MUST use it where they can;
 * for a protocol carrying personal data there is no reason to accept the weak
 * mode, so this AS declines `plain` explicitly rather than silently.
 */

import { createHash, timingSafeEqual } from "node:crypto";

/** The only challenge method this AS accepts. */
export const PKCE_METHOD_S256 = "S256";

/** RFC 7636 §4.1: the verifier is 43–128 characters of unreserved ASCII. */
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;

/**
 * base64url per RFC 7636 §appendix A: standard base64 with `+/` mapped to
 * `-_` and padding stripped. Node's `base64url` encoding already does this.
 */
export function computeS256Challenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export type PkceFailureCode =
  | "missing_verifier"
  | "invalid_verifier"
  | "unsupported_method"
  | "missing_challenge";

export interface PkceFailure {
  code: PkceFailureCode;
  message: string;
}

/**
 * Validate a challenge at authorization time.
 *
 * Rejecting an unsupported method here, rather than at redemption, means a
 * client learns its flow is unusable before the owner is asked to consent to
 * anything — failing after consent would waste a real human decision.
 */
export function validateCodeChallenge(
  challenge: string | undefined,
  method: string | undefined,
  options: { required: boolean },
): PkceFailure | null {
  if (challenge === undefined || challenge.length === 0) {
    if (!options.required) return null;
    return {
      code: "missing_challenge",
      message: "code_challenge is required for the authorization code flow",
    };
  }

  // An absent method defaults to `plain` under RFC 7636 §4.3. We do not accept
  // plain, so an omitted method is an explicit error rather than a silent
  // downgrade to the mode we refuse.
  if (method !== PKCE_METHOD_S256) {
    return {
      code: "unsupported_method",
      message: `code_challenge_method must be ${PKCE_METHOD_S256}; 'plain' is not accepted`,
    };
  }

  return null;
}

/**
 * Verify a presented verifier against the stored challenge at redemption.
 *
 * The comparison is constant-time. A challenge is not a secret in the way a
 * password is — it is already public in the authorization request — but the
 * verifier is, and an early-exit comparison over attacker-chosen input is a
 * habit worth not forming in an authorization server.
 */
export function verifyCodeVerifier(
  verifier: string | undefined,
  storedChallenge: string | null,
  storedMethod: string | null,
): PkceFailure | null {
  if (storedChallenge === null || storedChallenge.length === 0) {
    // The code was issued without PKCE. Whether that is allowed is the
    // authorization endpoint's decision (see `validateCodeChallenge`); by the
    // time a code exists, there is nothing to verify against.
    return null;
  }

  if (storedMethod !== PKCE_METHOD_S256) {
    // A stored non-S256 method means the code was minted by a path that did
    // not enforce the method check. Fail closed rather than honouring it.
    return {
      code: "unsupported_method",
      message:
        "authorization code carries an unsupported code_challenge_method",
    };
  }

  if (verifier === undefined || verifier.length === 0) {
    return {
      code: "missing_verifier",
      message: "code_verifier is required to redeem this authorization code",
    };
  }

  if (!VERIFIER_RE.test(verifier)) {
    // Enforcing the shape stops a trivially-guessable short verifier from
    // being accepted just because it happens to hash correctly.
    return {
      code: "invalid_verifier",
      message:
        "code_verifier must be 43-128 characters of [A-Za-z0-9-._~] (RFC 7636 §4.1)",
    };
  }

  const computed = computeS256Challenge(verifier);
  const a = Buffer.from(computed, "utf8");
  const b = Buffer.from(storedChallenge, "utf8");
  if (a.length !== b.length || !timingSafeEqual(a, b)) {
    return {
      code: "invalid_verifier",
      message: "code_verifier does not match the code_challenge",
    };
  }

  return null;
}
