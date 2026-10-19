/**
 * Oracles for PKCE (RFC 7636) on the PDPP authorization-code flow.
 *
 * The property under test is the one PKCE exists for: an intercepted
 * authorization code must be useless to whoever intercepted it. Every negative
 * case below is a real attack shape — a stolen code redeemed with no verifier,
 * with a guessed verifier, or replayed after a failed guess.
 */

import { describe, expect, it } from "vitest";
import {
  computeS256Challenge,
  PKCE_METHOD_S256,
  validateCodeChallenge,
  verifyCodeVerifier,
} from "./pkce.js";

/** RFC 7636 §4.1: 43–128 chars of unreserved ASCII. */
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);

describe("RFC 7636 appendix B — the worked example", () => {
  it("derives the specification's own challenge from its own verifier", () => {
    // The appendix B vector. If this drifts, the base64url encoding is wrong
    // and every client computing a challenge per spec would be rejected.
    expect(
      computeS256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
    ).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
  });

  it("produces base64url with no padding", () => {
    expect(CHALLENGE).not.toContain("=");
    expect(CHALLENGE).not.toContain("+");
    expect(CHALLENGE).not.toContain("/");
  });
});

describe("challenge validation at authorization time", () => {
  it("accepts a well-formed S256 challenge", () => {
    expect(
      validateCodeChallenge(CHALLENGE, PKCE_METHOD_S256, { required: true }),
    ).toBeNull();
  });

  it("rejects a missing challenge when PKCE is required", () => {
    const failure = validateCodeChallenge(undefined, undefined, {
      required: true,
    });
    expect(failure?.code).toBe("missing_challenge");
  });

  it("rejects the plain method explicitly", () => {
    // RFC 7636 permits `plain` for constrained clients. It is useless here:
    // an attacker who sees the authorization request has the verifier.
    const failure = validateCodeChallenge(CHALLENGE, "plain", {
      required: true,
    });
    expect(failure?.code).toBe("unsupported_method");
  });

  it("rejects an omitted method rather than defaulting to plain", () => {
    // RFC 7636 §4.3 defaults an absent method to `plain`. Silently accepting
    // that would downgrade to the mode we refuse.
    const failure = validateCodeChallenge(CHALLENGE, undefined, {
      required: true,
    });
    expect(failure?.code).toBe("unsupported_method");
  });

  it("rejects an unknown method", () => {
    const failure = validateCodeChallenge(CHALLENGE, "S512", {
      required: true,
    });
    expect(failure?.code).toBe("unsupported_method");
  });

  it("permits an absent challenge only when a deployment opts out", () => {
    expect(
      validateCodeChallenge(undefined, undefined, { required: false }),
    ).toBeNull();
  });
});

describe("verifier checking at redemption", () => {
  it("accepts the verifier that produced the challenge", () => {
    expect(
      verifyCodeVerifier(VERIFIER, CHALLENGE, PKCE_METHOD_S256),
    ).toBeNull();
  });

  it("rejects a missing verifier against a PKCE-bound code", () => {
    // The stolen-code case: the attacker has the code and no verifier.
    const failure = verifyCodeVerifier(undefined, CHALLENGE, PKCE_METHOD_S256);
    expect(failure?.code).toBe("missing_verifier");
  });

  it("rejects an empty verifier", () => {
    const failure = verifyCodeVerifier("", CHALLENGE, PKCE_METHOD_S256);
    expect(failure?.code).toBe("missing_verifier");
  });

  it("rejects a wrong verifier of valid shape", () => {
    // A guess that is well-formed but does not hash to the challenge.
    const wrong = "X".repeat(43);
    const failure = verifyCodeVerifier(wrong, CHALLENGE, PKCE_METHOD_S256);
    expect(failure?.code).toBe("invalid_verifier");
  });

  it("rejects a verifier that is too short to be a real one", () => {
    const failure = verifyCodeVerifier("abc", CHALLENGE, PKCE_METHOD_S256);
    expect(failure?.code).toBe("invalid_verifier");
  });

  it("rejects a verifier that is too long", () => {
    const failure = verifyCodeVerifier(
      "a".repeat(129),
      CHALLENGE,
      PKCE_METHOD_S256,
    );
    expect(failure?.code).toBe("invalid_verifier");
  });

  it("rejects a verifier with characters outside the unreserved set", () => {
    const failure = verifyCodeVerifier(
      `${"a".repeat(42)}$`,
      CHALLENGE,
      PKCE_METHOD_S256,
    );
    expect(failure?.code).toBe("invalid_verifier");
  });

  it("rejects the challenge presented as if it were the verifier", () => {
    // A confused or malicious client echoing back what it saw. The challenge
    // is public; accepting it would make PKCE decorative.
    const failure = verifyCodeVerifier(CHALLENGE, CHALLENGE, PKCE_METHOD_S256);
    expect(failure?.code).toBe("invalid_verifier");
  });

  it("fails closed on a stored non-S256 method", () => {
    // A code minted by some path that skipped the method check must not be
    // honoured just because it carries a challenge.
    const failure = verifyCodeVerifier(VERIFIER, VERIFIER, "plain");
    expect(failure?.code).toBe("unsupported_method");
  });

  it("has nothing to check when the code carries no challenge", () => {
    expect(verifyCodeVerifier(undefined, null, null)).toBeNull();
    expect(verifyCodeVerifier(VERIFIER, "", null)).toBeNull();
  });
});
