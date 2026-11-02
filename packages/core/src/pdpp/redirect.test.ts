/**
 * Oracles for redirect URI validation (RFC 6749 §3.1.2, §10.6; RFC 8252 §7.3).
 *
 * The threat: the authorization code is delivered via this redirect, so an
 * unvalidated target is code misdelivery. The owner sees a legitimate consent
 * screen, approves, and the code goes to the attacker — who, having chosen the
 * PKCE challenge too, holds the verifier and redeems it.
 */

import { describe, expect, it } from "vitest";
import {
  validateRedirectUri,
  type RegisteredRedirectPolicy,
} from "./redirect.js";

const policy: RegisteredRedirectPolicy = {
  client_id: "concert_finder",
  redirect_uris: ["https://app.example.com/callback"],
};

describe("exact matching against registered URIs", () => {
  it("accepts the registered URI", () => {
    expect(
      validateRedirectUri("https://app.example.com/callback", policy),
    ).toBeNull();
  });

  it("canonicalizes case and dot segments before comparing", () => {
    // Canonicalization is not fuzzy matching: these ARE the same URI.
    expect(
      validateRedirectUri("https://App.Example.com/cb/../callback", policy),
    ).toBeNull();
  });

  it("rejects an attacker-controlled host", () => {
    const failure = validateRedirectUri(
      "https://evil.example.com/steal",
      policy,
    );
    expect(failure?.code).toBe("unregistered_redirect_uri");
  });

  it("rejects a suffix near-miss on the registered host", () => {
    // The classic: `app.example.com.evil.test` passes a naive startsWith.
    expect(
      validateRedirectUri("https://app.example.com.evil.test/callback", policy)
        ?.code,
    ).toBe("unregistered_redirect_uri");
  });

  it("rejects a subdomain of the registered host", () => {
    expect(
      validateRedirectUri("https://evil.app.example.com/callback", policy)
        ?.code,
    ).toBe("unregistered_redirect_uri");
  });

  it("rejects a longer path that merely starts with the registered one", () => {
    expect(
      validateRedirectUri("https://app.example.com/callback/extra", policy)
        ?.code,
    ).toBe("unregistered_redirect_uri");
  });

  it("rejects an added query string", () => {
    // A registered URI carrying a query is a different endpoint; so is one
    // that gains a parameter the registration never sanctioned.
    expect(
      validateRedirectUri(
        "https://app.example.com/callback?next=//evil",
        policy,
      )?.code,
    ).toBe("unregistered_redirect_uri");
  });

  it("rejects a different port", () => {
    expect(
      validateRedirectUri("https://app.example.com:8443/callback", policy)
        ?.code,
    ).toBe("unregistered_redirect_uri");
  });
});

describe("scheme and shape gates", () => {
  it.each([
    ["javascript", "javascript:alert(document.cookie)"],
    ["data", "data:text/html,<script>fetch('//evil')</script>"],
    ["file", "file:///etc/passwd"],
  ])("rejects the %s scheme", (_label, uri) => {
    expect(validateRedirectUri(uri, policy)?.code).toBe(
      "insecure_redirect_uri",
    );
  });

  it("rejects plain http for a non-loopback host", () => {
    expect(
      validateRedirectUri("http://app.example.com/callback", policy)?.code,
    ).toBe("insecure_redirect_uri");
  });

  it("permits loopback http for a native app (RFC 8252 §7.3)", () => {
    const native: RegisteredRedirectPolicy = {
      client_id: "desktop",
      redirect_uris: ["http://127.0.0.1:7777/cb"],
    };
    expect(validateRedirectUri("http://127.0.0.1:7777/cb", native)).toBeNull();
  });

  it("rejects a fragment (RFC 6749 §3.1.2)", () => {
    expect(
      validateRedirectUri("https://app.example.com/callback#x", policy)?.code,
    ).toBe("malformed_redirect_uri");
  });

  it("rejects a relative or malformed URI", () => {
    expect(validateRedirectUri("/callback", policy)?.code).toBe(
      "malformed_redirect_uri",
    );
    expect(validateRedirectUri("", policy)?.code).toBe(
      "malformed_redirect_uri",
    );
    expect(validateRedirectUri(undefined, policy)?.code).toBe(
      "malformed_redirect_uri",
    );
  });
});

describe("failing closed without registration", () => {
  it("refuses an unregistered client outright", () => {
    // No registration means no safe target. An AS that falls back to trusting
    // the request when it has no policy has no policy.
    expect(
      validateRedirectUri("https://anything.example.com/cb", null)?.code,
    ).toBe("no_registered_redirect_uris");
  });

  it("refuses a client registered with an empty redirect list", () => {
    expect(
      validateRedirectUri("https://app.example.com/callback", {
        client_id: "concert_finder",
        redirect_uris: [],
      })?.code,
    ).toBe("no_registered_redirect_uris");
  });

  it("checks the scheme before consulting registration", () => {
    // A javascript: URI is refused on its own terms, so a misconfigured
    // registration can never make one acceptable.
    expect(
      validateRedirectUri("javascript:alert(1)", {
        client_id: "x",
        redirect_uris: ["javascript:alert(1)"],
      })?.code,
    ).toBe("insecure_redirect_uri");
  });
});

describe("multiple registered URIs", () => {
  const multi: RegisteredRedirectPolicy = {
    client_id: "multi",
    redirect_uris: [
      "https://app.example.com/callback",
      "https://app.example.com/alt",
      "http://127.0.0.1:9000/cb",
    ],
  };

  it("accepts any exact member", () => {
    for (const uri of multi.redirect_uris) {
      expect(validateRedirectUri(uri, multi)).toBeNull();
    }
  });

  it("still rejects a non-member", () => {
    expect(
      validateRedirectUri("https://app.example.com/other", multi)?.code,
    ).toBe("unregistered_redirect_uri");
  });
});
