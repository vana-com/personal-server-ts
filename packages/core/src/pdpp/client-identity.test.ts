/**
 * URL-hosted client identity, and the bounds that make fetching one safe.
 *
 * §6 requires an AS to accept a valid URL-hosted client identity rather than
 * rejecting it solely for not being preregistered. Implementing that means the
 * AS fetches a URL chosen by an untrusted caller — a server-side request
 * forgery primitive if unbounded.
 *
 * So most of these cases are about refusal. The happy path is one test; the
 * rest pin the reasons a fetch must not happen, or must not be trusted once it
 * has.
 */

import { describe, expect, it, vi } from "vitest";
import {
  MAX_CLIENT_DOCUMENT_BYTES,
  resolveUrlHostedClientIdentity,
  type ClientDocumentFetcher,
} from "./client-identity.js";
import type { DeclarationTrustPolicy } from "./declaration.js";

const CLIENT_ID = "https://app.example.com/pdpp-client";
const REDIRECT = "https://app.example.com/callback";

/** Mirrors a deployment that allowlists one host. */
const POLICY: DeclarationTrustPolicy = {
  trustedHosts: ["app.example.com"],
};

const OPEN_POLICY: DeclarationTrustPolicy = { allowAnyHttpsHost: true };

function documentFetcher(
  body: unknown,
  overrides: { finalUrl?: string; status?: number } = {},
): ClientDocumentFetcher {
  return async (url) => ({
    body: typeof body === "string" ? body : JSON.stringify(body),
    finalUrl: overrides.finalUrl ?? url,
    status: overrides.status ?? 200,
  });
}

const VALID_DOCUMENT = {
  client_id: CLIENT_ID,
  client_name: "Example App",
  redirect_uris: [REDIRECT],
};

describe("a valid URL-hosted client identity is accepted", () => {
  it("resolves a redirect policy from the document", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher(VALID_DOCUMENT),
      policy: POLICY,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    // Same shape a config registration produces, so the caller's exact-match
    // redirect rule applies identically to both.
    expect(result.policy).toEqual({
      client_id: CLIENT_ID,
      redirect_uris: [REDIRECT],
    });
    expect(result.verifiedDomain).toBe("app.example.com");
  });
});

describe("the fetch is bounded before it happens", () => {
  it("refuses a non-https client_id without fetching", async () => {
    const fetcher = vi.fn();
    const result = await resolveUrlHostedClientIdentity({
      clientId: "http://app.example.com/pdpp-client",
      fetcher: fetcher as unknown as ClientDocumentFetcher,
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "untrusted_client_url" },
      ok: false,
    });
    // The point: no outbound request at all.
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a loopback address without fetching", async () => {
    const fetcher = vi.fn();
    const result = await resolveUrlHostedClientIdentity({
      clientId: "https://127.0.0.1/pdpp-client",
      fetcher: fetcher as unknown as ClientDocumentFetcher,
      policy: OPEN_POLICY,
    });

    expect(result).toMatchObject({ ok: false });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a link-local metadata address without fetching", async () => {
    // The canonical SSRF target: cloud instance metadata.
    const fetcher = vi.fn();
    const result = await resolveUrlHostedClientIdentity({
      clientId: "https://169.254.169.254/latest/meta-data/",
      fetcher: fetcher as unknown as ClientDocumentFetcher,
      policy: OPEN_POLICY,
    });

    expect(result).toMatchObject({ ok: false });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a private RFC1918 address without fetching", async () => {
    const fetcher = vi.fn();
    const result = await resolveUrlHostedClientIdentity({
      clientId: "https://10.0.0.5/pdpp-client",
      fetcher: fetcher as unknown as ClientDocumentFetcher,
      policy: OPEN_POLICY,
    });

    expect(result).toMatchObject({ ok: false });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("refuses a host outside the deployment's allowlist", async () => {
    const fetcher = vi.fn();
    const result = await resolveUrlHostedClientIdentity({
      clientId: "https://attacker.example/pdpp-client",
      fetcher: fetcher as unknown as ClientDocumentFetcher,
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "untrusted_client_url" },
      ok: false,
    });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("treats a non-URL client_id as not URL-hosted, without fetching", async () => {
    const fetcher = vi.fn();
    const result = await resolveUrlHostedClientIdentity({
      clientId: "music_recommendations",
      fetcher: fetcher as unknown as ClientDocumentFetcher,
      policy: POLICY,
    });

    expect(result).toMatchObject({ ok: false });
    expect(fetcher).not.toHaveBeenCalled();
  });
});

describe("a redirect cannot escape the gate", () => {
  it("re-checks where the fetch actually landed", async () => {
    // Allowlisted start, disallowed finish. Checking only the requested URL
    // would let a redirect reach exactly what the gate exists to block.
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher(VALID_DOCUMENT, {
        finalUrl: "https://attacker.example/pdpp-client",
      }),
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "untrusted_client_url" },
      ok: false,
    });
  });

  it("refuses a redirect to a private address", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: "https://app.example.com/pdpp-client",
      fetcher: documentFetcher(VALID_DOCUMENT, {
        finalUrl: "https://169.254.169.254/",
      }),
      policy: OPEN_POLICY,
    });

    expect(result).toMatchObject({ ok: false });
  });
});

describe("the retrieved document must earn trust", () => {
  it("refuses a document asserting a different client_id", async () => {
    // Without this, any allowlisted host could publish a document claiming to
    // be someone else's client and inherit their redirect policy.
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher({
        ...VALID_DOCUMENT,
        client_id: "https://app.example.com/some-other-client",
      }),
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "client_id_mismatch" },
      ok: false,
    });
  });

  it("refuses a document with no redirect_uris", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher({ client_id: CLIENT_ID, client_name: "X" }),
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "invalid_document" },
      ok: false,
    });
  });

  it("refuses a document whose redirect_uris are all unusable", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher({ ...VALID_DOCUMENT, redirect_uris: ["", 42] }),
      policy: POLICY,
    });

    expect(result).toMatchObject({ ok: false });
  });

  it("refuses a body over the size cap", async () => {
    const huge = JSON.stringify({
      ...VALID_DOCUMENT,
      padding: "x".repeat(MAX_CLIENT_DOCUMENT_BYTES),
    });
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher(huge),
      policy: POLICY,
    });

    expect(result).toMatchObject({ failure: { code: "too_large" }, ok: false });
  });

  it("refuses malformed JSON", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher("not json at all"),
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "invalid_document" },
      ok: false,
    });
  });

  it("refuses a non-200 response", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: documentFetcher(VALID_DOCUMENT, { status: 404 }),
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "fetch_failed" },
      ok: false,
    });
  });

  it("turns a thrown fetch into a typed failure", async () => {
    const result = await resolveUrlHostedClientIdentity({
      clientId: CLIENT_ID,
      fetcher: async () => {
        throw new Error("ECONNREFUSED");
      },
      policy: POLICY,
    });

    expect(result).toMatchObject({
      failure: { code: "fetch_failed" },
      ok: false,
    });
  });
});
