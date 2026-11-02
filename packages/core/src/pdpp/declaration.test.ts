/**
 * Oracles for bounded declaration retrieval (§5 acceptance, §10 retrieval
 * hygiene) and §9 AS item 16 (one exact retained snapshot).
 *
 * The retrieval tests use an injected fetcher rather than real sockets: the
 * property under test is that the *fence* rejects a URL, which does not
 * require the request to actually leave the machine — and must not, since
 * several cases deliberately target link-local metadata endpoints.
 */

import { describe, expect, it, vi } from "vitest";
import {
  checkDeclarationUrl,
  computeDeclarationDigest,
  MAX_DECLARATION_BYTES,
  parseDeclaration,
  retrieveDeclaration,
  type DeclarationTrustPolicy,
} from "./declaration.js";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";

const openPolicy: DeclarationTrustPolicy = { allowAnyHttpsHost: true };

function validDocument(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    source_id: SOURCE_ID,
    source_kind: "connector",
    version: "2026-08-11",
    streams: [
      {
        name: "top_artists",
        fields: ["id", "name", "source_updated_at"],
        required_fields: ["id"],
        consent_time_field: "source_updated_at",
        primary_key: ["id"],
      },
    ],
    ...overrides,
  });
}

function jsonResponse(body: string, init: ResponseInit = {}): Response {
  return new Response(body, {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

describe("§10 — retrieval is fenced", () => {
  it("rejects a non-HTTPS declaration URL", () => {
    const failure = checkDeclarationUrl(
      "http://registry.example/d.json",
      openPolicy,
    );
    expect(failure?.code).toBe("insecure_scheme");
  });

  it.each([
    ["loopback", "https://127.0.0.1/d.json"],
    ["private 10/8", "https://10.0.0.5/d.json"],
    ["private 172.16/12", "https://172.16.3.4/d.json"],
    ["private 192.168/16", "https://192.168.1.1/d.json"],
    ["cloud metadata link-local", "https://169.254.169.254/latest/meta-data/"],
    ["localhost", "https://localhost/d.json"],
    ["IPv6 loopback", "https://[::1]/d.json"],
    ["IPv6 unique-local", "https://[fd00::1]/d.json"],
  ])("rejects a %s address", (_label, url) => {
    const failure = checkDeclarationUrl(url, openPolicy);
    expect(failure?.code).toBe("private_address");
  });

  it("rejects a host outside the deployment trust policy", () => {
    // An explicit policy is required; reachability is not trust.
    const failure = checkDeclarationUrl("https://random.example/d.json", {
      trustedHosts: ["registry.pdpp.dev"],
    });
    expect(failure?.code).toBe("untrusted_source");
  });

  it("accepts a host the policy names", () => {
    expect(
      checkDeclarationUrl("https://registry.pdpp.dev/d.json", {
        trustedHosts: ["registry.pdpp.dev"],
      }),
    ).toBeNull();
  });

  it("re-validates every redirect hop, not just the first URL", async () => {
    // The attack this stops: a public, policy-approved host that 302s to the
    // cloud metadata endpoint. A one-shot check at the start would follow it.
    const fetcher = vi.fn().mockResolvedValueOnce(
      new Response(null, {
        status: 302,
        headers: { location: "https://169.254.169.254/latest/meta-data/" },
      }),
    );

    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("private_address");
    // Crucially: it never fetched the metadata endpoint.
    expect(fetcher).toHaveBeenCalledTimes(1);
  });

  it("bounds the redirect chain", async () => {
    const fetcher = vi.fn().mockResolvedValue(
      new Response(null, {
        status: 302,
        headers: { location: "https://registry.pdpp.dev/next.json" },
      }),
    );
    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("too_many_redirects");
  });

  it("rejects an oversized declaration body", async () => {
    const huge = JSON.stringify({
      padding: "x".repeat(MAX_DECLARATION_BYTES + 10),
    });
    const fetcher = vi.fn().mockResolvedValue(jsonResponse(huge));
    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("too_large");
  });

  it("retrieves and snapshots a valid declaration", async () => {
    const body = validDocument();
    const fetcher = vi.fn().mockResolvedValue(jsonResponse(body));
    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.source_id).toBe(SOURCE_ID);
    expect(result.snapshot.version).toBe("2026-08-11");
    expect(result.snapshot.digest).toBe(computeDeclarationDigest(body));
  });
});

describe("§5 — declaration acceptance", () => {
  it("rejects a declaration claiming a different source_id", () => {
    // Otherwise a trusted host could serve authority for a source it does not own.
    const result = parseDeclaration(
      validDocument({
        source_id: "https://registry.pdpp.dev/connectors/other",
      }),
      SOURCE_ID,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("source_id_mismatch");
  });

  it("rejects a digest mismatch", () => {
    const result = parseDeclaration(validDocument(), SOURCE_ID, "0".repeat(64));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("digest_mismatch");
  });

  it("accepts a matching digest", () => {
    const body = validDocument();
    const result = parseDeclaration(
      body,
      SOURCE_ID,
      computeDeclarationDigest(body),
    );
    expect(result.ok).toBe(true);
  });

  it("rejects required_fields not present in the stream schema", () => {
    // The per-stream consent floor must be satisfiable from the schema.
    const result = parseDeclaration(
      validDocument({
        streams: [
          {
            name: "top_artists",
            fields: ["id", "name"],
            required_fields: ["id", "phantom"],
            primary_key: ["id"],
          },
        ],
      }),
      SOURCE_ID,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_document");
  });

  it("rejects a preset naming the same stream twice", () => {
    // §6: duplicate stream names make the declaration invalid; this is not
    // deferred to grant issuance.
    const result = parseDeclaration(
      validDocument({
        selection_presets: [
          {
            name: "dupe",
            streams: [{ name: "top_artists" }, { name: "top_artists" }],
          },
        ],
      }),
      SOURCE_ID,
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_document");
  });

  it("rejects a stream declared twice", () => {
    const result = parseDeclaration(
      validDocument({
        streams: [
          {
            name: "s",
            fields: ["id"],
            required_fields: [],
            primary_key: ["id"],
          },
          {
            name: "s",
            fields: ["id"],
            required_fields: [],
            primary_key: ["id"],
          },
        ],
      }),
      SOURCE_ID,
    );
    expect(result.ok).toBe(false);
  });

  it("rejects a malformed document", () => {
    const result = parseDeclaration("{not json", SOURCE_ID);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("invalid_document");
  });

  it("rejects an unknown source_kind", () => {
    const result = parseDeclaration(
      validDocument({ source_kind: "something_else" }),
      SOURCE_ID,
    );
    expect(result.ok).toBe(false);
  });

  it("derives provenance from the declaration, never from the request", () => {
    // §6 "Source kinds": a selection request does not carry source.kind; the
    // AS derives it from the accepted declaration.
    const result = parseDeclaration(
      validDocument({ source_kind: "provider_native" }),
      SOURCE_ID,
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.source_kind).toBe("provider_native");
  });
});

describe("§10 / review C9 — the size cap bounds allocation, not just the outcome", () => {
  it("aborts a stream that exceeds the cap without buffering it whole", async () => {
    // A host that omits Content-Length and streams forever. If the cap only
    // checked after `text()`, this would allocate unboundedly before failing.
    let delivered = 0;
    let cancelled = false;
    const chunk = new Uint8Array(64 * 1024);

    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        delivered += chunk.byteLength;
        // Far more than the cap if anything let it run to completion.
        if (delivered > MAX_DECLARATION_BYTES * 50) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
      cancel() {
        cancelled = true;
      },
    });

    const fetcher = vi.fn().mockResolvedValue(
      new Response(body, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("too_large");
    // The property that matters: we stopped near the cap rather than reading
    // the whole hostile stream. The exact figure is a little above the cap
    // because ReadableStream pulls ahead by a few chunks before our reader
    // sees them — bounded overshoot, not unbounded allocation. Asserted
    // generously so stream-internal buffering changes do not make this flaky,
    // but far below the ~12MB the producer was willing to send.
    expect(delivered).toBeLessThan(MAX_DECLARATION_BYTES * 4);
    expect(cancelled).toBe(true);
  });

  it("still rejects an oversized body that lies about content-length", async () => {
    const huge = "x".repeat(MAX_DECLARATION_BYTES + 1024);
    const fetcher = vi.fn().mockResolvedValue(
      new Response(huge, {
        status: 200,
        headers: { "content-type": "application/json", "content-length": "10" },
      }),
    );
    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.failure.code).toBe("too_large");
  });

  it("still accepts a declaration inside the cap", async () => {
    const body = validDocument();
    const fetcher = vi.fn().mockResolvedValue(jsonResponse(body));
    const result = await retrieveDeclaration(
      "https://registry.pdpp.dev/d.json",
      SOURCE_ID,
      openPolicy,
      { fetcher },
    );
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.snapshot.digest).toBe(computeDeclarationDigest(body));
  });
});
