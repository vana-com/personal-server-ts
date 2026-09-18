/**
 * Real bootstrap wiring for §6 URL-hosted client identity.
 *
 * `resolveUrlHostedClientIdentity` and `boundedClientDocumentFetcher` each
 * have their own unit suites (`client-identity.test.ts`,
 * `client-document-fetch.test.ts`). What neither proves is that a real
 * `createServer` boot actually connects them: that `pdpp.urlHostedClientHosts`
 * is what turns `resolveClientIdentity` on, that a static `clients`
 * registration still wins, and that an empty allowlist makes zero outbound
 * network calls rather than merely failing closed after trying.
 *
 * These drive `createServer` — the real CLI/Docker entrypoint — and assert on
 * `/pdpp/v1/authorize` responses, the same surface an operator's deployment
 * exposes.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createServer, type ServerContext } from "../bootstrap.js";
import { initializeDatabase } from "../storage/index-schema.js";
import * as clientDocumentFetch from "./client-document-fetch.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);
const REDIRECT = "https://client.example.com/callback";
const CLIENT_ID = "https://client.example.com/pdpp-client.json";

const DECLARATION = JSON.stringify({
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let ctx: ServerContext | undefined;

async function seedScope(scope: string): Promise<void> {
  const db = initializeDatabase(join(tempDir, "index.db"));
  db.prepare(
    `INSERT INTO data_files (file_id, path, scope, collected_at, size_bytes)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(
    "file-1",
    `${scope.split(".").join("/")}/2026-01-01T00:00:00Z.json`,
    scope,
    "2026-01-01T00:00:00Z",
    128,
  );
  db.close();
}

async function writeDeclaration(): Promise<string> {
  const { mkdir, writeFile } = await import("node:fs/promises");
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "spotify.json");
  await writeFile(path, DECLARATION, "utf-8");
  return path;
}

function pdppConfig(overrides: {
  declarationPaths: string[];
  clients?: Array<{ clientId: string; redirectUris: string[] }>;
  urlHostedClientHosts?: string[];
}) {
  return ServerConfigSchema.parse({
    tunnel: { enabled: false },
    pdpp: {
      enabled: true,
      declarationPaths: overrides.declarationPaths,
      clients: overrides.clients ?? [],
      urlHostedClientHosts: overrides.urlHostedClientHosts ?? [],
    },
  });
}

async function boot(config: ReturnType<typeof pdppConfig>) {
  return createServer(config, {
    serverDir: tempDir,
    dataDir: join(tempDir, "data"),
  });
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-url-client-boot-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

async function ownerToken(context: ServerContext): Promise<string> {
  const response = await context.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: { authorization: `Bearer ${context.devToken}` },
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as { access_token: string };
  return body.access_token;
}

function authorizeBody(overrides: Record<string, unknown> = {}) {
  return {
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    authorization_details: [
      {
        type: "https://pdpp.dev/data-access",
        source: { id: SOURCE_ID },
        purpose_code: "https://pdpp.dev/purpose/personalization",
        access_mode: "continuous",
        streams: [{ name: "top_artists" }],
      },
    ],
    ...overrides,
  };
}

describe("an empty allowlist makes zero outbound calls", () => {
  it("never invokes the fetcher and refuses the unregistered client", async () => {
    const fetchSpy = vi.spyOn(
      clientDocumentFetch,
      "boundedClientDocumentFetcher",
    );

    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        urlHostedClientHosts: [], // the default; explicit here for clarity
      }),
    );
    const token = await ownerToken(ctx);

    const response = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(authorizeBody()),
    });

    // Registration-only behavior, preserved exactly: an unregistered client
    // is refused, not fetched.
    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("the allowlist wires the real resolver into a real boot", () => {
  it("reaches the bounded fetcher for an allowlisted host and carries its truthful identity into the review", async () => {
    // The fetcher's own bounds (HTTPS-only, timeout, byte cap, redirect
    // refusal, connect-time DNS validation) have their own unit suite
    // against a real local server (client-document-fetch.test.ts), and the
    // resolver's document handling has its own suite
    // (client-identity.test.ts). What's proven here is the wiring: a real
    // `createServer` boot, given `urlHostedClientHosts`, actually calls the
    // production `boundedClientDocumentFetcher` with the requested URL — and
    // whatever that fetcher truthfully returns is what the owner is shown.
    const fetchSpy = vi
      .spyOn(clientDocumentFetch, "boundedClientDocumentFetcher")
      .mockImplementation(async (url) => {
        expect(url).toBe(CLIENT_ID);
        return {
          status: 200,
          finalUrl: url,
          body: JSON.stringify({
            client_id: CLIENT_ID,
            client_name: "Real Client Document",
            redirect_uris: [REDIRECT],
          }),
        };
      });

    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        clients: [],
        urlHostedClientHosts: ["client.example.com"],
      }),
    );
    const token = await ownerToken(ctx);

    const opened = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(authorizeBody()),
    });
    expect(opened.status).toBe(201);
    expect(fetchSpy).toHaveBeenCalledWith(CLIENT_ID);

    const { session_id } = (await opened.json()) as { session_id: string };
    const reviewed = await ctx.app.request(
      `/pdpp/v1/authorize/${session_id}/review`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(reviewed.status).toBe(200);
    const { review } = (await reviewed.json()) as {
      review: {
        requester: { display_name: string; verified_domain?: string };
      };
    };
    // Truthful identity: the name and domain the real fetch returned, not a
    // fabricated or inline one.
    expect(review.requester.display_name).toBe("Real Client Document");
    expect(review.requester.verified_domain).toBe("client.example.com");
  });

  it("refuses a host outside the allowlist without attempting a fetch", async () => {
    const fetchSpy = vi.spyOn(
      clientDocumentFetch,
      "boundedClientDocumentFetcher",
    );
    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        urlHostedClientHosts: ["some-other-host.example"],
      }),
    );
    const token = await ownerToken(ctx);

    const response = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(authorizeBody()),
    });

    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

describe("a static registration always wins over the URL-hosted path", () => {
  it("never calls the fetcher when the client is registered, even with a matching allowlist", async () => {
    const fetchSpy = vi.spyOn(
      clientDocumentFetch,
      "boundedClientDocumentFetcher",
    );
    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
        urlHostedClientHosts: ["client.example.com"],
      }),
    );
    const token = await ownerToken(ctx);

    const response = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(authorizeBody()),
    });

    // Registered, so admitted purely from config -- and no fetch was needed.
    expect(response.status).toBe(201);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("only falls through to the URL-hosted path when the client is unregistered", async () => {
    const fetchSpy = vi
      .spyOn(clientDocumentFetch, "boundedClientDocumentFetcher")
      .mockResolvedValue(null);
    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        clients: [{ clientId: "some_other_client", redirectUris: [REDIRECT] }],
        urlHostedClientHosts: ["client.example.com"],
      }),
    );
    const token = await ownerToken(ctx);

    await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(authorizeBody()), // CLIENT_ID, not "some_other_client"
    });

    expect(fetchSpy).toHaveBeenCalledWith(CLIENT_ID);
  });
});

describe("exact redirect validation still applies to a URL-hosted client", () => {
  /**
   * The document validly declares REDIRECT and only REDIRECT. Resolution
   * itself succeeds -- so a refusal below can only come from the exact-match
   * check, not from resolution failing anyway.
   */
  function mockValidDocument() {
    return vi
      .spyOn(clientDocumentFetch, "boundedClientDocumentFetcher")
      .mockResolvedValue({
        status: 200,
        finalUrl: CLIENT_ID,
        body: JSON.stringify({
          client_id: CLIENT_ID,
          client_name: "Example Client",
          redirect_uris: [REDIRECT],
        }),
      });
  }

  it("refuses a redirect_uri the document does not declare", async () => {
    mockValidDocument();
    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        urlHostedClientHosts: ["client.example.com"],
      }),
    );
    const token = await ownerToken(ctx);

    const response = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(
        authorizeBody({ redirect_uri: "https://attacker.example/steal" }),
      ),
    });

    expect(response.status).toBe(400);
  });

  it("accepts the exact redirect_uri the document declares", async () => {
    mockValidDocument();
    await seedScope("spotify.top_artists");
    ctx = await boot(
      pdppConfig({
        declarationPaths: [await writeDeclaration()],
        urlHostedClientHosts: ["client.example.com"],
      }),
    );
    const token = await ownerToken(ctx);

    const response = await ctx.app.request("/pdpp/v1/authorize", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(authorizeBody({ redirect_uri: REDIRECT })),
    });

    expect(response.status).toBe(201);
  });
});
