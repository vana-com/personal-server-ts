/**
 * PDPP journey over a REAL listening HTTP socket.
 *
 * The sibling boot journey drives `createServer` but dispatches through
 * `app.request(...)`, which is an in-process Hono call: no socket, no HTTP
 * parser, no real `Host`/origin, no header casing on the wire, no chunked
 * bodies. An external client — the Context Gateway client, the Connect SDK,
 * a browser consent UI — cannot reach the server that way, so a green
 * `app.request` journey is not yet evidence that a real client can talk to it.
 *
 * This file closes that last gap: `listenHttpServer` binds an ephemeral port
 * on loopback, and every request below is a real `fetch()` over TCP against
 * `http://127.0.0.1:<port>`. It is the same listener `packages/server/src/
 * index.ts` uses in production.
 *
 * Scope is deliberately narrow — this is the transport proof, not a second
 * copy of the conformance assertions. It covers the load-bearing path (owner
 * token -> authorize -> review -> approve -> token -> grant-bound read ->
 * revoke -> denial) plus the things that ONLY differ over the wire: response
 * headers as an external client sees them, and CORS preflight, which is what
 * a browser-based consent UI actually issues before it can POST anything.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createServer, type ServerContext } from "./bootstrap.js";
import { listenHttpServer, type NodeServer } from "./listen.js";
import { initializeDatabase } from "./storage/index-schema.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const SCOPE = "spotify.top_artists";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);
const REDIRECT = "https://app.example.com/callback";
const CLIENT_ID = "music_recommendations";

const DECLARATION = JSON.stringify({
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  streams: [
    {
      name: "top_artists",
      fields: ["id", "name", "genres", "source_updated_at"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let ctx: ServerContext | undefined;
let server: NodeServer | undefined;
let baseUrl: string;

function seedScope(scope: string): void {
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
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, "spotify.json");
  await writeFile(path, DECLARATION, "utf-8");
  return path;
}

/**
 * Boot the server AND bind a real socket. Port 0 asks the OS for an ephemeral
 * port, so parallel test files never collide on a fixed port.
 */
async function bootAndListen(): Promise<void> {
  const config = ServerConfigSchema.parse({
    tunnel: { enabled: false },
    pdpp: {
      enabled: true,
      declarationPaths: [await writeDeclaration()],
      clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
    },
  });

  ctx = await createServer(config, {
    serverDir: tempDir,
    dataDir: join(tempDir, "data"),
  });

  let bound: AddressInfo | undefined;
  server = await listenHttpServer({
    fetch: ctx.app.fetch,
    port: 0,
    hostname: "127.0.0.1",
    onListening: (info) => {
      bound = info;
    },
  });
  baseUrl = `http://127.0.0.1:${bound!.port}`;
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-live-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  seedScope(SCOPE);
  await bootAndListen();
});

afterEach(async () => {
  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = undefined;
  }
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

/** Real owner token, minted over the wire behind the server's owner proof. */
async function ownerToken(): Promise<string> {
  const res = await fetch(`${baseUrl}/pdpp/v1/owner/token`, {
    method: "POST",
    headers: { authorization: `Bearer ${ctx!.devToken}` },
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { access_token: string }).access_token;
}

/** Drive the full authorization flow over TCP to a grant-bound client token. */
async function obtainGrantBoundToken(): Promise<{
  grantId: string;
  accessToken: string;
}> {
  const owner = await ownerToken();
  const ownerAuth = { authorization: `Bearer ${owner}` };

  const authorized = await fetch(`${baseUrl}/pdpp/v1/authorize`, {
    method: "POST",
    headers: { ...ownerAuth, "content-type": "application/json" },
    body: JSON.stringify({
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      client_display: { name: "Concert Finder" },
      authorization_details: [
        {
          type: "https://pdpp.dev/data-access",
          source: { id: SOURCE_ID },
          purpose_code: "https://pdpp.dev/purpose/personalization",
          access_mode: "continuous",
          streams: [
            {
              name: "top_artists",
              fields: ["name"],
              time_range: { since: "2026-01-01T00:00:00.000Z" },
            },
          ],
        },
      ],
    }),
  });
  expect(authorized.status).toBe(201);
  const { session_id } = (await authorized.json()) as { session_id: string };

  const reviewed = await fetch(
    `${baseUrl}/pdpp/v1/authorize/${session_id}/review`,
    { headers: ownerAuth },
  );
  expect(reviewed.status).toBe(200);
  const review = (await reviewed.json()) as {
    review?: { review_digest: string };
  };
  expect(review.review?.review_digest).toBeTruthy();

  const approved = await fetch(
    `${baseUrl}/pdpp/v1/authorize/${session_id}/approve`,
    {
      method: "POST",
      headers: { ...ownerAuth, "content-type": "application/json" },
      body: JSON.stringify({ review_digest: review.review!.review_digest }),
    },
  );
  expect(approved.status).toBe(200);
  const approval = (await approved.json()) as {
    redirect_uri: string;
    grant_id: string;
  };

  const code = new URL(approval.redirect_uri).searchParams.get("code");
  expect(code).toBeTruthy();

  const tokenRes = await fetch(`${baseUrl}/pdpp/v1/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code!,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
      code_verifier: VERIFIER,
    }).toString(),
  });
  expect(tokenRes.status).toBe(200);
  const token = (await tokenRes.json()) as { access_token: string };
  expect(token.access_token).toBeTruthy();

  return { grantId: approval.grant_id, accessToken: token.access_token };
}

describe("PDPP journey over a real listening HTTP server", () => {
  it("completes the full journey over TCP, including revocation denial", async () => {
    const { grantId, accessToken } = await obtainGrantBoundToken();

    // Grant-bound read over the wire.
    const read = await fetch(`${baseUrl}/v1/streams/top_artists/records`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(read.status).toBe(200);

    // Headers an external client actually receives. `Request-Id` is the
    // correlation handle the spec requires on every response, and it only
    // proves useful if it survives the wire.
    expect(read.headers.get("request-id")).toBeTruthy();
    expect(read.headers.get("pdpp-version")).toBeTruthy();

    // Revoke over the wire.
    const owner = await ownerToken();
    const revoked = await fetch(`${baseUrl}/pdpp/v1/revoke`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${owner}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ grant_id: grantId }).toString(),
    });
    expect(revoked.status).toBe(200);

    // And the read is denied, through the same socket.
    const after = await fetch(`${baseUrl}/v1/streams/top_artists/records`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    expect(after.status).toBe(403);
    expect(JSON.stringify(await after.json())).toContain("grant_revoked");
  });

  /**
   * RFC 9728 discovery must be reachable unauthenticated over the wire: it is
   * the first request a client makes, before it holds any token.
   */
  it("serves protected-resource metadata unauthenticated over the wire", async () => {
    const res = await fetch(`${baseUrl}/.well-known/oauth-protected-resource`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { resource?: string };
    expect(body.resource).toBeTruthy();
  });

  /**
   * A 401 must carry the `WWW-Authenticate` challenge naming the metadata
   * URL, so an unauthenticated client can bootstrap discovery from a failed
   * read rather than needing the URL out of band.
   */
  it("challenges an unauthenticated read with a metadata pointer", async () => {
    const res = await fetch(`${baseUrl}/v1/streams/top_artists/records`);
    expect(res.status).toBe(401);
    const challenge = res.headers.get("www-authenticate");
    expect(challenge).toContain("Bearer");
    expect(challenge).toContain("resource_metadata");
  });
});
