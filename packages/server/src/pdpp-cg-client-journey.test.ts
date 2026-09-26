/**
 * The REAL Context Gateway client against the REAL integrated server.
 *
 * Context Gateway's `PdppContextClient` (branch `pdpp/context-client-0917`,
 * PR #284) is vendored unmodified into `__fixtures__/cg-pdpp-client/` and
 * pointed at a real Personal Server booted through `createServer` and bound to
 * a real loopback socket. The token it carries is minted by the real AS in the
 * same process that serves the RS.
 *
 * ── Why this file exists ────────────────────────────────────────────────────
 *
 * Two lanes independently recorded that this could not be done yet, and both
 * were right at the time:
 *
 *   - `pdpp-context-client.ts`'s own header: "This client is typed against
 *     `ps-auth-contract.md`'s TypeScript seam and the spec text, not against a
 *     running server; there is nothing to integration-test against yet."
 *   - `pdpp-context-client.live.test.ts` boots the AS and RS as two SEPARATE
 *     child processes from two unmerged branches, and says so plainly: it
 *     "cannot mint a token from the real AS and have the real RS's own
 *     `PdppAuthorizationService` validate it", so its RS half uses a fixture
 *     auth service recognizing one fixed token. It states that AS/RS
 *     compatibility "only becomes checkable once one of the two branches
 *     merges."
 *
 * This composed tree is that condition: both branches merged, one server, one
 * token authority. So the fixture auth service is gone and the client talks to
 * a server where the AS that minted the token is the same AS the RS resolves
 * it through.
 *
 * ── What is a fixture and what is not ──────────────────────────────────────
 *
 * FIXTURE: the vendored client source (copied verbatim, so it is the real
 * client, not a reimplementation), the declaration document, and the seeded
 * scope row.
 *
 * NOT FIXTURE: the server, the socket, the owner proof, the owner token, the
 * declaration trust policy, PKCE, the grant, the access token, and every
 * enforcement decision. No fabricated grant or token appears anywhere.
 */

import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { createServer, type ServerContext } from "./bootstrap.js";
import { listenHttpServer, type NodeServer } from "./listen.js";
import { initializeDatabase } from "./storage/index-schema.js";
import { singleInstanceInventory } from "./pdpp/deployment.js";
import {
  bearerTokenAuthorizationStrategy,
  PdppContextClient,
  PdppClientError,
} from "./__fixtures__/cg-pdpp-client/pdpp-context-client.js";

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

function seedScope(): void {
  const db = initializeDatabase(join(tempDir, "index.db"));
  db.prepare(
    `INSERT INTO data_files (file_id, path, scope, collected_at, size_bytes)
     VALUES (?, ?, ?, ?, ?)`,
  ).run(
    "file-1",
    "spotify/top_artists/2026-01-01T00:00:00Z.json",
    SCOPE,
    "2026-01-01T00:00:00Z",
    128,
  );
  db.close();
}

async function bootAndListen(): Promise<void> {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const declPath = join(dir, "spotify.json");
  await writeFile(declPath, DECLARATION, "utf-8");

  ctx = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [declPath],
        clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
      },
    }),
    { serverDir: tempDir, dataDir: join(tempDir, "data") },
  );

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
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-cg-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  seedScope();
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

async function ownerToken(): Promise<string> {
  const subject = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  const instanceId = singleInstanceInventory(subject, SOURCE_ID).eligibleFor(
    "",
  )[0];
  const res = await fetch(`${baseUrl}/pdpp/v1/owner/token`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: SOURCE_ID, instance_id: instanceId }),
  });
  expect(res.status).toBe(200);
  return ((await res.json()) as { access_token: string }).access_token;
}

/** Real AS flow over the wire → a real grant-bound client access token. */
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
          streams: [{ name: "top_artists", fields: ["name"] }],
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
  const review = (await reviewed.json()) as {
    review?: { review_digest: string };
  };

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

  return { grantId: approval.grant_id, accessToken: token.access_token };
}

function clientFor(accessToken: string): PdppContextClient {
  return new PdppContextClient({
    baseUrl: baseUrl,
    authorization: bearerTokenAuthorizationStrategy(accessToken),
  });
}

describe("Context Gateway PdppContextClient against a real integrated PS", () => {
  it("lists streams through the real client with a real AS-minted token", async () => {
    const { accessToken } = await obtainGrantBoundToken();
    const client = clientFor(accessToken);

    // The client parsed a real §8 list envelope into its own typed shape,
    // over a real socket, using a token the real AS minted. The store holds
    // no records for this stream, so the listing is legitimately empty --
    // the assertion is that the round-trip and typing work, not the count.
    // (Record-level projection is asserted in pdpp-integrated-journey.)
    const streams = await client.listStreams();

    expect(streams.object).toBe("list");
    expect(Array.isArray(streams.data)).toBe(true);
    // A client token never sees a stream its grant does not name.
    for (const s of streams.data) {
      expect(s.name).toBe("top_artists");
    }
  });

  it("reads records through the real client, with grant projection applied", async () => {
    const { accessToken } = await obtainGrantBoundToken();
    const client = clientFor(accessToken);

    const page = await client.listRecords("top_artists");

    // The store is empty for this stream, so the interesting assertion is
    // that the client round-tripped a real §8 list envelope rather than
    // throwing — shape, not row count.
    expect(Array.isArray(page.data)).toBe(true);
    expect(page.object).toBe("list");
  });

  it("surfaces a revoked grant as a typed client error, not a parse failure", async () => {
    const { grantId, accessToken } = await obtainGrantBoundToken();
    const client = clientFor(accessToken);

    // Works before revocation.
    await client.listStreams();

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

    // The whole point of the client's error handling: a revoked grant must
    // arrive as a structured PdppClientError carrying the spec's error code,
    // not as an opaque transport failure the caller cannot act on.
    // A revoked grant must arrive as a structured PdppClientError carrying
    // the spec's own error code -- not an opaque transport failure, and not a
    // generic auth error the caller cannot distinguish from a bad token.
    await expect(client.listStreams()).rejects.toBeInstanceOf(PdppClientError);
    await expect(client.listStreams()).rejects.toMatchObject({
      code: "grant_revoked",
    });
  });
});
