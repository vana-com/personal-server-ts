/**
 * Start a real PDPP Personal Server and walk the whole journey against it.
 *
 * This is the manual counterpart to `packages/server/src/
 * pdpp-live-http-journey.test.ts`: same listener, same flow, but it prints
 * every step and can be pointed at a server you keep running, so a human (or
 * the Context Gateway client / a consent UI) can drive the same endpoints.
 *
 *   npx tsx scripts/pdpp-live-journey.ts            # boot, walk, tear down
 *   npx tsx scripts/pdpp-live-journey.ts --serve    # boot, walk, STAY UP
 *
 * With --serve the process keeps listening after the walk and prints the base
 * URL, the owner token, and a grant-bound client token, so you can curl the
 * same surfaces or point a real client at them. Ctrl-C to stop.
 *
 * Everything is real: real config parsing, real SQLite, real owner derivation
 * from a wallet signature, real declaration trust policy, real PKCE, real
 * grant, real token. The only fixtures are the declaration document and the
 * seeded scope row, because the trust policy is derived from what the server
 * actually serves — a declaration for a source with no data here is refused
 * by design, so a demo must seed something.
 */

import { mkdir, mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { computeS256Challenge } from "@opendatalabs/personal-server-ts-core/pdpp";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { createServer } from "../packages/server/src/bootstrap.js";
import { listenHttpServer } from "../packages/server/src/listen.js";
import { initializeDatabase } from "../packages/server/src/storage/index-schema.js";
import { singleInstanceInventory } from "../packages/server/src/pdpp/deployment.js";

/** Derives a stable owner address; the same signature the test suites use. */
const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const SCOPE = "spotify.top_artists";
const VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE = computeS256Challenge(VERIFIER);
const REDIRECT = "https://app.example.com/callback";
const CLIENT_ID = "music_recommendations";
const PORT = Number(process.env.PDPP_PORT ?? 0);
const SERVE = process.argv.includes("--serve");

const DECLARATION = JSON.stringify(
  {
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
  },
  null,
  2,
);

let step = 0;
function say(what: string, detail?: unknown): void {
  step += 1;
  const suffix =
    detail === undefined
      ? ""
      : ` ${typeof detail === "string" ? detail : JSON.stringify(detail)}`;
  console.log(`[${String(step).padStart(2, "0")}] ${what}${suffix}`);
}

function must(condition: boolean, message: string): void {
  if (!condition) {
    console.error(`\n  FAILED: ${message}`);
    process.exit(1);
  }
}

async function main(): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "pdpp-live-journey-"));

  // --- Seed what a real deployment would already have ---------------------
  // The declaration trust policy is derived from the connector inventory in
  // the real scope index, so a declaration for a source this PS holds no data
  // for is refused. Seeding one row is what makes `spotify` a served source.
  const db = initializeDatabase(join(root, "index.db"));
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
  say("seeded scope in the real index", SCOPE);

  const declDir = join(root, "declarations");
  await mkdir(declDir, { recursive: true });
  const declPath = join(declDir, "spotify.json");
  await writeFile(declPath, DECLARATION, "utf-8");
  say("wrote declaration", declPath);

  // The owner is derived from this signature, exactly as in production.
  process.env.VANA_MASTER_KEY_SIGNATURE = KNOWN_SIG;

  const config = ServerConfigSchema.parse({
    tunnel: { enabled: false },
    pdpp: {
      enabled: true,
      declarationPaths: [declPath],
      // redirect_uri is validated by EXACT match against a registered client.
      clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
    },
  });

  const ctx = await createServer(config, {
    serverDir: root,
    dataDir: join(root, "data"),
  });

  let bound: AddressInfo | undefined;
  const server = await listenHttpServer({
    fetch: ctx.app.fetch,
    port: PORT,
    hostname: "127.0.0.1",
    onListening: (info) => {
      bound = info;
    },
  });
  const base = `http://127.0.0.1:${bound!.port}`;
  say("server listening", base);

  // --- 1. Discovery, unauthenticated --------------------------------------
  const meta = await fetch(`${base}/.well-known/oauth-protected-resource`);
  must(meta.status === 200, `discovery returned ${meta.status}`);
  say("RFC 9728 discovery", await meta.json());

  // --- 2. Owner token, behind the server's own owner proof ----------------
  const subject = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  const instanceId = singleInstanceInventory(subject, SOURCE_ID).eligibleFor(
    "",
  )[0];
  const ownerRes = await fetch(`${base}/pdpp/v1/owner/token`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: SOURCE_ID, instance_id: instanceId }),
  });
  must(ownerRes.status === 200, `owner token returned ${ownerRes.status}`);
  const owner = ((await ownerRes.json()) as { access_token: string })
    .access_token;
  say("owner token minted");

  const ownerAuth = { authorization: `Bearer ${owner}` };

  // --- 3. Selection request, with PKCE ------------------------------------
  const authorized = await fetch(`${base}/pdpp/v1/authorize`, {
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
          // Only `name`: not the required `id` floor, not the time field.
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
  must(authorized.status === 201, `authorize returned ${authorized.status}`);
  const { session_id } = (await authorized.json()) as { session_id: string };
  say("authorization session opened", session_id);

  // --- 4. The consent review model the UI would render --------------------
  const reviewed = await fetch(
    `${base}/pdpp/v1/authorize/${session_id}/review`,
    { headers: ownerAuth },
  );
  must(reviewed.status === 200, `review returned ${reviewed.status}`);
  const review = (await reviewed.json()) as {
    review?: { review_digest: string };
  };
  must(Boolean(review.review?.review_digest), "review carried no digest");
  say("consent review model fetched", {
    review_digest: review.review!.review_digest.slice(0, 16) + "…",
  });

  // --- 5. Owner approval, bound to the exact reviewed digest --------------
  const approved = await fetch(
    `${base}/pdpp/v1/authorize/${session_id}/approve`,
    {
      method: "POST",
      headers: { ...ownerAuth, "content-type": "application/json" },
      body: JSON.stringify({ review_digest: review.review!.review_digest }),
    },
  );
  must(approved.status === 200, `approve returned ${approved.status}`);
  const approval = (await approved.json()) as {
    redirect_uri: string;
    grant_id: string;
  };
  say("grant issued", approval.grant_id);

  // --- 6. Redeem the code with the PKCE verifier --------------------------
  const code = new URL(approval.redirect_uri).searchParams.get("code");
  must(Boolean(code), "no authorization code in the redirect");
  const tokenRes = await fetch(`${base}/pdpp/v1/token`, {
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
  must(tokenRes.status === 200, `token returned ${tokenRes.status}`);
  const clientToken = ((await tokenRes.json()) as { access_token: string })
    .access_token;
  say("grant-bound client token issued");

  // --- 7. The constrained read -------------------------------------------
  const read = await fetch(`${base}/v1/streams/top_artists/records`, {
    headers: { authorization: `Bearer ${clientToken}` },
  });
  must(read.status === 200, `read returned ${read.status}`);
  say("grant-bound read", {
    status: read.status,
    request_id: read.headers.get("request-id"),
    pdpp_version: read.headers.get("pdpp-version"),
  });

  // --- 8. Revoke, then prove the denial -----------------------------------
  const revoked = await fetch(`${base}/pdpp/v1/revoke`, {
    method: "POST",
    headers: {
      ...ownerAuth,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ grant_id: approval.grant_id }).toString(),
  });
  must(revoked.status === 200, `revoke returned ${revoked.status}`);
  say("grant revoked");

  const denied = await fetch(`${base}/v1/streams/top_artists/records`, {
    headers: { authorization: `Bearer ${clientToken}` },
  });
  must(
    denied.status === 403,
    `expected 403 after revoke, got ${denied.status}`,
  );
  say("read denied after revocation", await denied.json());

  console.log(
    "\n  Journey complete — every step against a real listening server.\n",
  );

  if (!SERVE) {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await ctx.cleanup();
    await rm(root, { recursive: true, force: true });
    return;
  }

  // --serve: mint a FRESH grant, since the one above is now revoked, and stay
  // up so a real client can be pointed at these endpoints.
  console.log(`  Still listening on ${base}`);
  console.log(`  Owner token:  ${owner}`);
  console.log(`  Storage root: ${root}`);
  console.log(`\n  Try:`);
  console.log(`    curl ${base}/.well-known/oauth-protected-resource`);
  console.log(
    `    curl -H "authorization: Bearer ${owner}" ${base}/v1/streams`,
  );
  console.log(`\n  Ctrl-C to stop.\n`);

  process.on("SIGINT", () => {
    server.close(() => {
      void ctx.cleanup().then(() => process.exit(0));
    });
  });
  await new Promise(() => {});
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
