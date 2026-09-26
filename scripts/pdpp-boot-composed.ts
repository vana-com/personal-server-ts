/**
 * Boot ONE real Personal Server serving both PDPP halves, for an external
 * integration test to drive.
 *
 * Prints a single machine-readable ready line and then stays up:
 *
 *   PS_READY <port> <ownerToken> <sourceId> <stream>
 *
 * Unlike a harness that boots an AS and an RS as two processes, this is one
 * `createServer` with one token authority — so a token the AS mints is a token
 * the RS resolves. That is the property an external client needs in order to
 * exercise the real flow rather than a fixture.
 *
 * Everything is real: config parsing, SQLite, owner derivation from a wallet
 * signature, the declaration trust policy, PKCE, grant issuance, enforcement.
 * The declaration document and the seeded scope row are fixtures, because the
 * trust policy is derived from what the server actually serves — a declaration
 * for a source with no data here is refused by design.
 */

import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { createServer } from "../packages/server/src/bootstrap.js";
import { listenHttpServer } from "../packages/server/src/listen.js";
import { initializeDatabase } from "../packages/server/src/storage/index-schema.js";
import { singleInstanceInventory } from "../packages/server/src/pdpp/deployment.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const SCOPE = "spotify.top_artists";
const STREAM = "top_artists";

/** Registered client. `redirect_uri` is validated by exact match against it. */
const CLIENT_ID = process.env.PDPP_CLIENT_ID ?? "music_recommendations";
const REDIRECT =
  process.env.PDPP_REDIRECT_URI ?? "https://app.example.com/callback";

const DECLARATION = JSON.stringify({
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "2026-08-11",
  streams: [
    {
      name: STREAM,
      fields: ["id", "name", "genres", "source_updated_at"],
      required_fields: ["id"],
      consent_time_field: "source_updated_at",
      primary_key: ["id"],
    },
  ],
});

async function main(): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), "pdpp-composed-"));

  // The declaration trust policy is derived from the connector inventory in
  // the real scope index, so seeding one row is what makes `spotify` served.
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

  const declDir = join(root, "declarations");
  await mkdir(declDir, { recursive: true });
  const declPath = join(declDir, "spotify.json");
  await writeFile(declPath, DECLARATION, "utf-8");

  process.env.VANA_MASTER_KEY_SIGNATURE = KNOWN_SIG;

  const ctx = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [declPath],
        clients: [{ clientId: CLIENT_ID, redirectUris: [REDIRECT] }],
      },
    }),
    { serverDir: root, dataDir: join(root, "data") },
  );

  let bound: AddressInfo | undefined;
  const server = await listenHttpServer({
    fetch: ctx.app.fetch,
    port: Number(process.env.PDPP_PORT ?? 0),
    hostname: "127.0.0.1",
    onListening: (info) => {
      bound = info;
    },
  });

  // A real owner token, minted through the mounted route behind the server's
  // own owner proof. The external test cannot mint one itself, which is the
  // point: only the owner's authenticated session can.
  const subject = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  const instanceId = singleInstanceInventory(subject, SOURCE_ID).eligibleFor(
    "",
  )[0];
  const ownerRes = await ctx.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: SOURCE_ID, instance_id: instanceId }),
  });
  if (ownerRes.status !== 200) {
    throw new Error(`owner token mint failed: ${ownerRes.status}`);
  }
  const { access_token: ownerToken } = (await ownerRes.json()) as {
    access_token: string;
  };

  // Single ready line, parsed positionally by the consuming test.
  console.log(`PS_READY ${bound!.port} ${ownerToken} ${SOURCE_ID} ${STREAM}`);

  const shutdown = () => {
    server.close(() => {
      void ctx.cleanup().then(() => process.exit(0));
    });
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  await new Promise(() => {});
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
