import { access, mkdtemp, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const DECLARATION = JSON.stringify({
  source_id: "https://registry.pdpp.dev/connectors/spotify",
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

const KNOWN_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

const CHILD = String.raw`
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

const rootPath = process.env.PDPP_CLEANUP_TEST_ROOT;
const declarationPath = join(rootPath, "declaration.json");
await writeFile(declarationPath, process.env.PDPP_CLEANUP_TEST_DECLARATION);
const { loadConfig } = await import("./packages/server/dist/config/index.js");
const { createServer } = await import("./packages/server/dist/bootstrap.js");
const { initializeDatabase } = await import("./packages/server/dist/storage/index-schema.js");
const config = await loadConfig({ rootPath });
const indexDb = initializeDatabase(join(rootPath, "index.db"));
indexDb.prepare(
  "INSERT INTO data_files (file_id, path, scope, collected_at, size_bytes) VALUES (?, ?, ?, ?, ?)",
).run("file-1", "spotify/top_artists/fixture.json", "spotify.top_artists", "2026-01-01T00:00:00Z", 1);
indexDb.close();
config.pdpp.enabled = true;
config.pdpp.declarationPaths = [declarationPath];
config.pdpp.methods = [{ method_id: "spotify", declaration_path: declarationPath }];
config.pdpp.clients = [{
  clientId: "music_recommendations",
  redirectUris: ["https://app.example.com/callback"],
}];
config.devUi.enabled = true;
config.sync.enabled = false;
config.tunnel.enabled = false;
const context = await createServer(config, {
  rootPath,
  ownerSignature: process.env.PDPP_CLEANUP_TEST_SIGNATURE,
});
console.log("PDPP_DATABASES_OPENED", config.pdpp.enabled);
const ownerTokenResponse = await context.app.request("/pdpp/v1/owner/token", {
  method: "POST",
  headers: {
    authorization: "Bearer " + context.devToken,
    "content-type": "application/json",
  },
  body: JSON.stringify({ source_id: "https://registry.pdpp.dev/connectors/spotify" }),
});
if (!ownerTokenResponse.ok) {
  throw new Error("owner token failed: " + ownerTokenResponse.status);
}
const { access_token: ownerToken } = await ownerTokenResponse.json();
const sessionResponse = await context.app.request("/pdpp/v1/authorize", {
  method: "POST",
  headers: {
    authorization: "Bearer " + ownerToken,
    "content-type": "application/json",
  },
  body: JSON.stringify({
    client_id: "music_recommendations",
    redirect_uri: "https://app.example.com/callback",
    state: "cleanup-test",
    code_challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    code_challenge_method: "S256",
    client_display: { name: "Cleanup test" },
    authorization_details: [{
      type: "https://pdpp.dev/data-access",
      source: { id: "https://registry.pdpp.dev/connectors/spotify" },
      purpose_code: "https://pdpp.dev/purpose/personalization",
      access_mode: "continuous",
      streams: [{ name: "top_artists" }],
    }],
  }),
});
if (sessionResponse.status !== 201) {
  throw new Error("authorization failed: " + sessionResponse.status);
}
const { session_id: sessionId } = await sessionResponse.json();
const reviewResponse = await context.app.request(
  "/pdpp/v1/authorize/" + sessionId + "/review",
  { headers: { authorization: "Bearer " + ownerToken } },
);
if (!reviewResponse.ok) throw new Error("review failed: " + reviewResponse.status);
await context.cleanup();
console.log("CLEANUP_COMPLETED");
`;

describe("Personal Server SQLite cleanup in a Node child process", () => {
  let rootPath: string;

  afterEach(async () => {
    if (rootPath) await rm(rootPath, { recursive: true, force: true });
  });

  it("closes the PDPP SQLite databases before Node exits", async () => {
    expect(process.versions.node.split(".")[0]).toBe("24");
    rootPath = await mkdtemp(join(tmpdir(), "ps-bootstrap-cleanup-"));
    const child = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", CHILD],
      {
        cwd: process.cwd(),
        encoding: "utf8",
        env: {
          ...process.env,
          PDPP_CLEANUP_TEST_ROOT: rootPath,
          PDPP_CLEANUP_TEST_DECLARATION: DECLARATION,
          PDPP_CLEANUP_TEST_SIGNATURE: KNOWN_SIGNATURE,
        },
      },
    );

    expect(child.error).toBeUndefined();
    expect(child.signal).toBeNull();
    expect(
      child.status,
      `child stdout:\n${child.stdout}\nchild stderr:\n${child.stderr}`,
    ).toBe(0);
    expect(child.stdout).toContain("CLEANUP_COMPLETED");
    expect(child.stdout).toContain("PDPP_DATABASES_OPENED true");
    expect(child.stderr).not.toContain("Assertion failed: (env) != nullptr");
    await expect(
      access(join(rootPath, "pdpp-declarations.db")),
    ).resolves.toBeUndefined();
    await expect(
      access(join(rootPath, "pdpp-auth.db")),
    ).resolves.toBeUndefined();
  });
});
