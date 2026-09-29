/**
 * Desktop's current source identifiers against a real, bootstrapped PS.
 *
 * These requests intentionally use no connection fixture registration. The
 * PS must bootstrap account one and accept the legacy Desktop source keys at
 * the HTTP boundary while storing canonical retained source ids.
 */
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import Database from "better-sqlite3";
import { createServer, type ServerContext } from "./bootstrap.js";
import { initializeDatabase } from "./storage/index-schema.js";
import { createSqliteRecordStore } from "./storage/pdpp-records-sqlite-store.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const SOURCE_ID = "https://registry.pdpp.dev/sources/claude";
const DESKTOP_SOURCE_URI = "https://registry.pdpp.dev/connectors/claude";
const PUBLIC_SOURCE_ID = "claude";
const SCOPE = "claude.profile";
const DECLARATION = JSON.stringify({
  source_id: SOURCE_ID,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "profile",
      fields: ["id", "name"],
      required_fields: ["id"],
      primary_key: ["id"],
    },
  ],
});

let tempDir: string;
let ctx: ServerContext | undefined;
let owner: string;
let legacyId: string;

function seedScope() {
  const db = initializeDatabase(join(tempDir, "index.db"));
  db.prepare(
    `INSERT INTO data_files (file_id, path, scope, collected_at, size_bytes)
     VALUES (?, ?, ?, ?, ?)`,
  ).run("file-1", "claude/profile/seed.json", SCOPE, "2026-09-01T00:00:00Z", 1);
  db.close();
}

async function boot() {
  const declarationPath = join(tempDir, "declarations", "claude.json");
  await mkdir(join(tempDir, "declarations"), { recursive: true });
  await writeFile(declarationPath, DECLARATION, "utf-8");
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [declarationPath],
        methods: [{ method_id: "claude", declaration_path: declarationPath }],
      },
    }),
    { serverDir: tempDir, dataDir: join(tempDir, "data") },
  );
}

function seedRegisteredConnection() {
  const db = new Database(join(tempDir, "index.db"));
  try {
    createSqliteRecordStore(db).registerConnection({
      instance: "conn_123e4567-e89b-42d3-a456-426614174000",
      sourceId: SOURCE_ID,
      method: "claude",
      label: "Existing account",
    });
  } finally {
    db.close();
  }
}

async function mintOwnerToken(sourceId: string): Promise<Response> {
  return ctx!.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: sourceId, instance_id: legacyId }),
  });
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-desktop-compat-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  legacyId = `claude:${owner}`;
  seedScope();
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("Desktop multi-account compatibility on a real Personal Server", () => {
  it("lets a new Claude owner read account one's binding without fixture registration", async () => {
    ctx = await boot();
    const tokenResponse = await mintOwnerToken(SOURCE_ID);
    expect(tokenResponse.status).toBe(200);
    const { access_token: token } = (await tokenResponse.json()) as {
      access_token: string;
    };

    const binding = await ctx!.app.request(
      `/pdpp/instances/${encodeURIComponent(legacyId)}/binding`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(binding.status).toBe(200);
    expect(await binding.json()).toMatchObject({
      method: "claude",
      generation: 1,
      configured_active_method: "claude",
    });
  });

  it("accepts Desktop's source URI and public id while returning a refresh-matchable row", async () => {
    ctx = await boot();
    const tokenResponse = await mintOwnerToken(DESKTOP_SOURCE_URI);
    expect(tokenResponse.status).toBe(200);
    const { access_token: token } = (await tokenResponse.json()) as {
      access_token: string;
    };

    const registration = await ctx!.app.request(
      "/pdpp/connections/conn_123e4567-e89b-42d3-a456-426614174000",
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: DESKTOP_SOURCE_URI,
          method_id: "claude",
          label: "Claude account",
        }),
      },
    );
    expect(registration.status).toBe(200);
    expect((await registration.json()).source_id).toBe(SOURCE_ID);

    const listed = await ctx!.app.request(
      `/pdpp/connections?source_id=${PUBLIC_SOURCE_ID}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as {
      connections: Array<{
        connection_id: string;
        source_id: string;
        method_id: string;
      }>;
    };
    expect(body.connections).toContainEqual({
      connection_id: legacyId,
      source_id: PUBLIC_SOURCE_ID,
      method_id: "claude",
      label: "",
    });
    expect(body.connections).toContainEqual({
      connection_id: "conn_123e4567-e89b-42d3-a456-426614174000",
      source_id: PUBLIC_SOURCE_ID,
      method_id: "claude",
      label: "Claude account",
    });
  });

  it("does not mint source authority for aliases without a retained declaration", async () => {
    ctx = await boot();
    const response = await mintOwnerToken(
      "https://registry.pdpp.dev/connectors/oura",
    );
    expect(response.status).toBe(404);
  });

  it("does not add account one when a connection is already registered", async () => {
    seedRegisteredConnection();
    ctx = await boot();

    const tokenResponse = await mintOwnerToken(SOURCE_ID);
    expect(tokenResponse.status).toBe(200);
    const { access_token: token } = (await tokenResponse.json()) as {
      access_token: string;
    };
    const listed = await ctx!.app.request(
      `/pdpp/connections?source_id=${PUBLIC_SOURCE_ID}`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(listed.status).toBe(200);
    const body = (await listed.json()) as {
      connections: Array<{ connection_id: string }>;
    };
    expect(
      body.connections.map((connection) => connection.connection_id),
    ).toEqual(["conn_123e4567-e89b-42d3-a456-426614174000"]);

    const db = new Database(join(tempDir, "index.db"), { readonly: true });
    try {
      const row = db
        .prepare(
          "SELECT COUNT(*) AS n FROM pdpp_instance_binding WHERE instance = ?",
        )
        .get(legacyId) as { n: number };
      expect(row.n).toBe(0);
    } finally {
      db.close();
    }

    const phantomBinding = await ctx!.app.request(
      `/pdpp/instances/${encodeURIComponent(legacyId)}/binding`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(phantomBinding.status).toBe(401);
  });
});
