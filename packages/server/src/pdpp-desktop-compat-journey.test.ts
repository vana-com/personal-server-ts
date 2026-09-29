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

async function boot(
  connectionMethods: { source_id: string; method_id: string }[] = [],
  canonicalEnabled = true,
) {
  const declarationPath = join(tempDir, "declarations", "claude.json");
  await mkdir(join(tempDir, "declarations"), { recursive: true });
  await writeFile(declarationPath, DECLARATION, "utf-8");
  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: canonicalEnabled,
        declarationPaths: canonicalEnabled ? [declarationPath] : [],
        methods: canonicalEnabled
          ? [{ method_id: "claude", declaration_path: declarationPath }]
          : [],
        connectionMethods,
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

async function mintOwnerToken(
  sourceId: string,
  instanceId: string | undefined = legacyId,
): Promise<Response> {
  return ctx!.app.request("/pdpp/v1/owner/token", {
    method: "POST",
    headers: {
      authorization: `Bearer ${ctx!.devToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ source_id: sourceId, instance_id: instanceId }),
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

  it("serves connection management for an undeclared canonical-off source", async () => {
    const ouraSource = "https://registry.pdpp.dev/sources/oura";
    ctx = await boot([{ source_id: ouraSource, method_id: "oura" }], false);
    expect(ctx.config.pdpp.connectionMethods).toEqual([
      { source_id: ouraSource, method_id: "oura" },
    ]);
    expect((await ctx.app.request("/pdpp/capabilities")).status).toBe(200);

    const tokenResponse = await mintOwnerToken(
      "https://registry.pdpp.dev/connectors/oura",
    );
    expect(tokenResponse.status, await tokenResponse.clone().text()).toBe(200);
    const { access_token: token } = (await tokenResponse.json()) as {
      access_token: string;
    };

    const empty = await ctx.app.request("/pdpp/connections?source_id=oura", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(empty.status).toBe(200);
    expect((await empty.json()).connections).toEqual([]);

    const connectionId = "conn_123e4567-e89b-42d3-a456-426614174000";
    const registered = await ctx.app.request(
      `/pdpp/connections/${connectionId}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          source_id: "https://registry.pdpp.dev/connectors/oura",
          method_id: "oura",
          label: "Account B",
        }),
      },
    );
    expect(registered.status).toBe(200);
    expect((await registered.json()).source_id).toBe(ouraSource);

    const listed = await ctx.app.request("/pdpp/connections?source_id=oura", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect((await listed.json()).connections).toMatchObject([
      {
        connection_id: connectionId,
        source_id: "oura",
        method_id: "oura",
        label: "Account B",
      },
    ]);

    const accountTokenResponse = await mintOwnerToken(ouraSource, connectionId);
    expect(accountTokenResponse.status).toBe(200);
    const { access_token: accountToken } =
      (await accountTokenResponse.json()) as { access_token: string };
    const canonicalWrite = await ctx.app.request(
      "/v1/streams/profile/records/ingest?method=oura&binding_generation=1",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${accountToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance: connectionId,
          key: "record-1",
          data: { id: "record-1" },
          emitted_at: "2026-09-01T00:00:00Z",
        }),
      },
    );
    expect(canonicalWrite.status).not.toBe(200);

    const deleted = await ctx.app.request(`/pdpp/connections/${connectionId}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}` },
    });
    expect(deleted.status).toBe(200);
    const afterDelete = await ctx.app.request(
      "/pdpp/connections?source_id=oura",
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect((await afterDelete.json()).connections).toEqual([]);

    const canonicalRead = await ctx.app.request("/v1/streams/profile/records", {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(canonicalRead.status).not.toBe(200);
  });

  it("does not reactivate retained canonical writers when a source is registry-only", async () => {
    ctx = await boot();
    await ctx.cleanup();
    ctx = await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        pdpp: {
          enabled: true,
          declarationPaths: [],
          methods: [],
          connectionMethods: [{ source_id: SOURCE_ID, method_id: "claude" }],
        },
      }),
      { serverDir: tempDir, dataDir: join(tempDir, "data") },
    );

    const tokenResponse = await mintOwnerToken(SOURCE_ID);
    expect(tokenResponse.status).toBe(200);
    const { access_token: token } = (await tokenResponse.json()) as {
      access_token: string;
    };
    const write = await ctx.app.request(
      "/v1/streams/profile/records/ingest?method=claude&binding_generation=1",
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance: legacyId,
          key: "record-1",
          data: { id: "record-1" },
          emitted_at: "2026-09-01T00:00:00Z",
        }),
      },
    );
    expect(write.status).toBe(409);
    expect(await write.json()).toMatchObject({
      error: { code: "method_inactive" },
    });
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

  it("registers every legacy-data source after upgrading an empty connection registry", async () => {
    const sources = [
      {
        source_id: "https://registry.pdpp.dev/connectors/github",
        method_id: "github",
      },
      {
        source_id: "https://registry.pdpp.dev/connectors/oura",
        method_id: "oura",
      },
    ];
    const legacyScopes = ["github.profile", "oura.sleep"];
    const db = new Database(join(tempDir, "index.db"));
    try {
      db.exec("DELETE FROM data_files");
    } finally {
      db.close();
    }
    ctx = await boot(sources, false);

    for (const source of sources) {
      const tokenResponse = await mintOwnerToken(source.source_id);
      expect(tokenResponse.status).toBe(200);
      const { access_token: token } = (await tokenResponse.json()) as {
        access_token: string;
      };
      const listed = await ctx.app.request(
        `/pdpp/connections?source_id=${encodeURIComponent(source.source_id)}`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      expect((await listed.json()).connections).toEqual([]);
    }

    for (const scope of legacyScopes) {
      const written = await ctx.app.request(`/v1/data/${scope}`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${ctx.devToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ id: `${scope}-legacy-row` }),
      });
      expect(written.status, await written.clone().text()).toBe(201);
    }

    await ctx.cleanup();
    ctx = await boot(sources, false);
    for (const source of sources) {
      const tokenResponse = await mintOwnerToken(source.source_id);
      expect(tokenResponse.status).toBe(200);
      const { access_token: token } = (await tokenResponse.json()) as {
        access_token: string;
      };
      const listed = await ctx.app.request(
        `/pdpp/connections?source_id=${encodeURIComponent(source.source_id)}`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      expect(listed.status).toBe(200);
      const body = (await listed.json()) as {
        connections: Array<{
          connection_id: string;
          label: string;
          method_id: string;
          source_id: string;
        }>;
      };
      expect(body.connections).toEqual([
        {
          connection_id: `${source.source_id.split("/").at(-1)}:${owner}`,
          label: "",
          method_id: source.method_id,
          source_id: source.source_id,
        },
      ]);
    }

    await ctx.cleanup();
    ctx = await boot(sources, false);
    for (const source of sources) {
      const tokenResponse = await mintOwnerToken(source.source_id);
      const { access_token: token } = (await tokenResponse.json()) as {
        access_token: string;
      };
      const listed = await ctx.app.request(
        `/pdpp/connections?source_id=${encodeURIComponent(source.source_id)}`,
        { headers: { authorization: `Bearer ${token}` } },
      );
      expect(listed.status).toBe(200);
      const body = (await listed.json()) as {
        connections: Array<{
          connection_id: string;
          label: string;
          method_id: string;
          source_id: string;
        }>;
      };
      expect(body.connections).toEqual([
        {
          connection_id: `${source.source_id.split("/").at(-1)}:${owner}`,
          label: "",
          method_id: source.method_id,
          source_id: source.source_id,
        },
      ]);
    }
  });
});
