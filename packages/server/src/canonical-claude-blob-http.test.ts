import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import Ajv from "ajv";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as canonicalReader from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

const SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const SOURCE = "https://registry.pdpp.dev/sources/anthropic";
const CONTROL = "claude-blob-http-synthetic-control";
const collected = "2026-09-01T12:00:00Z";
const profile = {
  id: "org",
  organization_id: "org",
  full_name: "Synthetic reader",
  plan: null,
  name_source: "users_json",
  metadata_status: "valid",
};
let root: string, ctx: ServerContext, instance: string, token: string;

beforeEach(async () => {
  const parent = join(homedir(), ".tmp");
  await mkdir(parent, { recursive: true });
  root = await mkdtemp(join(parent, "claude-blob-http-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", SIGNATURE);
  vi.stubEnv("PS_ACCESS_TOKEN", CONTROL);
  const owner = (await recoverServerOwner(SIGNATURE)).toLowerCase();
  instance = `anthropic:${owner}`;
  const declaration = join(root, "declaration.json");
  await writeFile(
    declaration,
    JSON.stringify({
      source_id: SOURCE,
      source_kind: "connector",
      version: "1",
      streams: [
        {
          name: "account_profile",
          fields: Object.keys(profile),
          required_fields: ["id"],
          primary_key: ["id"],
        },
        {
          name: "projects",
          fields: ["id", "name", "blob_ref"],
          required_fields: ["id"],
          primary_key: ["id"],
        },
        {
          name: "project_documents",
          fields: [
            "id",
            "project_id",
            "filename",
            "content",
            "create_time",
            "update_time",
          ],
          required_fields: ["id"],
          primary_key: ["id"],
        },
      ],
    }),
  );
  ctx = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [declaration],
        methods: [{ method_id: "anthropic", declaration_path: declaration }],
      },
    }),
    { serverDir: root, dataDir: join(root, "data") },
  );
  token = await registerTestConnection(ctx.app, ctx.devToken!, owner, SOURCE);
});
afterEach(async () => {
  await ctx?.cleanup();
  await rm(root, { recursive: true, force: true });
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

async function replace(stream: string, rows: Record<string, unknown>[]) {
  const response = await ctx.app.request(
    `/v1/streams/${stream}/records/replace?method=anthropic&binding_generation=1`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance,
        emitted_at: collected,
        source_collected_at: collected,
        records: rows.map((data) => ({
          key: data.id,
          data,
          emitted_at: collected,
        })),
      }),
    },
  );
  expect({
    status: response.status,
    body: await response.json(),
  }).toMatchObject({ status: 200 });
}
async function files(path: string): Promise<string[]> {
  const entries = await readdir(path, { withFileTypes: true });
  return (
    await Promise.all(
      entries.map(async (entry) =>
        entry.isDirectory()
          ? files(join(path, entry.name))
          : [join(path, entry.name)],
      ),
    )
  ).flat();
}

it("serves the owner's actual app envelope directly from SQLite/blob bytes without storing a projected file", async () => {
  const payload = {
    uuid: "project-1",
    name: "Research",
    docs: [
      {
        uuid: "doc-1",
        filename: "notes.txt",
        content: "Synthetic notes",
        created_at: collected,
      },
    ],
  };
  const bytes = new TextEncoder().encode(
    JSON.stringify({
      format: "anthropic-source-record-v1",
      stream: "projects",
      record_key: "project-1",
      payload,
    }),
  );
  const upload = await ctx.app.request(
    `/v1/blobs/ingest?instance=${encodeURIComponent(instance)}&method=anthropic&binding_generation=1`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: bytes,
    },
  );
  expect(upload.status).toBe(200);
  const blob_ref = await upload.json();
  await replace("account_profile", [profile]);
  await replace("projects", [{ id: "project-1", name: "Research", blob_ref }]);
  // Public mutable-state P7 completion is explicit TEST evidence only.
  await replace("project_documents", [
    {
      id: "doc-1",
      project_id: "project-1",
      filename: "notes.txt",
      content: "Synthetic notes",
      create_time: collected,
      update_time: null,
    },
  ]);
  const db = new Database(join(root, "index.db"), { readonly: true });
  const snapshot = () => ({
    rows: db
      .prepare("SELECT * FROM pdpp_records ORDER BY instance,stream,record_key")
      .all(),
    versions: db
      .prepare(
        "SELECT * FROM pdpp_record_changes ORDER BY instance,stream,record_key,version",
      )
      .all(),
    receipts: db
      .prepare("SELECT * FROM pdpp_stream_completion ORDER BY instance,stream")
      .all(),
    blob: db.prepare("SELECT * FROM pdpp_blob_bytes ORDER BY blob_id").all(),
  });
  try {
    const before = snapshot();
    const first = await ctx.app.request("/v1/data/claude.projects", {
      headers: { authorization: `Bearer ${CONTROL}` },
    });
    expect(first.status).toBe(200);
    const firstText = await first.text();
    const body = JSON.parse(firstText);
    expect(body).toEqual({
      version: "1.0",
      scope: "claude.projects",
      collectedAt: "2026-09-01T12:00:00.000Z",
      data: {
        profile: { name: "Synthetic reader", plan: null },
        organizationId: "org",
        total: 1,
        source: "official-export",
        projects: [
          {
            id: "project-1",
            title: "Research",
            href: "/project/project-1",
            label: "Project, Research",
            createdAt: null,
            updatedAt: null,
            archived: false,
            detail: {
              uuid: "project-1",
              name: "Research",
              description: null,
              created_at: null,
              updated_at: null,
              prompt_template: null,
              creator: null,
              is_private: null,
              is_starter_project: null,
              archived_at: null,
              docs: [
                {
                  uuid: "doc-1",
                  filename: "notes.txt",
                  content: "Synthetic notes",
                  created_at: collected,
                  updated_at: null,
                },
              ],
              raw_docs: [
                {
                  uuid: "doc-1",
                  filename: "notes.txt",
                  content: "Synthetic notes",
                  created_at: collected,
                },
              ],
            },
          },
        ],
      },
    });
    const schema = JSON.parse(
      await readFile(
        new URL(
          "../../core/src/legacy-projection/legacy-schemas/claude.projects.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    expect(
      new Ajv({ allErrors: true }).validate(schema.schema, body.data),
    ).toBe(true);
    const second = await ctx.app.request("/v1/data/claude.projects", {
      headers: { authorization: `Bearer ${CONTROL}` },
    });
    expect(await second.text()).toBe(firstText);
    expect(snapshot()).toEqual(before);
    expect(
      (await files(join(root, "data"))).filter((path) =>
        path.includes("claude.projects"),
      ),
    ).toEqual([]);
    const stored = db
      .prepare("SELECT bytes FROM pdpp_blob_bytes WHERE blob_id=?")
      .get(blob_ref.blob_id) as { bytes: Buffer };
    expect(createHash("sha256").update(stored.bytes).digest("hex")).toBe(
      blob_ref.sha256,
    );
    const unauthorized = await ctx.app.request("/v1/data/claude.projects");
    expect(unauthorized.status).toBe(401);
  } finally {
    db.close();
  }
});

it("returns an owner HTTP 503 budget refusal with zero copied bodies and no stored projection", async () => {
  const payload = { uuid: "p", name: "Small source", docs: [] };
  const bytes = new TextEncoder().encode(
    JSON.stringify({
      format: "anthropic-source-record-v1",
      stream: "projects",
      record_key: "p",
      payload,
    }),
  );
  const upload = await ctx.app.request(
    `/v1/blobs/ingest?instance=${encodeURIComponent(instance)}&method=anthropic&binding_generation=1`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: bytes,
    },
  );
  expect(upload.status).toBe(200);
  const blob_ref = await upload.json();
  await replace("account_profile", [profile]);
  await replace("projects", [{ id: "p", name: "Small source", blob_ref }]);
  await replace("project_documents", []);
  const readActual = canonicalReader.readCanonicalLegacyScope;
  let byteCalls = 0;
  // Lower only the private read budget; the actual route, authority and SQLite reader run.
  vi.spyOn(canonicalReader, "readCanonicalLegacyScope").mockImplementation(
    (input) =>
      readActual({
        ...input,
        blobByteBudget: bytes.length - 1,
        store: {
          ...input.store,
          getBlobBytes(id) {
            byteCalls++;
            return input.store.getBlobBytes?.(id);
          },
        },
      }),
  );
  const response = await ctx.app.request("/v1/data/claude.projects", {
    headers: { authorization: `Bearer ${CONTROL}` },
  });
  expect(response.status).toBe(503);
  expect(await response.json()).toMatchObject({
    error: "CANONICAL_VIEW_UNAVAILABLE",
    reason: "blob_read_budget_exceeded",
    status: "unavailable",
  });
  expect(byteCalls).toBe(0);
  expect(
    (await files(join(root, "data"))).filter((path) =>
      path.includes("claude.projects"),
    ),
  ).toEqual([]);
});
