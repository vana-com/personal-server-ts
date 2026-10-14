/**
 * POST /v1/records/completions on a REAL bootstrapped Personal Server, over a
 * real listening socket, with owner tokens issued by the real AS.
 *
 * This proves the route and its authority. It does not prove that Desktop
 * calls it; no native host exists in this repo.
 */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";
import { listenHttpServer, type NodeServer } from "./listen.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const CLAUDE = "https://registry.pdpp.dev/connectors/claude";
const OURA = "https://registry.pdpp.dev/connectors/oura";
const T1 = "2026-09-10T06:30:00.000Z";

const declaration = (sourceId: string, streams: object[]) =>
  JSON.stringify({
    source_id: sourceId,
    source_kind: "connector",
    version: "1",
    streams,
  });
const CLAUDE_DECLARATION = declaration(CLAUDE, [
  {
    name: "messages",
    semantics: "append_only",
    fields: ["id", "text"],
    required_fields: ["id"],
    primary_key: ["id"],
  },
  {
    name: "profile",
    fields: ["id", "name"],
    required_fields: ["id"],
    primary_key: ["id"],
  },
]);
const OURA_DECLARATION = declaration(OURA, [
  {
    name: "sleep",
    fields: ["id", "score"],
    required_fields: ["id"],
    primary_key: ["id"],
  },
]);

let tempDir: string;
let ctx: ServerContext | undefined;
let server: NodeServer | undefined;
let baseUrl: string;
let owner: string;

const sha = (preimage: string) =>
  createHash("sha256").update(preimage, "utf8").digest("hex");
const claudeInstance = () => `claude:${owner}`;
const emptyMessagesSha = () =>
  sha(`["${CLAUDE}","${claudeInstance()}","claude",1,"messages",[]]`);

async function writeDeclaration(name: string, document: string) {
  const dir = join(tempDir, "declarations");
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${name}.json`);
  await writeFile(path, document, "utf-8");
  return path;
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "pdpp-completion-http-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  const claude = await writeDeclaration("claude", CLAUDE_DECLARATION);
  const oura = await writeDeclaration("oura", OURA_DECLARATION);
  ctx = await createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [claude, oura],
        methods: [
          { method_id: "claude", declaration_path: claude },
          { method_id: "oura", declaration_path: oura },
        ],
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

const ownerToken = (sourceId: string) =>
  registerTestConnection(ctx!.app, ctx!.devToken!, owner, sourceId);

const wireBody = (overrides: Record<string, unknown> = {}) => ({
  source_id: CLAUDE,
  instance: claudeInstance(),
  source_collected_at: T1,
  collection_time_basis: "host_run_finished",
  streams: [
    {
      stream: "messages",
      coverage: "full_stream",
      live_count: 0,
      snapshot_sha256: emptyMessagesSha(),
    },
  ],
  ...overrides,
});

function post(
  token: string | undefined,
  body: string | object,
  query = "?method=claude&binding_generation=1",
  headers: Record<string, string> = {},
) {
  return fetch(`${baseUrl}/v1/records/completions${query}`, {
    method: "POST",
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      "content-type": "application/json",
      ...headers,
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

/** A second read-only connection to the server's real records database. */
function inspect<T>(read: (db: InstanceType<typeof Database>) => T): T {
  const db = new Database(join(tempDir, "index.db"), { readonly: true });
  try {
    return read(db);
  } finally {
    db.close();
  }
}

describe("POST /v1/records/completions", () => {
  it("lets the owner record an empty append-only stream and stores one receipt and no rows", async () => {
    const token = await ownerToken(CLAUDE);

    const response = await post(token, wireBody());

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      receipts: [
        {
          instance: claudeInstance(),
          stream: "messages",
          method: "claude",
          generation: 1,
          source_collected_at: T1,
          live_count: 0,
          snapshot_sha256: emptyMessagesSha(),
          collection_time_basis: "host_run_finished",
        },
      ],
    });
    inspect((db) => {
      expect(
        db
          .prepare("SELECT stream, snapshot_sha256 FROM pdpp_stream_completion")
          .all(),
      ).toEqual([{ stream: "messages", snapshot_sha256: emptyMessagesSha() }]);
      for (const table of [
        "pdpp_records",
        "pdpp_record_changes",
        "pdpp_record_arrival",
      ]) {
        expect(db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()).toEqual({
          n: 0,
        });
      }
    });
  });

  it("refuses a missing token and a token scoped to another source, changing nothing", async () => {
    const claudeToken = await ownerToken(CLAUDE);
    const ouraToken = await ownerToken(OURA);
    const before = inspect((db) => dumpState(db));

    expect((await post(undefined, wireBody())).status).toBe(401);
    expect((await post(ouraToken, wireBody())).status).toBe(401);
    expect(
      (await post(claudeToken, wireBody({ source_id: OURA }))).status,
    ).toBe(401);

    expect(inspect((db) => dumpState(db))).toEqual(before);
  });

  it("conflicts when an empty proof meets retained history, which survives", async () => {
    const token = await ownerToken(CLAUDE);
    const ingested = await fetch(
      `${baseUrl}/v1/streams/messages/records/ingest?method=claude&binding_generation=1`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          instance: claudeInstance(),
          key: "k1",
          data: { id: "k1", text: "A" },
          emitted_at: "2026-09-01T00:00:00Z",
        }),
      },
    );
    expect(ingested.status).toBe(200);
    const before = inspect((db) => dumpState(db));

    const response = await post(token, wireBody());

    expect(response.status).toBe(409);
    expect(
      ((await response.json()) as { error: { code: string } }).error.code,
    ).toBe("snapshot_conflict");
    expect(inspect((db) => dumpState(db))).toEqual(before);
    const proven = await post(
      token,
      wireBody({
        streams: [
          {
            stream: "messages",
            coverage: "full_stream",
            live_count: 1,
            snapshot_sha256: sha(
              `["${CLAUDE}","${claudeInstance()}","claude",1,"messages",[["k1",{"id":"k1","text":"A"}]]]`,
            ),
          },
        ],
      }),
    );
    expect(proven.status).toBe(200);
  });

  it("replays an exact proof byte for byte and refuses an older time", async () => {
    const token = await ownerToken(CLAUDE);
    expect((await post(token, wireBody())).status).toBe(200);
    const stored = inspect((db) => dumpState(db));

    expect((await post(token, wireBody())).status).toBe(200);
    expect(inspect((db) => dumpState(db))).toEqual(stored);

    const older = await post(
      token,
      wireBody({ source_collected_at: "2026-09-09T06:30:00.000Z" }),
    );
    expect(older.status).toBe(409);
    expect(inspect((db) => dumpState(db))).toEqual(stored);
  });

  it("holds the 64 KiB bound over a real socket", async () => {
    const token = await ownerToken(CLAUDE);
    const sized = (bytes: number) => {
      const json = JSON.stringify(wireBody());
      return json + " ".repeat(bytes - Buffer.byteLength(json));
    };
    expect((await post(token, sized(65536))).status).toBe(200);
    const before = inspect((db) => dumpState(db));

    expect((await post(token, sized(65537))).status).toBe(413);
    // Multibyte: 40 000 two-byte characters, 80 000 bytes.
    expect(
      (
        await post(
          token,
          JSON.stringify(wireBody({ instance: "é".repeat(40000) })),
        )
      ).status,
    ).toBe(413);
    // No Content-Length: a chunked body.
    const bytes = new TextEncoder().encode(sized(65537));
    const chunked = await fetch(
      `${baseUrl}/v1/records/completions?method=claude&binding_generation=1`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            for (let i = 0; i < bytes.length; i += 8192) {
              controller.enqueue(bytes.slice(i, i + 8192));
            }
            controller.close();
          },
        }),
        duplex: "half",
      } as RequestInit,
    );
    expect(chunked.status).toBe(413);
    expect(inspect((db) => dumpState(db))).toEqual(before);
  });
});

/** Every table the completion route must leave alone, plus the receipts. */
function dumpState(db: InstanceType<typeof Database>) {
  const all = (table: string, order: string) =>
    db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
  return {
    records: all("pdpp_records", "instance, stream, record_key"),
    changes: all("pdpp_record_changes", "id"),
    arrival: all("pdpp_record_arrival", "instance, stream, record_key"),
    clock: all("pdpp_write_clock", "id"),
    binding: all("pdpp_instance_binding", "instance"),
    receipts: all("pdpp_stream_completion", "instance, stream"),
  };
}
