/**
 * Boot journey for the legacy import (IMPORT_SOURCE_EMPTY_IN_PRODUCTION): a
 * REAL `createServer` on a device whose canonical record store already holds
 * rows, with stream sync writing on. Nothing is passed as the import source;
 * the rows reach the seed intake from the production wiring alone, with no
 * run of any connector.
 */

import {
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { StreamSyncWriter } from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  createMemoryImportAuthority,
  type AccountModeReader,
} from "@opendatalabs/personal-server-ts-core/sync";
import { createServer, type ServerContext } from "./bootstrap.js";
import { initializeDatabase } from "./storage/index-schema.js";
import { createTestBoundRecordStore } from "./__fixtures__/bound-record-store.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const SOURCE_ID = "https://registry.pdpp.dev/connectors/spotify";
const SCOPE = "spotify.top_artists";
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

/** The account-mode authority says `switched` for this owner and knows no other. */
const switchedFor = (owner: string): AccountModeReader => ({
  read: (asked) =>
    asked.toLowerCase() === owner.toLowerCase() ? "switched" : "unknown",
});

let tempDir: string;
let ctx: ServerContext | undefined;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "canonical-import-boot-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  vi.unstubAllEnvs();
  await rm(tempDir, { recursive: true, force: true });
});

describe("the legacy import in a real boot", () => {
  it("stages the device's canonical rows at boot, with no connector run (BOOT_IMPORT_NEVER_BOUND, BOOT_PUBLISH_NOT_WIRED, STATUS_HIDES_EXCLUDED, STATUS_ROUTE_UNAUTHENTICATED)", async () => {
    const owner = await recoverServerOwner(KNOWN_SIG);
    // The device's legacy data: one index row for the scope (so the
    // declaration is trusted) and canonical rows under its connection.
    const db = initializeDatabase(join(tempDir, "index.db"));
    db.prepare(
      `INSERT INTO data_files (file_id, path, scope, collected_at, size_bytes)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(
      "file-1",
      "spotify/top_artists.json",
      SCOPE,
      "2026-01-01T00:00:00Z",
      1,
    );
    const store = createTestBoundRecordStore(
      db as unknown as Database.Database,
    );
    const instance = `spotify:${owner.toLowerCase()}`;
    store.registerConnection({
      instance,
      sourceId: SOURCE_ID,
      method: "spotify",
      label: "Spotify",
    });
    for (const id of ["a1", "a2", "a3"]) {
      store.ingestBatch(
        [
          {
            instance,
            stream: "top_artists",
            key: id,
            data: { id, name: `artist ${id}` },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: "spotify", generation: 1 },
      );
    }
    // A row of a stream no declaration names: it stays in the legacy file.
    store.ingestBatch(
      [
        {
          instance,
          stream: "ghost",
          key: "g1",
          data: { id: "g1" },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "spotify", generation: 1 },
    );
    db.close();
    // The registry is not reachable in this test: the writer's own publish is
    // observed, not run (the core tests run it).
    const authority = createMemoryImportAuthority();
    const published: string[] = [];
    vi.spyOn(StreamSyncWriter.prototype, "publishSeed").mockImplementation(
      async (connector: string) => {
        published.push(connector);
        return { state: "done" as const, skipped: [] };
      },
    );

    await mkdir(join(tempDir, "declarations"), { recursive: true });
    const declarationPath = join(tempDir, "declarations", "spotify.json");
    await writeFile(declarationPath, DECLARATION, "utf-8");
    ctx = await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        sync: { enabled: true },
        streamSync: { write: true },
        devUi: { enabled: true },
        pdpp: {
          enabled: true,
          declarationPaths: [declarationPath],
          methods: [
            { method_id: "spotify", declaration_path: declarationPath },
          ],
        },
      }),
      {
        serverDir: tempDir,
        dataDir: join(tempDir, "data"),
        accountMode: switchedFor(owner),
        importAuthority: authority,
      },
    );
    // The pass runs in the background after the stores open. Its receipt is
    // in the stream-sync home; so are the staged rows.
    const ledgerFile = async () => {
      const found = (await readdir(tempDir, { recursive: true })).find((path) =>
        path.endsWith(join("legacy-retire", "ledger.json")),
      );
      return found
        ? (JSON.parse(await readFile(join(tempDir, found), "utf8")) as {
            owner: string;
            imported: Record<
              string,
              { staged?: Record<string, number>; published?: true } | undefined
            >;
          })
        : null;
    };
    let ledger = await ledgerFile();
    for (let i = 0; i < 400 && !ledger?.imported.spotify?.published; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      ledger = await ledgerFile();
    }
    expect(ledger).toMatchObject({
      owner: owner.toLowerCase(),
      imported: { spotify: { staged: { top_artists: 3 }, published: true } },
    });
    // The staged rows are handed to the writer's own publish (BOOT_PUBLISH_NOT_WIRED).
    expect(published).toEqual(["spotify"]);
    // Done is told to the authority once, for the server's owner (not kept in the ledger).
    for (let i = 0; i < 100 && authority.doneCalls.length === 0; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(authority.doneCalls).toEqual([owner.toLowerCase()]);
    // The owner can see what stayed behind (STATUS_ROUTE_UNAUTHENTICATED).
    const ask = (token?: string) =>
      ctx!.app.request("/v1/stream-sync/import-status", {
        headers: token ? { authorization: `Bearer ${token}` } : {},
      });
    expect((await ask()).status).toBe(401);
    expect((await ask("not-the-token")).status).toBe(401);
    const status = await ask(ctx!.devToken);
    expect(status.status).toBe(200);
    const text = await status.text();
    expect(JSON.parse(text)).toEqual({
      complete: true,
      abandoned: false,
      stayed: 1,
      connectors: [
        {
          connector: "spotify",
          state: "published",
          attempts: 0,
          staged: 3,
          stayed: 1,
          excluded: [{ reason: "unmapped_stream", rows: 1 }],
        },
      ],
    });
    expect(text).not.toContain("ghost");
    const rows = (await readdir(tempDir, { recursive: true })).filter((path) =>
      path.endsWith("rows.ndjson"),
    );
    expect(rows).toHaveLength(1);
    const lines = (await readFile(join(tempDir, rows[0]!), "utf8"))
      .split("\n")
      .filter(Boolean)
      .map((line) => (JSON.parse(line) as { id: string }).id);
    expect(lines.sort()).toEqual(["a1", "a2", "a3"]);
  }, 60_000);

  it("completes empty when PDPP is off, instead of holding every connector (PDPP_OFF_STALLS_IMPORT)", async () => {
    const owner = await recoverServerOwner(KNOWN_SIG);
    const authority = createMemoryImportAuthority();
    ctx = await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        sync: { enabled: true },
        streamSync: { write: true },
      }),
      {
        serverDir: tempDir,
        dataDir: join(tempDir, "data"),
        accountMode: switchedFor(owner),
        importAuthority: authority,
      },
    );
    // Without a canonical store the import has nothing to read, and is done.
    for (let i = 0; i < 400 && authority.doneCalls.length === 0; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    expect(authority.doneCalls).toEqual([owner.toLowerCase()]);
  }, 60_000);

  it("does nothing until the account-mode authority says switched (BOOT_MODE_IGNORED)", async () => {
    const owner = await recoverServerOwner(KNOWN_SIG);
    const authority = createMemoryImportAuthority();
    for (const accountMode of [
      undefined, // no authority bound
      { read: () => "unswitched" as const },
      switchedFor(`0x${"cd".repeat(20)}`), // switched, but for another account
    ]) {
      ctx = await createServer(
        ServerConfigSchema.parse({
          tunnel: { enabled: false },
          sync: { enabled: true },
          streamSync: { write: true },
        }),
        {
          serverDir: tempDir,
          dataDir: join(tempDir, "data"),
          ...(accountMode ? { accountMode } : {}),
          importAuthority: authority,
        },
      );
      await new Promise((resolve) => setTimeout(resolve, 400));
      expect(authority.doneCalls).toEqual([]);
      expect(await authority.importPending(owner)).toBe(true);
      await ctx.cleanup();
      ctx = undefined;
    }
  }, 60_000);

  it("closes the stream writer's gate unless the mode says it may open (BOOT_UNKNOWN_OPENS_GATE)", async () => {
    const boot = async (accountMode?: AccountModeReader) => {
      ctx = await createServer(
        ServerConfigSchema.parse({
          tunnel: { enabled: false },
          sync: { enabled: true },
          streamSync: { write: true },
        }),
        {
          serverDir: tempDir,
          dataDir: join(tempDir, "data"),
          ...(accountMode ? { accountMode } : {}),
          importAuthority: createMemoryImportAuthority(),
        },
      );
      const writer = ctx.streamSyncWriter!;
      const attempt = writer.beginRun({
        runId: "gate-probe",
        connector: "spotify",
        observedAt: 1,
        identity: "none",
        userConnect: false,
        checkpointUsed: null,
      });
      return attempt.then(
        () => "admitted",
        (error: Error) => error.name,
      );
    };
    // No port bound, and a port that does not know the owner: no decision.
    expect(await boot()).toBe("ImportPendingError");
    await ctx?.cleanup();
    ctx = undefined;
    expect(await boot({ read: () => "unknown" })).toBe("ImportPendingError");
    await ctx?.cleanup();
    ctx = undefined;
    // The account is not switched: nothing to wait for.
    expect(await boot({ read: () => "unswitched" })).not.toBe(
      "ImportPendingError",
    );
  }, 60_000);

  it("runs the legacy retire cycle only for a switched account (BOOT_RETIRE_MODE_IGNORED)", async () => {
    const owner = await recoverServerOwner(KNOWN_SIG);
    const report = async (accountMode?: AccountModeReader) => {
      ctx = await createServer(
        ServerConfigSchema.parse({
          tunnel: { enabled: false },
          sync: { enabled: true },
          streamSync: { write: true, read: true },
        }),
        {
          serverDir: tempDir,
          dataDir: join(tempDir, "data"),
          ...(accountMode ? { accountMode } : {}),
          importAuthority: createMemoryImportAuthority(),
        },
      );
      const result = await ctx.syncManager!.legacyRetireReport();
      await ctx.cleanup();
      ctx = undefined;
      return result;
    };
    expect(await report()).toBeNull(); // no port: unknown
    expect(await report({ read: () => "unknown" })).toBeNull();
    expect(await report({ read: () => "unswitched" })).toBeNull();
    expect(await report(switchedFor(owner))).not.toBeNull(); // the gate can open
  }, 90_000);
});
