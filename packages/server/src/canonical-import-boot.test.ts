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
  it("stages the device's canonical rows at boot, with no connector run (BOOT_IMPORT_NEVER_BOUND)", async () => {
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
    db.close();

    await mkdir(join(tempDir, "declarations"), { recursive: true });
    const declarationPath = join(tempDir, "declarations", "spotify.json");
    await writeFile(declarationPath, DECLARATION, "utf-8");
    ctx = await createServer(
      ServerConfigSchema.parse({
        tunnel: { enabled: false },
        sync: { enabled: true },
        streamSync: { write: true },
        pdpp: {
          enabled: true,
          declarationPaths: [declarationPath],
          methods: [
            { method_id: "spotify", declaration_path: declarationPath },
          ],
        },
      }),
      { serverDir: tempDir, dataDir: join(tempDir, "data") },
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
            importComplete: boolean;
            imported: Record<
              string,
              { staged?: Record<string, number> } | undefined
            >;
          })
        : null;
    };
    let ledger = await ledgerFile();
    for (let i = 0; i < 400 && !ledger?.imported.spotify; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
      ledger = await ledgerFile();
    }
    expect(ledger).toMatchObject({
      owner: owner.toLowerCase(),
      importComplete: true,
      imported: { spotify: { staged: { top_artists: 3 } } },
    });
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
});
