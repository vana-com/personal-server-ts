import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { initializeDatabase } from "./index-schema.js";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  createScopeDeletionHistory,
  migrateScopeDeletionHistory,
} from "./scope-deletion-history.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const SOURCE = "https://registry.pdpp.dev/sources/oura";
const at = "2026-09-10T00:00:00Z";
const moduleUrl = (file: string) =>
  pathToFileURL(join(process.cwd(), "packages/server/src/storage", file)).href;

describe("scope deletion migration process interruption", () => {
  it.each(["between entries", "inside transaction"])(
    "recovers after a kill %s",
    async (mode) => {
      const dir = mkdtempSync(join(tmpdir(), "scope-migration-crash-"));
      const path = join(dir, "index.db");
      let db = initializeDatabase(path);
      let store = createSqliteRecordStore(db);
      try {
        createScopeDeletionHistory(db, OWNER, store);
        store.registerConnection({
          instance: "connection",
          sourceId: SOURCE,
          method: "oura",
          label: "",
        });
        for (const stream of ["activity", "readiness"]) {
          store.replaceStream({
            instance: "connection",
            stream,
            method: "oura",
            generation: 1,
            primaryKey: ["id"],
            emittedAt: at,
            sourceCollectedAt: at,
            envelopes: [
              {
                instance: "connection",
                stream,
                key: stream,
                data: { id: stream },
                emitted_at: at,
              },
            ],
          });
          db.prepare(
            "INSERT INTO vana_scope_deletion_history (owner_address, scope, deleted_at, tombstone_version) VALUES (?, ?, ?, ?)",
          ).run(OWNER, `oura.${stream}`, "2026-09-11T00:00:00Z", "1");
        }
        if (mode === "inside transaction")
          db.exec(
            "CREATE TRIGGER pause_migration BEFORE UPDATE OF generation ON pdpp_instance_binding WHEN OLD.generation = 2 BEGIN SELECT pause_test(); END",
          );
        store.close();
        const source = `
        import Database from 'better-sqlite3';
        import { writeSync } from 'node:fs';
        import { createSqliteRecordStore } from ${JSON.stringify(moduleUrl("pdpp-records-sqlite-store.ts"))};
        import { migrateScopeDeletionHistory } from ${JSON.stringify(moduleUrl("scope-deletion-history.ts"))};
        const db = new Database(${JSON.stringify(path)});
        const pause = () => { writeSync(1, 'READY\\n'); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0); return 0; };
        db.function('pause_test', pause);
        const store = createSqliteRecordStore(db);
        migrateScopeDeletionHistory(db, ${JSON.stringify(OWNER)}, store, {info(fields) { if (${JSON.stringify(mode)} === 'between entries' && fields.scope === 'oura.readiness') pause(); }, error() {}});
      `;
        const child = spawn(
          process.execPath,
          ["--import", "tsx", "--input-type=module", "--eval", source],
          { stdio: ["ignore", "pipe", "pipe"] },
        );
        let errorOutput = "";
        child.stderr.setEncoding("utf8");
        child.stderr.on("data", (data: string) => {
          errorOutput += data;
        });
        try {
          await new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(
              () =>
                reject(
                  new Error(
                    `child did not reach interruption point: ${errorOutput}`,
                  ),
                ),
              15_000,
            );
            child.stdout.setEncoding("utf8");
            child.stdout.on("data", (data: string) => {
              if (data.includes("READY")) {
                clearTimeout(timeout);
                resolve();
              }
            });
            child.once("error", (error) => {
              clearTimeout(timeout);
              reject(error);
            });
            child.once("exit", () => {
              clearTimeout(timeout);
              reject(
                new Error(`child exited before interruption: ${errorOutput}`),
              );
            });
          });
        } finally {
          if (child.exitCode === null && child.signalCode === null) {
            const closed = once(child, "close");
            child.kill("SIGKILL");
            await closed;
          }
        }
        db = initializeDatabase(path);
        store = createSqliteRecordStore(db);
        const history = createScopeDeletionHistory(db, OWNER, store);
        expect(history.get("oura.activity")?.eraseApplied).toBe(true);
        expect(history.get("oura.readiness")?.eraseApplied).not.toBe(true);
        expect(
          store.getRecord("connection", "activity", "activity"),
        ).toBeUndefined();
        expect(
          store.getRecord("connection", "readiness", "readiness"),
        ).toBeDefined();
        if (mode === "inside transaction")
          db.exec("DROP TRIGGER pause_migration");
        migrateScopeDeletionHistory(db, OWNER, store, {
          info() {},
          error() {
            throw new Error("retry failed");
          },
        });
        expect(history.get("oura.readiness")?.eraseApplied).toBe(true);
        expect(
          store.getRecord("connection", "readiness", "readiness"),
        ).toBeUndefined();
      } finally {
        if (db.open) store.close();
        rmSync(dir, { recursive: true, force: true });
      }
    },
    30_000,
  );
});
