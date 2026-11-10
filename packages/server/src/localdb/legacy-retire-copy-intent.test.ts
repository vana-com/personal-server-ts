import { afterEach, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, cpSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import {
  runLegacyRetireDryRun,
  type LegacyRetireDryRunOptions,
} from "./legacy-retire-dry-run.js";
import { openLegacyAccess } from "./legacy-access.js";
import { initializeDatabase } from "../storage/index-schema.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { createLegacyEraseLedger } from "../../../core/src/localdb/import-ledger.js";
import { retireLegacyCopies } from "../../../core/src/localdb/legacy-retire.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
it.each([false, true])(
  "dry-run-admits-copied-intent-and-refuses-escape: %s",
  async (escape) => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "ps3-copy-intent-"));
    roots.push(root);
    const original = join(root, "original");
    const input = join(root, "copy");
    const scratch = join(root, "scratch");
    mkdirSync(join(original, "data"), { recursive: true });
    mkdirSync(scratch);
    const raw = initializeDatabase(join(original, "index.db"));
    raw.close();
    const identity = { owner: "0xabc", network: "test", deviceId: "device" };
    const local = await openLocalDb(
      openBetterSqlite3(join(original, "local.sqlite")),
      identity,
    );
    await createLegacyEraseLedger(local, () => 1).record({
      id: "opaque",
      path: escape
        ? join(root, "outside.json")
        : join(original, "data", "missing.json"),
      contentHash: "a".repeat(64),
      revision: "revision",
      dataSet: "fixture.items",
      sources: [{ source: "source", connectionId: "control", stream: "items" }],
    });
    await local.close();
    cpSync(original, input, { recursive: true });
    const before = readFileSync(join(input, "local.sqlite"));
    const unavailable = async (): Promise<never> => {
      throw new Error("external capability");
    };
    const reports: unknown[] = [];
    const options: LegacyRetireDryRunOptions & { originalStoreRoot: string } = {
      copyRoot: input,
      originalStoreRoot: original,
      scratchRoot: scratch,
      owner: "0xabc",
      network: "test",
      declarations: [],
      isSwitched: async () => true,
      isQuiescent: async () => true,
      verifyBinding: async () => true,
      resolveTarget: async () => null,
      legacyWriteSeal: {
        commit: unavailable,
        remove: async (work) => work(),
        admit: () => null,
        verdict: () => "switched",
      },
      localDatabasePath: "local.sqlite",
      legacyDatabasePath: "index.db",
      openAccess: openLegacyAccess,
      readBack: () => async () => [],
      retire: retireLegacyCopies,
      reportFile: (r) => reports.push(r),
      openScratch: async (paths) => {
        const db = await openLocalDb(
          openBetterSqlite3(paths.localDatabasePath),
          identity,
        );
        const native = initializeDatabase(paths.legacyDatabasePath);
        const deps: LocalSyncDeps = {
          db,
          queue: connectionQueue(),
          ownerAddress: "0xabc",
          registry: {
            read: unavailable,
            post: unavailable,
            listControlRows: unavailable,
            listStreamRows: unavailable,
          },
          blobs: { get: unavailable, put: unavailable },
          keys: {
            namespaceHmac: unavailable,
            encrypt: unavailable,
            encryptPart: unavailable,
            decrypt: unavailable,
          },
          signer: { signAddData: unavailable },
          logger: { info() {}, warn() {} },
          now: () => 1,
          newOp: () => "op",
        };
        return {
          deps,
          legacyDb: native,
          close: async () => {
            await db.close();
            native.close();
          },
        };
      },
    };
    if (escape) await expect(runLegacyRetireDryRun(options)).rejects.toThrow();
    else {
      expect(await runLegacyRetireDryRun(options)).toMatchObject({
        mode: "dry-run",
        files: 1,
        ready: 0,
        deleted: 0,
      });
      expect(reports).toEqual([
        expect.objectContaining({ file: "opaque", decision: "held" }),
      ]);
    }
    expect(readFileSync(join(input, "local.sqlite"))).toEqual(before);
  },
);
