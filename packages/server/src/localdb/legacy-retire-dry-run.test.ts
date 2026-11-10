import Database from "better-sqlite3";
import { createHash } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import {
  runLegacyRetireDryRun,
  type LegacyRetireDryRunOptions,
} from "./legacy-retire-dry-run.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { createImportLedger } from "../../../core/src/localdb/import-ledger.js";
import { retireLegacyCopies } from "../../../core/src/localdb/legacy-retire.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type {
  ImportReceipt,
  LegacyCopy,
  LegacyRetireFileReport,
} from "../../../core/src/localdb/legacy-import-types.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});
const receipt: ImportReceipt = {
  source: "source",
  revision: "revision",
  connectionId: "control",
  stream: "items",
  generation: 1,
  highestSeq: 1,
  rows: 1,
  fingerprint: "a".repeat(64),
  state: "imported",
  reason: null,
  at: 1,
};
async function fixture(missing = false) {
  const root = mkdtempSync(join(process.cwd(), ".dry-run-test-"));
  roots.push(root);
  const input = join(root, "copy");
  const scratch = join(root, "scratch");
  mkdirSync(join(input, "data"), { recursive: true });
  mkdirSync(scratch);
  const native = new Database(join(input, "index.db"));
  native.exec(
    "CREATE TABLE fixture (n INTEGER); INSERT INTO fixture VALUES (1)",
  );
  native.close();
  const initial = await openLocalDb(
    openBetterSqlite3(join(input, "local.sqlite")),
    { owner: "0xabc", network: "test", deviceId: "device" },
  );
  await initial.batch([
    {
      sql: "INSERT INTO connections (connection_id,connector,ns,generation,control_state) VALUES ('control','fixture','known',1,'active')",
    },
    {
      sql: "INSERT INTO stream_state (connection_id,stream,primary_key,semantics,incremental,publish_watermark) VALUES ('control','items','[\"id\"]','mutable_state',1,1)",
    },
    ...(!missing ? createImportLedger(initial).statements(receipt) : []),
  ]);
  await initial.close();
  writeFileSync(
    join(input, "data", "copy.json"),
    JSON.stringify({ fixture: "payload" }),
  );
  const reports: LegacyRetireFileReport[] = [];
  const erase = vi.fn(async () => {
    throw new Error("input erase forbidden");
  });
  const accessClose = vi.fn(async () => {});
  const handleClose = vi.fn(async () => {});
  const unavailable = async (): Promise<never> => {
    throw new Error("unexpected external port");
  };
  let op = 0;
  const options: LegacyRetireDryRunOptions = {
    copyRoot: input,
    scratchRoot: scratch,
    owner: "0xabc",
    network: "test",
    declarations: [],
    isSwitched: async () => true,
    isQuiescent: async () => true,
    verifyBinding: async () => true,
    legacyWriteSeal: {
      commit: unavailable,
      remove: async (work) => work(),
      admit: () => null,
      verdict: () => "switched",
    },
    resolveTarget: async () => null,
    localDatabasePath: "local.sqlite",
    legacyDatabasePath: "index.db",
    openScratch: vi.fn(async (paths) => {
      expect(paths.localDatabasePath.startsWith(scratch)).toBe(true);
      expect(paths.legacyDatabasePath.startsWith(scratch)).toBe(true);
      const db = await openLocalDb(openBetterSqlite3(paths.localDatabasePath), {
        owner: "0xabc",
        network: "test",
        deviceId: "device",
      });
      const raw = new Database(paths.legacyDatabasePath);
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
        newOp: () => `op-${++op}`,
      };
      return {
        deps,
        legacyDb: raw,
        close: async () => {
          await db.close();
          raw.close();
          await handleClose();
        },
      };
    }),
    openAccess: vi.fn(async (supplied) => ({
      owner: supplied.owner,
      network: supplied.network,
      async *sources() {},
      async *copyRecords() {
        yield {};
      },
      async *copies() {
        yield {
          id: "opaque",
          path: join(supplied.root, "data", "copy.json"),
          contentHash: "raw-hash",
          revision: "revision",
          dataSet: "fixture.scope",
          sources: [
            { source: "source", connectionId: "control", stream: "items" },
          ],
        } satisfies LegacyCopy;
      },
      erase,
      erasedWithIntent: async () => false,
      finishErase: async () => {
        throw new Error("unexpected journal write");
      },
      close: accessClose,
    })),
    readBack: (deps, access) => {
      expect("erase" in access).toBe(false);
      expect("finishErase" in access).toBe(false);
      return async (copy) => {
        const stored = await createImportLedger(deps.db).get(
          "source",
          "control",
          "items",
        );
        return [
          {
            receipt: stored,
            actual: { rows: 1, fingerprint: receipt.fingerprint },
            copy,
            pass: !!stored,
            reason: stored ? null : "missing_receipt",
            projections: [
              {
                dataSet: copy.dataSet,
                expectedHash: "projection",
                actualHash: "projection",
                pass: true,
              },
            ],
          },
        ];
      };
    },
    retire: retireLegacyCopies,
    reportFile: (report) => reports.push(report),
  };
  return {
    root,
    input,
    scratch,
    options,
    reports,
    erase,
    accessClose,
    handleClose,
  };
}
function tree(root: string): string {
  const hash = createHash("sha256");
  function visit(dir: string) {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
      a.name.localeCompare(b.name),
    )) {
      hash.update(entry.name);
      if (entry.isDirectory()) visit(join(dir, entry.name));
      else hash.update(readFileSync(join(dir, entry.name)));
    }
  }
  visit(root);
  return hash.digest("hex");
}
it("dry-run-per-file-deletes-nothing-flag-on", async () => {
  const f = await fixture();
  writeFileSync(
    join(f.input, "config.json"),
    JSON.stringify({ streamSync: { retireLegacy: true } }),
  );
  const before = tree(f.input);
  expect(await runLegacyRetireDryRun(f.options)).toEqual({
    mode: "dry-run",
    files: 1,
    ready: 1,
    deleted: 0,
  });
  expect(tree(f.input)).toBe(before);
  expect(f.erase).not.toHaveBeenCalled();
  expect(f.reports).toEqual([
    { file: "opaque", decision: "ready", reason: null },
  ]);
  expect(readdirSync(f.scratch)).toEqual([]);
  expect(f.handleClose).toHaveBeenCalledTimes(1);
  expect(f.accessClose).toHaveBeenCalledTimes(1);
});
it("dry-run-refuses-live-or-symlink", async () => {
  const f = await fixture();
  writeFileSync(join(f.input, "local.sqlite-wal"), "");
  await expect(runLegacyRetireDryRun(f.options)).rejects.toThrow(
    "dry_run_live_database_refused",
  );
  rmSync(join(f.input, "local.sqlite-wal"));
  symlinkSync(
    join(f.input, "data", "copy.json"),
    join(f.input, "data", "link.json"),
  );
  await expect(runLegacyRetireDryRun(f.options)).rejects.toThrow(
    "dry_run_symlink_refused",
  );
  expect(f.options.openScratch).not.toHaveBeenCalled();
  await expect(
    runLegacyRetireDryRun({ ...f.options, copyRoot: "/live-source" }),
  ).rejects.toThrow("dry_run_copy_required");
});
it("dry-run-config-ambiguous", async () => {
  const f = await fixture();
  writeFileSync(join(f.input, "config.json"), "invalid config");
  writeFileSync(join(f.input, "server.json"), "also invalid");
  expect((await runLegacyRetireDryRun(f.options)).ready).toBe(1);
  await expect(
    runLegacyRetireDryRun({ ...f.options, localDatabasePath: "index.db" }),
  ).rejects.toThrow("dry_run_ambiguous_layout");
  await expect(
    runLegacyRetireDryRun({
      ...f.options,
      localDatabasePath: "../escape.sqlite",
    }),
  ).rejects.toThrow("dry_run_ambiguous_layout");
});
it("dry-run-no-import-publish-network", async () => {
  const f = await fixture();
  const before = tree(f.input);
  const retire: LegacyRetireDryRunOptions["retire"] = async (
    deps,
    access,
    options,
  ) => {
    for (const action of [
      () => deps.registry.read("scope"),
      () => deps.registry.listControlRows(),
      () => deps.blobs.get("scope", "blob"),
      () => deps.signer.signAddData({} as never),
    ])
      await expect(action()).rejects.toThrow(
        "dry_run_external_capability_refused",
      );
    await expect(access.erase({} as LegacyCopy)).rejects.toThrow(
      "dry_run_erase_refused",
    );
    expect(access.erasedWithIntent).toBeUndefined();
    const prior = await deps.db.query("SELECT * FROM import_ledger");
    const result = await retireLegacyCopies(deps, access, options);
    expect(await deps.db.query("SELECT * FROM import_ledger")).toEqual(prior);
    return result;
  };
  expect((await runLegacyRetireDryRun({ ...f.options, retire })).deleted).toBe(
    0,
  );
  expect(tree(f.input)).toBe(before);
});
it("dry-run-missing-receipt-holds", async () => {
  const f = await fixture(true);
  expect((await runLegacyRetireDryRun(f.options)).ready).toBe(0);
  expect(f.reports[0]?.decision).toBe("held");
  expect(f.erase).not.toHaveBeenCalled();
});
it("dry-run-closes-and-cleans-after-failure", async () => {
  const f = await fixture();
  const before = tree(f.input);
  await expect(
    runLegacyRetireDryRun({
      ...f.options,
      retire: async () => {
        throw new Error("fixture failure");
      },
    }),
  ).rejects.toThrow("fixture failure");
  expect(f.handleClose).toHaveBeenCalledTimes(1);
  expect(f.accessClose).toHaveBeenCalledTimes(1);
  expect(readdirSync(f.scratch)).toEqual([]);
  expect(tree(f.input)).toBe(before);
});
it("dry-run-owner-mismatch-and-untrusted-mode-refuse", async () => {
  const f = await fixture();
  await expect(
    runLegacyRetireDryRun({ ...f.options, owner: "0xdef" }),
  ).rejects.toThrow("dry_run_identity_mismatch");
  expect(f.options.openAccess).not.toHaveBeenCalled();
  expect(f.handleClose).toHaveBeenCalledTimes(1);
  await expect(
    runLegacyRetireDryRun({ ...f.options, isQuiescent: async () => false }),
  ).rejects.toThrow("dry_run_not_quiescent");
  expect(readdirSync(f.scratch)).toEqual([]);
});
it("dry-run-detects-input-mutation", async () => {
  const f = await fixture();
  await expect(
    runLegacyRetireDryRun({
      ...f.options,
      retire: async (deps, access, options) => {
        writeFileSync(join(f.input, "data", "copy.json"), "changed by fixture");
        return retireLegacyCopies(deps, access, options);
      },
    }),
  ).rejects.toThrow("dry_run_input_changed");
  expect(readdirSync(f.scratch)).toEqual([]);
});
it("dry-run-reports-independent-copies-without-paths-or-bodies", async () => {
  const f = await fixture();
  const original = f.options.openAccess;
  const openAccess: LegacyRetireDryRunOptions["openAccess"] = async (
    options,
  ) => {
    const access = await original(options);
    return {
      ...access,
      async *copies() {
        for await (const copy of access.copies()) {
          yield { ...copy, id: "held-copy", sources: [] };
          yield copy;
        }
      },
    };
  };
  expect(
    await runLegacyRetireDryRun({ ...f.options, openAccess }),
  ).toMatchObject({ files: 2, ready: 1, deleted: 0 });
  expect(f.reports.map((r) => r.decision)).toEqual(["held", "ready"]);
  for (const report of f.reports)
    expect(Object.keys(report).sort()).toEqual(["decision", "file", "reason"]);
  expect(JSON.stringify(f.reports)).not.toContain(f.input);
  expect(JSON.stringify(f.reports)).not.toContain("payload");
});
