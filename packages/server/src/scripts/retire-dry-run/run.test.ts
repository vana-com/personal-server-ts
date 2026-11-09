/**
 * The read-only dry run, end to end on the #595 synthetic fixture persisted to
 * a data folder with the real SQLite store. Each hard requirement has a test
 * named for it; the network is a fake gateway and storage behind `fetch`.
 */

import { createHash } from "node:crypto";
import {
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { join, relative } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createRetireHost,
  retireLegacyFiles,
  RetireLedger,
} from "@opendatalabs/personal-server-ts-core/sync";
import type * as CoreSync from "@opendatalabs/personal-server-ts-core/sync";
import { createMemoryStreamSyncFiles } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { CopyOnlyError } from "./copy-only.js";
import { NetworkGuardError } from "./network-guard.js";
import { redactFile, type RedactedReport } from "./report.js";
import { runLegacyRetireDryRun, type DryRunOptions } from "./run.js";
import {
  CHAIN_ID,
  persistFixture,
  type PersistedFixture,
} from "./persisted-fixture.test-utils.js";

const hooks = vi.hoisted(() => ({
  retire: null as null | ((...args: unknown[]) => Promise<unknown>),
}));
vi.mock(
  "@opendatalabs/personal-server-ts-core/sync",
  async (importOriginal) => {
    const actual = await importOriginal<typeof CoreSync>();
    return {
      ...actual,
      retireLegacyFiles: (
        ...args: Parameters<typeof actual.retireLegacyFiles>
      ) =>
        hooks.retire
          ? hooks.retire(...args)
          : actual.retireLegacyFiles(...args),
    };
  },
);

// Each test persists the 4000-record fixture; a loaded machine needs time.
vi.setConfig({ testTimeout: 60_000 });

const homes: string[] = [];
afterEach(async () => {
  vi.unstubAllGlobals();
  hooks.retire = null;
  for (const home of homes.splice(0)) {
    await rm(home, { recursive: true, force: true });
  }
});

async function fixture(
  options: Parameters<typeof persistFixture>[0] = {
    importDone: true,
    fullRun: true,
  },
): Promise<PersistedFixture> {
  const p = await persistFixture(options);
  homes.push(p.home);
  vi.stubGlobal("fetch", p.fetch);
  return p;
}

const optionsOf = (p: PersistedFixture): DryRunOptions => ({
  dataDir: p.dataDir,
  outPath: p.outPath,
  home: p.home,
  masterKeySignature: p.signature,
  now: () => new Date("2026-11-09T00:00:00Z"),
});

/** sha256 of every file under a folder, keyed by relative path. */
async function hashTree(root: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  const pending = [root];
  while (pending.length > 0) {
    const dir = pending.pop()!;
    for (const item of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, item.name);
      if (item.isDirectory()) pending.push(path);
      else {
        out[relative(root, path)] = createHash("sha256")
          .update(await readFile(path))
          .digest("hex");
      }
    }
  }
  return out;
}

const exists = (path: string) =>
  stat(path).then(
    () => true,
    () => false,
  );

describe("COPY_ONLY", () => {
  it("refuses a folder outside ~/.tmp, and writes nothing", async () => {
    const p = await fixture();
    const outside = join(p.home, "elsewhere");
    await mkdir(outside, { recursive: true });
    await expect(
      runLegacyRetireDryRun({ ...optionsOf(p), dataDir: outside }),
    ).rejects.toMatchObject({ reason: "not_under_home_tmp" });
    expect(await exists(p.outPath)).toBe(false);
  });

  it("refuses ~/.vana, also through a symlink from ~/.tmp", async () => {
    const p = await fixture();
    const vana = join(p.home, ".vana");
    await mkdir(vana, { recursive: true });
    await expect(
      runLegacyRetireDryRun({ ...optionsOf(p), dataDir: vana }),
    ).rejects.toMatchObject({ reason: "under_vana_home" });
    const link = join(p.home, ".tmp", "link");
    await symlink(vana, link);
    await expect(
      runLegacyRetireDryRun({ ...optionsOf(p), dataDir: link }),
    ).rejects.toMatchObject({ reason: "under_vana_home" });
  });

  it("refuses a folder that holds a -shm file, and says why", async () => {
    const p = await fixture();
    await writeFile(join(p.dataDir, "index.db-shm"), "x");
    const error = await runLegacyRetireDryRun(optionsOf(p)).catch((e) => e);
    expect(error).toBeInstanceOf(CopyOnlyError);
    expect(error.reason).toBe("has_shm_file");
    expect(error.message).toMatch(/-shm/);
    expect(await exists(p.outPath)).toBe(false);
  });

  it("refuses a symlink inside the folder and an --out inside it", async () => {
    const p = await fixture();
    await symlink(join(p.home, ".tmp"), join(p.dataDir, "data", "escape"));
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      reason: "has_symlink",
    });
    await rm(join(p.dataDir, "data", "escape"));
    await expect(
      runLegacyRetireDryRun({
        ...optionsOf(p),
        outPath: join(p.dataDir, "report.json"),
      }),
    ).rejects.toMatchObject({ reason: "out_inside_data_dir" });
  });

  it("reads a legacy row that names a path outside the folder as unreadable", async () => {
    const p = await fixture();
    const report = await runLegacyRetireDryRun(optionsOf(p));
    // Every file was read from inside the folder; the guard in the store
    // turns a traversing scope or time into an unreadable file, not a read.
    expect(report.status).toBe("ok");
    const { openLegacyStore } = await import("./legacy-store.js");
    const store = await openLegacyStore({
      rootDir: p.dataDir,
      scratchDir: join(p.home, ".tmp", "scratch-trav"),
    });
    await expect(
      store.storage.readEnvelope("chatgpt.memories", "../../../../etc/passwd"),
    ).rejects.toThrow();
    store.close();
  });
});

describe("NO_REMOTE_WRITES", () => {
  const post = (url: string) => fetch(url, { method: "POST", body: "x" });

  it("aborts the run when the code under test POSTs to the gateway", async () => {
    const p = await fixture();
    hooks.retire = async () => {
      await post("https://gateway.test/v1/data");
      throw new Error("unreachable");
    };
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toBeInstanceOf(
      NetworkGuardError,
    );
    expect(p.requests.filter((r) => r.method !== "GET")).toEqual([]);
    const written = JSON.parse(await readFile(p.outPath, "utf8"));
    expect(written).toMatchObject({
      status: "aborted",
      abortReason: "network_guard",
      files: [],
    });
  });

  it("aborts even when the code under test swallows the refusal", async () => {
    const p = await fixture();
    const actual = await vi.importActual<typeof CoreSync>(
      "@opendatalabs/personal-server-ts-core/sync",
    );
    hooks.retire = async (...args) => {
      await post("https://gateway.test/v1/data").catch(() => undefined);
      return actual.retireLegacyFiles(
        ...(args as Parameters<typeof actual.retireLegacyFiles>),
      );
    };
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toBeInstanceOf(
      NetworkGuardError,
    );
    expect(p.requests.filter((r) => r.method !== "GET")).toEqual([]);
  });

  it("aborts on a GET to a host outside the Dev gateway and storage", async () => {
    const p = await fixture();
    hooks.retire = async () => {
      await fetch("https://elsewhere.test/v1/data");
      throw new Error("unreachable");
    };
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      violation: { reason: "host_not_allowed", host: "elsewhere.test" },
    });
    expect(p.requests.map((r) => r.host)).not.toContain("elsewhere.test");
  });

  it("restores fetch after the run", async () => {
    const p = await fixture();
    await runLegacyRetireDryRun(optionsOf(p));
    expect(globalThis.fetch).toBe(p.fetch);
  });
});

describe("NO_LOCAL_DELETES", () => {
  it("leaves every file of the folder byte-identical, with files that would be deleted", async () => {
    const p = await fixture();
    const before = await hashTree(p.dataDir);
    expect(Object.keys(before).some((f) => f.endsWith("index.db-wal"))).toBe(
      true,
    );
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.totals.wouldDelete).toBe(3);
    expect(await hashTree(p.dataDir)).toEqual(before);
    expect(
      Object.keys(await hashTree(p.dataDir)).filter((f) => f.endsWith("-shm")),
    ).toEqual([]);
  });

  it("opens a scratch copy of the database, removed at the end", async () => {
    const p = await fixture();
    await runLegacyRetireDryRun(optionsOf(p));
    expect(await exists(`${p.outPath}.work`)).toBe(false);
  });
});

describe("NO_IMPORT_NO_PUBLISH", () => {
  it("only reads: every request is a GET to the gateway or storage", async () => {
    const p = await fixture();
    await runLegacyRetireDryRun(optionsOf(p));
    expect(p.requests.length).toBeGreaterThan(0);
    expect(new Set(p.requests.map((r) => r.method))).toEqual(new Set(["GET"]));
    expect(new Set(p.requests.map((r) => r.host))).toEqual(
      new Set(["gateway.test", "storage.test"]),
    );
  });

  it("does not run an import: with none done, files report no_import and nothing is deleted", async () => {
    const p = await fixture({ importDone: false, fullRun: true });
    const before = await hashTree(p.dataDir);
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.deviceImport).toEqual({ complete: false, connectors: 0 });
    expect(report.files.every((f) => f.decision === "no_import")).toBe(true);
    expect(report.totals.wouldDelete).toBe(0);
    // The published view is still compared, so the report says what a later
    // import would find.
    expect(report.files.filter((f) => f.readback === "pass")).toHaveLength(3);
    expect(await hashTree(p.dataDir)).toEqual(before);
  });

  it("uses no writer, importer, sync manager or server bootstrap", async () => {
    const dir = join(process.cwd(), "packages/server/src/scripts");
    const forbidden =
      /\b(StreamSyncWriter|LegacyImporter|createSyncManager|createServer|openFsStreamSyncHome|createStreamSyncIntake|uploadAll|downloadAll|startRun)\b/;
    const files = [
      ...(await readdir(join(dir, "retire-dry-run"))).map((f) =>
        join(dir, "retire-dry-run", f),
      ),
      join(dir, "legacy-retire-dry-run.ts"),
    ].filter((f) => f.endsWith(".ts") && !/\.test(-utils)?\.ts$/.test(f));
    expect(files.length).toBeGreaterThan(6);
    for (const file of files) {
      const code = (await readFile(file, "utf8")).replace(
        /\/\*[\s\S]*?\*\/|\/\/.*$/gm,
        "",
      );
      expect(code, file).not.toMatch(forbidden);
    }
  });
});

describe("REPORT_REDACTED", () => {
  it("holds counts, short hashes and verdicts, and none of the fixture's values", async () => {
    const p = await fixture();
    const report = await runLegacyRetireDryRun(optionsOf(p));
    const text = await readFile(p.outPath, "utf8");
    expect(JSON.parse(text)).toEqual(JSON.parse(JSON.stringify(report)));
    for (const secret of [
      "synthetic memory",
      "mem-0",
      "evt-0",
      "folder-0",
      "Synthetic folder",
      "Synthetic Person",
      "user_0",
      "acct-0",
      "example/repo",
      "Renamed after the legacy file was made",
      p.ownerAddress.toLowerCase().slice(2),
      p.signature.slice(2, 30),
      p.dataDir,
      p.home,
      ".json",
    ]) {
      expect(text.toLowerCase(), secret).not.toContain(secret.toLowerCase());
    }
    // No hash is longer than 8 hex characters.
    expect(text.match(/[0-9a-fA-F]{9,}/g)).toBeNull();
    expect(report.files.every((f) => /^[0-9a-f]{8}$/.test(f.version))).toBe(
      true,
    );
    expect(
      report.files.every(
        (f) => f.matchedHash === "" || /^[0-9a-f]{8}$/.test(f.matchedHash),
      ),
    ).toBe(true);
    expect(Object.keys(report.files[0]!).sort()).toEqual(
      [
        "counts",
        "decision",
        "importDone",
        "matchedHash",
        "readback",
        "readbackReason",
        "scope",
        "version",
        "wouldDelete",
      ].sort(),
    );
  });
});

describe("the synthetic fixture, in memory and persisted", () => {
  it("gives the same table (same table as the in-memory dry run)", async () => {
    const p = await fixture();
    const { fx } = p;

    // The in-memory dry run of #595, on the same fixture.
    const ledger = new RetireLedger(createMemoryStreamSyncFiles());
    await ledger.update((d) => void (d.importComplete = true));
    const memory = await retireLegacyFiles({
      storage: fx.storage,
      host: createRetireHost({
        reader: fx.reader,
        writer: { fullRunSince: async () => true },
        ledger,
      }),
      ledger,
      deleteEnabled: true,
      dryRun: true,
    });
    const readbacks = (await ledger.read()).readbacks;
    const memoryTable = memory.files
      .map((f) => redactFile(f, readbacks[`${f.scope}|${f.version}`] ?? null))
      .map(({ version: _v, ...row }) => row);

    const persisted = await runLegacyRetireDryRun(optionsOf(p));
    const persistedTable = persisted.files.map(
      ({ version: _v, ...row }) => row,
    );

    const byScope = (rows: { scope: string }[]) =>
      [...rows].sort((a, b) => a.scope.localeCompare(b.scope));
    expect(byScope(persistedTable)).toEqual(byScope(memoryTable));
    expect(persisted.mode).toBe("dry-run");
    expect(persisted.files.map((f) => [f.scope, f.decision]).sort()).toEqual([
      ["chatgpt.conversations", "readback_failed"],
      ["chatgpt.memories", "ready"],
      ["github.events", "ready"],
      ["icloud_notes.folders", "readback_failed"],
      ["instagram.following", "ready"],
    ]);
    expect(
      persisted.files.find((f) => f.scope === "instagram.following")?.counts
        .fenced,
    ).toBeGreaterThan(0);
  });

  it("a fenced file waits for a full re-collect when the device has none", async () => {
    const p = await fixture({ importDone: true, fullRun: false });
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(
      report.files.find((f) => f.scope === "instagram.following")?.decision,
    ).toBe("fence_not_recollected");
    expect(report.totals.wouldDelete).toBe(2);
  });
});

describe("the device mirror", () => {
  it("without the device's registry mirror a fenced file cannot be explained and is kept", async () => {
    const p = await fixture({ importDone: true, fullRun: true, mirror: false });
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.publishedListing.deviceMirror).toBe(false);
    const fenced = report.files.find((f) => f.scope === "instagram.following");
    expect(fenced).toMatchObject({ readback: "fail", wouldDelete: false });
    expect(report.totals.wouldDelete).toBe(2);
  });

  it("with it, the report says so", async () => {
    const p = await fixture();
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.publishedListing.deviceMirror).toBe(true);
  });
});

describe("setup", () => {
  it("needs the owner signature from the environment", async () => {
    const p = await fixture();
    await expect(
      runLegacyRetireDryRun({ ...optionsOf(p), masterKeySignature: undefined }),
    ).rejects.toMatchObject({ code: "no_owner_signature" });
    await expect(
      runLegacyRetireDryRun({ ...optionsOf(p), masterKeySignature: "0x12" }),
    ).rejects.toMatchObject({ code: "bad_owner_signature" });
  });
});

void CHAIN_ID;
type _Unused = RedactedReport;
