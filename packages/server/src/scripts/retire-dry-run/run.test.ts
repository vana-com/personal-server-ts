/**
 * The read-only dry run, end to end on the #595 synthetic fixture persisted to
 * a data folder with the real SQLite store. Each hard requirement has a test
 * named for it; the network is a fake gateway and storage behind `fetch`.
 */

import { createHash } from "node:crypto";
import {
  link,
  lstat,
  mkdir,
  readdir,
  readFile,
  rename,
  rm,
  stat,
  symlink,
  utimes,
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
import { DEV_GATEWAY_HOSTS, DEV_STORAGE_HOSTS } from "./hosts.js";
import { redactFile, scopeHash, type RedactedReport } from "./report.js";
import { runLegacyRetireDryRun, type DryRunOptions } from "./run.js";
import {
  CHAIN_ID,
  GATEWAY_URL,
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

/** The tool's own scratch folders left in the home's ~/.tmp. */
async function scratchFolders(p: PersistedFixture): Promise<string[]> {
  return (await readdir(join(p.home, ".tmp"))).filter((n) =>
    n.startsWith("retire-dry-run-"),
  );
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
      await post(`${GATEWAY_URL}/v1/data`);
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
      await post(`${GATEWAY_URL}/v1/data`).catch(() => undefined);
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

  it("aborts if the folder changes during the run (tripwire)", async () => {
    const p = await fixture();
    const actual = await vi.importActual<typeof CoreSync>(
      "@opendatalabs/personal-server-ts-core/sync",
    );
    hooks.retire = async (...args) => {
      await writeFile(join(p.dataDir, "data", "stray.json"), "{}");
      return actual.retireLegacyFiles(
        ...(args as Parameters<typeof actual.retireLegacyFiles>),
      );
    };
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toThrow(
      "data_folder_changed",
    );
    expect(JSON.parse(await readFile(p.outPath, "utf8"))).toMatchObject({
      status: "aborted",
      abortReason: "data_folder_changed",
    });
  });

  it("gives the retire pass a store whose delete always fails", async () => {
    const p = await fixture();
    hooks.retire = async (deps) => {
      const { storage } = deps as {
        storage: { deleteVersion(s: string, c: string): Promise<boolean> };
      };
      return storage.deleteVersion(
        "chatgpt.memories",
        "2026-11-01T00:00:00.000Z",
      );
    };
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toThrow(
      "never deletes",
    );
    expect(await exists(join(p.dataDir, "data"))).toBe(true);
  });

  it("opens a scratch copy of the database, removed at the end", async () => {
    const p = await fixture();
    await runLegacyRetireDryRun(optionsOf(p));
    expect(await exists(`${p.outPath}.work`)).toBe(false);
    expect(await scratchFolders(p)).toEqual([]);
  });
});

describe("NO_IMPORT_NO_PUBLISH", () => {
  it("only reads: every request is a GET to the gateway or storage", async () => {
    const p = await fixture();
    await runLegacyRetireDryRun(optionsOf(p));
    expect(p.requests.length).toBeGreaterThan(0);
    expect(new Set(p.requests.map((r) => r.method))).toEqual(new Set(["GET"]));
    expect(new Set(p.requests.map((r) => r.host))).toEqual(
      new Set([DEV_GATEWAY_HOSTS[0], DEV_STORAGE_HOSTS[0]]),
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
        "connector",
        "scopeHash",
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
    const byHash = (rows: { scopeHash: string }[]) =>
      [...rows].sort((a, b) => a.scopeHash.localeCompare(b.scopeHash));

    const persisted = await runLegacyRetireDryRun(optionsOf(p));
    const persistedTable = persisted.files.map(
      ({ version: _v, ...row }) => row,
    );

    expect(byHash(persistedTable)).toEqual(byHash(memoryTable));
    expect(persisted.mode).toBe("dry-run");
    expect(
      persisted.files.map((f) => [f.scopeHash, f.decision]).sort(),
    ).toEqual(
      [
        ["chatgpt.conversations", "readback_failed"],
        ["chatgpt.memories", "ready"],
        ["github.events", "ready"],
        ["icloud_notes.folders", "readback_failed"],
        ["instagram.following", "ready"],
      ]
        .map(([scope, decision]) => [scopeHash(scope!), decision])
        .sort(),
    );
    expect(
      persisted.files.find(
        (f) => f.scopeHash === scopeHash("instagram.following"),
      )?.counts.fenced,
    ).toBeGreaterThan(0);
  });

  it("a fenced file waits for a full re-collect when the device has none", async () => {
    const p = await fixture({ importDone: true, fullRun: false });
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(
      report.files.find((f) => f.scopeHash === scopeHash("instagram.following"))
        ?.decision,
    ).toBe("fence_not_recollected");
    expect(report.totals.wouldDelete).toBe(2);
  });
});

describe("the device mirror", () => {
  it("without the device's registry mirror a fenced file cannot be explained and is kept", async () => {
    const p = await fixture({ importDone: true, fullRun: true, mirror: false });
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.publishedListing.deviceMirror).toBe(false);
    const fenced = report.files.find(
      (f) => f.scopeHash === scopeHash("instagram.following"),
    );
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

describe("the --out path and the scratch folder", () => {
  it("refuses an --out that is a symlink to the copy's database, and leaves it", async () => {
    const p = await fixture();
    const before = await hashTree(p.dataDir);
    await symlink(join(p.dataDir, "index.db"), p.outPath);
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      reason: "out_not_a_plain_file",
    });
    expect(await hashTree(p.dataDir)).toEqual(before);
  });

  it("refuses an --out that is a hard link, a folder, or in a symlinked folder of the copy", async () => {
    const p = await fixture();
    const before = await hashTree(p.dataDir);
    await link(join(p.dataDir, "index.db"), p.outPath);
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      reason: "out_not_a_plain_file",
    });
    await rm(p.outPath);
    await mkdir(p.outPath);
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      reason: "out_not_a_plain_file",
    });
    await rm(p.outPath, { recursive: true });
    const through = join(p.home, ".tmp", "through");
    await symlink(p.dataDir, through);
    await expect(
      runLegacyRetireDryRun({
        ...optionsOf(p),
        outPath: join(through, "report.json"),
      }),
    ).rejects.toMatchObject({ reason: "out_inside_data_dir" });
    expect(await hashTree(p.dataDir)).toEqual(before);
  });

  it("replaces, and does not follow, a link planted at --out after the check", async () => {
    const p = await fixture();
    const before = await hashTree(p.dataDir);
    const actual = await vi.importActual<typeof CoreSync>(
      "@opendatalabs/personal-server-ts-core/sync",
    );
    hooks.retire = async (...args) => {
      await symlink(join(p.dataDir, "index.db"), p.outPath);
      return actual.retireLegacyFiles(
        ...(args as Parameters<typeof actual.retireLegacyFiles>),
      );
    };
    await runLegacyRetireDryRun(optionsOf(p));
    expect(await hashTree(p.dataDir)).toEqual(before);
    expect((await lstat(p.outPath)).isFile()).toBe(true);
    expect(JSON.parse(await readFile(p.outPath, "utf8")).status).toBe("ok");
  });

  it("keeps a copy named like the scratch of --out (the exact pair)", async () => {
    const p = await fixture();
    const copy = join(p.home, ".tmp", "r.json.work");
    await rename(p.dataDir, copy);
    const before = await hashTree(copy);
    const out = join(p.home, ".tmp", "r.json");
    const report = await runLegacyRetireDryRun({
      ...optionsOf(p),
      dataDir: copy,
      outPath: out,
    });
    expect(report.status).toBe("ok");
    expect(await hashTree(copy)).toEqual(before);
    expect(await exists(out)).toBe(true);
  });

  it("does not delete a folder that already sits at <out>.work", async () => {
    const p = await fixture();
    const sibling = `${p.outPath}.work`;
    await mkdir(sibling);
    await writeFile(join(sibling, "keep.txt"), "mine");
    await runLegacyRetireDryRun(optionsOf(p));
    expect(await readFile(join(sibling, "keep.txt"), "utf8")).toBe("mine");
  });

  it("refuses a scratch folder that is not empty: a stale -wal would be replayed", async () => {
    const p = await fixture();
    const scratch = join(p.home, ".tmp", "stale-scratch");
    await mkdir(scratch);
    await writeFile(join(scratch, "index.db-wal"), "stale");
    const { openLegacyStore } = await import("./legacy-store.js");
    await expect(
      openLegacyStore({ rootDir: p.dataDir, scratchDir: scratch }),
    ).rejects.toThrow("not empty");
  });
});

describe("the pinned Dev hosts", () => {
  const writeConfig = async (p: PersistedFixture, config: unknown) =>
    writeFile(join(p.dataDir, "config.json"), JSON.stringify(config));

  it("refuses a gateway from the copy's config that is not pinned, before any request", async () => {
    const p = await fixture();
    await writeConfig(p, { gateway: { url: "https://gateway.evil.test" } });
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      code: "host_not_pinned",
    });
    expect(p.requests).toEqual([]);
    expect(await exists(p.outPath)).toBe(false);
  });

  it("refuses the production storage host, from the config and from a flag", async () => {
    const p = await fixture();
    await writeConfig(p, {
      gateway: { url: GATEWAY_URL },
      storage: { config: { vana: { apiUrl: "https://storage.vana.org" } } },
    });
    await expect(runLegacyRetireDryRun(optionsOf(p))).rejects.toMatchObject({
      code: "host_not_pinned",
    });
    await expect(
      runLegacyRetireDryRun({
        ...optionsOf(p),
        storageUrl: "https://storage.vana.org",
      }),
    ).rejects.toMatchObject({ code: "host_not_pinned" });
    expect(p.requests).toEqual([]);
  });

  it("uses the pinned Dev hosts when the copy has no config at all", async () => {
    const p = await fixture();
    await rm(join(p.dataDir, "config.json"));
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.hosts).toEqual({
      gateway: DEV_GATEWAY_HOSTS[0],
      storage: DEV_STORAGE_HOSTS[0],
    });
  });

  it("refuses loopback unless the test-only switch is on", async () => {
    const p = await fixture();
    await expect(
      runLegacyRetireDryRun({
        ...optionsOf(p),
        gatewayUrl: "http://127.0.0.1:9",
      }),
    ).rejects.toMatchObject({ code: "host_not_pinned" });
  });
});

describe("the setup error for a bad owner signature", () => {
  it("is fixed text, and holds nothing from the input", async () => {
    const p = await fixture();
    const wrong = `0x${"ab".repeat(65)}` as const;
    const error = await runLegacyRetireDryRun({
      ...optionsOf(p),
      masterKeySignature: wrong,
    }).catch((e) => e);
    expect(error).toMatchObject({ code: "bad_owner_signature" });
    expect(error.message).not.toMatch(/[0-9a-f]{6}/i);
    expect(await readFile(p.outPath, "utf8")).not.toContain("abab");
  });
});

describe("REPORT_REDACTED, scopes and names", () => {
  it("prints a connector label and a hash for a scope, never the scope", async () => {
    const p = await fixture();
    const report = await runLegacyRetireDryRun(optionsOf(p));
    const text = await readFile(p.outPath, "utf8");
    for (const scope of p.fx.scopes.map((s) => s.scope)) {
      expect(text, scope).not.toContain(scope);
      expect(text, scope).not.toContain(scope.split(".").slice(1).join("."));
    }
    expect(report.files.map((f) => f.connector).sort()).toEqual(
      p.fx.scopes.map((s) => s.scope.split(".")[0]).sort(),
    );
    expect(report.files.every((f) => /^[0-9a-f]{8}$/.test(f.scopeHash))).toBe(
      true,
    );
  });

  it("names no file of the folder in a refusal", async () => {
    const p = await fixture();
    const odd = join(p.dataDir, "data", "alice-private.db-shm");
    await writeFile(odd, "x");
    const shm = await runLegacyRetireDryRun(optionsOf(p)).catch((e) => e);
    expect(shm.reason).toBe("has_shm_file");
    expect(shm.message).not.toContain("alice");
    await rm(odd);
    const linked = join(p.dataDir, "data", "bob-secret-link");
    await symlink(p.home, linked);
    const sym = await runLegacyRetireDryRun(optionsOf(p)).catch((e) => e);
    expect(sym.reason).toBe("has_symlink");
    expect(sym.message).not.toContain("bob");
  });
});

describe("the age of the copy", () => {
  it("is the newest file time of the copy, in the report", async () => {
    const p = await fixture();
    const old = new Date("2026-11-01T00:00:00Z");
    for (const name of Object.keys(await hashTree(p.dataDir))) {
      await utimes(join(p.dataDir, name), old, old);
    }
    const newest = new Date("2026-11-08T12:34:56Z");
    await utimes(join(p.dataDir, "index.db-wal"), newest, newest);
    const report = await runLegacyRetireDryRun(optionsOf(p));
    expect(report.copy).toEqual({
      newestFileModified: "2026-11-08T12:34:56.000Z",
      files: Object.keys(await hashTree(p.dataDir)).length,
    });
    expect(JSON.parse(await readFile(p.outPath, "utf8")).copy).toEqual(
      report.copy,
    );
  });
});

void CHAIN_ID;
type _Unused = RedactedReport;
