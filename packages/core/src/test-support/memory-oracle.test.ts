/**
 * Calibrates the instrument itself, on synthetic workloads with known memory.
 * The instrument must read a bounded workload near zero, and must read a
 * synchronous materialize-then-free of N MiB as roughly N MiB, the case a
 * sampler misses.
 */

import { spawn } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { createTempRoot, run } from "./memory-oracle.js";

const WORKLOADS = fileURLToPath(
  new URL("./memory-oracle.calibration.ts", import.meta.url),
);
const MiB = 1024 * 1024;
const HELD_MiB = 256;

describe("memory-oracle calibration", () => {
  it("runs compiled JavaScript without a TypeScript loader", async () => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-js-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export function args() { return process.execArgv; }",
      );
      const measured = await run<string[]>({ module, exportName: "args" });
      expect(measured.result).not.toContain("tsx");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("caps the young-generation semi-space only when asked", async () => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-semi-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export function args() { return process.execArgv; }",
      );
      const capped = await run<string[]>({
        module,
        exportName: "args",
        maxSemiSpaceMiB: 4,
      });
      expect(capped.result).toContain("--max-semi-space-size=4");
      const unset = await run<string[]>({ module, exportName: "args" });
      expect(unset.result.join(" ")).not.toContain("semi-space");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  // The bounded case churns the same total through short-lived buffers, paced.
  // Its peak must stay well below a retained accumulation of that size.
  it("reads a bounded churn well below a retained accumulation", async () => {
    const r = await run({
      module: WORKLOADS,
      exportName: "bounded",
      args: { mib: HELD_MiB },
    });
    expect(r.baselineBytes).toBeGreaterThan(0);
    expect(r.peakBytes).toBeLessThan(0.5 * HELD_MiB * MiB);
  }, 60_000);

  it("reads a retained accumulation at its full size", async () => {
    const r = await run({
      module: WORKLOADS,
      exportName: "accumulate",
      args: { mib: HELD_MiB },
    });
    expect(r.peakBytes).toBeGreaterThanOrEqual(0.9 * HELD_MiB * MiB);
  }, 60_000);

  it("reads a synchronous materialize-then-free at its full size", async () => {
    const r = await run({
      module: WORKLOADS,
      exportName: "materializeThenFree",
      args: { mib: HELD_MiB },
    });
    expect(r.peakBytes).toBeGreaterThanOrEqual(0.9 * HELD_MiB * MiB);
  }, 60_000);

  // The header contract says a retained peak shows in full in both GC
  // modes: the timer only reclaims garbage, it cannot lower the HWM or
  // free live data.
  it('reads a retained accumulation at its full size with gc "none"', async () => {
    const r = await run(
      {
        module: WORKLOADS,
        exportName: "accumulate",
        args: { mib: HELD_MiB },
      },
      { gc: "none" },
    );
    expect(r.peakBytes).toBeGreaterThanOrEqual(0.9 * HELD_MiB * MiB);
  }, 60_000);

  // "€" is three bytes in UTF-8, and a ~300 KiB report line arrives in
  // several stdout chunks. 65536 is not a multiple of 3, so a chunk boundary
  // falls inside a character; decoding each chunk on its own replaces the
  // split bytes with U+FFFD while JSON.parse still succeeds.
  it("returns multi-byte characters intact across stdout chunks", async () => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-unicode-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        `export function unicode() { return "€".repeat(100_000); }`,
      );
      const measured = await run<string>({
        module,
        exportName: "unicode",
      });
      expect(measured.result).toBe("€".repeat(100_000));
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);

  it("passes heapLimitMiB and env through to the child", async () => {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-opts-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        `export function probe() { return { argv: process.execArgv, marker: process.env.MEMORY_ORACLE_TEST_MARKER ?? null }; }`,
      );
      const measured = await run<{ argv: string[]; marker: string | null }>({
        module,
        exportName: "probe",
        heapLimitMiB: 512,
        env: { MEMORY_ORACLE_TEST_MARKER: "oracle-env-ok" },
      });
      expect(measured.result.argv).toContain("--max-old-space-size=512");
      expect(measured.result.marker).toBe("oracle-env-ok");
      const plain = await run<{ argv: string[]; marker: string | null }>({
        module,
        exportName: "probe",
      });
      expect(plain.result.argv).toContain("--max-old-space-size=2048");
      expect(plain.result.marker).toBeNull();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 60_000);
});

describe("memory-oracle temp roots", () => {
  function withTempParent(run: (parent: string) => void): void {
    const parent = mkdtempSync(join(tmpdir(), "memory-oracle-roots-"));
    try {
      run(parent);
    } finally {
      rmSync(parent, { recursive: true, force: true });
    }
  }

  it("requires a nonempty prefix before resolving the parent", () => {
    expect(() => createTempRoot("", "/fixture/unused-parent")).toThrow(
      "Invalid temp-root prefix",
    );
  });

  it("rejects both platform separators and NUL before resolving the parent", () => {
    for (const prefix of ["fixture/path", "fixture\\path", "fixture\0root"]) {
      expect(() => createTempRoot(prefix, "/fixture/unused-parent")).toThrow(
        "Invalid temp-root prefix",
      );
    }
  });

  it("reports a missing temp-root parent without creating it", () => {
    withTempParent((parent) => {
      const missing = join(parent, "missing");
      const exitListeners = process.listenerCount("exit");
      expect(() => createTempRoot("oracle-", missing)).toThrow(/ENOENT/);
      expect(readdirSync(parent)).toEqual([]);
      expect(process.listenerCount("exit")).toBe(exitListeners);
    });
  });

  it("rejects a file as the temp-root parent without changing it", () => {
    withTempParent((parent) => {
      const file = join(parent, "not-a-directory");
      writeFileSync(file, "synthetic sentinel");
      const exitListeners = process.listenerCount("exit");
      expect(() => createTempRoot("oracle-", file)).toThrow(/ENOTDIR/);
      expect(readdirSync(parent)).toEqual(["not-a-directory"]);
      expect(readFileSync(file, "utf8")).toBe("synthetic sentinel");
      expect(process.listenerCount("exit")).toBe(exitListeners);
    });
  });

  it("disposes a root and can safely dispose it again", () => {
    withTempParent((parent) => {
      const { root, dispose } = createTempRoot("oracle-", parent);
      expect(existsSync(root)).toBe(true);
      dispose();
      expect(existsSync(root)).toBe(false);
      expect(dispose).not.toThrow();
    });
  });

  it("keeps a live owner's root when a second root is created", () => {
    withTempParent((parent) => {
      const first = createTempRoot("oracle-", parent);
      try {
        const second = createTempRoot("oracle-", parent);
        try {
          expect(existsSync(first.root)).toBe(true);
          expect(second.root).not.toBe(first.root);
        } finally {
          second.dispose();
        }
      } finally {
        first.dispose();
      }
    });
  });

  it("disposes a root even when setup throws", () => {
    withTempParent((parent) => {
      const { root, dispose } = createTempRoot("oracle-", parent);
      expect(() => {
        try {
          throw new Error("synthetic setup failure");
        } finally {
          dispose();
        }
      }).toThrow("synthetic setup failure");
      expect(existsSync(root)).toBe(false);
    });
  });

  it("reaps only old markerless roots and never follows a sibling symlink", () => {
    withTempParent((parent) => {
      const old = mkdtempSync(join(parent, "oracle-"));
      const fresh = mkdtempSync(join(parent, "oracle-"));
      const other = mkdtempSync(join(parent, "other-"));
      const link = join(parent, "oracle-abcdef");
      const yesterday = new Date(Date.now() - 25 * 60 * 60 * 1_000);
      utimesSync(old, yesterday, yesterday);
      utimesSync(other, yesterday, yesterday);
      symlinkSync(other, link, "dir");
      const next = createTempRoot("oracle-", parent);
      try {
        expect(existsSync(old)).toBe(false);
        expect(existsSync(fresh)).toBe(true);
        expect(existsSync(other)).toBe(true);
        expect(lstatSync(link).isSymbolicLink()).toBe(true);
      } finally {
        next.dispose();
      }
    });
  });

  it("keeps a stale root whose owner marker is not a valid pid", () => {
    withTempParent((parent) => {
      const yesterday = new Date(Date.now() - 25 * 60 * 60 * 1_000);
      // A marker that is not "<pid>\n" cannot prove its owner is gone.
      const garbage = mkdtempSync(join(parent, "oracle-"));
      writeFileSync(join(garbage, ".memory-oracle-owner"), "not-a-pid\n");
      utimesSync(garbage, yesterday, yesterday);
      // A pid outside the valid range cannot be signalled either.
      const huge = mkdtempSync(join(parent, "oracle-"));
      writeFileSync(join(huge, ".memory-oracle-owner"), "9999999999\n");
      utimesSync(huge, yesterday, yesterday);
      const next = createTempRoot("oracle-", parent);
      try {
        expect(existsSync(garbage)).toBe(true);
        expect(existsSync(huge)).toBe(true);
      } finally {
        next.dispose();
      }
    });
  });

  it("sweeps the root of a worker killed before it could dispose", async () => {
    const parent = mkdtempSync(join(tmpdir(), "memory-oracle-roots-"));
    const moduleUrl = new URL("./memory-oracle.ts", import.meta.url).href;
    const child = spawn(
      process.execPath,
      [
        "--import",
        "tsx",
        "--input-type=module",
        "--eval",
        `import { createTempRoot } from ${JSON.stringify(moduleUrl)};
          console.log(createTempRoot("oracle-", process.argv[1]).root);
          setInterval(() => {}, 1e6);`,
        parent,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const childExit = once(child, "close");
    try {
      const output = createInterface({ input: child.stdout });
      const orphan = await Promise.race([
        once(output, "line").then(([line]) => String(line)),
        childExit.then(() => {
          throw new Error("worker exited before creating its root");
        }),
      ]);
      output.close();
      expect(existsSync(orphan)).toBe(true);
      expect(child.kill("SIGKILL")).toBe(true);
      expect(await childExit).toEqual([null, "SIGKILL"]);
      expect(existsSync(orphan)).toBe(true);

      const next = createTempRoot("oracle-", parent);
      try {
        expect(existsSync(orphan)).toBe(false);
      } finally {
        next.dispose();
      }
    } finally {
      child.kill("SIGKILL");
      await childExit.catch(() => {});
      rmSync(parent, { recursive: true, force: true });
    }
  }, 15_000);

  it("rejects an empty or path-like temp-root prefix", () => {
    withTempParent((parent) => {
      expect(() => createTempRoot("", parent)).toThrow(
        "Invalid temp-root prefix",
      );
      expect(() => createTempRoot("a/b", parent)).toThrow(
        "Invalid temp-root prefix",
      );
      expect(() => createTempRoot("a\\0b", parent)).toThrow(
        "Invalid temp-root prefix",
      );
      // No root was left behind by the rejected prefixes.
      expect(readdirSync(parent)).toEqual([]);
    });
  });
});

describe("memory-oracle workload contract", () => {
  it("loads the module without calling an export in load-only mode", async () => {
    const root = mkdtempSync(join(tmpdir(), "memory-oracle-load-only-"));
    try {
      const module = join(root, "workload.mjs");
      const marker = join(root, "imported.txt");
      writeFileSync(
        module,
        [
          'import { writeFileSync } from "node:fs";',
          "writeFileSync(" + JSON.stringify(marker) + ', "loaded");',
          'export function mustNotRun() { throw new Error("wrong invocation"); }',
        ].join("\n"),
      );
      const measured = await run({ module, exportName: "" });
      expect(readFileSync(marker, "utf8")).toBe("loaded");
      expect(measured.result).toBe(null);
      expect(measured.baselineBytes).toBeGreaterThan(0);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);

  it("passes the JSON argument to the named async export and returns its result", async () => {
    const root = mkdtempSync(join(tmpdir(), "memory-oracle-workload-"));
    try {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export async function work(input) { return { payload: input, present: true }; }",
      );
      const args = {
        values: [0, false, null, "fixture"],
        nested: { count: 3 },
      };
      const measured = await run(
        { module, exportName: "work", args },
        { gc: "none" },
      );
      expect(measured.result).toEqual({ payload: args, present: true });
      expect(measured.peakBytes).toBe(
        Math.max(0, measured.rawPeakBytes - measured.baselineBytes),
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 30_000);
});

describe("memory-oracle error paths", () => {
  function withWorkloadDir<T>(runFn: (root: string) => Promise<T>): Promise<T> {
    const temporary = join(homedir(), ".tmp");
    mkdirSync(temporary, { recursive: true });
    const root = mkdtempSync(join(temporary, "memory-oracle-errors-"));
    return runFn(root).finally(() => {
      rmSync(root, { recursive: true, force: true });
    });
  }

  it("rejects when the workload module file does not exist", async () => {
    await withWorkloadDir(async (root) => {
      await expect(
        run({
          module: join(root, "does-not-exist.mjs"),
          exportName: "work",
        }),
      ).rejects.toThrow(/memory-oracle child for work exited 1/);
    });
  }, 30_000);

  it("rejects when the workload has no such export", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(module, "export function other() { return 1; }");
      await expect(run({ module, exportName: "missing" })).rejects.toThrow(
        /has no function export missing/,
      );
    });
  }, 30_000);

  it("rejects with the workload error when the workload throws", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        'export function boom() { throw new Error("workload exploded"); }',
      );
      await expect(run({ module, exportName: "boom" })).rejects.toThrow(
        /memory-oracle child for boom exited 1: .*workload exploded/s,
      );
    });
  }, 30_000);

  it("does not treat a normally exiting workload without a report as a measurement", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        'export function stop() { process.stderr.write("fixture stopped before measuring"); process.exit(0); }',
      );
      await expect(run({ module, exportName: "stop" })).rejects.toThrow(
        /memory-oracle child for stop exited 0: fixture stopped before measuring/,
      );
    });
  }, 30_000);

  it("keeps ordinary workload stdout out of the returned measurement", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        'export function work() { console.log("fixture progress"); return { ok: true }; }',
      );
      const measured = await run({ module, exportName: "work" });
      expect(measured.result).toEqual({ ok: true });
      expect(measured.peakBytes).toBe(
        Math.max(0, measured.rawPeakBytes - measured.baselineBytes),
      );
    });
  }, 30_000);

  it("rejects an unknown gc mode from the child", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(module, "export function noop() { return 0; }");
      await expect(
        run(
          { module, exportName: "noop" },
          // @ts-expect-error testing a runtime-only invalid value
          { gc: "bogus" },
        ),
      ).rejects.toThrow(/unknown gc mode bogus/);
    });
  }, 30_000);

  // The child prints its own report line after the workload returns, and the
  // parent parses the last MEMORY_ORACLE line. A workload that schedules a
  // later line therefore controls what the parent parses.
  it("rejects a syntactically valid report with the wrong shape", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export function poisonReport(line) { setTimeout(() => { process.stdout.write(`MEMORY_ORACLE ${line}\\n`); }, 10); return 0; }",
      );
      await expect(
        run({ module, exportName: "poisonReport", args: "{}" }),
      ).rejects.toThrow(/malformed report/);
    });
  }, 30_000);

  // Before the fix the JSON.parse throw escaped the close handler, so the
  // promise never settled (and the throw surfaced as an uncaught error).
  it("rejects a malformed report line instead of hanging", async () => {
    await withWorkloadDir(async (root) => {
      const module = join(root, "workload.mjs");
      writeFileSync(
        module,
        "export function poisonReport(line) { setTimeout(() => { process.stdout.write(`MEMORY_ORACLE ${line}\\n`); }, 10); return 0; }",
      );
      await expect(
        run({ module, exportName: "poisonReport", args: "{not json" }),
      ).rejects.toThrow(/unreadable report/);
    });
  }, 30_000);
});
