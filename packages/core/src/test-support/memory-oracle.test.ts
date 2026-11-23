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
});
