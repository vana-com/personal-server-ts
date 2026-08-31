import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type * as NodeFs from "node:fs";

/**
 * `pkg`'s snapshot filesystem cannot be created on a real host, so the two
 * reads the module makes are redirected at a fixture directory. Everything
 * else — the mkdir, the temp write, the rename, the chmod — runs for real
 * against a temp dir, which is the half worth exercising.
 */
const fixture = vi.hoisted(() => ({ root: "" }));

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof NodeFs>();
  const remap = (p: unknown) =>
    typeof p === "string" && p.startsWith("/snapshot/")
      ? join(fixture.root, p.slice("/snapshot/".length))
      : p;
  return {
    ...actual,
    readFileSync: (p: unknown, ...rest: unknown[]) =>
      (actual.readFileSync as (...a: unknown[]) => unknown)(remap(p), ...rest),
    existsSync: (p: unknown) =>
      (actual.existsSync as (...a: unknown[]) => boolean)(remap(p)),
  };
});

const {
  NODE_PATH_ENV,
  PACKAGED_NODE_NAME,
  isPackagedBinary,
  isSnapshotPath,
  materializeFromSnapshot,
  packagedBinDir,
  resolveSandboxNodePath,
} = await import("./pkg-runtime.js");

/** A plain Node process, as the module probes it. */
const nodeProcess = (overrides?: {
  execPath?: string;
  env?: Record<string, string>;
}) => ({
  versions: { node: "22.0.0" },
  execPath: overrides?.execPath ?? "/usr/local/bin/node",
  env: overrides?.env ?? {},
});

/** The same process, inside a `pkg` single-file binary. */
const pkgProcess = (overrides?: {
  execPath?: string;
  env?: Record<string, string>;
  marker?: "pkg" | "versions";
}) => {
  const base = {
    versions: { node: "22.0.0" } as Record<string, string>,
    execPath: overrides?.execPath ?? "/Applications/Vana.app/sidecar",
    env: overrides?.env ?? {},
  };
  return overrides?.marker === "versions"
    ? { ...base, versions: { ...base.versions, pkg: "6.6.0" } }
    : { ...base, pkg: { entrypoint: "/snapshot/server/index.js" } };
};

describe("query/pkg-runtime", () => {
  describe("isPackagedBinary", () => {
    it("is false for a plain Node process", () => {
      expect(isPackagedBinary(nodeProcess())).toBe(false);
    });

    it("is true when the loader set process.pkg", () => {
      expect(isPackagedBinary(pkgProcess())).toBe(true);
    });

    it("is true when only process.versions.pkg is set", () => {
      expect(isPackagedBinary(pkgProcess({ marker: "versions" }))).toBe(true);
    });
  });

  describe("isSnapshotPath", () => {
    it("matches both snapshot roots", () => {
      expect(isSnapshotPath("/snapshot/server/dist/query/runner.js")).toBe(
        true,
      );
      expect(isSnapshotPath("C:\\snapshot\\server\\runner.js")).toBe(true);
    });

    it("does not match a real path that merely starts with the same letters", () => {
      expect(isSnapshotPath("/snapshots/backup/node")).toBe(false);
      expect(isSnapshotPath("/usr/local/bin/node")).toBe(false);
    });
  });

  describe("packagedBinDir", () => {
    it("is the same <root>/bin the tunnel layer installs frpc into", () => {
      expect(packagedBinDir("/home/u/personal-server")).toBe(
        "/home/u/personal-server/bin",
      );
    });
  });

  describe("resolveSandboxNodePath off pkg", () => {
    it("resolves the running interpreter and binds nothing", () => {
      const result = resolveSandboxNodePath({ proc: nodeProcess() });
      expect(result).toEqual({
        ok: true,
        path: "/usr/local/bin/node",
        bind: false,
      });
    });

    it("still honours an explicit nodePath, and binds it because it moved", () => {
      const result = resolveSandboxNodePath({
        proc: nodeProcess(),
        nodePath: "/opt/node22/bin/node",
      });
      expect(result).toEqual({
        ok: true,
        path: "/opt/node22/bin/node",
        bind: true,
      });
    });

    it("never consults the env or <root>/bin off pkg", () => {
      const result = resolveSandboxNodePath({
        proc: nodeProcess({ env: { [NODE_PATH_ENV]: "/opt/other/node" } }),
        storageRoot: "/home/u/personal-server",
        isFile: () => true,
      });
      expect(result).toEqual({
        ok: true,
        path: "/usr/local/bin/node",
        bind: false,
      });
    });
  });

  describe("resolveSandboxNodePath under pkg", () => {
    it("refuses to run when no real interpreter is available", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess(),
        isFile: () => false,
      });
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("unreachable");
      expect(result.reason).toContain("process.execPath is the server");
      expect(result.reason).toContain(NODE_PATH_ENV);
    });

    it("never falls back to process.execPath, which is the sidecar itself", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess({ execPath: "/Applications/Vana.app/sidecar" }),
        // Everything exists, including the sidecar: only the rule keeps it out.
        isFile: () => true,
        nodePath: "/Applications/Vana.app/sidecar",
      });
      expect(result.ok).toBe(false);
    });

    it("takes an explicit nodePath and binds it into the read policy", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess(),
        nodePath: "/Applications/Vana.app/Resources/node",
        isFile: (p) => p === "/Applications/Vana.app/Resources/node",
      });
      expect(result).toEqual({
        ok: true,
        path: "/Applications/Vana.app/Resources/node",
        bind: true,
      });
    });

    it("falls back to the env var", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess({ env: { [NODE_PATH_ENV]: "/opt/node/bin/node" } }),
        isFile: (p) => p === "/opt/node/bin/node",
      });
      expect(result).toEqual({
        ok: true,
        path: "/opt/node/bin/node",
        bind: true,
      });
    });

    it("falls back to <root>/bin, the frpc layout", () => {
      const expected = join(
        "/home/u/personal-server",
        "bin",
        PACKAGED_NODE_NAME,
      );
      const result = resolveSandboxNodePath({
        proc: pkgProcess(),
        storageRoot: "/home/u/personal-server",
        isFile: (p) => p === expected,
      });
      expect(result).toEqual({ ok: true, path: expected, bind: true });
    });

    it("prefers the explicit path over the env over <root>/bin", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess({ env: { [NODE_PATH_ENV]: "/opt/env/node" } }),
        storageRoot: "/home/u/personal-server",
        nodePath: "/opt/explicit/node",
        isFile: () => true,
      });
      expect(result.ok && result.path).toBe("/opt/explicit/node");
    });

    it("refuses a directory, which would re-allow more than one binary", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess(),
        nodePath: tmpdir(),
      });
      expect(result.ok).toBe(false);
    });

    it("refuses a candidate that is itself a snapshot path", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess(),
        nodePath: "/snapshot/server/node",
        isFile: () => true,
      });
      expect(result.ok).toBe(false);
    });

    it("skips a named interpreter that is not actually there", () => {
      const result = resolveSandboxNodePath({
        proc: pkgProcess({ env: { [NODE_PATH_ENV]: "/opt/missing/node" } }),
        storageRoot: "/home/u/personal-server",
        isFile: (p) =>
          p === join("/home/u/personal-server", "bin", PACKAGED_NODE_NAME),
      });
      expect(result.ok && result.path).toBe(
        join("/home/u/personal-server", "bin", PACKAGED_NODE_NAME),
      );
    });
  });

  describe("materializeFromSnapshot", () => {
    let dest: string;

    beforeEach(() => {
      fixture.root = mkdtempSync(join(tmpdir(), "pkg-snapshot-"));
      dest = mkdtempSync(join(tmpdir(), "pkg-bin-"));
      mkdirSync(join(fixture.root, "vendor"), { recursive: true });
      writeFileSync(join(fixture.root, "vendor", "apply-seccomp"), "ELF-ish");
    });

    afterEach(() => {
      rmSync(fixture.root, { recursive: true, force: true });
      rmSync(dest, { recursive: true, force: true });
    });

    it("returns a real path untouched, so the non-pkg case copies nothing", () => {
      const real = join(fixture.root, "vendor", "apply-seccomp");
      expect(
        materializeFromSnapshot(real, dest, { version: "0.0.74", mode: 0o755 }),
      ).toBe(real);
      expect(() => readFileSync(join(dest, "apply-seccomp"))).toThrow();
    });

    it("copies a snapshot path onto the real filesystem under <root>/bin", () => {
      const out = materializeFromSnapshot(
        "/snapshot/vendor/apply-seccomp",
        join(dest, "bin"),
        { version: "0.0.74", mode: 0o755 },
      );
      expect(out).toBe(join(dest, "bin", "apply-seccomp"));
      expect(isSnapshotPath(out)).toBe(false);
      expect(readFileSync(out, "utf8")).toBe("ELF-ish");
    });

    it("writes a version file beside it and reuses the copy on the next call", () => {
      const args = [
        "/snapshot/vendor/apply-seccomp",
        join(dest, "bin"),
        { version: "0.0.74", mode: 0o755 },
      ] as const;
      const out = materializeFromSnapshot(...args);
      const meta = JSON.parse(readFileSync(`${out}-version.json`, "utf8"));
      expect(meta.version).toBe("0.0.74");

      // A second call must not re-copy: prove it by changing the installed
      // bytes and watching them survive.
      writeFileSync(out, "unchanged");
      expect(materializeFromSnapshot(...args)).toBe(out);
      expect(readFileSync(out, "utf8")).toBe("unchanged");
    });

    it("reinstalls when the version moves on", () => {
      const out = materializeFromSnapshot(
        "/snapshot/vendor/apply-seccomp",
        join(dest, "bin"),
        { version: "0.0.74", mode: 0o755 },
      );
      writeFileSync(out, "stale");
      materializeFromSnapshot(
        "/snapshot/vendor/apply-seccomp",
        join(dest, "bin"),
        {
          version: "0.0.75",
          mode: 0o755,
        },
      );
      expect(readFileSync(out, "utf8")).toBe("ELF-ish");
    });

    it("leaves no partial file behind", () => {
      materializeFromSnapshot(
        "/snapshot/vendor/apply-seccomp",
        join(dest, "bin"),
        {
          version: "0.0.74",
          mode: 0o755,
        },
      );
      expect(() =>
        readFileSync(join(dest, "bin", "_apply-seccomp.partial")),
      ).toThrow();
    });
  });
});
