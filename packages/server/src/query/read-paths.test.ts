import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  ReadPathError,
  resolveReadPath,
  resolveReadPaths,
} from "./read-paths.js";

/**
 * Design §3 risk 1: "Data under a grant is one bad `readPaths` computation
 * away from exposure." The OS policy allows exactly what it is handed, so
 * these tests target the derivation rather than the enforcement.
 */

let root: string;
let outside: string;
let granted: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "rp-root-"));
  outside = mkdtempSync(join(tmpdir(), "rp-outside-"));
  granted = join(root, "oura_sleep.json");
  writeFileSync(granted, "[]");
  writeFileSync(join(outside, "secret.json"), "SECRET");
  mkdirSync(join(root, "nested"), { recursive: true });
  writeFileSync(join(root, "nested", "ok.json"), "[]");
});

afterAll(() => {
  for (const d of [root, outside]) rmSync(d, { recursive: true, force: true });
});

describe("resolveReadPath", () => {
  it("accepts a path inside the data root", () => {
    expect(resolveReadPath(granted, root)).toContain("oura_sleep.json");
  });

  it("accepts a nested path inside the data root", () => {
    expect(resolveReadPath(join(root, "nested", "ok.json"), root)).toContain(
      "ok.json",
    );
  });

  it("rejects a relative path", () => {
    expect(() => resolveReadPath("oura_sleep.json", root)).toThrow(
      ReadPathError,
    );
    expect(() => resolveReadPath("oura_sleep.json", root)).toThrow(
      /not absolute/,
    );
  });

  it("rejects a path outside the data root", () => {
    expect(() => resolveReadPath(join(outside, "secret.json"), root)).toThrow(
      /escapes the data root/,
    );
  });

  it("rejects `..` traversal that escapes the root", () => {
    const traversal = join(root, "..", "..", "etc", "passwd");
    expect(() => resolveReadPath(traversal, root)).toThrow(ReadPathError);
  });

  it("rejects a symlink inside the root that points outside it", () => {
    // The string is contained; the inode is not. A purely lexical check
    // passes this and leaks the target — which is the whole point.
    const link = join(root, "sneaky-link.json");
    rmSync(link, { force: true });
    symlinkSync(join(outside, "secret.json"), link);
    expect(() => resolveReadPath(link, root)).toThrow(ReadPathError);
  });

  it("rejects a symlinked directory that escapes the root", () => {
    const linkDir = join(root, "sneaky-dir");
    rmSync(linkDir, { force: true, recursive: true });
    symlinkSync(outside, linkDir);
    expect(() => resolveReadPath(join(linkDir, "secret.json"), root)).toThrow(
      ReadPathError,
    );
  });

  it("rejects filesystem and system roots outright", () => {
    for (const p of ["/", "/etc", "/dev", "/proc"]) {
      expect(() => resolveReadPath(p, root), p).toThrow(ReadPathError);
    }
  });

  it("rejects an empty path", () => {
    expect(() => resolveReadPath("", root)).toThrow(/empty/);
  });

  it("rejects a NUL byte (truncation attack on the policy string)", () => {
    expect(() => resolveReadPath(`${granted}\0/etc/passwd`, root)).toThrow(
      /NUL byte/,
    );
  });

  it("rejects a path that does not exist rather than passing it through", () => {
    expect(() => resolveReadPath(join(root, "nope.json"), root)).toThrow(
      /cannot be resolved/,
    );
  });

  it("does not treat a sibling-prefix directory as contained", () => {
    // `/data-evil` must not count as inside `/data`.
    const sibling = `${root}-evil`;
    mkdirSync(sibling, { recursive: true });
    writeFileSync(join(sibling, "x.json"), "[]");
    try {
      expect(() => resolveReadPath(join(sibling, "x.json"), root)).toThrow(
        /escapes the data root/,
      );
    } finally {
      rmSync(sibling, { recursive: true, force: true });
    }
  });
});

describe("resolveReadPaths", () => {
  it("deduplicates and sorts", () => {
    const r = resolveReadPaths([granted, granted], root);
    expect(r).toHaveLength(1);
  });

  it("fails the whole request if any single path is unsafe", () => {
    // Silently dropping the bad one would produce an answer whose coverage
    // claims a scope it never read.
    expect(() =>
      resolveReadPaths([granted, join(outside, "secret.json")], root),
    ).toThrow(ReadPathError);
  });
});
