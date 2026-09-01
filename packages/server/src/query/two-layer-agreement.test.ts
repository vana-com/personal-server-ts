/**
 * The two layers must agree on the grant, in the real server wiring.
 *
 * 4b's `two-layer.test.ts` pins this contract at the unit level: what
 * `vana.scopes()` names and what `resolveScopePath` resolves must be
 * set-equal. This is the other half — the OS layer's `readPaths`, as actually
 * built by `createSandboxToolHost`, must correspond to exactly the same set.
 *
 * Design §3 risk 1: "data under a grant is one bad `readPaths` computation
 * away from exposure". A disagreement in either direction is a bug:
 *
 * - OS wider than the API → a scope the script cannot name is still on disk
 *   inside the sandbox, one interpreter defect away from being read.
 * - API wider than the OS → the script can name a scope whose file the
 *   sandbox will deny, which surfaces as a confusing mid-run failure rather
 *   than an honest "not granted".
 */

import {
  mkdtempSync,
  mkdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Sandbox } from "@opendatalabs/personal-server-ts-core/query";
import { createSandboxToolHost } from "./sandbox-tool-host.js";

let root: string;
let dataRoot: string;
let scratch: string;
const paths: Record<string, string> = {};

/** Records the spec it was handed; never actually runs anything. */
function recordingSandbox(): Sandbox & { lastReadPaths: string[] } {
  const rec = {
    lastReadPaths: [] as string[],
    async run(_script: string, spec: { readPaths: string[] }) {
      rec.lastReadPaths = spec.readPaths;
      return {
        stdout: "",
        stderr: "",
        exitCode: 0,
        timedOut: false,
        truncated: false,
        durationMs: 0,
        termination: "completed" as const,
        enforcement: {
          filesystemRead: true,
          filesystemWrite: true,
          network: true,
          cpu: true,
          memory: true,
          processCount: true,
          wallClock: true,
          notes: [],
        },
        violations: [],
      };
    },
    async capabilities() {
      return { available: true as const, enforcement: {} as never };
    },
  };
  return rec as unknown as Sandbox & { lastReadPaths: string[] };
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "two-layer-"));
  dataRoot = join(root, "data");
  scratch = join(root, "scratch");
  mkdirSync(dataRoot, { recursive: true });
  mkdirSync(scratch, { recursive: true });
  for (const scope of ["oura.sleep", "spotify.streams", "bank.transactions"]) {
    paths[scope] = join(dataRoot, `${scope}.json`);
    writeFileSync(paths[scope]!, "[]");
  }
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

describe("the OS layer and the capability layer agree on the grant", () => {
  it("readPaths corresponds exactly to the named scopes", async () => {
    const granted = ["oura.sleep", "spotify.streams"];
    const sandbox = recordingSandbox();
    const host = createSandboxToolHost({
      sandbox,
      scopes: granted.map((scope) => ({ scope, path: paths[scope]! })),
      dataRoot,
      scratchDir: scratch,
      budget: { toolCalls: 10, outputBytes: 1000 },
      limits: {
        cpuMs: 1000,
        memoryMb: 128,
        wallClockMs: 1000,
        maxOutputBytes: 1000,
      },
      runnerBundlePath: paths["oura.sleep"]!, // any readable file; never executed
    });

    await host.execute("vana.note('x')");

    const named = (await host.listScopes()).map((s) => s.scope).sort();
    expect(named).toEqual([...granted].sort());

    // Every allowed path belongs to a named scope, and every named scope has
    // exactly one allowed path. Set equality in both directions.
    //
    // Compared on REALPATHS: `resolveReadPaths` resolves symlinks, which is
    // load-bearing on macOS where /var -> /private/var and the kernel policy
    // matches the resolved path. An unresolved allow entry silently fails to
    // re-open a region a resolved deny closed.
    const expected = granted.map((s) => realpathSync(paths[s]!)).sort();
    expect([...sandbox.lastReadPaths].sort()).toEqual(expected);
    expect(host.readPaths.length).toBe(granted.length);
  });

  it("an ungranted scope's file is absent from readPaths", async () => {
    const sandbox = recordingSandbox();
    const host = createSandboxToolHost({
      sandbox,
      scopes: [{ scope: "oura.sleep", path: paths["oura.sleep"]! }],
      dataRoot,
      scratchDir: scratch,
      budget: { toolCalls: 10, outputBytes: 1000 },
      limits: {
        cpuMs: 1000,
        memoryMb: 128,
        wallClockMs: 1000,
        maxOutputBytes: 1000,
      },
      runnerBundlePath: paths["oura.sleep"]!,
    });

    await host.execute("vana.note('x')");

    expect(sandbox.lastReadPaths).not.toContain(paths["bank.transactions"]);
    expect(host.readPaths).not.toContain(paths["bank.transactions"]);
    const named = (await host.listScopes()).map((s) => s.scope);
    expect(named).not.toContain("bank.transactions");
  });

  it("refuses a granted path that escapes the data root", () => {
    expect(() =>
      createSandboxToolHost({
        sandbox: recordingSandbox(),
        scopes: [{ scope: "evil", path: join(root, "..", "escape.json") }],
        dataRoot,
        scratchDir: scratch,
        budget: { toolCalls: 10, outputBytes: 1000 },
        limits: {
          cpuMs: 1000,
          memoryMb: 128,
          wallClockMs: 1000,
          maxOutputBytes: 1000,
        },
      }),
    ).toThrow();
  });
});
