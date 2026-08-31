import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { SandboxSpec } from "@opendatalabs/personal-server-ts-core/query";
import { createNodeSandbox } from "./node-sandbox.js";
import { NODE_PATH_ENV } from "./pkg-runtime.js";

/**
 * The OS layer's behaviour inside a `pkg` single-file binary.
 *
 * `pkg` is simulated the way the loader does it — by setting `process.pkg`
 * before the sandbox is constructed — because the resolution this exercises
 * reads the same marker the real loader sets, and building a binary is not
 * something a unit test can do. What that leaves unverified is called out in
 * the report: this covers the resolution and the refusal, not a real
 * `/snapshot`.
 */
type Mutable = { pkg?: unknown };

describe("query/node-sandbox under pkg", () => {
  let root: string;
  let spec: SandboxSpec;

  const baseSpec = (writePath: string): SandboxSpec => ({
    readPaths: [],
    writePath,
    denyNetwork: true,
    cpuMs: 5_000,
    memoryMb: 512,
    wallClockMs: 15_000,
    maxOutputBytes: 64 * 1024,
  });

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), "ps-pkg-"));
    spec = baseSpec(root);
  });

  afterEach(() => {
    delete (process as Mutable).pkg;
    delete process.env[NODE_PATH_ENV];
    rmSync(root, { recursive: true, force: true });
  });

  it("refuses to run when there is no interpreter but the sidecar itself", async () => {
    (process as Mutable).pkg = { entrypoint: "/snapshot/server/index.js" };
    const sandbox = createNodeSandbox({ dataRoot: root, storageRoot: root });

    const result = await sandbox.run("console.log('never runs')", spec);

    expect(result.termination).toBe("sandboxUnavailable");
    expect(result.exitCode).toBe(-1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("no Node interpreter for the sandbox");
    expect(result.stderr).toContain("process.execPath is the server");
    // Nothing may be claimed as enforced for a run that never happened.
    expect(result.enforcement.filesystemRead).toBe(false);
    expect(result.enforcement.filesystemWrite).toBe(false);
    expect(result.enforcement.network).toBe(false);
  });

  it("reports the same refusal through capabilities()", async () => {
    (process as Mutable).pkg = { entrypoint: "/snapshot/server/index.js" };
    const sandbox = createNodeSandbox({ dataRoot: root, storageRoot: root });

    const caps = await sandbox.capabilities();

    expect(caps.available).toBe(false);
    if (caps.available) throw new Error("unreachable");
    expect(caps.reason).toContain(NODE_PATH_ENV);
  });

  it("runs once a real interpreter is named, binding it into the read policy", async () => {
    // A wrapper standing in for the node the sidecar would install in
    // `<root>/bin/`: it lives under a directory `broadDenyRead` closes, so it
    // only runs at all because the resolved interpreter is re-allowed.
    const wrapper = join(root, "node-wrapper");
    writeFileSync(
      wrapper,
      // The marker is what makes this falsifiable: plain `process.execPath`
      // would run the script just as happily and print nothing.
      `#!/bin/sh\necho WRAPPER-RAN >&2\nexec ${process.execPath} "$@"\n`,
      { mode: 0o755 },
    );
    chmodSync(wrapper, 0o755);

    (process as Mutable).pkg = { entrypoint: "/snapshot/server/index.js" };
    process.env[NODE_PATH_ENV] = wrapper;
    const sandbox = createNodeSandbox({ dataRoot: root, storageRoot: root });

    const caps = await sandbox.capabilities();
    if (!caps.available) {
      // No OS sandbox on this machine; the refusal cases above still hold.
      expect(caps.reason).not.toContain(NODE_PATH_ENV);
      return;
    }

    const result = await sandbox.run("console.log('WRAPPED-OK')", spec);

    expect(result.termination).toBe("completed");
    expect(result.stdout).toContain("WRAPPED-OK");
    expect(result.stderr).toContain("WRAPPER-RAN");
  });

  it("leaves the ordinary Node path resolving to process.execPath", async () => {
    const sandbox = createNodeSandbox({ dataRoot: root });
    const caps = await sandbox.capabilities();
    if (!caps.available) return;

    const result = await sandbox.run(
      "console.log(process.execPath === undefined ? 'no' : 'PLAIN-OK')",
      spec,
    );

    expect(result.termination).toBe("completed");
    expect(result.stdout).toContain("PLAIN-OK");
  });
});
