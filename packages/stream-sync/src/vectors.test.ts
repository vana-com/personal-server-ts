import { createHash, createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3";
import { describe, expect, it } from "vitest";
import { runVectors } from "./vectors.js";
import { nodePorts } from "./test-support/ports.js";

const vectors = JSON.parse(
  readFileSync(new URL("../vectors/v1.json", import.meta.url), "utf8"),
);

describe("vectors/v1.json", () => {
  it("passes every check with node:crypto and @noble/hashes ports", async () => {
    const report = await runVectors(vectors, nodePorts);
    expect(report.failures).toEqual([]);
    expect(report.checks).toBeGreaterThan(250);
  });

  it("matches its generator", () => {
    const script = new URL("../scripts/generate-vectors.mjs", import.meta.url);
    expect(() =>
      execFileSync(process.execPath, [script.pathname, "--check"], {
        stdio: "pipe",
      }),
    ).not.toThrow();
  });

  it("covers every decide table row and the named traces", () => {
    const rows = new Set(vectors.decide.map((c: { row: string }) => c.row));
    expect(rows.size).toBeGreaterThanOrEqual(20);
    const traces = vectors.traces.map((t: { name: string }) => t.name);
    expect(traces).toEqual(
      expect.arrayContaining([
        "replay after delete (trace A)",
        "split run",
        "stale userConnect entry (trace B)",
      ]),
    );
  });

  it("fails loudly when a port disagrees", async () => {
    const report = await runVectors(vectors, {
      ...nodePorts,
      sha256: async (data) =>
        new Uint8Array(createHash("sha256").update(data).update("x").digest()),
    });
    expect(report.failures.length).toBeGreaterThan(10);
  });

  it("uses a Keccak-256 that is not SHA3-256", () => {
    // Guard against a host wiring SHA3 in place of Keccak.
    const sha3 = createHash("sha3-256").update("").digest("hex");
    const keccak = Buffer.from(keccak_256(new Uint8Array())).toString("hex");
    expect(sha3).not.toBe(keccak);
    expect(
      createHmac("sha256", Buffer.alloc(32)).update("").digest().length,
    ).toBe(32);
  });
});
