import { describe, expect, it } from "vitest";
import { runConformance, type VectorFile } from "./conformance.js";
import { webCryptoSha256 } from "./hash.js";
import { loadVectors, nodeSha256, VECTOR_NAMES } from "./test-support/index.js";

describe("conformance vectors", () => {
  const files = loadVectors();

  it("ships every vector kind with cases", () => {
    expect(files.map((f) => f.kind)).toEqual([...VECTOR_NAMES]);
    for (const file of files) {
      expect(file.vectorVersion).toBe(1);
      expect(file.cases.length).toBeGreaterThan(0);
    }
  });

  for (const [label, sha256] of [
    ["Web Crypto", webCryptoSha256],
    ["an injected SHA-256", nodeSha256],
  ] as const) {
    it(`passes every vector with ${label}`, async () => {
      const results = await runConformance(files, { sha256 });
      const failures = results.filter((r) => !r.ok);
      expect(failures).toEqual([]);
      expect(results.length).toBe(
        files.reduce((n, f) => n + f.cases.length, 0),
      );
    });
  }

  it("reports a failure when an expected value is wrong", async () => {
    const tampered: VectorFile = {
      vectorVersion: 1,
      kind: "canonical-json",
      cases: [{ name: "wrong", input: { a: 1 }, expected: '{"a":2}' }],
    };
    const [result] = await runConformance([tampered], { sha256: nodeSha256 });
    expect(result?.ok).toBe(false);
  });

  it("reports an unknown kind and an unexpected error", async () => {
    const results = await runConformance(
      [
        { vectorVersion: 1, kind: "nope", cases: [{ name: "x" }] },
        {
          vectorVersion: 1,
          kind: "overlay",
          cases: [
            { name: "throws", primaryKey: [], base: [], run: [], expected: [] },
          ],
        },
      ],
      { sha256: nodeSha256 },
    );
    expect(results.map((r) => r.ok)).toEqual([false, false]);
  });
});
