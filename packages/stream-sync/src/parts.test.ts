import { describe, expect, it } from "vitest";
import { InvalidPartSizeError } from "./errors.js";
import { DEFAULT_PART_SIZE_BYTES, split } from "./parts.js";
import { nodeSha256 } from "./test-support/index.js";
import { assemble } from "./assemble.js";
import { decodeHead, encodeHead, buildHead } from "./head.js";
import type { JsonObject } from "./json.js";
import { overlay } from "./overlay.js";
import { stamped } from "./test-support/index.js";

describe("split", () => {
  it("defaults to 4 MiB", () => {
    expect(DEFAULT_PART_SIZE_BYTES).toBe(4 * 1024 * 1024);
  });

  it.each([0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2])(
    "rejects part size %s",
    async (size) => {
      await expect(
        split(stamped([{ id: 1 }], 1), nodeSha256, size),
      ).rejects.toThrow(InvalidPartSizeError);
    },
  );

  it("splits a stream larger than the default limit into parts that each fit and read back whole", async () => {
    const filler = "x".repeat(3000);
    const records: JsonObject[] = Array.from({ length: 3200 }, (_, id) => ({
      id,
      filler,
    }));
    const sorted = overlay([], stamped(records, 1730851200000), ["id"]);
    const { parts, warnings } = await split(sorted, nodeSha256);
    expect(warnings).toEqual([]);
    expect(parts.length).toBeGreaterThan(2);
    for (const part of parts)
      expect(part.bytes.length).toBeLessThanOrEqual(DEFAULT_PART_SIZE_BYTES);
    const head = decodeHead(
      encodeHead(
        buildHead({
          stream: "s",
          connectionId: "c",
          parts,
          recordCount: sorted.length,
          baseVersion: null,
        }),
      ),
    );
    const byHash = new Map(parts.map((p) => [p.hash, p.bytes]));
    const back = await assemble(head, async (h) => byHash.get(h), nodeSha256);
    expect(back).toEqual(sorted);
  });

  it("is deterministic across runs", async () => {
    const records = stamped([{ id: 1, b: 1, a: 2 }, { id: 2 }], 7);
    const a = await split(records, nodeSha256, 50);
    const b = await split(records, nodeSha256, 50);
    expect(a.parts.map((p) => p.hash)).toEqual(b.parts.map((p) => p.hash));
  });
});
