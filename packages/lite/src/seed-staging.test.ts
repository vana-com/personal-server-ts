import { expect, it } from "vitest";
import { createPsLiteSeedStaging } from "./seed-staging.js";
import { createMemoryPsLiteStateStore } from "./test-support/memory.js";
import type { PsLiteStateStore } from "./state.js";

it("persists bounded JSON-compatible chunks and reopens them in the same owner/network", async () => {
  const memory = createMemoryPsLiteStateStore();
  let largestChunk = 0;
  const store: PsLiteStateStore = {
    ...memory,
    async set(key, value) {
      if (typeof value === "string")
        largestChunk = Math.max(
          largestChunk,
          new TextEncoder().encode(value).length,
        );
      // Phone state ports may serialize through JSON instead of structured clone.
      await memory.set(key, JSON.parse(JSON.stringify(value)));
    },
  };
  const staging = createPsLiteSeedStaging(store, "0xabc", "network");
  const install = await staging.installId();
  const encoder = new TextEncoder();
  async function* body() {
    yield encoder.encode(
      JSON.stringify({
        primaryKey: ["id"],
        profile: { key: null, version: "1" },
        records: 600,
      }) + "\n",
    );
    for (let i = 0; i < 600; i++)
      yield encoder.encode(
        JSON.stringify({ id: i, text: "x".repeat(4096) }) + "\n",
      );
  }
  expect(await staging.stage("fixture", "items", body())).toMatchObject({
    records: 600,
    invalid: 0,
  });
  expect(largestChunk).toBeLessThan(1024 * 1024 + 8192);
  const reopened = createPsLiteSeedStaging(store, "0xAbC", "network");
  expect(await reopened.installId()).toBe(install);
  const source = reopened.source(install, async () => ({
    receipts: {},
    skipped: [],
  }));
  let count = 0;
  for await (const row of source.records("fixture", "items")) {
    expect(row.id).toBe(count++);
    expect(row.text).toHaveLength(4096);
  }
  expect(count).toBe(600);
  for (const isolated of [
    createPsLiteSeedStaging(store, "0xdef", "network"),
    createPsLiteSeedStaging(store, "0xabc", "other"),
  ]) {
    expect(await isolated.staged("fixture")).toEqual({});
    expect(await isolated.installId()).not.toBe(install);
  }
  await reopened.drop("fixture", "items");
  expect(await reopened.staged("fixture")).toEqual({});
});
