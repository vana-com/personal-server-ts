import { describe, expect, it } from "vitest";
import { countRegistryRequests } from "./request-counter.js";
import type { StreamSyncRegistry } from "./ports.js";

function fake() {
  const calls: string[] = [];
  const registry = {
    async read(scope: string) {
      calls.push(`read:${scope}`);
      return { scope };
    },
    async listHeads() {
      calls.push("listHeads");
      return [];
    },
    async probeChange() {
      calls.push("probeChange");
      return "m";
    },
    async waitForChange() {
      calls.push("waitForChange");
      return { seq: "1", changed: false };
    },
    label: "not a function",
  } as unknown as StreamSyncRegistry;
  return { registry, calls };
}

describe("countRegistryRequests", () => {
  it("counts the cycle's registry calls and passes arguments and results through", async () => {
    const { registry, calls } = fake();
    const counted = countRegistryRequests(registry);
    expect(counted.count()).toBe(0);
    await expect(
      (
        counted.registry as unknown as { read(s: string): Promise<unknown> }
      ).read("a"),
    ).resolves.toEqual({ scope: "a" });
    await (
      counted.registry as unknown as { listHeads(): Promise<unknown> }
    ).listHeads();
    expect(counted.count()).toBe(2);
    expect(calls).toEqual(["read:a", "listHeads"]);
  });

  it("does not count the change feed: the push and the probe are not the cycle", async () => {
    const { registry } = fake();
    const counted = countRegistryRequests(registry);
    await counted.registry.probeChange!();
    await counted.registry.waitForChange!(
      undefined,
      1,
      new AbortController().signal,
    );
    expect(counted.count()).toBe(0);
  });

  it("leaves non-function members alone", () => {
    const { registry } = fake();
    const counted = countRegistryRequests(registry);
    expect((counted.registry as unknown as { label: string }).label).toBe(
      "not a function",
    );
  });
});
