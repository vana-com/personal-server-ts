import { expect, it, vi } from "vitest";
import {
  createGatewayStreamSyncRegistry,
  parseBatchPolicy,
} from "./registry.js";

it("retains and caches the gateway batch bounds when an unknown text field is added", async () => {
  const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
    expect(init?.method).toBe("OPTIONS");
    return new Response(null, {
      status: 204,
      headers: {
        "batch-policy": "rows=2;mode=fast;bytes=100;requires=3;lockedScopes=4",
      },
    });
  });
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.example.invalid/",
    ownerAddress: "0x" + "11".repeat(20),
    fetch,
  });
  const expected = { rows: 2, bytes: 100, requires: 3, lockedScopes: 4 };
  await expect(registry.readBatchPolicy!()).resolves.toEqual(expected);
  await expect(registry.readBatchPolicy!()).resolves.toEqual(expected);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("still rejects malformed known bounds when unknown text fields are present", () => {
  expect(
    parseBatchPolicy("mode=fast;rows=0;bytes=100;requires=3"),
  ).toBeUndefined();
  expect(
    parseBatchPolicy("mode=fast;rows=2;bytes=100;requires=3;lockedScopes=x"),
  ).toBeUndefined();
});
