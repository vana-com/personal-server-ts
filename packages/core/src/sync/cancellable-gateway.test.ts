import { describe, expect, it, vi } from "vitest";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";

import {
  declaresRegistrationSignal,
  withCancellableRegistration,
} from "./cancellable-gateway.js";

const params = {
  ownerAddress: "0xabc",
  scope: "s.a",
  dataHash: "0x1",
  metadataHash: "0x2",
  expectedVersion: "1",
  signature: "0xsig",
} as never;

const sdkClient = () =>
  ({
    registerDataPoint: vi.fn(),
    getServer: vi.fn(),
  }) as unknown as GatewayClient;

describe("registration signal capability", () => {
  it("is declared by the wrapper, not by an arbitrary client", () => {
    const client = sdkClient();
    expect(declaresRegistrationSignal(client)).toBe(false);
    const wrapped = withCancellableRegistration(client, "https://gw.test");
    expect(declaresRegistrationSignal(wrapped)).toBe(true);
    // Wrapping again keeps the same client.
    expect(withCancellableRegistration(wrapped, "https://gw.test")).toBe(
      wrapped,
    );
  });

  it("passes the signal on, and defers to the SDK call without one", async () => {
    const client = sdkClient();
    const fetchImpl = vi.fn(
      async (_url: unknown, _init?: RequestInit) =>
        new Response(JSON.stringify({ dataPointId: "0xid" })),
    );
    const wrapped = withCancellableRegistration(
      client,
      "https://gw.test/",
      fetchImpl as never,
    );
    const controller = new AbortController();
    await wrapped.registerDataPoint(params, { signal: controller.signal });
    expect(fetchImpl.mock.calls[0]?.[0]).toBe("https://gw.test/v1/data");
    expect(fetchImpl.mock.calls[0]?.[1]?.signal).toBe(controller.signal);
    await wrapped.registerDataPoint(params);
    expect(client.registerDataPoint).toHaveBeenCalledWith(params);
  });

  it("reads an array body like the SDK helper: no fields", async () => {
    const wrapped = withCancellableRegistration(
      sdkClient(),
      "https://gw.test",
      (async () =>
        new Response(JSON.stringify([{ dataPointId: "0xid" }]))) as never,
    );
    const result = await wrapped.registerDataPoint(params, {
      signal: new AbortController().signal,
    });
    expect(result.dataPointId).toBeUndefined();
  });
});
