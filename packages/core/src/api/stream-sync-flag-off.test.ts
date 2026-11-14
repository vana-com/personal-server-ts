import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
  type StreamSyncReadPort,
} from "./index.js";

const payment = vi.hoisted(() => ({
  challenge: vi.fn(async () => ({ x402Version: 1, accepts: [] })),
}));
vi.mock("../payment/index.js", () => ({
  buildChallenge: payment.challenge,
  parsePaymentHeader: () => null,
  verifyPayment: vi.fn(),
}));
vi.mock("../sync/data-point-id.js", () => ({
  computeDataPointId: () => `0x${"1".repeat(64)}`,
}));

const SCOPE = "pdpp.example.items";
const HEAD = { scope: "pdpp.example~0123456789abcdef.items", version: 7 };

function fixture(mode: "unknown" | "unswitched" | "switched") {
  const storageCalls = vi.fn(() => {
    throw new Error("Legacy storage must not be used");
  });
  const storage = new Proxy({}, { get: () => storageCalls });
  const modeRead = vi.fn(() => mode);
  const resolve = vi.fn(async () => ({
    kind: "view",
    cursor: "cursor-7",
    served: HEAD,
    body: new Response("{}").body!,
  }));
  const authorize = vi.fn(async () => ({ grantId: "owner" }));
  const deps = {
    accountMode: { read: modeRead },
    storage,
    legacyScopeView: { readLatest: storageCalls },
    streamSyncRead: { resolve } as unknown as StreamSyncReadPort,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: authorize,
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    logger: { debug: vi.fn(), error: vi.fn() },
    serverOwner: "0x0000000000000000000000000000000000000001",
    createLogId: () => "read-1",
  } as unknown as PersonalServerDataApiDeps;
  return { deps, modeRead, resolve, authorize, storageCalls };
}

function get(deps: PersonalServerDataApiDeps, query = "") {
  return handlePersonalServerDataRequest(
    new Request(`https://server.example/${SCOPE}${query}`),
    deps,
  );
}

describe("#596 account-mode data reads", () => {
  it("takes the mode once before any read and keeps that route for empty version selectors", async () => {
    const f = fixture("switched");
    const events: string[] = [];
    f.modeRead.mockImplementation(() => {
      events.push("mode");
      return events.length === 1 ? "switched" : "unknown";
    });
    const decision = await f.resolve();
    f.resolve.mockClear();
    f.resolve.mockImplementation(async () => {
      events.push("resolve");
      expect(f.modeRead).toHaveBeenCalledTimes(1);
      return decision;
    });
    const response = await get(f.deps, "?fileId=&at=");
    expect(response.status).toBe(200);
    expect(events).toEqual(["mode", "resolve"]);
    expect(f.modeRead).toHaveBeenCalledTimes(1);
    expect(f.resolve).toHaveBeenCalledWith(
      expect.objectContaining({
        scope: SCOPE,
        legacyFile: false,
      }),
    );
    expect(f.storageCalls).not.toHaveBeenCalled();
    await response.body?.cancel();
  });

  it("answers unknown mode with retryable ACCOUNT_MODE_UNKNOWN only after auth", async () => {
    const f = fixture("unknown");
    f.authorize.mockImplementation(async () => {
      expect(f.modeRead).toHaveBeenCalledTimes(1);
      expect(f.storageCalls).not.toHaveBeenCalled();
      return { grantId: "owner" };
    });
    const response = await get(f.deps);
    expect(f.authorize).toHaveBeenCalledTimes(1);
    expect(f.authorize).toHaveBeenCalledWith(
      expect.objectContaining({ metadataOnly: true }),
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(response.headers.get("Retry-After")).toBe("5");
    expect(f.resolve).not.toHaveBeenCalled();
    expect(f.storageCalls).not.toHaveBeenCalled();

    f.authorize.mockRejectedValueOnce(new Error("Authentication refused"));
    const denied = await get(f.deps);
    expect(denied.status).toBe(500);
    expect((await denied.json()).error.errorCode).not.toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(f.resolve).not.toHaveBeenCalled();
    expect(f.storageCalls).not.toHaveBeenCalled();
  });

  it("wraps an explicit history read and binds settlement to that selected head", async () => {
    const f = fixture("switched");
    f.deps.streamSyncRead!.olderVersions = {
      list: vi.fn(),
      counts: () => ({ served: 0, gone: 0, off: 0 }),
      read: vi.fn(async (_scope, _select, selected) => {
        selected?.({ ...HEAD, observedAt: 1000 });
        return new Response("[]").body!;
      }),
    };
    const result = await get(f.deps, "?fileId=retained");
    expect(result.status).toBe(200);
    expect((await result.json()).data).toEqual({ records: [] });
    expect(f.authorize).toHaveBeenLastCalledWith(
      expect.objectContaining({ servedEntry: expect.objectContaining(HEAD) }),
    );
    expect(f.resolve).not.toHaveBeenCalled();
    expect(f.storageCalls).not.toHaveBeenCalled();
  });

  it("binds x402 to the served head without storage.findEntry", async () => {
    const f = fixture("switched");
    f.authorize.mockResolvedValue({
      grantId: `0x${"2".repeat(64)}`,
      builder: "0x0000000000000000000000000000000000000002",
    } as never);
    f.deps.paymentEnabled = true;
    f.deps.gateway = { getGrant: vi.fn(async () => ({})) } as never;
    f.deps.gatewayConfig = { chainId: 1 } as never;
    f.deps.gatewayUrl = "https://gateway.example";
    payment.challenge.mockClear();
    const response = await get(f.deps);
    expect(response.status).toBe(402);
    expect(payment.challenge).toHaveBeenCalledTimes(1);
    expect(payment.challenge).toHaveBeenCalledWith(
      expect.objectContaining({
        entry: { ...HEAD, dataPointId: `0x${"1".repeat(64)}` },
      }),
    );
    expect(f.storageCalls).not.toHaveBeenCalled();
  });

  it("makes zero storage calls for switched POSTs, including delegated writes", async () => {
    for (const delegated of [false, true]) {
      const f = fixture("switched");
      const releaseProof = vi.fn(async () => undefined);
      if (delegated) {
        f.deps.auth.authorizeWrite = vi.fn(async () => ({
          builder: "0x0000000000000000000000000000000000000002",
          grantId: "grant-1",
          attribution: {},
          releaseProof,
        })) as never;
      }
      const response = await handlePersonalServerDataRequest(
        new Request(`https://server.example/${SCOPE}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        }),
        f.deps,
      );
      expect(response.status).toBe(426);
      expect(f.storageCalls).not.toHaveBeenCalled();
      expect(f.resolve).not.toHaveBeenCalled();
      expect(f.modeRead).toHaveBeenCalledTimes(1);
      expect(releaseProof).toHaveBeenCalledTimes(delegated ? 1 : 0);
    }
  });
});
