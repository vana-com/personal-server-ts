import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
  type StreamSyncReadPort,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

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

  it("returns a retryable refusal when the local reader is busy", async () => {
    const f = fixture("switched");
    f.resolve.mockResolvedValueOnce({
      kind: "busy",
      retryAfterSeconds: 5,
    } as never);
    const response = await get(f.deps);
    expect(response.status).toBe(503);
    expect(response.headers.get("Retry-After")).toBe("5");
    expect((await response.json()).error.errorCode).toBe(
      "STREAM_SYNC_READ_BUSY",
    );
  });

  it("answers 410 to a version selector: no older version has a body", async () => {
    const f = fixture("switched");
    for (const selector of ["?fileId=retained", "?at=2025-01-01T00:00:00Z"]) {
      const result = await get(f.deps, selector);
      expect(result.status).toBe(410);
      expect((await result.json()).error.errorCode).toBe(
        "STREAM_HISTORY_UNAVAILABLE",
      );
    }
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

/**
 * With stream sync off (account mode `unswitched`) every read answers as it
 * did before stream sync existed. `__snapshots__/stream-sync-flag-off.json`
 * records 88 such reads, taken on the commit before the read side was added.
 * This test replays them and compares with that file; it must never rewrite it.
 */
const PARITY = join(
  dirname(fileURLToPath(import.meta.url)),
  "../legacy-projection/__fixtures__/parity",
);
const SNAPSHOT = join(
  dirname(fileURLToPath(import.meta.url)),
  "__snapshots__/stream-sync-flag-off.json",
);
const COLLECTED_AT = "2026-10-01T00:00:00.000Z";
const BUILDER = "0x000000000000000000000000000000000000bEEF";

/** Parity fixtures that carry a legacy body; the first file per scope. */
function parityBodies(): { scope: string; data: unknown }[] {
  const byScope = new Map<string, unknown>();
  for (const name of readdirSync(PARITY).sort()) {
    if (!name.endsWith(".json")) continue;
    const fixture = JSON.parse(readFileSync(join(PARITY, name), "utf8"));
    if (fixture.legacyBody === undefined || byScope.has(fixture.scope))
      continue;
    byScope.set(fixture.scope, fixture.legacyBody);
  }
  return [...byScope].map(([scope, data]) => ({ scope, data }));
}

async function unswitchedDeps(): Promise<PersonalServerDataApiDeps> {
  const storage = createMemoryDataStorage();
  const envelopes = parityBodies();
  envelopes.push({
    scope: "pdpp.acme.items",
    data: {
      records: [
        { id: "a", n: 1 },
        { id: "b", n: 2 },
      ],
    },
  });
  for (const { scope, data } of envelopes) {
    const written = await storage.writeEnvelope({
      version: "1.0" as const,
      scope,
      collectedAt: COLLECTED_AT,
      data,
    });
    storage.insertEntry({
      fileId: null,
      path: written.relativePath,
      scope,
      collectedAt: COLLECTED_AT,
      sizeBytes: written.sizeBytes,
    } as never);
  }
  return {
    storage,
    accountMode: { read: () => "unswitched" },
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async ({ request }: { request: Request }) =>
        request.headers.get("x-test-builder")
          ? { builder: BUILDER, grantId: "grant-1" }
          : { builder: BUILDER, grantId: "owner" },
      ),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    serverOwner: "0x0000000000000000000000000000000000000001",
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
  } as unknown as PersonalServerDataApiDeps;
}

function snapshotRequests() {
  const requests: { name: string; path: string; builder?: boolean }[] = [];
  for (const { scope } of parityBodies()) {
    requests.push({ name: `owner ${scope}`, path: `/${scope}` });
    requests.push({
      name: `builder ${scope}`,
      path: `/${scope}`,
      builder: true,
    });
  }
  requests.push(
    { name: "raw pdpp stream", path: "/pdpp.acme.items" },
    {
      name: "connection and cursor ignored",
      path: "/pdpp.acme.items?connection=0123456789abcdef&cursor=abc",
    },
    {
      name: "bad connection ignored",
      path: "/chatgpt.conversations?connection=zz",
    },
    { name: "stored view", path: "/pdpp.acme.items?view=stored" },
    { name: "unknown scope", path: "/acme.nothing" },
    { name: "physical stream name", path: "/pdpp.acme~0123456789abcdef.items" },
    { name: "physical control name", path: "/pdpp.acme~0123456789abcdef" },
    { name: "identity-less physical name", path: "/pdpp.acme~.items" },
  );
  return requests;
}

describe("data reads with stream sync off", () => {
  it("answer every recorded read as the snapshot says", async () => {
    const deps = await unswitchedDeps();
    const observed: Record<string, unknown> = {};
    for (const request of snapshotRequests()) {
      const response = await handlePersonalServerDataRequest(
        new Request(`https://ps.example.com${request.path}`, {
          headers: request.builder ? { "x-test-builder": "1" } : {},
        }),
        deps,
      );
      const body = await response.text();
      observed[request.name] = {
        status: response.status,
        contentType: response.headers.get("content-type"),
        source: response.headers.get("x-vana-data-source"),
        bytes: body.length,
        sha256: createHash("sha256").update(body).digest("hex"),
      };
    }
    expect(observed).toEqual(JSON.parse(readFileSync(SNAPSHOT, "utf8")));
  });
});
