/**
 * The body read and its payments follow the account storage mode.
 *
 * A switched account is answered from stream data only: the legacy storage
 * port and the legacy scope view are spies that throw on any call, so a read
 * that reaches them fails loudly. Every test drives production code.
 */
import { describe, expect, it, vi } from "vitest";
import {
  createAccountStorageMode,
  handlePersonalServerDataRequest,
  type AccountStorageMode,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";
import type { ReadDecision } from "../stream-sync-read/service.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const BUILDER = "0x000000000000000000000000000000000000bEEF" as const;
const GRANT = `0x${"11".repeat(32)}`;
const T = Date.parse("2026-11-01T00:00:00Z");
const STREAM_SCOPE = "pdpp.acme.items";
const LEGACY_SCOPE = "notes.entries";

const switchedMode = () =>
  createAccountStorageMode({ owner: OWNER, source: () => true });
const unswitchedMode = () =>
  createAccountStorageMode({ owner: OWNER, source: () => false });
const unknownMode = () =>
  createAccountStorageMode({
    owner: OWNER,
    source: () => {
      throw new Error("Account unreachable");
    },
  });

/** Wraps a legacy port so any call is recorded and throws. */
function spyOn<T extends object>(target: T, calls: string[]): T {
  return new Proxy(target, {
    get(inner, key, receiver) {
      const value = Reflect.get(inner, key, receiver);
      if (typeof value !== "function") return value;
      return () => {
        calls.push(String(key));
        throw new Error(`legacy storage was read: ${String(key)}`);
      };
    },
  });
}

/** Legacy bodies exist only in storage. Every call to them is recorded. */
async function legacyOnlyStorage(scope = LEGACY_SCOPE) {
  const real = createMemoryDataStorage();
  const seed = await handlePersonalServerDataRequest(
    new Request(`https://ps.example/${scope}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ records: [{ id: "legacy-only" }] }),
    }),
    baseDeps({ storage: real }),
  );
  expect(seed.status).toBe(201);
  const calls: string[] = [];
  const legacyScopeView = spyOn(
    {
      readLatest: async () => ({ kind: "none" }),
      listingFor: () => ({}),
      listCanonicalScopes: () => [],
      ownsScope: () => false,
      verdictFor: () => [],
      resetTakeover: () => undefined,
      isReset: () => false,
    },
    calls,
  );
  return {
    real,
    calls,
    storage: spyOn(real, calls),
    legacyScopeView: legacyScopeView as never,
  };
}

function baseDeps(
  extra: Partial<PersonalServerDataApiDeps> = {},
): PersonalServerDataApiDeps {
  return {
    storage: createMemoryDataStorage(),
    serverOwner: OWNER,
    auth: {
      authorizeOwner: vi.fn(async () => undefined),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(async () => undefined),
    },
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
    ...extra,
  };
}

/** A stream head for `pdpp.acme.items`, served by the real read service. */
async function streamService(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [
      { id: "stream-a", v: 1 },
      { id: "stream-b", v: 1 },
    ],
    observedAt: T - 1000,
    profileVersion: "1.0.0",
  });
  const service = await f.service();
  await f.sync(service);
  return service;
}

/** A service that has no head for the scope: the connector was never seen. */
async function emptyStreamService(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const service = await f.service();
  await f.sync(service);
  return service;
}

const get = (path: string, init?: RequestInit) =>
  new Request(`https://ps.example${path}`, init);

describe("LEGACY_ON_SWITCH_BODY: a switched account's body read never reaches legacy storage", () => {
  it("serves the stream head and makes zero legacy calls (STREAM_SERVED_BODY)", async () => {
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: await streamService(401),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-vana-data-source")).toBe("stream-sync");
    const body = (await response.json()) as {
      data: { records: Array<{ id: string }> };
    };
    expect(body.data.records.map((r) => r.id).sort()).toEqual([
      "stream-a",
      "stream-b",
    ]);
    expect(JSON.stringify(body)).not.toContain("legacy-only");
    expect(legacy.calls).toEqual([]);
  });

  // LEGACY_FALLBACK
  it("refuses a scope with no stream head instead of serving the legacy body", async () => {
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: await emptyStreamService(402),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(404);
    const text = await response.text();
    expect(JSON.parse(text).error.errorCode).toBe("STREAM_DATA_NOT_FOUND");
    expect(text).not.toContain("legacy-only");
    expect(legacy.calls).toEqual([]);
  });

  // LEGACY_FALLBACK
  it("refuses a legacy-only scope that no stream names", async () => {
    const legacy = await legacyOnlyStorage();
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: await streamService(403),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${LEGACY_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(404);
    expect(await response.text()).not.toContain("legacy-only");
    expect(legacy.calls).toEqual([]);
  });

  // LEGACY_FALLBACK
  it("serves nothing from legacy when a stream decision says the connector was deleted", async () => {
    const legacy = await legacyOnlyStorage();
    const deleted: ReadDecision = { kind: "unavailable", reason: "deleted" };
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: { resolve: async () => deleted },
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${LEGACY_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(410);
    expect(legacy.calls).toEqual([]);
  });

  // READER_PRESENCE_AS_MODE
  it("refuses with a typed 503 when switched and no stream reader is wired", async () => {
    const legacy = await legacyOnlyStorage();
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${LEGACY_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "STREAM_READER_UNAVAILABLE",
    );
    expect(legacy.calls).toEqual([]);
  });

  // UNKNOWN_READS_LEGACY
  it("returns the selector's refusal when the mode is unknown and touches no store", async () => {
    const legacy = await legacyOnlyStorage();
    const resolve = vi.fn();
    const deps = baseDeps({
      accountStorageMode: unknownMode(),
      streamSyncRead: { resolve },
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${LEGACY_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(resolve).not.toHaveBeenCalled();
    expect(legacy.calls).toEqual([]);
  });

  // EXPLICIT_HISTORY_BYPASS
  it.each([
    ["fileId", "?fileId=file-1"],
    ["at", "?at=2026-11-01T00:00:00.000Z"],
    ["view=stored", "?view=stored"],
  ])(
    "refuses explicit history by %s and does not read legacy or the stream service",
    async (_name, query) => {
      const legacy = await legacyOnlyStorage();
      const resolve = vi.fn();
      const deps = baseDeps({
        accountStorageMode: switchedMode(),
        streamSyncRead: { resolve },
        storage: legacy.storage,
        legacyScopeView: legacy.legacyScopeView,
      });
      for (const scope of [LEGACY_SCOPE, STREAM_SCOPE]) {
        const response = await handlePersonalServerDataRequest(
          get(`/${scope}${query}`),
          deps,
        );
        expect(response.status, `${scope}${query}`).toBe(404);
        const text = await response.text();
        expect(JSON.parse(text).error.errorCode).toBe(
          "STREAM_HISTORY_UNAVAILABLE",
        );
        expect(text).not.toContain("legacy-only");
      }
      expect(resolve).not.toHaveBeenCalled();
      expect(legacy.calls).toEqual([]);
    },
  );

  // EXPLICIT_HISTORY_BYPASS
  it("does not let an empty fileId or at hide explicit history behind a latest read", async () => {
    // An empty value selects no version: it is a latest read, as storage
    // already treats it, and the stream view answers.
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: await streamService(404),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}?fileId=&at=`),
      deps,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-vana-data-source")).toBe("stream-sync");
    expect(legacy.calls).toEqual([]);
  });
});

describe("UNSWITCHED_PARITY_BODY: an unswitched account reads as before", () => {
  /** The same requests against deps with the given mode, or none. */
  async function transcript(accountStorageMode?: AccountStorageMode) {
    const storage = createMemoryDataStorage();
    const deps = baseDeps({ storage, accountStorageMode });
    const written = await handlePersonalServerDataRequest(
      new Request(`https://ps.example/${LEGACY_SCOPE}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ records: [{ id: 1 }] }),
      }),
      deps,
    );
    const entry = storage.findEntry({ scope: LEGACY_SCOPE })!;
    storage.updateFileId(entry.path, "file-1");
    const fileId = "file-1";
    const out = [{ path: "POST", status: written.status, body: "" }];
    for (const path of [
      `/${LEGACY_SCOPE}`,
      `/${LEGACY_SCOPE}?view=stored`,
      `/${LEGACY_SCOPE}?fileId=${fileId}`,
      `/${LEGACY_SCOPE}?at=${entry.collectedAt}`,
      `/${LEGACY_SCOPE}?fileId=missing`,
      `/missing.scope`,
    ]) {
      const response = await handlePersonalServerDataRequest(get(path), deps);
      out.push({
        path,
        status: response.status,
        body: await response.text(),
      });
    }
    return out;
  }

  // UNSWITCHED_CHANGED
  it("answers latest, stored view and explicit history exactly as with no mode wired", async () => {
    const baseline = await transcript(undefined);
    expect(baseline.map((r) => r.status)).toEqual([
      201, 200, 200, 200, 200, 404, 404,
    ]);
    expect(await transcript(unswitchedMode())).toEqual(baseline);
  });

  // UNSWITCHED_CHANGED
  it("still serves a stream view from the reader on an unswitched account", async () => {
    const deps = baseDeps({
      accountStorageMode: unswitchedMode(),
      streamSyncRead: await streamService(405),
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-vana-data-source")).toBe("stream-sync");
  });

  // UNSWITCHED_CHANGED
  it("answers a legacy body when the reader says legacy, as before", async () => {
    const storage = createMemoryDataStorage();
    const deps = baseDeps({
      storage,
      accountStorageMode: unswitchedMode(),
      streamSyncRead: { resolve: async () => ({ kind: "pass" }) },
    });
    await handlePersonalServerDataRequest(
      new Request(`https://ps.example/${LEGACY_SCOPE}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ records: [{ id: 1 }] }),
      }),
      deps,
    );
    const response = await handlePersonalServerDataRequest(
      get(`/${LEGACY_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("x-vana-data-source")).toBe("legacy");
  });
});

describe("HTTP payments follow the mode", () => {
  const grant = {
    id: GRANT,
    grantorAddress: OWNER,
    granteeId: `0x${"22".repeat(32)}`,
    scopes: ["pdpp.*"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "pending",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "10000000000000000",
      dataAccessFee: "1000000000000000",
      totalDue: "11000000000000000",
    },
  };
  const signature = `0x${"aa".repeat(65)}` as const;

  function paidDeps(
    extra: Partial<PersonalServerDataApiDeps>,
  ): PersonalServerDataApiDeps {
    const authorizeBuilderRead = vi.fn(async () => ({
      builder: BUILDER,
      grantId: GRANT,
    }));
    return baseDeps({
      auth: {
        authorizeOwner: vi.fn(async () => undefined),
        authorizeBuilderList: vi.fn(async () => undefined),
        authorizeBuilderRead,
      } as never,
      gateway: { getGrant: vi.fn(async () => grant) } as never,
      gatewayConfig: {
        chainId: 14800,
        contracts: {
          dataRegistry: "0x0000000000000000000000000000000000000001",
          dataPortabilityPermissions:
            "0x0000000000000000000000000000000000000002",
          dataPortabilityServer: "0x0000000000000000000000000000000000000003",
          dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
          dataPortabilityEscrow: "0x0000000000000000000000000000000000000005",
          feeRegistry: "0x0000000000000000000000000000000000000006",
        },
      } as never,
      gatewayUrl: "https://gateway.test",
      paymentEnabled: true,
      serverAddress: "0x00000000000000000000000000000000000000aa",
      serverSigner: {
        signRecordDataAccess: async () => signature,
      } as never,
      ...extra,
    });
  }

  async function servedHead(
    service: Awaited<ReturnType<typeof streamService>>,
  ) {
    const decision = await service.resolve({
      scope: STREAM_SCOPE,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: false,
    });
    if (decision.kind !== "view" || decision.served === null) {
      throw new Error(`expected a registered view, got ${decision.kind}`);
    }
    await decision.body.cancel();
    return decision.served;
  }

  // CHARGE_OLD_ENTRY
  it("binds the challenge to the stream head that is served, with zero legacy calls (STREAM_SERVED_PAYMENT)", async () => {
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const service = await streamService(406);
    const head = await servedHead(service);
    const deps = paidDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: service,
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(402);
    const challenge = await response.json();
    expect(challenge.accepts[0].accessRecord).toMatchObject({
      dataPointId: computeDataPointId(OWNER, head.scope),
      version: String(head.version),
    });
    expect(legacy.calls).toEqual([]);
  });

  // SETTLE_BEFORE_SELECT
  it("does not look up a legacy entry for a paid read when the mode is unknown", async () => {
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const deps = paidDeps({
      accountStorageMode: unknownMode(),
      streamSyncRead: await streamService(407),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "ACCOUNT_MODE_UNKNOWN",
    );
    expect(legacy.calls).toEqual([]);
  });

  // SETTLE_BEFORE_SELECT
  it("does not look up a legacy entry for a paid read of a scope with no stream head", async () => {
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const deps = paidDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: await emptyStreamService(408),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
    );
    expect(response.status).toBe(404);
    expect(legacy.calls).toEqual([]);
  });

  // CHARGE_OLD_ENTRY
  it("settles an in-process paid read against the served stream head", async () => {
    const legacy = await legacyOnlyStorage(STREAM_SCOPE);
    const service = await streamService(409);
    const head = await servedHead(service);
    const authorizeBuilderRead = vi.fn(
      async (_input: Record<string, unknown>) => ({
        builder: BUILDER,
        grantId: GRANT,
      }),
    );
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      streamSyncRead: service,
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
      auth: {
        authorizeOwner: vi.fn(async () => undefined),
        authorizeBuilderList: vi.fn(async () => undefined),
        authorizeBuilderRead,
      } as never,
    });
    const response = await handlePersonalServerDataRequest(
      get(`/${STREAM_SCOPE}`),
      deps,
      { inProcess: { onServed: vi.fn() } },
    );
    expect(response.status).toBe(200);
    await response.text();
    // First the grant check without a charge, then the charging call that
    // names the stream head the read served.
    const calls = authorizeBuilderRead.mock.calls.map(([input]) => input);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({ metadataOnly: true });
    expect(calls[1]).toMatchObject({ servedEntry: head });
    expect(calls.every((input) => input["fileId"] === undefined)).toBe(true);
    expect(legacy.calls).toEqual([]);
  });

  // UNSWITCHED_CHANGED
  it("binds an unswitched paid read to the legacy entry, as before", async () => {
    async function challenge(accountStorageMode?: AccountStorageMode) {
      const storage = createMemoryDataStorage();
      const deps = paidDeps({ storage, accountStorageMode });
      await handlePersonalServerDataRequest(
        new Request(`https://ps.example/${LEGACY_SCOPE}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ records: [{ id: 1 }] }),
        }),
        deps,
      );
      const response = await handlePersonalServerDataRequest(
        get(`/${LEGACY_SCOPE}`),
        deps,
      );
      const body = await response.json();
      return {
        status: response.status,
        // The nonce and expiry are fresh per challenge.
        accepts: body.accepts?.map((a: Record<string, any>) => ({
          ...a,
          expiresAt: typeof a.expiresAt,
          message: { ...a.message, paymentNonce: "fresh" },
        })),
      };
    }
    const baseline = await challenge(undefined);
    expect(baseline.status).toBe(402);
    expect(await challenge(unswitchedMode())).toEqual(baseline);
  });
});

describe("the ingest timestamp helper is a write-path read", () => {
  // LEGACY_ON_SWITCH_BODY
  it("is never reached by a switched write: the gate refuses first", async () => {
    const legacy = await legacyOnlyStorage();
    const deps = baseDeps({
      accountStorageMode: switchedMode(),
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
    });
    const response = await handlePersonalServerDataRequest(
      new Request(`https://ps.example/${LEGACY_SCOPE}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ records: [{ id: 2 }] }),
      }),
      deps,
    );
    expect(response.status).toBe(426);
    expect(legacy.calls).toEqual([]);
  });
});
