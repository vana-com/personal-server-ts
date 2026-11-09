import { describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "./index.js";
import type { PersonalServerDataApiDeps } from "./index.js";
import { createAccountStorageMode } from "./account-storage-mode.js";
import type { AccountStorageMode } from "./account-storage-mode.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { Fixture, masterKey } from "../stream-sync-read/service-fixture.js";
import { testOwnerKey } from "../stream-sync-read/testing.js";
import type { StreamSyncReadService } from "../stream-sync-read/service.js";

/**
 * The scope listing and history routes of a switched account answer from
 * stream data only: a scope is listed if and only if the same caller can read
 * it, and nothing here reaches legacy storage.
 */

const BUILDER = "0x000000000000000000000000000000000000bEEF";
const T = Date.parse("2026-11-01T00:00:00Z");
const LEGACY_ONLY = "legacy.only";

const switched = (): AccountStorageMode =>
  createAccountStorageMode({ source: () => true });
const unswitched = (): AccountStorageMode =>
  createAccountStorageMode({ source: () => false });
const unknown = (): AccountStorageMode =>
  createAccountStorageMode({
    source: () => {
      throw new Error("account unreachable");
    },
  });

/** Storage and canonical view that fail the test on any call. */
function throwingLegacy() {
  const calls: string[] = [];
  const trap = (label: string) =>
    new Proxy(
      {},
      {
        get: (_target, name) => {
          if (name === "then") return undefined;
          return () => {
            calls.push(`${label}.${String(name)}`);
            throw new Error(`legacy read: ${label}.${String(name)}`);
          };
        },
      },
    );
  return {
    calls,
    storage: trap("storage") as never,
    legacyScopeView: trap("legacyScopeView") as never,
  };
}

async function readerWithStreams(): Promise<StreamSyncReadService> {
  const f = new Fixture(await testOwnerKey(masterKey(11)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [{ id: "a" }, { id: "b" }],
    observedAt: T - 1000,
  });
  // A deleted connection: its stream is not readable, so it is not listed.
  const nsGone = await f.key.ns("gone", "account-1");
  await f.activate("gone", nsGone);
  await f.publish({
    connector: "gone",
    ns: nsGone,
    stream: "items",
    generation: 1,
    records: [{ id: "x" }],
    observedAt: T - 1000,
  });
  await f.deleteConnection("gone", nsGone);
  const service = await f.service();
  await f.sync(service);
  return service;
}

function authPort(grantedScopes?: string[]) {
  return {
    authorizeOwner: vi.fn(async () => undefined),
    authorizeBuilderList: vi.fn(async () =>
      grantedScopes
        ? { builder: BUILDER, grantId: "grant-1", grantedScopes }
        : undefined,
    ),
    authorizeBuilderRead: vi.fn(async () =>
      grantedScopes
        ? { builder: BUILDER, grantId: "grant-1" }
        : { builder: BUILDER, grantId: "owner" },
    ),
  } as never;
}

function baseDeps(
  extra: Partial<PersonalServerDataApiDeps>,
  grantedScopes?: string[],
): PersonalServerDataApiDeps {
  return {
    storage: createMemoryDataStorage(),
    auth: authPort(grantedScopes),
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-11-01T00:00:00.000Z"),
    createLogId: () => "log-1",
    ...extra,
  };
}

async function get(deps: PersonalServerDataApiDeps, path: string) {
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com${path}`),
    deps,
  );
  const text = await response.text();
  let body: any;
  try {
    body = JSON.parse(text);
  } catch {
    body = undefined;
  }
  return { status: response.status, text, body };
}

async function seedLegacy(
  storage: ReturnType<typeof createMemoryDataStorage>,
  scope: string,
) {
  const envelope = {
    version: "1.0" as const,
    scope,
    collectedAt: "2026-10-01T00:00:00.000Z",
    data: { rows: [1] },
  };
  const written = await storage.writeEnvelope(envelope);
  storage.insertEntry({
    fileId: null,
    path: written.relativePath,
    scope,
    collectedAt: envelope.collectedAt,
    sizeBytes: written.sizeBytes,
  } as never);
}

const ROUTES = [
  "/",
  "/additions",
  "/acme.items/versions",
  "/acme.items/lineage",
  "/acme.items/lineage/1",
];

describe("switched listing and history", () => {
  // LEGACY_ON_SWITCH_LISTING
  it("makes no legacy-storage call on any listing or history route", async () => {
    const legacy = throwingLegacy();
    const deps = baseDeps({
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
      accountStorageMode: switched(),
      streamSyncRead: await readerWithStreams(),
    });
    for (const path of ROUTES) {
      const { status } = await get(deps, path);
      expect(status, path).not.toBe(500);
    }
    expect(legacy.calls).toEqual([]);
  });

  // LEGACY_ON_SWITCH_LISTING, typed refusal
  it("refuses versions, lineage and additions with a typed error", async () => {
    const deps = baseDeps({
      accountStorageMode: switched(),
      streamSyncRead: await readerWithStreams(),
    });
    for (const path of ROUTES.slice(1)) {
      const { status, body } = await get(deps, path);
      expect(status, path).toBe(501);
      expect(body.error.errorCode, path).toBe("STREAM_HISTORY_UNSUPPORTED");
    }
  });

  // STREAM_SERVED_LISTING
  it("lists the stream scope for the owner", async () => {
    const deps = baseDeps({
      accountStorageMode: switched(),
      streamSyncRead: await readerWithStreams(),
    });
    const { status, body } = await get(deps, "/");
    expect(status).toBe(200);
    expect(body.scopes.map((s: any) => s.scope)).toEqual(["pdpp.acme.items"]);
    expect(body.total).toBe(1);
    expect(body.scopes[0].versionCount).toBe(1);
  });

  // LIST_LEGACY
  it("does not list a scope that only legacy storage holds", async () => {
    const storage = createMemoryDataStorage();
    await seedLegacy(storage, LEGACY_ONLY);
    const deps = baseDeps({
      storage,
      accountStorageMode: switched(),
      streamSyncRead: await readerWithStreams(),
    });
    const { body } = await get(deps, "/");
    expect(body.scopes.map((s: any) => s.scope)).not.toContain(LEGACY_ONLY);
  });

  // LIST_HIDES_READABLE
  it("lists exactly the scopes the same caller can read", async () => {
    const deps = baseDeps({
      accountStorageMode: switched(),
      streamSyncRead: await readerWithStreams(),
    });
    const listed = (await get(deps, "/")).body.scopes.map((s: any) => s.scope);
    const candidates = [
      "pdpp.acme.items",
      "pdpp.acme.missing",
      "pdpp.gone.items",
      "pdpp.nobody.items",
    ];
    const readable: string[] = [];
    for (const scope of candidates) {
      if ((await get(deps, `/${scope}`)).status === 200) readable.push(scope);
    }
    expect(readable).toEqual(["pdpp.acme.items"]);
    expect(listed).toEqual(readable);
  });

  it("lists only what a grant covers, and pages the same set", async () => {
    const reader = await readerWithStreams();
    const covered = baseDeps(
      { accountStorageMode: switched(), streamSyncRead: reader },
      ["pdpp.acme.*"],
    );
    expect((await get(covered, "/")).body.scopes).toHaveLength(1);
    const other = baseDeps(
      { accountStorageMode: switched(), streamSyncRead: reader },
      ["other.*"],
    );
    expect((await get(other, "/")).body.total).toBe(0);
    const paged = await get(
      baseDeps({ accountStorageMode: switched(), streamSyncRead: reader }),
      "/?limit=1&offset=1",
    );
    expect(paged.body.scopes).toEqual([]);
    expect(paged.body.total).toBe(1);
  });

  // READER_PRESENCE_AS_MODE
  it("refuses a switched listing with no stream reader, never legacy", async () => {
    const legacy = throwingLegacy();
    const deps = baseDeps({
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
      accountStorageMode: switched(),
    });
    const { status, body } = await get(deps, "/");
    expect(status).toBe(503);
    expect(body.error.errorCode).toBe("STREAM_READER_UNAVAILABLE");
    expect(legacy.calls).toEqual([]);
  });

  it("returns the selector's refusal when the mode is unknown", async () => {
    const legacy = throwingLegacy();
    const deps = baseDeps({
      storage: legacy.storage,
      legacyScopeView: legacy.legacyScopeView,
      accountStorageMode: unknown(),
      streamSyncRead: await readerWithStreams(),
    });
    for (const path of ROUTES) {
      const { status, body } = await get(deps, path);
      expect(status, path).toBe(503);
      expect(body.error.errorCode, path).toBe("ACCOUNT_MODE_UNKNOWN");
    }
    expect(legacy.calls).toEqual([]);
  });
});

describe("unswitched listing and history", () => {
  // UNSWITCHED_PARITY_LISTING
  it("answers byte for byte as with no mode wired", async () => {
    const seed = async () => {
      const storage = createMemoryDataStorage();
      await seedLegacy(storage, LEGACY_ONLY);
      return storage;
    };
    const reader = await readerWithStreams();
    const plain = baseDeps({ storage: await seed(), streamSyncRead: reader });
    const gated = baseDeps({
      storage: await seed(),
      streamSyncRead: reader,
      accountStorageMode: unswitched(),
    });
    for (const path of [
      "/",
      "/additions",
      `/${LEGACY_ONLY}/versions`,
      `/${LEGACY_ONLY}/lineage`,
    ]) {
      const a = await get(plain, path);
      const b = await get(gated, path);
      expect(b, path).toEqual(a);
    }
    const listed = (await get(gated, "/")).body.scopes.map((s: any) => s.scope);
    expect(listed).toContain(LEGACY_ONLY);
    const versions = await get(gated, `/${LEGACY_ONLY}/versions`);
    expect(versions.status).toBe(200);
    expect(versions.body.total).toBe(1);
  });
});
