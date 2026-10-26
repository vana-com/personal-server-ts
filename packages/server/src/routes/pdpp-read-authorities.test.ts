import { afterEach, expect, it, vi } from "vitest";
import type {
  PdppAuthorizationService,
  PdppTokenContext,
  Grant,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import {
  pdppRecordsRoutes,
  type PdppChainEnforcementPort,
} from "./pdpp-records.js";
import { pdppBlobsRoutes, BLOB_DELIVERY_CHUNK_BYTES } from "./pdpp-blobs.js";
const NOW = Date.parse("2026-10-21T20:00:00Z");
const headers = { Authorization: "Bearer t" };
const stores: ReturnType<typeof createMemoryRecordStore>[] = [];
afterEach(() => {
  vi.useRealTimers();
  for (const s of stores.splice(0)) s.close();
});
function fixture(grantExpiry?: string) {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  const store = createMemoryRecordStore();
  stores.push(store);
  const bytes = new Uint8Array(BLOB_DELIVERY_CHUNK_BYTES * 3).fill(7);
  const meta = store.storeBlobBytes(bytes, "application/octet-stream");
  store.ingestBatch(
    [
      {
        instance: "i",
        stream: "media",
        key: "private-record",
        data: { id: "private-record", blob_ref: { blob_id: meta.blobId } },
        emitted_at: "2026-04-01T00:00:00Z",
      },
    ],
    () => "append_only",
    () => ["id"],
  );
  const grant: Grant = {
    version: "0.1.0",
    grant_id: "g",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: grantExpiry,
    subject: { id: "s" },
    client: { client_id: "c" },
    source: { kind: "provider_native", id: "src" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      { name: "media", instance_ids: ["i"], fields: ["id", "blob_ref"] },
    ],
  };
  const context: PdppTokenContext = {
    active: true,
    tokenKind: "client",
    subjectId: "s",
    clientId: "c",
    grant,
    expiresAt: new Date(NOW + 60_000).toISOString(),
  };
  const resolveToken = vi.fn(async () => context);
  const auth: PdppAuthorizationService = { locality: "remote", resolveToken };
  const declarations = createStreamDeclarationRegistry([
    {
      name: "media",
      semantics: "append_only",
      primaryKey: ["id"],
      cursorField: "emitted_at",
      requiredFields: ["id"],
    },
  ]);
  return { store, bytes, meta, auth, declarations, resolveToken };
}
it("F1: refuses a record when the carried grant deadline passes inside the remote staleness bound", async () => {
  const f = fixture(new Date(NOW + 5_000).toISOString());
  const store = new Proxy(f.store, {
    get(target, key) {
      if (key === "getRecord")
        return (...args: Parameters<typeof target.getRecord>) => {
          const row = target.getRecord(...args);
          vi.setSystemTime(NOW + 6_000);
          return row;
        };
      const value = Reflect.get(target, key, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const response = await pdppRecordsRoutes({ ...f, store }).request(
    "/streams/media/records/private-record",
    { headers },
  );
  const text = await response.text();
  expect(response.status, text).toBe(403);
  expect(text).toContain("grant_expired");
  expect(text).not.toContain('"id":"private-record"');
  expect(f.resolveToken).toHaveBeenCalledTimes(1);
});
it("F1: refuses a blob chunk after its known grant deadline, before remote refresh is due", async () => {
  const f = fixture(new Date(NOW + 5_000).toISOString());
  const response = await pdppBlobsRoutes({
    ...f,
    readBlobBytes: async () => f.bytes,
  }).request(`/${f.meta.blobId}`, { headers });
  expect(response.status).toBe(200);
  const reader = response.body!.getReader();
  expect((await reader.read()).value!.length).toBe(BLOB_DELIVERY_CHUNK_BYTES);
  vi.setSystemTime(NOW + 6_000);
  await expect(reader.read()).rejects.toMatchObject({ code: "grant_expired" });
  expect(f.resolveToken).toHaveBeenCalledTimes(1);
});
it("F1: malformed carried grant expiry fails closed", async () => {
  const f = fixture("malformed");
  const response = await pdppRecordsRoutes(f).request(
    "/streams/media/records/private-record",
    { headers },
  );
  expect(response.status, await response.text()).toBe(403);
});
for (const method of ["GET", "HEAD"])
  it(`F2: ${method} blobs enforce the same configured chain denial as records`, async () => {
    const f = fixture();
    const chainEnforcement: PdppChainEnforcementPort = {
      authorize: vi.fn(async () => ({
        ok: false,
        retryable: false,
        cause: "revoked",
        reason: "permission revoked",
      })),
    };
    const deps = { ...f, chainEnforcement, readBlobBytes: async () => f.bytes };
    const record = await pdppRecordsRoutes(deps).request(
      "/streams/media/records/private-record",
      { headers },
    );
    expect(record.status).toBe(403);
    const response = await pdppBlobsRoutes(deps).request(`/${f.meta.blobId}`, {
      method,
      headers,
    });
    expect(
      response.status,
      `blob status=${response.status}, content-length=${response.headers.get("Content-Length")}`,
    ).toBe(403);
    expect(response.headers.get("Content-Length")).not.toBe(
      String(f.bytes.length),
    );
  });
it("F2: blob chunks reverify stale configured chain authority", async () => {
  const f = fixture();
  const authorize = vi
    .fn()
    .mockResolvedValueOnce({ ok: true })
    .mockResolvedValue({
      ok: false,
      retryable: false,
      cause: "revoked",
      reason: "permission revoked",
    });
  const deps = {
    ...f,
    chainEnforcement: { authorize },
    readBlobBytes: async () => f.bytes,
  };
  const response = await pdppBlobsRoutes(deps).request(`/${f.meta.blobId}`, {
    headers,
  });
  expect(response.status).toBe(200);
  const reader = response.body!.getReader();
  expect((await reader.read()).value!.length).toBe(BLOB_DELIVERY_CHUNK_BYTES);
  vi.setSystemTime(NOW + 31_000);
  await expect(reader.read()).rejects.toMatchObject({ code: "grant_revoked" });
  expect(authorize).toHaveBeenCalledTimes(2);
});
it("F2: known chain expiry refuses the next blob chunk inside 30 seconds", async () => {
  const f = fixture();
  const authorize = vi.fn(async () => ({
    ok: true as const,
    expiresAt: new Date(NOW + 5_000).toISOString(),
  }));
  const deps = {
    ...f,
    chainEnforcement: { authorize },
    readBlobBytes: async () => f.bytes,
  };
  const response = await pdppBlobsRoutes(deps).request(`/${f.meta.blobId}`, {
    headers,
  });
  const reader = response.body!.getReader();
  await reader.read();
  vi.setSystemTime(NOW + 6_000);
  await expect(reader.read()).rejects.toMatchObject({ code: "grant_expired" });
  expect(authorize).toHaveBeenCalledTimes(1);
});

it("F2: the mounted application forwards one deployment chain authority to records and blobs", async () => {
  const { createApp } = await import("../app.js");
  const f = fixture();
  const authorize = vi.fn(async () => ({
    ok: false as const,
    retryable: false as const,
    cause: "revoked" as const,
    reason: "permission revoked",
  }));
  const app = createApp({
    version: "test",
    startedAt: new Date(NOW),
    serverOrigin: "http://ps",
    serverOwner: "0x1111111111111111111111111111111111111111",
    gateway: {},
    logger: { info() {}, error() {}, warn() {}, debug() {} },
    accessLogWriter: { write: async () => undefined },
    hierarchyOptions: {},
    indexManager: {},
    pdpp: {
      ...f,
      chainEnforcement: { authorize },
      resource: "http://ps",
      configuredMethods: new Map(),
      bindingStore: {
        getInstanceBinding: () => ({ sourceId: "src", deletedAt: null }),
      },
      readBlobBytes: async () => f.bytes,
    },
  } as never);
  for (const path of [
    "/v1/streams/media/records/private-record",
    `/v1/blobs/${f.meta.blobId}`,
  ]) {
    const response = await app.request(path, { headers });
    expect(response.status, `configured authority omitted at ${path}`).toBe(
      403,
    );
  }
  expect(authorize).toHaveBeenCalledTimes(2);
});
