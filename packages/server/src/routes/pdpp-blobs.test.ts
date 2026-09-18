import { describe, it, expect, afterEach, vi } from "vitest";
import Database from "better-sqlite3";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type { Grant } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

function clientGrant(overrides: Partial<Grant["streams"][number]> = {}): Grant {
  return {
    version: "0.1.0",
    grant_id: "grant_1",
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "sub_1" },
    client: { client_id: "client_1" },
    source: { kind: "provider_native", id: "src_1" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "media",
        instance_ids: ["inst_1"],
        fields: ["id", "blob_ref"],
        ...overrides,
      },
    ],
  };
}

const declarations = createStreamDeclarationRegistry([
  {
    name: "media",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

const backends: Array<{
  name: string;
  createStore: () => PdppRecordStore;
}> = [
  { name: "memory", createStore: () => createMemoryRecordStore() },
  {
    name: "sqlite",
    createStore: () => createSqliteRecordStore(new Database(":memory:")),
  },
];

describe.each(backends)("pdpp blobs route ($name store)", ({ createStore }) => {
  let stores: PdppRecordStore[] = [];
  function newStore(): PdppRecordStore {
    const s = createStore();
    stores.push(s);
    return s;
  }

  afterEach(() => {
    for (const s of stores) s.close();
    stores = [];
  });

  it("returns 404 blob_not_found for an unknown blob_id", async () => {
    const store = newStore();
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
    });
    const res = await app.request("/blob_unknown", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("serves Content-Type/Content-Length/Cache-Control for an owner-authorized blob", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    // A blob_id alone is never sufficient (spec §8) -- even for an owner
    // token, the blob must be referenced by an actual record.
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async () => new Uint8Array(10),
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toBe("image/jpeg");
    expect(res.headers.get("Content-Length")).toBe("10");
    expect(res.headers.get("Cache-Control")).toBe("private, no-store");
  });

  it("supports HEAD for size checks", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
    });
    const res = await app.request("/blob_1", {
      method: "HEAD",
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("10");
  });

  it("rejects an owner token when the blob belongs to an instance outside instancesForSubject", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_other",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"], // does not include inst_other
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("denies an owner token when instancesForSubject is not wired up (fail closed, not fail open)", async () => {
    // No instancesForSubject resolver at all -- an owner token must not be
    // treated as "sees everything" just because ownership couldn't be
    // checked. Absence of the resolver must deny, not bypass.
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const readBlobBytes = vi.fn(async () => new Uint8Array(10));
    const app = pdppBlobsRoutes({
      readBlobBytes,
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      // instancesForSubject intentionally omitted.
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(404);
    expect(readBlobBytes).not.toHaveBeenCalled();
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("denies an owner token when instancesForSubject resolves an empty list", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const readBlobBytes = vi.fn(async () => new Uint8Array(10));
    const app = pdppBlobsRoutes({
      readBlobBytes,
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => [],
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(404);
    expect(readBlobBytes).not.toHaveBeenCalled();
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("denies an owner token with no subjectId, even with instancesForSubject wired up", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const readBlobBytes = vi.fn(async () => new Uint8Array(10));
    const app = pdppBlobsRoutes({
      readBlobBytes,
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner" }, // no subjectId
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(404);
    expect(readBlobBytes).not.toHaveBeenCalled();
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("returns 401 without a token", async () => {
    const store = newStore();
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({}),
      declarations,
    });
    const res = await app.request("/blob_1");
    expect(res.status).toBe(401);
  });

  it("serves a blob to a client token whose grant covers the referencing record", async () => {
    // Correctly-scoped case, spec §8 "Get a blob": the grant includes the
    // stream, the referencing record's instance and resources are within
    // scope, and blob_ref is in the granted fields.
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_ok",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_ok" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      }),
      declarations,
      readBlobBytes: async () => new Uint8Array(3),
    });
    const res = await app.request("/blob_ok", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("3");
  });

  it("denies a client token whose grant does not cover the record referencing the blob (C2 regression)", async () => {
    // The exact defect this fix closes: a grant scoped to a DIFFERENT
    // instance and a DIFFERENT resources allowlist, naming no record that
    // references this blob, must not be able to fetch it merely because
    // some stream's field list happens to include "blob_ref".
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_private",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_private",
          stream: "media",
          key: "media_private",
          data: { id: "media_private", blob_ref: { blob_id: "blob_private" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant({
            instance_ids: ["inst_other"],
            resources: ["some_other_record"],
          }),
        },
      }),
      declarations,
      readBlobBytes: async () => new Uint8Array(3),
    });
    const res = await app.request("/blob_private", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("denies a client token when blob_ref is not in the grant's authorized fields for the referencing stream", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant({ fields: ["id"] }), // blob_ref not granted
        },
      }),
      declarations,
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(404);
  });

  it("fails closed with a structured api_error when no readBlobBytes is wired up, instead of a fabricated 200", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      // readBlobBytes intentionally omitted.
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.code).toBe("api_error");
    expect(body.error.request_id).toBeTruthy();
  });

  it("fails closed with a structured api_error when the reader resolves undefined (bytes missing), instead of a 200 with an empty body", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async () => undefined,
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.code).toBe("api_error");
    expect(body.error.type).toBe("api_error");
  });

  it("fails closed with a structured api_error, not a leaked exception, when the reader throws", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async () => {
        throw new Error(
          "disk read failed: /var/blobs/blob_1 permission denied",
        );
      },
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.code).toBe("api_error");
    expect(body.error.type).toBe("api_error");
    expect(JSON.stringify(body)).not.toContain("disk read failed");
    expect(JSON.stringify(body)).not.toContain("/var/blobs");
  });

  it("returns a genuine zero-byte blob as a 200, distinct from absent bytes", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "application/octet-stream",
      sizeBytes: 0,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async () => new Uint8Array(0),
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const returned = new Uint8Array(await res.arrayBuffer());
    expect(returned.byteLength).toBe(0);
  });

  it("returns the exact stored bytes for a valid binary blob, byte-for-byte", async () => {
    const store = newStore();
    const payload = new Uint8Array([0, 1, 2, 255, 254, 3, 3, 3]);
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "application/octet-stream",
      sizeBytes: payload.byteLength,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async () => payload,
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const returned = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(returned)).toEqual(Array.from(payload));
  });

  it("serves a blob when the FIRST reference is inaccessible but a SECOND reference to the same bytes is granted (any-visible-reference regression)", async () => {
    // Identical blob bytes can legitimately be referenced by multiple
    // records/instances. If the store only surfaced one reference (e.g. an
    // unordered LIMIT 1 query), an inaccessible first record could hide an
    // accessible second one and cause a false denial.
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_shared",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_private",
          stream: "media",
          key: "media_private",
          data: { id: "media_private", blob_ref: { blob_id: "blob_shared" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_shared" } },
          emitted_at: "2026-04-01T00:00:01.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          // Grant covers only inst_1/media_1 -- not inst_private/media_private.
          grant: clientGrant(),
        },
      }),
      declarations,
      readBlobBytes: async () => new Uint8Array(3),
    });
    const res = await app.request("/blob_shared", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("3");
  });

  it("serves a blob to an owner token when the FIRST reference is on an unowned instance but a SECOND reference is on an owned one (owner any-visible-reference regression)", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_shared_owner",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_other",
          stream: "media",
          key: "media_other",
          data: {
            id: "media_other",
            blob_ref: { blob_id: "blob_shared_owner" },
          },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_shared_owner" } },
          emitted_at: "2026-04-01T00:00:01.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"], // does not include inst_other
      readBlobBytes: async () => new Uint8Array(3),
    });
    const res = await app.request("/blob_shared_owner", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("3");
  });

  it("denies a blob when NO visible reference passes authorization, even with multiple references (companion to the any-visible-reference regression)", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_shared_private",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_private_a",
          stream: "media",
          key: "media_a",
          data: {
            id: "media_a",
            blob_ref: { blob_id: "blob_shared_private" },
          },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_private_b",
          stream: "media",
          key: "media_b",
          data: {
            id: "media_b",
            blob_ref: { blob_id: "blob_shared_private" },
          },
          emitted_at: "2026-04-01T00:00:01.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          // Grant covers neither inst_private_a nor inst_private_b.
          grant: clientGrant(),
        },
      }),
      declarations,
      readBlobBytes: async () => new Uint8Array(3),
    });
    const res = await app.request("/blob_shared_private", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("denies a blob whose only visible reference has been deleted, even when an unauthorized instance's reference still exists", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_deleted_ref",
      mimeType: "image/jpeg",
      sizeBytes: 3,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_deleted_ref" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
        {
          instance: "inst_other",
          stream: "media",
          key: "media_other",
          data: {
            id: "media_other",
            blob_ref: { blob_id: "blob_deleted_ref" },
          },
          emitted_at: "2026-04-01T00:00:01.000Z",
        },
      ],
      () => "mutable_state",
      () => ["id"],
    );
    store.deleteRecord(
      "inst_1",
      "media",
      "media_1",
      "2026-04-02T00:00:00.000Z",
      "mutable_state",
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "client-tok": {
          active: true,
          tokenKind: "client",
          subjectId: "sub_1",
          grant: clientGrant(),
        },
      }),
      declarations,
      readBlobBytes: async () => new Uint8Array(3),
    });
    const res = await app.request("/blob_deleted_ref", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error.code).toBe("blob_not_found");
  });

  it("fails closed when the reader's byte count does not match declared sizeBytes, rather than misrepresenting Content-Length", async () => {
    const store = newStore();
    store.putBlobMeta({
      blobId: "blob_1",
      mimeType: "image/jpeg",
      sizeBytes: 10,
      sha256: "abc",
    });
    store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "media",
          key: "media_1",
          data: { id: "media_1", blob_ref: { blob_id: "blob_1" } },
          emitted_at: "2026-04-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
    );
    const app = pdppBlobsRoutes({
      store,
      auth: createFixtureAuthorizationService({
        "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
      }),
      declarations,
      instancesForSubject: () => ["inst_1"],
      readBlobBytes: async () => new Uint8Array(3), // does not match sizeBytes: 10
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error.code).toBe("api_error");
  });
});

/**
 * End-to-end proof that real ingestion (`store.storeBlobBytes`, the same
 * atomic write GET wires against via `store.getBlobBytes`) actually reaches
 * an authorized HTTP GET with exact bytes and headers -- not a stubbed
 * `readBlobBytes` standing in for storage that doesn't exist. Wires
 * `readBlobBytes` to `store.getBlobBytes` exactly the way `records-bootstrap.ts`
 * wires real boot.
 */
describe.each(backends)(
  "pdpp blobs route: real ingest-to-GET ($name store)",
  ({ createStore }) => {
    let stores: PdppRecordStore[] = [];
    function newStore(): PdppRecordStore {
      const s = createStore();
      stores.push(s);
      return s;
    }
    afterEach(() => {
      for (const s of stores) s.close();
      stores = [];
    });

    function appFor(
      store: PdppRecordStore,
      overrides: Partial<{
        instancesForSubject: (subjectId: string) => string[];
      }> = {},
    ) {
      return pdppBlobsRoutes({
        store,
        auth: createFixtureAuthorizationService({
          "owner-tok": { active: true, tokenKind: "owner", subjectId: "sub_1" },
        }),
        declarations,
        instancesForSubject:
          overrides.instancesForSubject ?? (() => ["inst_1"]),
        readBlobBytes: async (blobId) => store.getBlobBytes(blobId),
      });
    }

    it("serves the exact stored bytes and headers for a real ingested blob", async () => {
      const store = newStore();
      const payload = new Uint8Array([5, 4, 3, 2, 1, 0, 255]);
      const meta = store.storeBlobBytes(payload, "application/octet-stream");
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: meta.blobId } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      const app = appFor(store);
      const res = await app.request(`/${meta.blobId}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toBe("application/octet-stream");
      expect(res.headers.get("Content-Length")).toBe(
        String(payload.byteLength),
      );
      const returned = new Uint8Array(await res.arrayBuffer());
      expect(Array.from(returned)).toEqual(Array.from(payload));
    });

    it("denies GET for an unauthorized grant even though the blob bytes are genuinely stored", async () => {
      const store = newStore();
      const payload = new Uint8Array([1, 2, 3]);
      const meta = store.storeBlobBytes(payload, "image/jpeg");
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: meta.blobId } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      // Owner-scoped instances resolver excludes inst_1 -- an authenticated
      // but unauthorized-for-this-blob caller.
      const app = appFor(store, { instancesForSubject: () => ["inst_other"] });
      const res = await app.request(`/${meta.blobId}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error.code).toBe("blob_not_found");
    });

    it("denies GET once the only referencing record has been removed, even though the bytes are still stored", async () => {
      const store = newStore();
      const payload = new Uint8Array([1, 2, 3]);
      const meta = store.storeBlobBytes(payload, "image/jpeg");
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: meta.blobId } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
      );
      store.deleteRecord(
        "inst_1",
        "media",
        "media_1",
        "2026-04-02T00:00:00.000Z",
        "mutable_state",
      );
      const app = appFor(store);
      const res = await app.request(`/${meta.blobId}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(404);
      const body = await res.json();
      expect(body.error.code).toBe("blob_not_found");
    });

    it("fails closed on a real GET when the blob has metadata but was never given bytes (metadata-only row)", async () => {
      const store = newStore();
      store.putBlobMeta({
        blobId: "blob_metadata_only",
        mimeType: "image/jpeg",
        sizeBytes: 3,
        sha256: "abc",
      });
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: {
              id: "media_1",
              blob_ref: { blob_id: "blob_metadata_only" },
            },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      const app = appFor(store);
      const res = await app.request("/blob_metadata_only", {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error.code).toBe("api_error");
    });

    it("fails closed on a real GET when the stored bytes have been corrupted relative to their metadata", async () => {
      const store = newStore();
      const payload = new Uint8Array([1, 2, 3]);
      const meta = store.storeBlobBytes(payload, "image/jpeg");
      // Simulate corruption discovered at read time: metadata now disagrees
      // with the bytes actually on disk.
      store.putBlobMeta({ ...meta, sha256: "0".repeat(64) });
      store.ingestBatch(
        [
          {
            instance: "inst_1",
            stream: "media",
            key: "media_1",
            data: { id: "media_1", blob_ref: { blob_id: meta.blobId } },
            emitted_at: "2026-04-01T00:00:00.000Z",
          },
        ],
        () => "append_only",
        () => ["id"],
      );
      const app = appFor(store);
      const res = await app.request(`/${meta.blobId}`, {
        headers: { Authorization: "Bearer owner-tok" },
      });
      expect(res.status).toBe(500);
      const body = await res.json();
      expect(body.error.code).toBe("api_error");
    });
  },
);
