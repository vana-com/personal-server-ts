import { describe, it, expect } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
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

describe("pdpp blobs route", () => {
  it("returns 404 blob_not_found for an unknown blob_id", async () => {
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    });
    const res = await app.request("/blob_1", {
      method: "HEAD",
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("10");
  });

  it("rejects an owner token when the blob belongs to an instance outside instancesForSubject", async () => {
    const store = createMemoryRecordStore();
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

  it("returns 401 without a token", async () => {
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
    const store = createMemoryRecordStore();
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
      readBlobBytes: async () => payload,
    });
    const res = await app.request("/blob_1", {
      headers: { Authorization: "Bearer owner-tok" },
    });
    expect(res.status).toBe(200);
    const returned = new Uint8Array(await res.arrayBuffer());
    expect(Array.from(returned)).toEqual(Array.from(payload));
  });

  it("fails closed when the reader's byte count does not match declared sizeBytes, rather than misrepresenting Content-Length", async () => {
    const store = createMemoryRecordStore();
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
