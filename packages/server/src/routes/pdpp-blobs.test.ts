import { describe, it, expect } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

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
});
