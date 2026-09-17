/**
 * Blob reads must not be authorized by a field NAME alone.
 *
 * Regression for C2 from the combined server review. The client-token branch
 * of `authorizeBlobAccess` checked only whether ANY granted stream's resolved
 * scope contained a field called `blob_ref`. It never consulted
 * `instance_ids`, `resources`, or `time_constraint`, and never looked at which
 * record actually references the blob. The route's own comment deferred to
 * "a prior authorized record read in the same session", but the route is
 * stateless, so nothing verified that.
 *
 * Effect: any client whose grant happened to include a `blob_ref` field could
 * fetch ANY blob_id on the server — outside its instances, outside its
 * resources, outside its time window. Blob-ID secrecy was the only control.
 *
 * The RS lane's own `pdpp-blobs.test.ts` has four tests, all owner-token or
 * no-token, so the broken case had no coverage at all.
 *
 * `PdppBlobMeta` carries no back-reference to a record (`blobId`, `mimeType`,
 * `sizeBytes`, `sha256`), so authorizing a client token properly needs a
 * blob -> (instance, stream, record_key) reverse index — a record-store schema
 * change that belongs to the RS lane. Until that exists, client tokens are
 * refused outright. Owner reads are unaffected.
 */

import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";

const BLOB_ID = "blob_private";
const GRANTED_INSTANCE = "inst_granted";

const declarations = createStreamDeclarationRegistry([
  {
    name: "s",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

/**
 * A grant that names `blob_ref` among its fields — the only thing the old
 * check looked at — but is scoped to a DIFFERENT instance and a DIFFERENT
 * record than the blob below.
 */
const CROSS_GRANT = {
  version: "0.1.0",
  grant_id: "g1",
  issued_at: "2026-01-01T00:00:00.000Z",
  subject: { id: "sub" },
  client: { client_id: "c1" },
  source: { kind: "connector" as const, id: "src" },
  source_declaration: { version: "v1" },
  purpose_code: "p",
  access_mode: "continuous" as const,
  streams: [
    {
      name: "s",
      instance_ids: ["inst_other"],
      fields: ["id", "blob_ref"],
      resources: ["some_other_record"],
    },
  ],
};

function auth(kind: "client" | "owner"): PdppAuthorizationService {
  return {
    async resolveToken() {
      return kind === "client"
        ? {
            active: true,
            tokenKind: "client" as const,
            subjectId: "sub",
            grant: CROSS_GRANT as never,
            clientId: "c1",
          }
        : { active: true, tokenKind: "owner" as const, subjectId: "sub" };
    },
  };
}

function app(kind: "client" | "owner") {
  const store = createMemoryRecordStore();
  store.putBlobMeta({
    blobId: BLOB_ID,
    mimeType: "text/plain",
    sizeBytes: 3,
    sha256: "abc",
  });

  const a = new Hono();
  a.route(
    "/v1/blobs",
    pdppBlobsRoutes({
      store,
      auth: auth(kind),
      declarations,
      instancesForSubject: () => [GRANTED_INSTANCE],
      readBlobBytes: async () => new Uint8Array([1, 2, 3]),
    }),
  );
  return a;
}

const AUTH = { Authorization: "Bearer t" };

describe("blob reads are not authorized by a field name alone", () => {
  it("refuses a client token whose grant does not cover the referencing record", async () => {
    const res = await app("client").request(`/v1/blobs/${BLOB_ID}`, {
      headers: AUTH,
    });

    // Previously 200 with the bytes served, because the grant merely named a
    // field called `blob_ref`. Must not disclose the blob's existence either,
    // so 404 rather than 403.
    expect(res.status).toBe(404);
    expect(res.headers.get("Content-Length")).not.toBe("3");
  });

  it("refuses a client-token HEAD for the same reason", async () => {
    // HEAD leaks size and mime type through headers alone, so it needs the
    // same gate — Hono dispatches HEAD via the GET handler.
    const res = await app("client").request(`/v1/blobs/${BLOB_ID}`, {
      method: "HEAD",
      headers: AUTH,
    });
    expect(res.status).toBe(404);
  });

  it("still serves an owner-token read", async () => {
    // The owner carries no grant and reads their own store; narrowing the
    // client path must not touch this.
    const res = await app("owner").request(`/v1/blobs/${BLOB_ID}`, {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Length")).toBe("3");
  });
});
