/**
 * Three §8 wire-contract gaps found by an independent normative review.
 *
 * All three were invisible to the existing fixtures because those assert
 * ACCESS behavior — who may read what — while these are about the shape and
 * honesty of the response itself.
 *
 *  1. Stream metadata omitted `schema` and `selection` (§8 :1188-1201 owner,
 *     :1224-1244 client). A public response contract mismatch.
 *  2. A client's `fields` was parsed and then discarded, so `?fields=id`
 *     returned every granted field (§8 :1285, :1290, :1292 — an unsupported
 *     shape must not be silently ignored). The response did something other
 *     than what was asked, with a 200.
 *  3. Single-record reads never rejected client `expand[]` (§8 :1352-1359),
 *     so the declaration was consulted for a request that should have been
 *     refused first.
 */

import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const INSTANCE = "i1";
const AUTH = { Authorization: "Bearer t" };

/** A normative-shaped declaration: real JSON Schema, declared selection. */
const SCHEMA = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  type: "object",
  properties: {
    id: { type: "string" },
    name: { type: "string" },
    secret: { type: "string" },
  },
  required: ["id"],
};

const declarations = createStreamDeclarationRegistry([
  {
    name: "s",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
    schema: SCHEMA,
    selection: { fields: true, resources: false },
  },
]);

/** Grant covers id + name, never `secret`. */
const GRANT = {
  version: "0.1.0",
  grant_id: "grt_1",
  issued_at: "2026-01-01T00:00:00.000Z",
  subject: { id: "sub" },
  client: { client_id: "c1" },
  source: { kind: "connector" as const, id: "src" },
  source_declaration: { version: "v1" },
  purpose_code: "p",
  access_mode: "continuous" as const,
  streams: [{ name: "s", instance_ids: [INSTANCE], fields: ["id", "name"] }],
};

function auth(kind: "client" | "owner"): PdppAuthorizationService {
  return {
    async resolveToken() {
      return kind === "client"
        ? {
            active: true,
            tokenKind: "client" as const,
            subjectId: "sub",
            grant: GRANT as never,
            clientId: "c1",
          }
        : { active: true, tokenKind: "owner" as const, subjectId: "sub" };
    },
  };
}

function app(kind: "client" | "owner") {
  const store = createMemoryRecordStore();
  store.ingestBatch(
    [
      {
        instance: INSTANCE,
        stream: "s",
        key: "r1",
        data: { id: "r1", name: "n1", secret: "LEAK" },
        emitted_at: "2026-05-01T00:00:00.000Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );

  const a = new Hono();
  a.route(
    "/v1",
    pdppRecordsRoutes({
      store,
      auth: auth(kind),
      declarations,
      instancesForSubject: () => [INSTANCE],
    }),
  );
  return a;
}

describe("§8 stream metadata carries schema and selection", () => {
  it("returns the full declared schema and selection to an owner", async () => {
    const res = await app("owner").request("/v1/streams/s", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();

    expect(body.schema).toEqual(SCHEMA);
    expect(body.selection).toEqual({ fields: true, resources: false });
  });

  it("returns a GRANT-CLOSED schema to a client", async () => {
    const res = await app("client").request("/v1/streams/s", { headers: AUTH });
    expect(res.status).toBe(200);
    const body = await res.json();

    // Only granted fields. A client must not learn that `secret` exists.
    expect(Object.keys(body.schema.properties).sort()).toEqual(["id", "name"]);
    expect(body.schema.properties.secret).toBeUndefined();
    // `required` is intersected with the grant, not passed through.
    expect(body.schema.required).toEqual(["id"]);
    // The declared capability is still reported.
    expect(body.selection).toEqual({ fields: true, resources: false });
  });
});

describe("§8 client `fields` narrows within the grant", () => {
  it("honors a sparse fieldset instead of ignoring it", async () => {
    const res = await app("client").request(
      "/v1/streams/s/records?fields=name",
      { headers: AUTH },
    );
    expect(res.status).toBe(200);
    const body = await res.json();

    // `name` plus the schema-required `id` floor — NOT every granted field.
    expect(Object.keys(body.data[0].data).sort()).toEqual(["id", "name"]);
  });

  it("keeps the required floor even when not requested", async () => {
    const res = await app("client").request(
      "/v1/streams/s/records?fields=name",
      {
        headers: AUTH,
      },
    );
    const body = await res.json();
    // §8 keeps schema-required fields in every projection.
    expect(body.data[0].data.id).toBe("r1");
  });

  it("REJECTS a field outside the grant rather than silently dropping it", async () => {
    // A client asking for something it was never granted has made an error it
    // needs to see; quietly returning less would let it believe it received
    // the field.
    const res = await app("client").request(
      "/v1/streams/s/records?fields=secret",
      { headers: AUTH },
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.param).toBe("fields");
  });

  it("never lets a client widen beyond its grant", async () => {
    const res = await app("client").request(
      "/v1/streams/s/records?fields=id,name,secret",
      { headers: AUTH },
    );
    expect(res.status).toBe(400);
  });

  it("still returns the full granted set when no fields are requested", async () => {
    const res = await app("client").request("/v1/streams/s/records", {
      headers: AUTH,
    });
    const body = await res.json();
    expect(Object.keys(body.data[0].data).sort()).toEqual(["id", "name"]);
  });

  it("leaves owner field selection unchanged", async () => {
    const res = await app("owner").request(
      "/v1/streams/s/records?fields=secret",
      { headers: AUTH },
    );
    // An owner reading their own store is not grant-constrained.
    expect(res.status).toBe(200);
  });
});

describe("§8 client-only params are rejected on single-record reads", () => {
  it("rejects client expand[] before consulting the declaration", async () => {
    const res = await app("client").request(
      "/v1/streams/s/records/r1?expand[]=other",
      { headers: AUTH },
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error.code).toBe("invalid_request");
  });

  it("rejects client view on a single-record read", async () => {
    const res = await app("client").request(
      "/v1/streams/s/records/r1?view=basic",
      { headers: AUTH },
    );
    expect(res.status).toBe(400);
  });

  it("still serves a plain single-record client read", async () => {
    const res = await app("client").request("/v1/streams/s/records/r1", {
      headers: AUTH,
    });
    expect(res.status).toBe(200);
  });
});
