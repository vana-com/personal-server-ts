/**
 * A malformed cursor is a client error, not a server fault.
 *
 * Two distinct error classes flow out of the cursor path and both mean "this
 * cursor is not usable":
 *
 *   - `InvalidCursorError` (`storage/pdpp-records/types.ts`) — the token
 *     decoded fine but was reused against a different `order`, or is the wrong
 *     cursor kind. This was already mapped to 400 `invalid_cursor`.
 *   - `InvalidCursorSyntaxError` (`storage/pdpp-records/cursor.ts`) — the
 *     token is not base64url JSON at all. This was NOT mapped, so it escaped
 *     `toPdppError` as an unhandled throw: Hono returned a bare
 *     `500 Internal Server Error` with no PDPP error body.
 *
 * The 500 is the part that matters. Spec-core.md §8 requires the unified error
 * shape on every endpoint, and a 500 tells a client to retry a request that
 * can never succeed, while making a bad request look like a server fault to
 * anyone reading logs or alerting on 5xx rates.
 *
 * Confirmed by the conformance suite against a grant-bound token.
 */

import { describe, it, expect } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const INSTANCE = "i1";
const AUTH = { Authorization: "Bearer t" };

const declarations = createStreamDeclarationRegistry([
  {
    name: "s",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

/** A grant-bound client token — the case the suite reported. */
const GRANT = {
  version: "0.1.0",
  grant_id: "g1",
  issued_at: "2026-01-01T00:00:00.000Z",
  subject: { id: "sub" },
  client: { client_id: "c1" },
  source: { kind: "connector" as const, id: "src" },
  source_declaration: { version: "v1" },
  purpose_code: "p",
  access_mode: "continuous" as const,
  streams: [{ name: "s", instance_ids: [INSTANCE], fields: ["id", "name"] }],
};

const clientAuth: PdppAuthorizationService = {
  async resolveToken() {
    return {
      active: true,
      tokenKind: "client" as const,
      subjectId: "sub",
      grant: GRANT as never,
      clientId: "c1",
    };
  },
};

function fixture() {
  const store = createMemoryRecordStore();
  store.ingestBatch(
    [
      {
        instance: INSTANCE,
        stream: "s",
        key: "r1",
        data: { id: "r1", name: "n1" },
        emitted_at: "2026-05-01T00:00:00.000Z",
      },
      {
        instance: INSTANCE,
        stream: "s",
        key: "r2",
        data: { id: "r2", name: "n2" },
        emitted_at: "2026-05-02T00:00:00.000Z",
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
      auth: clientAuth,
      declarations,
      instancesForSubject: () => [INSTANCE],
    }),
  );
  return { app: a, store };
}

function mintedListCursor(order: "asc" | "desc") {
  const context = fixture();
  const page = context.store.listRecords("s", {
    instanceIds: [INSTANCE],
    limit: 1,
    order,
  });
  expect(page.nextCursor).toBeDefined();
  return { ...context, cursor: page.nextCursor! };
}

async function expectInvalidCursor(res: Response) {
  expect(res.status).toBe(400);
  const body = await res.json();
  expect(body.error.code).toBe("invalid_cursor");
  // The unified error shape, not a bare framework 500 body.
  expect(body.error.request_id).toBeTruthy();
}

describe("a malformed cursor is 400 invalid_cursor, never 500", () => {
  it("rejects a cursor that is not base64url at all", async () => {
    const res = await fixture().app.request(
      "/v1/streams/s/records?cursor=!!!nope!!!",
      {
        headers: AUTH,
      },
    );
    await expectInvalidCursor(res);
  });

  it("rejects base64url that does not decode to JSON", async () => {
    const res = await fixture().app.request(
      "/v1/streams/s/records?cursor=bm90LWpzb24",
      {
        headers: AUTH,
      },
    );
    await expectInvalidCursor(res);
  });

  it("rejects well-formed JSON that is not a cursor payload", async () => {
    // `{"hello":"world"}` — decodes, parses, but has no recognized `kind`.
    const cursor = btoa('{"hello":"world"}')
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    const res = await fixture().app.request(
      `/v1/streams/s/records?cursor=${cursor}`,
      {
        headers: AUTH,
      },
    );
    await expectInvalidCursor(res);
  });

  it("rejects an empty cursor value", async () => {
    const res = await fixture().app.request("/v1/streams/s/records?cursor=", {
      headers: AUTH,
    });
    // An empty cursor is absent, not malformed — it must not 500 either way.
    expect(res.status).not.toBe(500);
  });

  it("still rejects a valid cursor reused against a different order", async () => {
    // The already-mapped class, kept as a control so this fix cannot regress
    // wrong-order handling. The cursor must be minted by the store so it has
    // the current stream + epoch binding.
    const { app, cursor } = mintedListCursor("asc");
    const res = await app.request(
      `/v1/streams/s/records?order=desc&cursor=${encodeURIComponent(cursor)}`,
      { headers: AUTH },
    );
    await expectInvalidCursor(res);
  });

  it("still serves a valid cursor", async () => {
    // Positive control: the narrowing above must not reject store-minted
    // stream + epoch bound cursors.
    const { app, cursor } = mintedListCursor("desc");
    const res = await app.request(
      `/v1/streams/s/records?order=desc&cursor=${encodeURIComponent(cursor)}`,
      { headers: AUTH },
    );
    expect(res.status).toBe(200);
  });
});
