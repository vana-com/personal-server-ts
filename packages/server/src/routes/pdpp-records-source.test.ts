/** `source=` narrows an owner read on the Node route; it never widens one. */
import { describe, expect, it } from "vitest";
import type { RecordQuery } from "@opendatalabs/personal-server-ts-core/localdb";
import type { PdppTokenContext } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const SOURCE_A = "https://example.test/connectors/a";
const SOURCE_B = "https://example.test/connectors/b";
const listed: string[] = [];
const recordQuery = {
  async listRecords(input: { connectionId: string }) {
    listed.push(input.connectionId);
    return { records: [], nextCursor: null };
  },
} as unknown as RecordQuery;

function app(token: Partial<PdppTokenContext>) {
  listed.length = 0;
  return pdppRecordsRoutes({
    store: createMemoryRecordStore(),
    auth: createFixtureAuthorizationService({
      owner: { active: true, tokenKind: "owner", subjectId: "sub_1", ...token },
      client: {
        active: true,
        tokenKind: "client",
        subjectId: "sub_1",
      },
    }),
    declarations: createStreamDeclarationRegistry([
      {
        name: "items",
        semantics: "mutable_state",
        primaryKey: ["id"],
        cursorField: "id",
        requiredFields: ["id"],
      },
    ]),
    ownerSubjectId: "sub_1",
    accountStorageMode: { owner: "sub_1", read: () => "switched" },
    recordQuery,
    instancesForSubject: () => ["a1", "b1"],
    instancesForSource: (_subject, sourceId) =>
      sourceId === SOURCE_A ? ["a1"] : sourceId === SOURCE_B ? ["b1"] : [],
    sourceIdForConnector: (connector) =>
      ({ a: SOURCE_A, b: SOURCE_B })[connector],
  });
}

const get = (a: ReturnType<typeof app>, query: string, token = "owner") =>
  a.request(`/streams/items/records${query}`, {
    headers: { Authorization: `Bearer ${token}` },
  });

describe("source on GET /streams/:stream/records", () => {
  it("refuses a source that contradicts a source-scoped token", async () => {
    const a = app({ sourceId: SOURCE_A });
    const res = await get(a, "?source=b");
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("grant_stream_not_allowed");
    expect(listed).toEqual([]);
  });

  it("serves a source-scoped token, with or without the matching source", async () => {
    for (const query of ["", "?source=a", `?source=${SOURCE_A}`]) {
      const a = app({ sourceId: SOURCE_A });
      expect((await get(a, query)).status).toBe(200);
      expect(listed).toEqual(["a1"]);
    }
  });

  it("resolves an unscoped token through the named source only", async () => {
    const a = app({});
    expect((await get(a, "?source=b")).status).toBe(200);
    expect(listed).toEqual(["b1"]);
  });

  it("refuses an unscoped token that names no source, as before", async () => {
    const res = await get(app({}), "");
    expect(res.status).toBe(403);
    expect((await res.json()).error.code).toBe("grant_stream_not_allowed");
  });

  it("keeps an instance-scoped token inside its source", async () => {
    const a = app({ instanceIds: ["a1", "b1"] });
    expect((await get(a, "?source=a")).status).toBe(200);
    expect(listed).toEqual(["a1"]);
  });

  it("refuses a source on a client read", async () => {
    const res = await get(app({}), "?source=a", "client");
    expect(res.status).toBe(400);
  });
});
