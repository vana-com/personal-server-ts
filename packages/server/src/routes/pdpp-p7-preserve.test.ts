import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createSourceStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import { pdppRecordsRoutes } from "./pdpp-records.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";

const SRC = "https://test.invalid/connector";
const T1 = "2026-09-10T06:30:00.000Z";
const QUERY = "?method=m1&binding_generation=1";

const stream = (name: string, semantics: "append_only" | "mutable_state") => ({
  name,
  semantics,
  primaryKey: ["id"],
  cursorField: "emitted_at",
  requiredFields: ["id"],
});
const declarations = createSourceStreamDeclarationRegistry([
  {
    sourceId: SRC,
    instance: "inst_1",
    streams: [
      stream("playlists", "mutable_state"),
      stream("messages", "append_only"),
    ],
  },
]);
const grant: Grant = {
  version: "0.1.0",
  grant_id: "grant_1",
  issued_at: "2026-01-01T00:00:00Z",
  subject: { id: "sub_1" },
  client: { client_id: "client_1" },
  source: { kind: "provider_native", id: "src_1" },
  source_declaration: { version: "1" },
  purpose_code: "test",
  access_mode: "continuous",
  streams: [{ name: "playlists", instance_ids: ["inst_1"], fields: ["id"] }],
};
const tokens: Record<string, PdppTokenContext> = {
  owner: {
    active: true,
    tokenKind: "owner",
    subjectId: "sub_1",
    instanceIds: ["inst_1"],
  },
  client: { active: true, tokenKind: "client", subjectId: "sub_1", grant },
};

describe("POST /streams/:stream/records/replace completion_policy", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let app: ReturnType<typeof pdppRecordsRoutes>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "inst_1",
      sourceId: SRC,
      method: "m1",
      label: "Test",
    });
    app = pdppRecordsRoutes({
      store,
      bindingStore: store,
      configuredMethods: new Map([["inst_1", ["m1"]]]),
      auth: createFixtureAuthorizationService(tokens),
      declarations,
      ownerSubjectId: "sub_1",
      instancesForSubject: () => ["inst_1"],
    });
  });
  afterEach(() => store.close());

  const record = (id: string, v = 1) => ({
    key: id,
    data: { id, v },
    emitted_at: "2026-09-01T00:00:00Z",
  });
  const replace = (
    body: Record<string, unknown>,
    token = "owner",
    name = "playlists",
  ) =>
    app.request(`/streams/${name}/records/replace${QUERY}`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        instance: "inst_1",
        emitted_at: "2026-09-02T00:00:00Z",
        records: [record("a"), record("b")],
        ...body,
      }),
    });
  const state = () => ({
    receipts: db.prepare("SELECT * FROM pdpp_stream_completion").all(),
    records: db.prepare("SELECT * FROM pdpp_records ORDER BY record_key").all(),
    changes: db.prepare("SELECT * FROM pdpp_record_changes ORDER BY id").all(),
    clock: db.prepare("SELECT * FROM pdpp_write_clock").all(),
  });

  it("clears the receipt of an unchanged replay when the policy is absent", async () => {
    expect((await replace({ source_collected_at: T1 })).status).toBe(200);
    expect(state().receipts).toHaveLength(1);
    expect((await replace({})).status).toBe(200);
    expect(state().receipts).toEqual([]);
  });

  it("keeps the receipt byte for byte when the policy is set and nothing changed", async () => {
    await replace({ source_collected_at: "2026-09-10T08:30:00+02:00" });
    db.prepare("UPDATE pdpp_write_clock SET value = value + 7").run();
    const stored = state().receipts;
    const before = state();

    const response = await replace({
      completion_policy: "preserve_if_unchanged",
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      accepted: 0,
      unchanged: 2,
      deleted: 0,
    });
    expect(state().receipts).toEqual(stored);
    expect(state()).toEqual(before);
  });

  it.each([
    ["an added key", [record("a"), record("b"), record("c")]],
    ["a deleted key", [record("a")]],
    ["a changed value", [record("a"), record("b", 2)]],
  ])("drops the receipt for %s", async (_name, records) => {
    await replace({ source_collected_at: T1 });
    const response = await replace({
      completion_policy: "preserve_if_unchanged",
      records,
    });
    expect(response.status).toBe(200);
    expect(state().receipts).toEqual([]);
  });

  it("creates no receipt when there was none", async () => {
    await replace({});
    await replace({ completion_policy: "preserve_if_unchanged" });
    expect(state().receipts).toEqual([]);
  });

  it.each([
    [
      "a policy with source_collected_at",
      { completion_policy: "preserve_if_unchanged", source_collected_at: T1 },
    ],
    ["an unknown policy", { completion_policy: "keep" }],
    ["a numeric policy", { completion_policy: 1 }],
    ["a null policy", { completion_policy: null }],
    ["a boolean policy", { completion_policy: true }],
    [
      "an object policy",
      { completion_policy: { policy: "preserve_if_unchanged" } },
    ],
  ])("refuses %s with 400 and no write", async (_name, body) => {
    await replace({ source_collected_at: T1 });
    const before = state();
    const response = await replace(body);
    expect(response.status).toBe(400);
    expect(state()).toEqual(before);
  });

  it("still refuses an append_only stream, with or without the policy", async () => {
    for (const body of [{}, { completion_policy: "preserve_if_unchanged" }]) {
      const response = await replace(body, "owner", "messages");
      expect(response.status).toBe(400);
    }
    expect(state().records).toEqual([]);
  });

  it("keeps owner authority: a client token cannot use the policy", async () => {
    await replace({ source_collected_at: T1 });
    const before = state();
    const response = await replace(
      { completion_policy: "preserve_if_unchanged" },
      "client",
    );
    expect(response.status).toBe(401);
    expect(state()).toEqual(before);
  });
});
