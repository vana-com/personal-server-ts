import { createHash } from "node:crypto";
import Database from "better-sqlite3";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from "vitest";
import { createSourceStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  MAX_COMPLETION_BODY_BYTES,
  pdppRecordsRoutes,
  type PdppRecordsRouteDeps,
} from "./pdpp-records.js";
import { createSqliteRecordStore } from "../storage/pdpp-records-sqlite-store.js";

const SRC = "https://test.invalid/connector";
const SRC2 = "https://test.invalid/other";
const T1 = "2026-09-10T06:30:00.000Z";
const T2 = "2026-09-11T06:30:00.000Z";
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
      stream("messages", "append_only"),
      stream("playlists", "mutable_state"),
    ],
  },
  { sourceId: SRC2, streams: [stream("sleep", "mutable_state")] },
]);

const sha = (preimage: string) =>
  createHash("sha256").update(preimage, "utf8").digest("hex");
const EMPTY = sha(`["${SRC}","inst_1","m1",1,"messages",[]]`);

const clientGrant = (): Grant => ({
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
    { name: "playlists", instance_ids: ["inst_1"], fields: ["id", "name"] },
  ],
});

const tokens: Record<string, PdppTokenContext> = {
  "owner-tok": {
    active: true,
    tokenKind: "owner",
    subjectId: "sub_1",
    instanceIds: ["inst_1"],
  },
  "scoped-tok": {
    active: true,
    tokenKind: "owner",
    subjectId: "sub_1",
    sourceId: SRC,
  },
  "other-source-tok": {
    active: true,
    tokenKind: "owner",
    subjectId: "sub_1",
    sourceId: SRC2,
  },
  "other-owner-tok": {
    active: true,
    tokenKind: "owner",
    subjectId: "sub_2",
    instanceIds: ["inst_1"],
  },
  "no-instance-tok": {
    active: true,
    tokenKind: "owner",
    subjectId: "sub_1",
    instanceIds: [],
  },
  "client-tok": {
    active: true,
    tokenKind: "client",
    subjectId: "sub_1",
    grant: clientGrant(),
  },
};

const proof = (
  name: string,
  liveCount: number,
  digest: string,
  coverage = "full_stream",
) => ({
  stream: name,
  coverage,
  live_count: liveCount,
  snapshot_sha256: digest,
});
const wire = (overrides: Record<string, unknown> = {}) => ({
  source_id: SRC,
  instance: "inst_1",
  source_collected_at: T1,
  collection_time_basis: "host_run_finished",
  streams: [proof("messages", 0, EMPTY)],
  ...overrides,
});

describe("POST /records/completions", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let completeStreams: Mock<typeof store.completeStreams>;
  let app: ReturnType<typeof pdppRecordsRoutes>;

  const mount = (overrides: Partial<PdppRecordsRouteDeps> = {}) => {
    completeStreams = vi.fn(store.completeStreams);
    return pdppRecordsRoutes({
      store,
      bindingStore: { ...store, completeStreams },
      configuredMethods: new Map([["inst_1", ["m1"]]]),
      auth: createFixtureAuthorizationService(tokens),
      declarations,
      ownerSubjectId: "sub_1",
      instancesForSubject: () => ["inst_1"],
      instancesForSource: (_subject, source) =>
        source === SRC ? ["inst_1"] : [],
      ...overrides,
    });
  };

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "inst_1",
      sourceId: SRC,
      method: "m1",
      label: "Test",
    });
    app = mount();
  });
  afterEach(() => store.close());

  const post = (
    token: string | undefined,
    body: BodyInit,
    query = QUERY,
    headers: Record<string, string> = {},
  ) =>
    app.request(`/records/completions${query}`, {
      method: "POST",
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        "content-type": "application/json",
        ...headers,
      },
      body,
    });
  const postJson = (token: string | undefined, body: unknown, query = QUERY) =>
    post(token, JSON.stringify(body), query);

  const state = () => ({
    receipts: db
      .prepare("SELECT * FROM pdpp_stream_completion ORDER BY stream")
      .all(),
    records: db.prepare("SELECT * FROM pdpp_records").all(),
    changes: db.prepare("SELECT * FROM pdpp_record_changes").all(),
    arrival: db.prepare("SELECT * FROM pdpp_record_arrival").all(),
    clock: db.prepare("SELECT * FROM pdpp_write_clock").all(),
    binding: db.prepare("SELECT * FROM pdpp_instance_binding").all(),
  });

  function seedMessage() {
    const result = store.ingestBatch(
      [
        {
          instance: "inst_1",
          stream: "messages",
          key: "k1",
          data: { id: "k1", text: "A" },
          emitted_at: "2026-09-01T00:00:00.000Z",
        },
      ],
      () => "append_only",
      () => ["id"],
      { method: "m1", generation: 1 },
    );
    expect(result.rejected).toEqual([]);
  }

  describe("authority", () => {
    it.each([
      ["no token", undefined],
      ["a client (consumer) token", "client-tok"],
      ["an owner token of another subject", "other-owner-tok"],
      ["an owner token covering no instance", "no-instance-tok"],
      ["an owner token scoped to another source", "other-source-tok"],
      ["an unknown token", "nope"],
    ])("refuses %s with 401 and never invokes the store", async (_n, token) => {
      const before = state();
      const response = await postJson(token, wire());
      expect(response.status).toBe(401);
      expect(completeStreams).not.toHaveBeenCalled();
      expect(state()).toEqual(before);
    });

    it.each(["owner-tok", "scoped-tok"])("accepts %s", async (token) => {
      const response = await postJson(token, wire());
      expect(response.status).toBe(200);
      expect(completeStreams).toHaveBeenCalledOnce();
    });

    it("refuses an instance the token does not cover", async () => {
      store.registerConnection({
        instance: "inst_2",
        sourceId: SRC,
        method: "m1",
        label: "Two",
      });
      const before = state();
      const response = await postJson(
        "owner-tok",
        wire({ instance: "inst_2" }),
      );
      expect(response.status).toBe(401);
      expect(completeStreams).not.toHaveBeenCalled();
      expect(state()).toEqual(before);
    });

    it("refuses a body source that is not the instance's source with 409", async () => {
      const before = state();
      const response = await postJson("owner-tok", wire({ source_id: SRC2 }));
      expect(response.status).toBe(409);
      expect((await response.json()).error.code).toBe("source_mismatch");
      expect(completeStreams).not.toHaveBeenCalled();
      expect(state()).toEqual(before);
    });

    it("refuses a scoped token whose source differs from the body", async () => {
      const response = await postJson("scoped-tok", wire({ source_id: SRC2 }));
      expect(response.status).toBe(401);
      expect(completeStreams).not.toHaveBeenCalled();
    });

    it.each([
      [
        "a method that is not configured",
        "?method=other&binding_generation=1",
        409,
      ],
      ["a missing method", "?binding_generation=1", 400],
      ["a missing generation", "?method=m1", 400],
      ["a zero generation", "?method=m1&binding_generation=0", 400],
      ["a non-numeric generation", "?method=m1&binding_generation=x", 400],
      ["a stale generation", "?method=m1&binding_generation=2", 409],
    ])("refuses %s", async (_n, query, status) => {
      const before = state();
      const response = await postJson("owner-tok", wire(), query);
      expect(response.status).toBe(status);
      expect(state()).toEqual(before);
    });

    it("refuses a method configured twice for the instance", async () => {
      app = mount({ configuredMethods: new Map([["inst_1", ["m1", "m2"]]]) });
      const response = await postJson("owner-tok", wire());
      expect(response.status).toBe(409);
      expect(completeStreams).not.toHaveBeenCalled();
    });
  });

  describe("proof", () => {
    it("stores an empty append-only receipt with no row, history, arrival or clock change", async () => {
      const before = state();

      const response = await postJson("owner-tok", wire());

      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        receipts: [
          {
            instance: "inst_1",
            stream: "messages",
            method: "m1",
            generation: 1,
            source_collected_at: T1,
            write_seq: 0,
            live_count: 0,
            snapshot_sha256: EMPTY,
            collection_time_basis: "host_run_finished",
          },
        ],
      });
      const after = state();
      expect(after.receipts).toHaveLength(1);
      expect({ ...after, receipts: [] }).toEqual({ ...before, receipts: [] });
    });

    it("conflicts, with 409 and no change, when an empty proof meets retained history", async () => {
      seedMessage();
      const before = state();
      const response = await postJson("owner-tok", wire());
      expect(response.status).toBe(409);
      expect((await response.json()).error.code).toBe("snapshot_conflict");
      expect(state()).toEqual(before);
    });

    it("conflicts when the count matches but the digest does not", async () => {
      seedMessage();
      const before = state();
      const response = await postJson(
        "owner-tok",
        wire({ streams: [proof("messages", 1, EMPTY)] }),
      );
      expect(response.status).toBe(409);
      expect(state()).toEqual(before);
    });

    it("replays an exact proof without rewriting the receipt, and refuses an older time", async () => {
      expect((await postJson("owner-tok", wire())).status).toBe(200);
      const stored = state();
      // An unrelated write moves the clock; the replay must not rewrite.
      db.prepare("UPDATE pdpp_write_clock SET value = value + 5").run();
      const moved = state();
      db.exec(`
        CREATE TRIGGER no_rewrite BEFORE UPDATE ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'receipt rewritten'); END;
      `);

      const replay = await postJson("owner-tok", wire());
      expect(replay.status).toBe(200);
      expect(state()).toEqual(moved);
      expect(state().receipts).toEqual(stored.receipts);

      const older = await postJson(
        "owner-tok",
        wire({ source_collected_at: "2026-09-09T06:30:00.000Z" }),
      );
      expect(older.status).toBe(409);
      expect((await older.json()).error.code).toBe("time_conflict");
      db.exec("DROP TRIGGER no_rewrite");

      expect(
        (await postJson("owner-tok", wire({ source_collected_at: T2 }))).status,
      ).toBe(200);
      expect(
        (state().receipts[0] as { source_collected_at: string })
          .source_collected_at,
      ).toBe(T2);
    });

    it("stores nothing when one stream of two is refused", async () => {
      const before = state();
      const response = await postJson(
        "owner-tok",
        wire({
          streams: [proof("messages", 0, EMPTY), proof("playlists", 3, EMPTY)],
        }),
      );
      expect(response.status).toBe(409);
      expect(state()).toEqual(before);
    });

    it("surfaces a database fault as api_error and leaves the store unchanged", async () => {
      db.exec(`
        CREATE TRIGGER fault BEFORE INSERT ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'injected receipt fault'); END;
      `);
      const before = state();
      const response = await postJson("owner-tok", wire());
      expect(response.status).toBe(500);
      expect((await response.json()).error.code).toBe("api_error");
      expect(state()).toEqual(before);
    });

    it("takes primary keys from the loaded declarations, not the body", async () => {
      const response = await postJson(
        "owner-tok",
        wire({
          streams: [{ ...proof("messages", 0, EMPTY), primary_key: ["text"] }],
        }),
      );
      expect(response.status).toBe(400);
      expect(completeStreams).not.toHaveBeenCalled();
    });
  });

  describe("malformed bodies", () => {
    // Wrong wire forms never reach the store.
    const bad: [string, unknown][] = [
      ["a non-object body", []],
      ["a missing field", (({ instance: _i, ...rest }) => rest)(wire())],
      ["an unexpected top-level field", wire({ extra: 1 })],
      [
        "an unexpected stream field",
        wire({ streams: [{ ...proof("messages", 0, EMPTY), extra: 1 }] }),
      ],
      ["no streams", wire({ streams: [] })],
      ["a non-array streams", wire({ streams: "messages" })],
      ["a non-object stream entry", wire({ streams: ["messages"] })],
      [
        "a string live_count",
        wire({
          streams: [{ ...proof("messages", 0, EMPTY), live_count: "0" }],
        }),
      ],
    ];
    // Right wire forms with values outside the proof domain: the store's own
    // validation refuses them as 400 before it reads or writes anything.
    const outOfDomain: [string, unknown][] = [
      [
        "a negative live_count",
        wire({ streams: [proof("messages", -1, EMPTY)] }),
      ],
      [
        "a fractional live_count",
        wire({ streams: [proof("messages", 1.5, EMPTY)] }),
      ],
      [
        "an unsafe live_count",
        wire({ streams: [proof("messages", 2 ** 53, EMPTY)] }),
      ],
      [
        "an upper-case digest",
        wire({ streams: [proof("messages", 0, EMPTY.toUpperCase())] }),
      ],
      [
        "partial coverage",
        wire({ streams: [proof("messages", 0, EMPTY, "partial")] }),
      ],
      [
        "duplicate streams",
        wire({
          streams: [proof("messages", 0, EMPTY), proof("messages", 0, EMPTY)],
        }),
      ],
      ["an unknown stream", wire({ streams: [proof("nope", 0, EMPTY)] })],
      [
        "a stream of another source",
        wire({ streams: [proof("sleep", 0, EMPTY)] }),
      ],
      [
        "an offset time",
        wire({ source_collected_at: "2026-09-10T08:30:00.000+02:00" }),
      ],
      [
        "an impossible time",
        wire({ source_collected_at: "2026-13-01T00:00:00.000Z" }),
      ],
      ["another basis", wire({ collection_time_basis: "producer_asserted" })],
      ["a numeric instance", wire({ instance: 7 })],
    ];
    it.each([
      ...bad,
      [
        "more entries than declared streams",
        wire({
          streams: Array.from({ length: 4 }, (_, i) =>
            proof(`s${i}`, 0, EMPTY),
          ),
        }),
      ],
    ])("%s is refused before the store", async (_name, body) => {
      const before = state();
      const response = await postJson("owner-tok", body);
      expect(response.status).toBe(400);
      expect(completeStreams).not.toHaveBeenCalled();
      expect(state()).toEqual(before);
    });
    it.each(outOfDomain)(
      "%s is refused with no change",
      async (_name, body) => {
        const before = state();
        const response = await postJson("owner-tok", body);
        expect(response.status).toBe(400);
        expect(state()).toEqual(before);
      },
    );

    it.each([
      ["malformed JSON", "{"],
      ["an empty body", ""],
      ["invalid UTF-8", new Uint8Array([0x7b, 0xff, 0x7d])],
    ])("%s", async (_name, body) => {
      const before = state();
      const response = await post("owner-tok", body as BodyInit);
      expect(response.status).toBe(400);
      expect(completeStreams).not.toHaveBeenCalled();
      expect(state()).toEqual(before);
    });
  });

  describe("the 64 KiB body bound counts the bytes received", () => {
    const sized = (bytes: number, body: object = wire()) => {
      const json = JSON.stringify(body);
      return json + " ".repeat(bytes - new TextEncoder().encode(json).length);
    };

    it("accepts exactly 65536 bytes and refuses 65537 with 413 before the store", async () => {
      expect(MAX_COMPLETION_BODY_BYTES).toBe(65536);
      const at = await post("owner-tok", sized(65536));
      expect(at.status).toBe(200);
      expect(completeStreams).toHaveBeenCalledOnce();
      completeStreams.mockClear();

      const before = state();
      const over = await post("owner-tok", sized(65537));
      expect(over.status).toBe(413);
      expect(completeStreams).not.toHaveBeenCalled();
      expect(state()).toEqual(before);
    });

    it("counts bytes, not characters", async () => {
      // 40 000 characters of two bytes each is over the limit; 30 000 is not.
      const wide = (chars: number) =>
        JSON.stringify(wire({ instance: "é".repeat(chars) }));
      expect((await post("owner-tok", wide(40000))).status).toBe(413);
      expect((await post("owner-tok", wide(30000))).status).toBe(401);
      expect(completeStreams).not.toHaveBeenCalled();
    });

    it.each([
      ["a lying small Content-Length", "10"],
      ["a lying large Content-Length", "99999999"],
    ])("ignores %s when the body is over the limit", async (_n, length) => {
      const response = await post("owner-tok", sized(65537), QUERY, {
        "content-length": length,
      });
      expect(response.status).toBe(413);
      expect(completeStreams).not.toHaveBeenCalled();
    });

    it("measures a chunked body with no Content-Length", async () => {
      const bytes = new TextEncoder().encode(sized(65537));
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          for (let i = 0; i < bytes.length; i += 4096) {
            controller.enqueue(bytes.slice(i, i + 4096));
          }
          controller.close();
        },
      });
      const response = await app.request(`/records/completions${QUERY}`, {
        method: "POST",
        headers: {
          Authorization: "Bearer owner-tok",
          "content-type": "application/json",
        },
        body: stream,
        duplex: "half",
      } as RequestInit);
      expect(response.status).toBe(413);
      expect(completeStreams).not.toHaveBeenCalled();
    });

    it("does not read the body of an unauthenticated or consumer request", async () => {
      for (const token of [undefined, "client-tok"]) {
        const response = await post(token, sized(65537));
        expect(response.status).toBe(401);
      }
      expect(completeStreams).not.toHaveBeenCalled();
    });
  });

  describe("unsupported stores", () => {
    it("is not mounted without a binding store or without completeStreams", async () => {
      for (const overrides of [
        { bindingStore: undefined },
        {
          bindingStore: {
            getInstanceBinding: store.getInstanceBinding,
            storeBlobBytesForInstance: store.storeBlobBytesForInstance,
            replaceStream: store.replaceStream,
          },
        },
      ]) {
        const response = await mount(overrides).request(
          `/records/completions${QUERY}`,
          {
            method: "POST",
            headers: { Authorization: "Bearer owner-tok" },
            body: JSON.stringify(wire()),
          },
        );
        expect(response.status).toBe(404);
      }
    });
  });
});
