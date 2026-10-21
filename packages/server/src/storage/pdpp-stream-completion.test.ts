import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PdppRecordEnvelopeInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import {
  isCompletionTime,
  liveSnapshotDigest,
  parseCompletionRequest,
  StreamCompletionError,
} from "./pdpp-stream-completion.js";

const SOURCE = "https://registry.pdpp.dev/sources/claude";
const OTHER_SOURCE = "https://registry.pdpp.dev/sources/oura";
const METHOD = "anthropic";
const INSTANCE = "conn_a";
const T1 = "2026-09-10T06:30:00.000Z";
const T2 = "2026-09-11T06:30:00.000Z";
const T3 = "2026-09-12T06:30:00.000Z";

// Trusted declarations: the request never supplies primary keys.
const declarations = (source: string, stream: string) =>
  source === SOURCE
    ? (
        {
          messages: ["id"],
          profiles: ["id"],
          pairs: ["a", "b"],
        } as Record<string, string[]>
      )[stream]
    : undefined;

// Independent oracle: the expected preimage is spelled out by the test and
// hashed here, never through the production helper.
const sha = (preimage: string) =>
  createHash("sha256").update(preimage, "utf8").digest("hex");
const EMPTY_MESSAGES_SHA = sha(
  `["${SOURCE}","${INSTANCE}","${METHOD}",1,"messages",[]]`,
);

const proof = (stream: string, liveCount: number, snapshotSha256: string) => ({
  stream,
  coverage: "full_stream" as const,
  liveCount,
  snapshotSha256,
});

const request = (
  streams: ReturnType<typeof proof>[],
  sourceCollectedAt = T1,
) => ({
  instance: INSTANCE,
  sourceId: SOURCE,
  method: METHOD,
  generation: 1,
  sourceCollectedAt,
  collectionTimeBasis: "host_run_finished" as const,
  streams,
});

describe("stream completion over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: INSTANCE,
      sourceId: SOURCE,
      method: METHOD,
      label: "a",
    });
  });
  afterEach(() => store.close());

  const dump = (table: string, order: string) =>
    db.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();
  /** Every persisted table the operation must leave alone. */
  const nonReceiptState = () => ({
    records: dump("pdpp_records", "instance, stream, record_key"),
    changes: dump("pdpp_record_changes", "id"),
    arrival: dump("pdpp_record_arrival", "instance, stream, record_key"),
    binding: dump("pdpp_instance_binding", "instance"),
    clock: dump("pdpp_write_clock", "id"),
    blobs: dump("pdpp_blobs", "blob_id"),
    claims: dump("pdpp_blob_claims", "blob_id, instance"),
  });
  const receipts = () => dump("pdpp_stream_completion", "instance, stream");

  it("proves an empty declared append-only stream without writing anything else", () => {
    const before = nonReceiptState();

    const result = store.completeStreams(
      request([proof("messages", 0, EMPTY_MESSAGES_SHA)]),
      declarations,
    );

    expect(receipts()).toEqual([
      {
        instance: INSTANCE,
        stream: "messages",
        method: METHOD,
        generation: 1,
        source_collected_at: T1,
        write_seq: 0,
        live_count: 0,
        snapshot_sha256: EMPTY_MESSAGES_SHA,
        collection_time_basis: "host_run_finished",
      },
    ]);
    expect(result.receipts).toHaveLength(1);
    expect(nonReceiptState()).toEqual(before);
  });

  // --- fixtures ---------------------------------------------------------

  type Row = { key: string | string[]; data: Record<string, unknown> };
  function ingest(
    stream: string,
    rows: Row[],
    semantics: "append_only" | "mutable_state" = "append_only",
    instance = INSTANCE,
    target = store,
  ) {
    const envelopes: PdppRecordEnvelopeInput[] = rows.map((row) => ({
      instance,
      stream,
      key: row.key,
      data: row.data,
      emitted_at: "2026-09-01T00:00:00.000Z",
    }));
    const result = target.ingestBatch(
      envelopes,
      () => semantics,
      () => (stream === "pairs" ? ["a", "b"] : ["id"]),
      { method: METHOD, generation: 1 },
    );
    expect(result.rejected).toEqual([]);
    return result;
  }
  const preimage = (stream: string, pairs: string) =>
    `["${SOURCE}","${INSTANCE}","${METHOD}",1,"${stream}",${pairs}]`;
  const complete = (
    streams: ReturnType<typeof proof>[],
    at = T1,
    target = store,
  ) => target.completeStreams(request(streams, at), declarations);

  /** Runs `act`, asserts it throws `reason` and that nothing at all changed. */
  function expectRefusedWithoutChange(
    act: () => unknown,
    matcher: { reason: string } | { name: string },
  ) {
    const before = { ...nonReceiptState(), receipts: receipts() };
    expect(act).toThrow(expect.objectContaining(matcher));
    expect({ ...nonReceiptState(), receipts: receipts() }).toEqual(before);
  }

  // --- history is never cleared -----------------------------------------

  it("refuses an empty proof over retained append-only history and keeps it", () => {
    ingest("messages", [{ key: "k1", data: { id: "k1", text: "A" } }]);

    expectRefusedWithoutChange(
      () => complete([proof("messages", 0, EMPTY_MESSAGES_SHA)]),
      { reason: "snapshot_conflict" },
    );
    expect(store.getRecord(INSTANCE, "messages", "k1")?.data).toEqual({
      id: "k1",
      text: "A",
    });

    const correct = sha(
      preimage("messages", `[["k1",{"id":"k1","text":"A"}]]`),
    );
    complete([proof("messages", 1, correct)]);
    expect(receipts()).toHaveLength(1);
  });

  it("does not accept a matching count when the stored value differs", () => {
    ingest("messages", [{ key: "k1", data: { id: "k1", text: "B" } }]);
    const proofOfA = sha(
      preimage("messages", `[["k1",{"id":"k1","text":"A"}]]`),
    );

    expectRefusedWithoutChange(
      () => complete([proof("messages", 1, proofOfA)]),
      { reason: "snapshot_conflict" },
    );
  });

  // --- digest: independent byte vectors ---------------------------------

  describe("digest vectors", () => {
    function proves(
      stream: string,
      rows: Row[],
      expectedPairs: string,
      semantics: "append_only" | "mutable_state" = "append_only",
    ) {
      ingest(stream, rows, semantics);
      complete([
        proof(stream, rows.length, sha(preimage(stream, expectedPairs))),
      ]);
      expect(
        (receipts() as { stream: string }[]).filter((r) => r.stream === stream),
      ).toHaveLength(1);
    }

    it("orders pairs by encoded key in UTF-16 order, and object properties as canonicalJson does", () => {
      // Pair keys sort as strings: "10" < "2" < "9". Object properties follow
      // JS enumeration after sorting, so integer-like names come first and
      // numerically: 2, 10, then 01.
      proves(
        "messages",
        [
          { key: "9", data: { id: "9" } },
          {
            key: "10",
            data: { id: "10", "10": "ten", "2": "two", "01": "one" },
          },
          { key: "2", data: { id: "2" } },
        ],
        `[["10",{"2":"two","10":"ten","01":"one","id":"10"}],["2",{"id":"2"}],["9",{"id":"9"}]]`,
      );
    });

    it("orders by UTF-16 code units without normalization", () => {
      // U+1F600 is a surrogate pair (D83D..), so it sorts before U+E000.
      proves(
        "messages",
        ["", "\u{1F600}", "é", "é", "a"].map((id) => ({
          key: id,
          data: { id },
        })),
        `[["a",{"id":"a"}],["é",{"id":"é"}],["é",{"id":"é"}],["\u{1F600}",{"id":"\u{1F600}"}],["",{"id":""}]]`,
      );
    });

    it("escapes controls and keeps U+2028 raw", () => {
      proves(
        "messages",
        [{ key: "u", data: { id: "u", text: 'a b\u0007\n"q"\\' } }],
        '[["u",{"id":"u","text":"a b\\u0007\\n\\"q\\"\\\\"}]]',
      );
    });

    it("hashes parsed JSON number values", () => {
      proves(
        "messages",
        [
          {
            key: "n",
            data: {
              id: "n",
              nums: [-0, 1.0, 0.1, 1e-7, 1e-6, 1e20, 1e21, 9007199254740991],
            },
          },
        ],
        `[["n",{"id":"n","nums":[0,1,0.1,1e-7,0.000001,100000000000000000000,1e+21,9007199254740991]}]]`,
      );
    });

    it("keeps array order, nulls and nested objects in input-order-free form", () => {
      proves(
        "messages",
        [
          {
            key: "x",
            data: { id: "x", z: [null, { b: 1, a: [true, false] }], a: null },
          },
        ],
        `[["x",{"a":null,"id":"x","z":[null,{"a":[true,false],"b":1}]}]]`,
      );
    });

    it("encodes a compound key as the minified string array and a numeric id as its string", () => {
      proves(
        "pairs",
        [{ key: ["x", "y"], data: { a: "x", b: "y" } }],
        `[["[\\"x\\",\\"y\\"]",{"a":"x","b":"y"}]]`,
      );
      proves(
        "profiles",
        [{ key: "123", data: { id: 123 } }],
        `[["123",{"id":123}]]`,
      );
    });

    it("reads an array-looking key of a single-key stream as a literal string", () => {
      proves(
        "messages",
        [{ key: '["a","b"]', data: { id: '["a","b"]' } }],
        `[["[\\"a\\",\\"b\\"]",{"id":"[\\"a\\",\\"b\\"]"}]]`,
      );
    });

    it("changes with every identity element, even for an empty stream", () => {
      const variants = [
        [OTHER_SOURCE, INSTANCE, METHOD, 1, "messages"],
        [SOURCE, "conn_z", METHOD, 1, "messages"],
        [SOURCE, INSTANCE, "other", 1, "messages"],
        [SOURCE, INSTANCE, METHOD, 2, "messages"],
        [SOURCE, INSTANCE, METHOD, 1, "profiles"],
      ].map((tuple) => sha(`${JSON.stringify([...tuple, []])}`));
      expect(new Set([EMPTY_MESSAGES_SHA, ...variants]).size).toBe(6);
      for (const wrong of variants) {
        expectRefusedWithoutChange(
          () => complete([proof("messages", 0, wrong)]),
          { reason: "snapshot_conflict" },
        );
      }
    });

    it.each([
      [
        "an unknown data property",
        { id: "k", extra: 1 },
        { id: "k", extra: 2 },
      ],
      [
        "a data timestamp",
        { id: "k", create_time: "2026-01-01T00:00:00.000Z" },
        { id: "k", create_time: "2026-01-02T00:00:00.000Z" },
      ],
      [
        "emitted_at inside data",
        { id: "k", emitted_at: "a" },
        { id: "k", emitted_at: "b" },
      ],
    ])(
      "a same-count change of %s fails the old proof",
      (_name, before, after) => {
        ingest("profiles", [{ key: "k", data: before }], "mutable_state");
        const oldProof = sha(
          preimage("profiles", `[["k",${canonicalOf(before)}]]`),
        );
        ingest("profiles", [{ key: "k", data: after }], "mutable_state");

        expectRefusedWithoutChange(
          () => complete([proof("profiles", 1, oldProof)]),
          { reason: "snapshot_conflict" },
        );
        const newProof = sha(
          preimage("profiles", `[["k",${canonicalOf(after)}]]`),
        );
        complete([proof("profiles", 1, newProof)]);
      },
    );

    it("covers every blob_ref field: a same-count change of the reference fails the old proof", () => {
      const blob = (text: string) =>
        store.storeBlobBytesForInstance({
          instance: INSTANCE,
          method: METHOD,
          generation: 1,
          bytes: new TextEncoder().encode(text),
          mimeType: "text/plain",
        });
      const one = blob("one");
      const two = blob("two");
      const ref = (b: typeof one) => ({
        blob_id: b.blobId,
        mime_type: b.mimeType,
        size_bytes: b.sizeBytes,
        sha256: b.sha256,
      });
      const row = (b: typeof one) => ({ id: "k", blob_ref: ref(b) });
      ingest("profiles", [{ key: "k", data: row(one) }], "mutable_state");
      const oldProof = sha(
        preimage(
          "profiles",
          `[["k",{"blob_ref":{"blob_id":${JSON.stringify(one.blobId)},"mime_type":"text/plain","sha256":${JSON.stringify(one.sha256)},"size_bytes":${one.sizeBytes}},"id":"k"}]]`,
        ),
      );
      complete([proof("profiles", 1, oldProof)]);

      ingest("profiles", [{ key: "k", data: row(two) }], "mutable_state");
      expectRefusedWithoutChange(
        () => complete([proof("profiles", 1, oldProof)], T2),
        { reason: "snapshot_conflict" },
      );
    });

    it("ignores row and envelope metadata", () => {
      ingest("messages", [{ key: "k", data: { id: "k" } }]);
      db.prepare(
        "UPDATE pdpp_records SET emitted_at = '2030-01-01T00:00:00.000Z', version = 9 WHERE stream = 'messages'",
      ).run();
      complete([
        proof("messages", 1, sha(preimage("messages", `[["k",{"id":"k"}]]`))),
      ]);
    });

    it("excludes tombstones and other streams or instances", () => {
      ingest(
        "profiles",
        [
          { key: "a", data: { id: "a" } },
          { key: "b", data: { id: "b" } },
        ],
        "mutable_state",
      );
      store.deleteRecord(
        INSTANCE,
        "profiles",
        "b",
        "2026-09-02T00:00:00.000Z",
        "mutable_state",
      );
      store.registerConnection({
        instance: "conn_b",
        sourceId: SOURCE,
        method: METHOD,
        label: "b",
      });
      ingest(
        "profiles",
        [{ key: "z", data: { id: "z" } }],
        "mutable_state",
        "conn_b",
      );
      ingest("messages", [{ key: "m", data: { id: "m" } }]);
      complete([
        proof("profiles", 1, sha(preimage("profiles", `[["a",{"id":"a"}]]`))),
      ]);
    });

    it.each([
      ["a lone surrogate", `{"id":"s","t":"\\ud800"}`, "s"],
      ["a non-finite number", `{"id":"s","t":1e999}`, "s"],
    ])(
      "refuses stored data with %s instead of coercing it",
      (_name, json, key) => {
        db.prepare(
          "INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at) VALUES (?, 'messages', ?, ?, 1, 'x')",
        ).run(INSTANCE, key, json);
        expectRefusedWithoutChange(
          () => complete([proof("messages", 1, EMPTY_MESSAGES_SHA)]),
          { reason: "invalid_snapshot_data" },
        );
      },
    );

    it.each([
      [
        "a compound key that is not the minified array",
        "pairs",
        `[ "x", "y" ]`,
        { a: "x", b: "y" },
      ],
      [
        "a compound key of the wrong arity",
        "pairs",
        `["x"]`,
        { a: "x", b: "y" },
      ],
      [
        "a compound key that is a bare string",
        "pairs",
        "x",
        { a: "x", b: "y" },
      ],
      [
        "a compound key that disagrees with its data",
        "pairs",
        `["x","z"]`,
        { a: "x", b: "y" },
      ],
      ["a key that disagrees with its data", "messages", "k", { id: "other" }],
      ["data missing its primary key field", "messages", "k", { text: "t" }],
    ])("refuses %s", (_name, stream, recordKey, data) => {
      db.prepare(
        "INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at) VALUES (?, ?, ?, ?, 1, 'x')",
      ).run(INSTANCE, stream, recordKey, JSON.stringify(data));
      expectRefusedWithoutChange(
        () => complete([proof(stream, 1, EMPTY_MESSAGES_SHA)]),
        { reason: "invalid_snapshot_data" },
      );
    });
  });

  // --- request shape -----------------------------------------------------

  describe("request validation", () => {
    const good = proof("messages", 0, EMPTY_MESSAGES_SHA);
    const bad: [string, unknown][] = [
      ["no streams", { streams: [] }],
      ["duplicate streams", { streams: [good, good] }],
      ["partial coverage", { streams: [{ ...good, coverage: "partial" }] }],
      ["negative count", { streams: [{ ...good, liveCount: -1 }] }],
      ["fractional count", { streams: [{ ...good, liveCount: 1.5 }] }],
      ["unsafe count", { streams: [{ ...good, liveCount: 2 ** 53 }] }],
      ["NaN count", { streams: [{ ...good, liveCount: NaN }] }],
      ["numeric-string count", { streams: [{ ...good, liveCount: "0" }] }],
      [
        "uppercase digest",
        {
          streams: [
            { ...good, snapshotSha256: EMPTY_MESSAGES_SHA.toUpperCase() },
          ],
        },
      ],
      [
        "short digest",
        { streams: [{ ...good, snapshotSha256: EMPTY_MESSAGES_SHA.slice(1) }] },
      ],
      [
        "prefixed digest",
        {
          streams: [
            { ...good, snapshotSha256: `sha256:${EMPTY_MESSAGES_SHA}` },
          ],
        },
      ],
      [
        "a UTC offset time",
        { sourceCollectedAt: "2026-09-10T08:30:00.000+02:00" },
      ],
      [
        "a time without milliseconds",
        { sourceCollectedAt: "2026-09-10T06:30:00Z" },
      ],
      ["one fractional digit", { sourceCollectedAt: "2026-09-10T06:30:00.0Z" }],
      [
        "four fractional digits",
        { sourceCollectedAt: "2026-09-10T06:30:00.0000Z" },
      ],
      ["a lower-case t", { sourceCollectedAt: "2026-09-10t06:30:00.000Z" }],
      ["an impossible date", { sourceCollectedAt: "2026-02-30T06:30:00.000Z" }],
      ["another basis", { collectionTimeBasis: "producer_asserted" }],
      ["a zero generation", { generation: 0 }],
      ["an empty method", { method: "" }],
    ];
    it.each(bad)("refuses %s without reading or writing", (_name, override) => {
      expectRefusedWithoutChange(
        () =>
          store.completeStreams(
            { ...request([good]), ...(override as object) } as never,
            declarations,
          ),
        { reason: "invalid_request" },
      );
    });
  });

  // --- authority: binding and declarations -------------------------------

  describe("binding and declaration", () => {
    const ok = proof("messages", 0, EMPTY_MESSAGES_SHA);
    const attempt = (override: Partial<ReturnType<typeof request>>) => () =>
      store.completeStreams({ ...request([ok]), ...override }, declarations);

    it("never registers or creates a binding for an unknown instance", () => {
      expectRefusedWithoutChange(attempt({ instance: "conn_ghost" }), {
        reason: "connection_required",
      });
      expect(
        db
          .prepare(
            "SELECT COUNT(*) AS n FROM pdpp_instance_binding WHERE instance = 'conn_ghost'",
          )
          .get(),
      ).toEqual({ n: 0 });
    });

    it.each([
      ["source", { sourceId: OTHER_SOURCE }, "source_mismatch"],
      ["method", { method: "other" }, "instance_bound_to_other_method"],
      ["generation", { generation: 2 }, "binding_generation_mismatch"],
    ])("refuses another %s", (_name, override, reason) => {
      expectRefusedWithoutChange(attempt(override), { reason });
    });

    it("refuses a stale generation after reset and a deleted connection", () => {
      store.resetInstanceBinding({
        instance: INSTANCE,
        expectedMethod: METHOD,
        expectedGeneration: 1,
        nextMethod: METHOD,
      });
      expectRefusedWithoutChange(attempt({}), {
        reason: "binding_generation_mismatch",
      });
      store.deleteConnection(INSTANCE);
      expectRefusedWithoutChange(attempt({ generation: 2 }), {
        reason: "connection_deleted",
      });
    });

    it("refuses an undeclared stream and an unusable declaration", () => {
      expectRefusedWithoutChange(
        () =>
          store.completeStreams(
            request([proof("nope", 0, EMPTY_MESSAGES_SHA)]),
            declarations,
          ),
        { reason: "unknown_stream" },
      );
      expectRefusedWithoutChange(
        () => store.completeStreams(request([ok]), () => []),
        { reason: "invalid_declaration" },
      );
    });

    it("takes primary keys only from the trusted resolver", () => {
      ingest("messages", [{ key: "k", data: { id: "k" } }]);
      const wrongKeys = () => ["text"]; // data has no `text`
      expectRefusedWithoutChange(
        () =>
          store.completeStreams(
            request([proof("messages", 1, EMPTY_MESSAGES_SHA)]),
            wrongKeys,
          ),
        { reason: "invalid_snapshot_data" },
      );
    });
  });

  // --- all-or-nothing ----------------------------------------------------

  describe("atomicity", () => {
    const validMessages = () => proof("messages", 0, EMPTY_MESSAGES_SHA);
    const profilesProof = () =>
      proof("profiles", 1, sha(preimage("profiles", `[["p",{"id":"p"}]]`)));
    beforeEach(() =>
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state"),
    );

    it("validates every stream before writing any receipt, in either order", () => {
      db.exec(`
        CREATE TRIGGER early_write BEFORE INSERT ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'unexpected early receipt write'); END;
        CREATE TRIGGER early_update BEFORE UPDATE ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'unexpected early receipt write'); END;
      `);
      const wrongCount = proof("profiles", 5, profilesProof().snapshotSha256);
      for (const streams of [
        [validMessages(), wrongCount],
        [wrongCount, validMessages()],
      ]) {
        expectRefusedWithoutChange(() => complete(streams), {
          reason: "snapshot_conflict",
        });
      }
    });

    it.each(["no prior receipts", "prior receipts"])(
      "rolls both receipts back when the second write fails (%s)",
      (scenario) => {
        if (scenario === "prior receipts") {
          complete([validMessages(), profilesProof()], T1);
        }
        const before = { ...nonReceiptState(), receipts: receipts() };
        const failSecond = (when: string) =>
          db.exec(`
            CREATE TRIGGER fail_second BEFORE ${when} ON pdpp_stream_completion
            WHEN NEW.stream = 'profiles'
            BEGIN SELECT RAISE(ABORT, 'second receipt fault'); END;
          `);
        failSecond(scenario === "prior receipts" ? "UPDATE" : "INSERT");

        expect(() => complete([validMessages(), profilesProof()], T2)).toThrow(
          "second receipt fault",
        );
        expect({ ...nonReceiptState(), receipts: receipts() }).toEqual(before);

        db.exec("DROP TRIGGER fail_second");
        const result = complete([validMessages(), profilesProof()], T2);
        expect(result.receipts.map((r) => r.sourceCollectedAt)).toEqual([
          T2,
          T2,
        ]);
      },
    );
  });

  // --- time and replay ---------------------------------------------------

  describe("time and replay", () => {
    const messagesProof = () => proof("messages", 0, EMPTY_MESSAGES_SHA);
    const profile = () =>
      proof("profiles", 1, sha(preimage("profiles", `[["p",{"id":"p"}]]`)));
    const abortReceiptWrites = () =>
      db.exec(`
        CREATE TRIGGER no_insert BEFORE INSERT ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'receipt rewritten'); END;
        CREATE TRIGGER no_update BEFORE UPDATE ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'receipt rewritten'); END;
      `);

    it("keeps the receipt bytes of an exact replay after unrelated clock movement", () => {
      complete([messagesProof()], T1);
      const stored = receipts();
      store.registerConnection({
        instance: "conn_b",
        sourceId: OTHER_SOURCE,
        method: METHOD,
        label: "b",
      });
      ingest(
        "profiles",
        [{ key: "z", data: { id: "z" } }],
        "mutable_state",
        "conn_b",
      );
      expect(dump("pdpp_write_clock", "id")).not.toEqual([{ id: 1, value: 0 }]);
      abortReceiptWrites();
      const before = nonReceiptState();

      const replay = complete([messagesProof()], T1);

      expect(receipts()).toEqual(stored);
      expect(replay.receipts[0].writeSeq).toBe(0);
      expect(nonReceiptState()).toEqual(before);
    });

    it("stores the current clock as write_seq without advancing it", () => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      const clock = dump("pdpp_write_clock", "id");
      const result = complete([profile()], T1);
      expect(result.receipts[0].writeSeq).toBe(
        (clock[0] as { value: number }).value,
      );
      expect(dump("pdpp_write_clock", "id")).toEqual(clock);
    });

    it("replays one stream, refreshes another, and updates only receipt metadata", () => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      complete([messagesProof()], T2);
      complete([profile()], T1);
      const [messagesBefore] = receipts();
      db.exec(`
        CREATE TRIGGER no_messages BEFORE UPDATE ON pdpp_stream_completion
        WHEN NEW.stream = 'messages'
        BEGIN SELECT RAISE(ABORT, 'receipt rewritten'); END;
      `);
      const before = nonReceiptState();

      complete([messagesProof(), profile()], T2);

      const stored = receipts() as {
        stream: string;
        source_collected_at: string;
      }[];
      expect(stored[0]).toEqual(messagesBefore);
      expect(stored[1].source_collected_at).toBe(T2);
      expect(nonReceiptState()).toEqual(before);
    });

    it("refuses an older time than a valid receipt, even when only the second stream is older", () => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      complete([messagesProof()], T2);
      complete([profile()], T3);
      expectRefusedWithoutChange(() => complete([messagesProof()], T1), {
        reason: "time_conflict",
      });
      expectRefusedWithoutChange(
        () => complete([messagesProof(), profile()], T2),
        { reason: "time_conflict" },
      );
    });

    it("has no watermark after the receipt was invalidated", () => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      complete([profile()], T3);
      ingest(
        "profiles",
        [{ key: "p", data: { id: "p", more: 1 } }],
        "mutable_state",
      );
      expect(receipts()).toEqual([]);

      complete(
        [
          proof(
            "profiles",
            1,
            sha(preimage("profiles", `[["p",{"id":"p","more":1}]]`)),
          ),
        ],
        T1,
      );
      expect(receipts()).toHaveLength(1);
    });

    describe("a P7 receipt without digest", () => {
      function p7(at: string) {
        const result = store.replaceStream({
          instance: INSTANCE,
          stream: "profiles",
          method: METHOD,
          generation: 1,
          emittedAt: "2026-09-01T00:00:00.000Z",
          envelopes: [
            {
              instance: INSTANCE,
              stream: "profiles",
              key: "p",
              data: { id: "p" },
              emitted_at: "2026-09-01T00:00:00.000Z",
            },
          ],
          primaryKey: ["id"],
          sourceCollectedAt: at,
        });
        expect(result.applied).toBe(true);
      }

      it("compares instants, never offset text", () => {
        // 23:00-05:00 on the 10th is 04:00Z on the 11th: later than 01:00Z.
        p7("2026-09-10T23:00:00.000-05:00");
        expectRefusedWithoutChange(
          () => complete([profile()], "2026-09-11T01:00:00.000Z"),
          { reason: "time_conflict" },
        );
        expectRefusedWithoutChange(
          () => complete([profile()], "2026-09-11T03:59:59.999Z"),
          { reason: "time_conflict" },
        );
      });

      it("does not relabel the same instant as native proof", () => {
        p7("2026-09-10T08:30:00.000+02:00");
        expectRefusedWithoutChange(() => complete([profile()], T1), {
          reason: "time_conflict",
        });
      });

      it("accepts a strictly newer native proof and records the new basis", () => {
        p7("2026-09-10T08:30:00.000+02:00");
        const result = complete([profile()], "2026-09-10T06:30:00.001Z");
        expect(result.receipts[0]).toMatchObject({
          sourceCollectedAt: "2026-09-10T06:30:00.001Z",
          collectionTimeBasis: "host_run_finished",
          snapshotSha256: profile().snapshotSha256,
        });
      });
    });

    describe("a stored receipt that contradicts its data", () => {
      beforeEach(() => {
        ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
        complete([profile()], T1);
      });
      it.each([
        ["an unparseable time", "source_collected_at = 'garbage'"],
        ["another live count", "live_count = 7"],
        ["another generation", "generation = 4"],
        ["another method", "method = 'other'"],
        ["a write_seq from the future", "write_seq = 999"],
        ["a write_seq older than the last change", "write_seq = -1"],
        ["a basis without a digest", "snapshot_sha256 = NULL"],
        ["a digest without a basis", "collection_time_basis = NULL"],
        ["another digest", `snapshot_sha256 = '${"0".repeat(64)}'`],
        ["another basis", "collection_time_basis = 'other'"],
      ])("refuses %s", (_name, set) => {
        db.exec(`UPDATE pdpp_stream_completion SET ${set}`);
        expectRefusedWithoutChange(() => complete([profile()], T3), {
          reason: "invalid_prior_receipt",
        });
      });
    });
  });

  // --- invalidation ------------------------------------------------------

  describe("later writes", () => {
    it("drop only the written stream's receipt, while redelivery keeps it", () => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      complete([
        proof("messages", 0, EMPTY_MESSAGES_SHA),
        proof("profiles", 1, sha(preimage("profiles", `[["p",{"id":"p"}]]`))),
      ]);

      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      expect(receipts()).toHaveLength(2);

      ingest("profiles", [{ key: "q", data: { id: "q" } }], "mutable_state");
      expect((receipts() as { stream: string }[]).map((r) => r.stream)).toEqual(
        ["messages"],
      );

      ingest("messages", [{ key: "m", data: { id: "m" } }]);
      expect(receipts()).toEqual([]);
    });

    it("are not blocked by, and invalidate, a receipt for a deleted key", () => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      complete([
        proof("profiles", 1, sha(preimage("profiles", `[["p",{"id":"p"}]]`))),
      ]);
      store.deleteRecord(
        INSTANCE,
        "profiles",
        "p",
        "2026-09-02T00:00:00.000Z",
        "mutable_state",
      );
      expect(receipts()).toEqual([]);
    });

    it("reset erases the receipts of that connection only", () => {
      complete([proof("messages", 0, EMPTY_MESSAGES_SHA)]);
      store.resetInstanceBinding({
        instance: INSTANCE,
        expectedMethod: METHOD,
        expectedGeneration: 1,
        nextMethod: METHOD,
      });
      expect(receipts()).toEqual([]);
    });
  });

  // --- transaction mode, concurrency, restart ----------------------------

  describe("on a file database", () => {
    let dir: string;
    let statements: string[];
    let fileDb: InstanceType<typeof Database>;
    let fileStore: ReturnType<typeof createSqliteRecordStore>;
    const file = () => join(dir, "ps.sqlite");

    function open(timeout = 100) {
      fileDb = new Database(file(), {
        timeout,
        verbose: (sql) => statements.push(String(sql)),
      });
      fileStore = createSqliteRecordStore(fileDb);
    }
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "stream-completion-"));
      statements = [];
      open();
      fileStore.registerConnection({
        instance: INSTANCE,
        sourceId: SOURCE,
        method: METHOD,
        label: "a",
      });
    });
    afterEach(() => {
      try {
        fileStore.close();
      } catch {
        /* closed by the test */
      }
      rmSync(dir, { recursive: true, force: true });
    });

    const raw = (sql: string) => {
      const reader = new Database(file(), { readonly: true });
      try {
        return reader.prepare(sql).all();
      } finally {
        reader.close();
      }
    };

    it("takes the write lock first, validates everything, then writes under one commit", () => {
      ingest(
        "profiles",
        [{ key: "p", data: { id: "p" } }],
        "mutable_state",
        INSTANCE,
        fileStore,
      );
      statements.length = 0;
      complete(
        [
          proof("messages", 0, EMPTY_MESSAGES_SHA),
          proof("profiles", 1, sha(preimage("profiles", `[["p",{"id":"p"}]]`))),
        ],
        T1,
        fileStore,
      );
      const verbs = statements.map((sql) =>
        sql.trim().split(/\s+/)[0].toUpperCase(),
      );
      expect(statements[0]).toMatch(/^BEGIN IMMEDIATE/i);
      expect(verbs.filter((v) => v === "COMMIT")).toHaveLength(1);
      expect(verbs.at(-1)).toBe("COMMIT");
      const firstWrite = verbs.findIndex(
        (v) => v === "INSERT" || v === "UPDATE",
      );
      const liveReads = statements
        .map((sql, i) => [sql, i] as const)
        .filter(([sql]) => /FROM pdpp_records/.test(sql))
        .map(([, i]) => i);
      expect(Math.max(...liveReads)).toBeLessThan(firstWrite);
    });

    it("fails busy while another writer holds the lock, then judges the committed state", () => {
      const writerDb = new Database(file());
      const writer = createSqliteRecordStore(writerDb);
      const nonEmptyProof = proof("messages", 0, EMPTY_MESSAGES_SHA);
      writerDb.exec("BEGIN IMMEDIATE");
      expect(() => complete([nonEmptyProof], T1, fileStore)).toThrow(
        /locked|busy/i,
      );
      writerDb.exec("ROLLBACK");
      expect(raw("SELECT * FROM pdpp_stream_completion")).toEqual([]);

      ingest(
        "messages",
        [{ key: "k", data: { id: "k" } }],
        "append_only",
        INSTANCE,
        writer,
      );
      expect(() => complete([nonEmptyProof], T1, fileStore)).toThrow(
        expect.objectContaining({ reason: "snapshot_conflict" }),
      );
      expect(raw("SELECT * FROM pdpp_stream_completion")).toEqual([]);
      writer.close();
    });

    it("keeps receipts and replay across a real close and reopen", () => {
      complete([proof("messages", 0, EMPTY_MESSAGES_SHA)], T1, fileStore);
      const stored = raw("SELECT * FROM pdpp_stream_completion");
      const readerView = fileStore.listStreamCompletions(INSTANCE);
      fileStore.close();

      open();
      expect(raw("SELECT * FROM pdpp_stream_completion")).toEqual(stored);
      // The existing reader still reports exactly its seven fields.
      expect(fileStore.listStreamCompletions(INSTANCE)).toEqual(readerView);
      expect(Object.keys(readerView[0]).sort()).toEqual(
        [
          "generation",
          "instance",
          "liveCount",
          "method",
          "sourceCollectedAt",
          "stream",
          "writeSeq",
        ].sort(),
      );
      fileDb.exec(`
        CREATE TRIGGER no_rewrite BEFORE UPDATE ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'receipt rewritten'); END;
      `);
      complete([proof("messages", 0, EMPTY_MESSAGES_SHA)], T1, fileStore);
      expect(raw("SELECT * FROM pdpp_stream_completion")).toEqual(stored);
    });
  });

  // --- schema upgrade ----------------------------------------------------

  describe("schema v8 to v11", () => {
    it("keeps old receipts null-labelled and P7 behavior unchanged", () => {
      const dir = mkdtempSync(join(tmpdir(), "stream-completion-v8-"));
      try {
        const path = join(dir, "old.sqlite");
        const first = new Database(path);
        const created = createSqliteRecordStore(first);
        created.registerConnection({
          instance: INSTANCE,
          sourceId: SOURCE,
          method: METHOD,
          label: "a",
        });
        created.close();

        // Make it a v8 database holding a seven-field receipt.
        const old = new Database(path);
        const epoch = old
          .prepare("SELECT epoch FROM pdpp_store_metadata")
          .get();
        old.exec(`
          ALTER TABLE pdpp_stream_completion DROP COLUMN snapshot_sha256;
          ALTER TABLE pdpp_stream_completion DROP COLUMN collection_time_basis;
          UPDATE pdpp_schema_version SET version = 8;
          INSERT INTO pdpp_stream_completion
            (instance, stream, method, generation, source_collected_at, write_seq, live_count)
          VALUES ('${INSTANCE}', 'profiles', '${METHOD}', 1, '2026-09-10T08:30:00+02:00', 0, 0);
        `);
        old.close();

        const upgradedDb = new Database(path);
        const upgraded = createSqliteRecordStore(upgradedDb);
        expect(
          upgradedDb.prepare("SELECT version FROM pdpp_schema_version").get(),
        ).toEqual({ version: 17 });
        expect(
          upgradedDb.prepare("SELECT epoch FROM pdpp_store_metadata").get(),
        ).toEqual(epoch);
        expect(
          upgradedDb.prepare("SELECT * FROM pdpp_stream_completion").all(),
        ).toEqual([
          {
            instance: INSTANCE,
            stream: "profiles",
            method: METHOD,
            generation: 1,
            source_collected_at: "2026-09-10T08:30:00+02:00",
            write_seq: 0,
            live_count: 0,
            snapshot_sha256: null,
            collection_time_basis: null,
          },
        ]);

        // A seven-field insert still works, and P7 still replaces/deletes receipts.
        upgradedDb
          .prepare(
            "INSERT INTO pdpp_stream_completion (instance, stream, method, generation, source_collected_at, write_seq, live_count) VALUES (?, 'x', ?, 1, ?, 0, 0)",
          )
          .run(INSTANCE, METHOD, T1);
        const replace = (sourceCollectedAt?: string) =>
          upgraded.replaceStream({
            instance: INSTANCE,
            stream: "profiles",
            method: METHOD,
            generation: 1,
            emittedAt: "2026-09-01T00:00:00.000Z",
            envelopes: [],
            primaryKey: ["id"],
            sourceCollectedAt,
          });
        replace("2026-09-12T00:00:00+00:00");
        expect(
          upgradedDb
            .prepare(
              "SELECT source_collected_at, snapshot_sha256, collection_time_basis FROM pdpp_stream_completion WHERE stream = 'profiles'",
            )
            .get(),
        ).toEqual({
          source_collected_at: "2026-09-12T00:00:00+00:00",
          snapshot_sha256: null,
          collection_time_basis: null,
        });
        replace();
        expect(
          upgradedDb
            .prepare(
              "SELECT COUNT(*) AS n FROM pdpp_stream_completion WHERE stream = 'profiles'",
            )
            .get(),
        ).toEqual({ n: 0 });
        upgraded.close();

        // Re-opening does not rerun the migration.
        const again = new Database(path);
        const reopened = createSqliteRecordStore(again);
        expect(
          again.prepare("SELECT epoch FROM pdpp_store_metadata").get(),
        ).toEqual(epoch);
        reopened.close();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });

  // --- R1 repairs: malformed times, tampered receipts, schema drift ------

  describe("regex-shaped invalid times", () => {
    it.each([
      "2026-13-01T00:00:00.000Z",
      "2026-00-10T00:00:00.000Z",
      "2026-01-01T25:00:00.000Z",
      "2026-01-01T00:60:00.000Z",
      "2026-01-01T00:00:60.000Z",
      "2026-02-30T00:00:00.000Z",
    ])(
      "%s is not a completion time, and refuses typed with no reads or writes",
      (value) => {
        expect(isCompletionTime(value)).toBe(false);
        expect(() =>
          parseCompletionRequest(
            request([proof("messages", 0, EMPTY_MESSAGES_SHA)], value),
          ),
        ).toThrow(expect.objectContaining({ reason: "invalid_request" }));
        expectRefusedWithoutChange(
          () => complete([proof("messages", 0, EMPTY_MESSAGES_SHA)], value),
          { reason: "invalid_request" },
        );
      },
    );
  });

  describe("a native receipt whose stored fields left their domain", () => {
    const profile = () =>
      proof("profiles", 1, sha(preimage("profiles", `[["p",{"id":"p"}]]`)));
    beforeEach(() => {
      ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
      complete([profile()], T1);
      // An unrelated write moves the clock past the receipt.
      store.registerConnection({
        instance: "conn_b",
        sourceId: SOURCE,
        method: METHOD,
        label: "b",
      });
      ingest(
        "profiles",
        [{ key: "z", data: { id: "z" } }],
        "mutable_state",
        "conn_b",
      );
    });

    it.each([
      ["non-numeric text write_seq", "write_seq = 'garbage'"],
      ["fractional write_seq", "write_seq = 1.5"],
    ])(
      "refuses a %s for replay and for a newer proof, without repairing it",
      (_name, set) => {
        db.exec(`UPDATE pdpp_stream_completion SET ${set}`);
        for (const at of [T1, T2]) {
          expectRefusedWithoutChange(() => complete([profile()], at), {
            reason: "invalid_prior_receipt",
          });
        }
      },
    );

    it.each([
      ["a sub-millisecond time", "2026-09-10T06:30:00.0001Z"],
      ["a UTC offset time", "2026-09-10T08:30:00.000+02:00"],
      ["a time without milliseconds", "2026-09-10T06:30:00Z"],
    ])("refuses %s for exact replay and newer proof", (_name, stored) => {
      db.prepare(
        "UPDATE pdpp_stream_completion SET source_collected_at = ?",
      ).run(stored);
      for (const at of [T1, T2]) {
        expectRefusedWithoutChange(() => complete([profile()], at), {
          reason: "invalid_prior_receipt",
        });
      }
    });
  });

  it("still compares a digest-less P7 sub-millisecond time by parsed instant", () => {
    ingest("profiles", [{ key: "p", data: { id: "p" } }], "mutable_state");
    const result = store.replaceStream({
      instance: INSTANCE,
      stream: "profiles",
      method: METHOD,
      generation: 1,
      emittedAt: "2026-09-01T00:00:00.000Z",
      envelopes: [
        {
          instance: INSTANCE,
          stream: "profiles",
          key: "p",
          data: { id: "p" },
          emitted_at: "2026-09-01T00:00:00.000Z",
        },
      ],
      primaryKey: ["id"],
      sourceCollectedAt: "2026-09-10T06:30:00.0005Z",
    });
    expect(result.applied).toBe(true);
    const profile = proof(
      "profiles",
      1,
      sha(preimage("profiles", `[["p",{"id":"p"}]]`)),
    );
    expectRefusedWithoutChange(() => complete([profile], T1), {
      reason: "time_conflict",
    });
    complete([profile], "2026-09-10T06:30:00.001Z");
  });

  it("refuses malformed stored JSON as invalid snapshot data", () => {
    db.prepare(
      "INSERT INTO pdpp_records (instance, stream, record_key, data, version, emitted_at) VALUES (?, 'messages', 'k', '{not json', 1, 'x')",
    ).run(INSTANCE);
    expectRefusedWithoutChange(
      () => complete([proof("messages", 1, EMPTY_MESSAGES_SHA)]),
      { reason: "invalid_snapshot_data" },
    );
  });

  it("refuses two rows with one encoded key in the digest helper", () => {
    const identity = {
      sourceId: SOURCE,
      instance: INSTANCE,
      method: METHOD,
      generation: 1,
      stream: "messages",
    };
    const row = { recordKey: "a", dataJson: '{"id":"a"}' };
    expect(() => liveSnapshotDigest(identity, ["id"], [row, row])).toThrow(
      expect.any(StreamCompletionError),
    );
    expect(() => liveSnapshotDigest(identity, ["id"], [row])).not.toThrow();
  });

  describe("v9 column drift", () => {
    const columns = (database: InstanceType<typeof Database>) =>
      database.prepare("PRAGMA table_xinfo(pdpp_stream_completion)").all();

    /** A real v8 database file holding one seven-field receipt. */
    function v8File(dir: string, extraColumns = "") {
      const path = join(dir, "drift.sqlite");
      const first = new Database(path);
      createSqliteRecordStore(first).close();
      const old = new Database(path);
      old.exec(`
        ALTER TABLE pdpp_stream_completion DROP COLUMN snapshot_sha256;
        ALTER TABLE pdpp_stream_completion DROP COLUMN collection_time_basis;
        UPDATE pdpp_schema_version SET version = 8;
        INSERT INTO pdpp_stream_completion
          (instance, stream, method, generation, source_collected_at, write_seq, live_count)
        VALUES ('${INSTANCE}', 'profiles', '${METHOD}', 1, '2026-09-10T08:30:00+02:00', 0, 0);
        ${extraColumns}
      `);
      old.close();
      return path;
    }

    it.each([
      [
        "NOT NULL with a default",
        `ALTER TABLE pdpp_stream_completion ADD COLUMN snapshot_sha256 TEXT NOT NULL DEFAULT '';
         ALTER TABLE pdpp_stream_completion ADD COLUMN collection_time_basis TEXT NOT NULL DEFAULT '';`,
      ],
      [
        "another type",
        `ALTER TABLE pdpp_stream_completion ADD COLUMN snapshot_sha256 INTEGER;
         ALTER TABLE pdpp_stream_completion ADD COLUMN collection_time_basis TEXT;`,
      ],
      [
        "a non-null default",
        `ALTER TABLE pdpp_stream_completion ADD COLUMN snapshot_sha256 TEXT;
         ALTER TABLE pdpp_stream_completion ADD COLUMN collection_time_basis TEXT DEFAULT 'host_run_finished';`,
      ],
      [
        "a generated column",
        `ALTER TABLE pdpp_stream_completion ADD COLUMN snapshot_sha256 TEXT;
         ALTER TABLE pdpp_stream_completion ADD COLUMN collection_time_basis TEXT GENERATED ALWAYS AS (NULL) VIRTUAL;`,
      ],
    ])(
      "refuses to open a v8 database whose columns are %s, changing nothing",
      (_name, ddl) => {
        const dir = mkdtempSync(join(tmpdir(), "stream-completion-drift-"));
        try {
          const path = v8File(dir, ddl);
          const probe = new Database(path);
          const before = {
            columns: columns(probe),
            rows: probe.prepare("SELECT * FROM pdpp_stream_completion").all(),
            version: probe
              .prepare("SELECT version FROM pdpp_schema_version")
              .get(),
          };
          probe.close();

          const target = new Database(path);
          expect(() => createSqliteRecordStore(target)).toThrow(
            /snapshot_sha256|collection_time_basis/,
          );
          target.close();

          const after = new Database(path);
          expect({
            columns: columns(after),
            rows: after.prepare("SELECT * FROM pdpp_stream_completion").all(),
            version: after
              .prepare("SELECT version FROM pdpp_schema_version")
              .get(),
          }).toEqual(before);
          expect(before.version).toEqual({ version: 8 });
          after.close();
        } finally {
          rmSync(dir, { recursive: true, force: true });
        }
      },
    );

    it("accepts a rewound current schema and a genuine v8 upgrade", () => {
      const dir = mkdtempSync(join(tmpdir(), "stream-completion-rewind-"));
      try {
        const rewound = join(dir, "rewound.sqlite");
        createSqliteRecordStore(new Database(rewound)).close();
        const raw = new Database(rewound);
        raw.exec("UPDATE pdpp_schema_version SET version = 8");
        raw.close();
        const reopened = new Database(rewound);
        createSqliteRecordStore(reopened).close();

        const genuine = new Database(v8File(dir));
        const upgraded = createSqliteRecordStore(genuine);
        expect(
          genuine.prepare("SELECT version FROM pdpp_schema_version").get(),
        ).toEqual({ version: 17 });
        expect(
          genuine
            .prepare(
              "SELECT snapshot_sha256, collection_time_basis FROM pdpp_stream_completion",
            )
            .get(),
        ).toEqual({ snapshot_sha256: null, collection_time_basis: null });
        upgraded.close();
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  });
});

/** The canonical bytes of a data object, spelled out by key order for these fixtures. */
function canonicalOf(value: unknown): string {
  // Fixtures here have no integer-like property names, so sorted-key
  // JSON.stringify is the expected canonical text.
  const sort = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(sort)
      : v && typeof v === "object"
        ? Object.fromEntries(
            Object.entries(v as object)
              .sort(([a], [b]) => (a < b ? -1 : 1))
              .map(([k, x]) => [k, sort(x)]),
          )
        : v;
  return JSON.stringify(sort(value));
}
