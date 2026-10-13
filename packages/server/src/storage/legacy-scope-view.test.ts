import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createLegacyScopeView } from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";
import { createLegacyScopeViewStore } from "./legacy-scope-view-store.js";

const SRC = (name: string) => `https://registry.pdpp.dev/sources/${name}`;
const METHOD = "test_method";

describe("legacy scope view over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  let view: ReturnType<typeof createLegacyScopeView>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
    view = createLegacyScopeView({
      store: createLegacyScopeViewStore(db, store),
      configuredMethods: () => [METHOD],
    });
  });
  afterEach(() => store.close());

  function connect(instance: string, source: string) {
    store.registerConnection({
      instance,
      sourceId: SRC(source),
      method: METHOD,
      label: instance,
    });
  }

  const activity = (id: string, emittedAt: string) => ({
    instance: "",
    stream: "activity",
    key: id,
    data: { id, day: "2026-09-01", score: 80 },
    emitted_at: emittedAt,
  });

  function ingest(instance: string, ids: string[], emittedAt: string) {
    const result = store.ingestBatch(
      ids.map((id) => ({ ...activity(id, emittedAt), instance })),
      () => "mutable_state",
      () => ["id"],
      { method: METHOD, generation: 1 },
    );
    expect(result.rejected).toEqual([]);
  }

  function replace(instance: string, ids: string[], collectedAt: string) {
    store.replaceStream({
      instance,
      stream: "activity",
      method: METHOD,
      generation: 1,
      emittedAt: "2026-09-10T07:00:00.000Z",
      primaryKey: ["id"],
      envelopes: ids.map((id) => ({
        ...activity(id, "2026-09-10T07:00:00.000Z"),
        instance,
      })),
      sourceCollectedAt: collectedAt,
    });
  }

  it("refuses one scope bound by two sources that both hold the owner's data", async () => {
    connect("conn_a", "oura");
    connect("conn_b", "oura-browser");
    ingest("conn_a", ["a1"], "2026-09-01T00:00:00.000Z");
    ingest("conn_b", ["b1"], "2026-09-01T00:00:00.000Z");

    expect(await view.readLatest("oura.activity")).toEqual({
      kind: "refused",
      refusal: {
        status: "unavailable",
        reason: "ambiguous_connection",
        candidates: 2,
      },
    });
    expect(view.listingFor("oura.activity")).toEqual({ kind: "refused" });
  });

  it("reads the evidenced source when the other source's connection never held data", async () => {
    connect("conn_a", "oura");
    connect("conn_b", "oura-browser");
    ingest("conn_a", ["a1"], "2026-09-01T00:00:00.000Z");

    const read = await view.readLatest("oura.activity");
    expect(read.kind).toBe("canonical");
    expect(read.kind === "canonical" && read.envelope.data).toEqual({
      days: [{ id: "a1", day: "2026-09-01", score: 80 }],
    });
  });

  it("leaves a scope to the file path until a connection holds data", async () => {
    connect("conn_a", "oura");
    expect(await view.readLatest("oura.activity")).toEqual({ kind: "file" });
    expect(await view.readLatest("notes.manual")).toEqual({ kind: "file" });
    expect(view.listingFor("oura.activity")).toEqual({ kind: "file" });
  });

  it("lists the same collectedAt a read returns", async () => {
    connect("conn_a", "oura");
    const agree = async () => {
      const read = await view.readLatest("oura.activity");
      const listed = view.listingFor("oura.activity");
      expect(read.kind).toBe("canonical");
      expect(listed).toEqual({
        kind: "canonical",
        collectedAt: read.kind === "canonical" && read.envelope.collectedAt,
      });
    };

    // Rows only: the newest row time.
    ingest("conn_a", ["a1"], "2026-09-01T00:00:00.000Z");
    ingest("conn_a", ["a2"], "2026-09-03T00:00:00.000Z");
    await agree();
    // A receipt: the producer's collection time, older than the rows.
    replace("conn_a", ["a1", "a2"], "2026-09-09T00:00:00.000Z");
    await agree();
    // A later ingest leaves the receipt's live count stale: rows again.
    ingest("conn_a", ["a3"], "2026-09-12T00:00:00.000Z");
    await agree();
  });
});
