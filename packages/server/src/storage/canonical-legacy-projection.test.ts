import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  readCanonicalLegacyScope,
  resolveCanonicalConnection,
  type CanonicalLegacyReadStore,
} from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import type { PdppRecordEnvelopeInput } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const SRC = (name: string) => `https://registry.pdpp.dev/sources/${name}`;
const METHOD = "test_method";

describe("canonical legacy projection over the real SQLite record store", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;

  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
  });
  afterEach(() => store.close());

  function connect(instance: string, source: string, method = METHOD) {
    store.registerConnection({
      instance,
      sourceId: SRC(source),
      method,
      label: instance,
    });
    return { instance, sourceId: SRC(source), method };
  }

  function put(
    instance: string,
    stream: string,
    rows: Record<string, unknown>[],
    emittedAt = "2026-09-01T00:00:00.000Z",
    method = METHOD,
  ) {
    const envelopes: PdppRecordEnvelopeInput[] = rows.map((data) => ({
      instance,
      stream,
      key: String(data.id),
      data,
      emitted_at: emittedAt,
    }));
    const result = store.ingestBatch(
      envelopes,
      () => "mutable_state",
      () => ["id"],
      { method, generation: 1 },
    );
    expect(result.rejected).toEqual([]);
  }

  const activity = (id: string, day: string, score: number | null = 80) => ({
    id,
    day,
    score,
    steps: 1000,
    contributors: {},
  });

  const writes = () =>
    db.prepare("SELECT total_changes() AS n").get() as { n: number };

  it("reads live Claude inline records through the server's method binding without requiring export blobs", async () => {
    const selected = connect("conn_live", "claude", "anthropic-live");
    put(
      "conn_live",
      "account_plan",
      [{ id: "account_plan", account_id: "org", plan_display_name: "Team" }],
      undefined,
      "anthropic-live",
    );
    put(
      "conn_live",
      "conversations",
      [{ id: "existing", title: "Existing chat", message_count: 1 }],
      undefined,
      "anthropic-live",
    );
    put(
      "conn_live",
      "messages",
      [
        {
          id: "message",
          conversation_id: "existing",
          role: "human",
          content: "Actual message",
          attachments: [],
        },
      ],
      undefined,
      "anthropic-live",
    );
    const before = writes();
    const result = await readCanonicalLegacyScope({
      store,
      scope: "claude.conversations",
      selection: selected,
      profileBy: "method",
      requireClaudeRawBlobs: true,
    });
    expect(result).toMatchObject({
      ok: true,
      envelope: {
        data: {
          source: "live-session",
          conversations: [
            { id: "existing", messages: [{ content: "Actual message" }] },
          ],
        },
      },
    });
    expect(writes()).toEqual(before);
  });

  describe("connection selection", () => {
    it("reads only the selected connection when two accounts share a source", async () => {
      const a = connect("conn_a", "oura");
      const b = connect("conn_b", "oura");
      put("conn_a", "activity", [activity("a1", "2026-08-01")]);
      put("conn_b", "activity", [
        activity("b1", "2026-08-02"),
        activity("b2", "2026-08-03"),
      ]);

      const readA = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
      });
      const readB = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: b,
      });

      expect(
        readA.ok &&
          (readA.envelope.data.days as { id: string }[]).map((d) => d.id),
      ).toEqual(["a1"]);
      expect(
        readB.ok &&
          (readB.envelope.data.days as { id: string }[]).map((d) => d.id),
      ).toEqual(["b1", "b2"]);
      if (readA.ok && readB.ok) expect(readA.revision).not.toBe(readB.revision);
    });

    it("fails when several connections match and none was chosen", () => {
      connect("conn_a", "oura");
      connect("conn_b", "oura");
      expect(
        resolveCanonicalConnection(store, { sourceId: SRC("oura") }),
      ).toMatchObject({
        ok: false,
        reason: "ambiguous_connection",
        candidates: 2,
      });
      expect(
        resolveCanonicalConnection(store, {
          sourceId: SRC("oura"),
          instance: "conn_b",
        }),
      ).toMatchObject({
        ok: true,
        selection: { instance: "conn_b", method: METHOD },
      });
      expect(
        resolveCanonicalConnection(store, { sourceId: SRC("spotify") }),
      ).toMatchObject({
        ok: false,
        reason: "no_connection",
      });
    });

    it("refuses a selection that disagrees with the store binding or the scope's source", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [activity("a1", "2026-08-01")]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "oura.activity",
          selection: { ...a, method: "other" },
        }),
      ).toMatchObject({
        ok: false,
        reason: "connection_unavailable",
        detail: "method_mismatch",
      });
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "oura.activity",
          selection: { ...a, sourceId: SRC("spotify") },
        }),
      ).toMatchObject({ ok: false, reason: "scope_source_mismatch" });
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "oura.activity",
          selection: { ...a, instance: "conn_missing" },
        }),
      ).toMatchObject({
        ok: false,
        reason: "connection_unavailable",
        detail: "not_registered",
      });
      store.deleteConnection("conn_a");
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "oura.activity",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        reason: "connection_unavailable",
        detail: "deleted",
      });
    });

    it("leaves manual and unbound scope files to the file path", async () => {
      const a = connect("conn_a", "oura");
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "manual.notes",
          selection: a,
        }),
      ).toMatchObject({ ok: false, reason: "unbound_scope" });
    });
  });

  describe("paging", () => {
    it("returns every row when the scope spans many pages", async () => {
      const a = connect("conn_a", "oura");
      const rows = Array.from({ length: 23 }, (_, i) =>
        activity(
          `a${String(i).padStart(2, "0")}`,
          `2026-08-${String((i % 28) + 1).padStart(2, "0")}`,
        ),
      );
      put("conn_a", "activity", rows);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
        pageSize: 4,
      });
      expect(read.ok && (read.envelope.data.days as unknown[]).length).toBe(23);
      if (read.ok)
        expect(read.diagnostics.sourceRowCounts).toEqual({ activity: 23 });
    });
  });

  describe("one consistent snapshot", () => {
    // A second connection to the same WAL file is a second writer process.
    let dir: string;
    let fileDb: InstanceType<typeof Database>;
    let fileStore: ReturnType<typeof createSqliteRecordStore>;
    let writerDb: InstanceType<typeof Database>;
    let writerStore: ReturnType<typeof createSqliteRecordStore>;

    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), "canonical-legacy-"));
      fileDb = new Database(join(dir, "ps.sqlite"));
      fileStore = createSqliteRecordStore(fileDb);
      writerDb = new Database(join(dir, "ps.sqlite"));
      writerStore = createSqliteRecordStore(writerDb);
    });
    afterEach(() => {
      writerStore.close();
      fileStore.close();
      rmSync(dir, { recursive: true, force: true });
    });

    const stamp = (i: number) => `2026-09-0${i + 1}T00:00:00.000Z`;
    const ingest = (
      target: typeof fileStore,
      rows: { id: string; score: number; emittedAt: string }[],
    ) =>
      target.ingestBatch(
        rows.map(({ id, score, emittedAt }) => ({
          instance: "conn_a",
          stream: "activity",
          key: id,
          data: activity(id, "2026-08-01", score),
          emitted_at: emittedAt,
        })),
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      );

    function seedSix() {
      fileStore.registerConnection({
        instance: "conn_a",
        sourceId: SRC("oura"),
        method: METHOD,
        label: "a",
      });
      ingest(
        fileStore,
        Array.from({ length: 6 }, (_, i) => ({
          id: `a${i}`,
          score: 10,
          emittedAt: stamp(i),
        })),
      );
      return {
        instance: "conn_a",
        sourceId: SRC("oura"),
        method: METHOD,
      };
    }

    it("does not mix pages when a same-count update at an older emittedAt lands mid-read", async () => {
      const selection = seedSix();
      // Count and newest emittedAt stay the same, so a count/timestamp fence
      // cannot see this write. It rewrites an already-read row (a0) and an
      // unread row (a5) in one batch.
      let injected = false;
      const racing: CanonicalLegacyReadStore = {
        ...fileStore,
        listRecords(stream, options) {
          const page = fileStore.listRecords(stream, options);
          if (!injected) {
            injected = true;
            ingest(writerStore, [
              { id: "a0", score: 99, emittedAt: stamp(0) },
              { id: "a5", score: 99, emittedAt: stamp(5) },
            ]);
          }
          return page;
        },
      };
      const read = await readCanonicalLegacyScope({
        store: racing,
        scope: "oura.activity",
        selection,
        pageSize: 2,
      });
      expect(injected).toBe(true);
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      const scores = (read.envelope.data.days as { score: number }[]).map(
        (d) => d.score,
      );
      // Either every row before the write or every row after it.
      expect(new Set(scores).size).toBe(1);

      // The next read sees the write, with a different revision.
      const next = await readCanonicalLegacyScope({
        store: fileStore,
        scope: "oura.activity",
        selection,
        pageSize: 2,
      });
      expect(next.ok && next.revision).not.toBe(read.revision);
      expect(
        next.ok &&
          (next.envelope.data.days as { score: number }[]).map((d) => d.score),
      ).toEqual([99, 10, 10, 10, 10, 99]);
    });

    it("reads receipts in the same snapshot as the rows", async () => {
      fileStore.registerConnection({
        instance: "conn_a",
        sourceId: SRC("oura"),
        method: METHOD,
        label: "a",
      });
      fileStore.ingestBatch(
        [
          {
            instance: "conn_a",
            stream: "sleep",
            key: "s1",
            data: { id: "s1", day: "2026-08-01" },
            emitted_at: stamp(0),
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      );
      const selection = {
        instance: "conn_a",
        sourceId: SRC("oura"),
        method: METHOD,
      };
      // Another process commits an empty replace with its receipt after the
      // reader has seen the stream's (empty) rows.
      let injected = false;
      const racing: CanonicalLegacyReadStore = {
        ...fileStore,
        listRecords(stream, options) {
          const page = fileStore.listRecords(stream, options);
          if (!injected) {
            injected = true;
            writerStore.replaceStream({
              instance: "conn_a",
              stream: "activity",
              method: METHOD,
              generation: 1,
              emittedAt: stamp(1),
              primaryKey: ["id"],
              envelopes: [],
              sourceCollectedAt: stamp(1),
            });
          }
          return page;
        },
      };
      expect(
        await readCanonicalLegacyScope({
          store: racing,
          scope: "oura.activity",
          selection,
        }),
      ).toMatchObject({ ok: false, reason: "stream_completion_unknown" });
      expect(injected).toBe(true);
      const after = await readCanonicalLegacyScope({
        store: fileStore,
        scope: "oura.activity",
        selection,
      });
      expect(after.ok && after.envelope.collectedAt).toBe(stamp(1));
    });

    it("keeps every stream of a multi-stream scope in the same snapshot", async () => {
      fileStore.registerConnection({
        instance: "conn_a",
        sourceId: SRC("chatgpt"),
        method: METHOD,
        label: "a",
      });
      const conv = (id: string) => ({
        id,
        title: id,
        create_time: "2026-01-01T00:00:00.000Z",
        update_time: "2026-01-01T00:00:00.000Z",
        current_node: `${id}-m`,
        message_count_on_current_branch: 1,
      });
      const msg = (id: string, content: string) => ({
        id: `${id}-m`,
        conversation_id: id,
        parent_id: null,
        children_ids: [],
        role: "user",
        content,
        content_type: "text",
        create_time: "2026-01-01T00:00:00.000Z",
        on_current_branch: true,
      });
      const write = (
        target: typeof fileStore,
        stream: string,
        rows: Record<string, unknown>[],
      ) =>
        target.ingestBatch(
          rows.map((data) => ({
            instance: "conn_a",
            stream,
            key: String(data.id),
            data,
            emitted_at: "2026-09-01T00:00:00.000Z",
          })),
          () => "mutable_state",
          () => ["id"],
          { method: METHOD, generation: 1 },
        );
      write(fileStore, "conversations", [conv("c1")]);
      write(fileStore, "messages", [msg("c1", "before")]);
      let injected = false;
      const racing: CanonicalLegacyReadStore = {
        ...fileStore,
        listRecords(stream, options) {
          const page = fileStore.listRecords(stream, options);
          // After the first stream is read, rewrite the second.
          if (stream === "conversations" && !injected) {
            injected = true;
            write(writerStore, "messages", [msg("c1", "after")]);
          }
          return page;
        },
      };
      const read = await readCanonicalLegacyScope({
        store: racing,
        scope: "chatgpt.conversations",
        selection: {
          instance: "conn_a",
          sourceId: SRC("chatgpt"),
          method: METHOD,
        },
      });
      expect(injected).toBe(true);
      expect(
        read.ok &&
          (
            read.envelope.data.conversations as {
              messages: { content: string }[];
            }[]
          )[0]?.messages[0]?.content,
      ).toBe("before");
    });
  });

  describe("real source shapes", () => {
    it("keeps null and integer Oura scores", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [
        activity("a1", "2026-08-01", null),
        activity("a2", "2026-08-02", 77),
      ]);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
      });
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.envelope).toMatchObject({
        version: "1.0",
        scope: "oura.activity",
      });
      expect(read.envelope.data.days).toEqual([
        expect.objectContaining({ id: "a1", day: "2026-08-01", score: null }),
        expect.objectContaining({ id: "a2", day: "2026-08-02", score: 77 }),
      ]);
    });

    it("keeps Spotify added_at and YouTube watched dates as stored", async () => {
      const sp = connect("conn_sp", "spotify");
      put("conn_sp", "saved_tracks", [
        {
          id: "t1",
          name: "Song",
          artist_names: ["Artist"],
          album_name: "Album",
          duration_ms: 1000,
          added_at: "2026-01-02T03:04:05Z",
          uri: "spotify:track:t1",
          explicit: false,
        },
      ]);
      const saved = await readCanonicalLegacyScope({
        store,
        scope: "spotify.savedTracks",
        selection: sp,
      });
      expect(saved.ok && saved.envelope.data.savedTracks).toEqual([
        expect.objectContaining({
          added_at: "2026-01-02T03:04:05Z",
          name: "Song",
        }),
      ]);

      const yt = connect("conn_yt", "youtube");
      put("conn_yt", "watch_history", [
        {
          id: "h1",
          position: 0,
          watched_date: "2026-09-23",
          video_id: "v1",
          video_url: "https://youtube.com/watch?v=v1",
          video_title: "V",
          channel_title: "C",
          channel_url: null,
          view_count: 4,
          description: null,
        },
        {
          id: "h2",
          position: 1,
          watched_date: null,
          video_id: "v2",
          video_url: "https://youtube.com/watch?v=v2",
          video_title: "V2",
          channel_title: "C",
          channel_url: null,
          view_count: null,
          description: null,
        },
      ]);
      const history = await readCanonicalLegacyScope({
        store,
        scope: "youtube.history",
        selection: yt,
      });
      expect(history.ok && history.envelope.data.history).toEqual([
        expect.objectContaining({
          watchedAt: "2026-09-23",
          watchedAtText: "2026-09-23",
        }),
        expect.objectContaining({ watchedAt: null, watchedAtText: null }),
      ]);
    });
  });

  describe("empty versus rejected", () => {
    const goodConversation = {
      id: "c1",
      title: "t",
      create_time: "2026-01-01T00:00:00.000Z",
      update_time: "2026-01-01T00:00:00.000Z",
      current_node: "m1",
      message_count_on_current_branch: 1,
    };
    const goodMessage = {
      id: "m1",
      conversation_id: "c1",
      parent_id: null,
      children_ids: [],
      role: "user",
      content: "hi",
      content_type: "text",
      create_time: "2026-01-01T00:00:00.000Z",
      on_current_branch: true,
    };
    const badConversation = {
      id: "bad",
      current_node: null,
      message_count_on_current_branch: 1,
    };

    it("does not call a bound stream empty because an unrelated stream has data", async () => {
      const a = connect("conn_a", "chatgpt");
      put("conn_a", "memories", [
        {
          id: "mem1",
          content: "likes tea",
          created_at: "2026-01-01T00:00:00.000Z",
        },
      ]);
      // The store has no per-stream completion marker, so this is unknown,
      // never an empty history.
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "chatgpt.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "unavailable",
        reason: "stream_completion_unknown",
        streams: ["conversations", "messages"],
      });
    });

    it("names only the empty stream when its join stream has rows", async () => {
      const a = connect("conn_a", "chatgpt");
      put("conn_a", "conversations", [goodConversation]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "chatgpt.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["messages"],
      });
    });

    it("does not treat a fully tombstoned stream as proof of an empty fetch", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [activity("a1", "2026-08-01")]);
      put("conn_a", "sleep", [{ id: "s1", day: "2026-08-01" }]);
      store.deleteRecord(
        "conn_a",
        "activity",
        "a1",
        "2026-09-02T00:00:00.000Z",
        "mutable_state",
      );
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "oura.activity",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["activity"],
      });
    });

    it("does not call a connection with no synced rows empty", async () => {
      const a = connect("conn_a", "chatgpt");
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "chatgpt.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "unavailable",
        reason: "no_synced_data",
      });
    });

    it("rejects nonempty rows that all fail instead of serving an empty body", async () => {
      const a = connect("conn_a", "chatgpt");
      put("conn_a", "conversations", [badConversation]);
      put("conn_a", "messages", [goodMessage]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "chatgpt.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "incomplete",
        reason: "all_rows_rejected",
        stream: "conversations",
        sourceRows: 1,
        dropped: 1,
      });
    });

    it("delivers valid peers with explicit omission counts", async () => {
      const a = connect("conn_a", "chatgpt");
      put("conn_a", "conversations", [goodConversation, badConversation]);
      put("conn_a", "messages", [goodMessage]);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "chatgpt.conversations",
        selection: a,
      });
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.complete).toBe(false);
      expect(read.diagnostics.omissions).toEqual([
        expect.objectContaining({ stream: "conversations", count: 1 }),
      ]);
      expect(
        (read.envelope.data.conversations as { id: string }[]).map((c) => c.id),
      ).toEqual(["c1"]);
    });
  });

  describe("rows the legacy schema cannot hold", () => {
    it("never emits Oura rows with invalid days and keeps nullable scores", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [
        activity("good1", "2026-08-01", null),
        activity("nullday", null as unknown as string),
        activity("badday", "2026-13-40"),
        activity("good2", "2026-08-02", 77),
      ]);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
      });
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.complete).toBe(false);
      expect(read.diagnostics.omissions).toEqual([
        {
          stream: "activity",
          count: 2,
          reasons: ["Oura day is missing or not a YYYY-MM-DD date"],
        },
      ]);
      expect(read.envelope.data.days).toEqual([
        expect.objectContaining({
          id: "good1",
          day: "2026-08-01",
          score: null,
        }),
        expect.objectContaining({ id: "good2", day: "2026-08-02", score: 77 }),
      ]);
    });

    it("fails, not empty, when every nonempty Oura row is invalid", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [
        activity("x1", null as unknown as string),
        activity("x2", "yesterday"),
      ]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "oura.activity",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "incomplete",
        reason: "all_rows_rejected",
        stream: "activity",
        sourceRows: 2,
        dropped: 2,
      });
    });

    const track = (id: string, extra: Record<string, unknown> = {}) => ({
      id,
      name: `Song ${id}`,
      artist_names: ["A"],
      album_name: "Album",
      duration_ms: 1,
      added_at: "2026-01-02T03:04:05Z",
      uri: `spotify:track:${id}`,
      explicit: false,
      ...extra,
    });

    it("counts skipped Spotify tracks and keeps added_at on the rest", async () => {
      const sp = connect("conn_sp", "spotify");
      put("conn_sp", "saved_tracks", [
        track("ok"),
        track("noname", { name: null }),
        track("badartists", { artist_names: [1] }),
      ]);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "spotify.savedTracks",
        selection: sp,
      });
      expect(read.ok).toBe(true);
      if (!read.ok) return;
      expect(read.complete).toBe(false);
      expect(read.diagnostics.omissions).toEqual([
        expect.objectContaining({ stream: "saved_tracks", count: 2 }),
      ]);
      expect(read.envelope.data.savedTracks).toEqual([
        expect.objectContaining({
          name: "Song ok",
          added_at: "2026-01-02T03:04:05Z",
        }),
      ]);
    });

    it("fails when every Spotify track is skipped", async () => {
      const sp = connect("conn_sp", "spotify");
      put("conn_sp", "saved_tracks", [track("a", { name: null })]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "spotify.savedTracks",
          selection: sp,
        }),
      ).toMatchObject({
        ok: false,
        status: "incomplete",
        reason: "all_rows_rejected",
        stream: "saved_tracks",
        sourceRows: 1,
        dropped: 1,
      });
    });
  });

  describe("joins", () => {
    const profile = {
      id: "org1",
      organization_id: "org1",
      full_name: "N",
      plan: null,
      name_source: "none",
      metadata_status: "valid",
    };
    const conversation = (count: number) => ({
      id: "cv1",
      title: "T",
      create_time: null,
      update_time: null,
      project_id: null,
      message_count: count,
      is_starred: false,
    });
    const message = (id: string) => ({
      id,
      conversation_id: "cv1",
      role: "user",
      parent_id: null,
      content: "hi",
      create_time: "2026-01-01T00:00:00.000Z",
      update_time: null,
      attachments: [],
    });

    it("joins messages to their conversation within the selected connection", async () => {
      const a = connect("conn_a", "claude");
      put("conn_a", "account_profile", [profile]);
      put("conn_a", "conversations", [conversation(1)]);
      put("conn_a", "messages", [message("m1")]);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "claude.conversations",
        selection: a,
      });
      expect(read.ok).toBe(true);
      if (read.ok)
        expect(
          (read.envelope.data.conversations as { messages: unknown[] }[])[0]
            ?.messages,
        ).toHaveLength(1);
    });

    it("reports incomplete, not empty or short, when the detail rows are missing", async () => {
      const a = connect("conn_a", "claude");
      put("conn_a", "account_profile", [profile]);
      put("conn_a", "conversations", [conversation(2)]);
      put("conn_a", "messages", [message("m1")]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "claude.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "incomplete",
        reason: "projection_rejected",
        error: { kind: "incomplete_scope" },
      });
    });

    it("never joins detail rows from another connection", async () => {
      const a = connect("conn_a", "claude");
      connect("conn_b", "claude");
      put("conn_a", "account_profile", [profile]);
      put("conn_a", "conversations", [conversation(1)]);
      put("conn_a", "messages", [
        { ...message("m0"), conversation_id: "elsewhere" },
      ]);
      put("conn_b", "messages", [message("m1")]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "claude.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "incomplete",
        reason: "projection_rejected",
      });
    });

    it("fails explicitly for blob-backed rows instead of serving them empty", async () => {
      const a = connect("conn_a", "claude");
      put("conn_a", "account_profile", [profile]);
      put("conn_a", "conversations", [conversation(1)]);
      const blob = store.storeBlobBytesForInstance({
        instance: "conn_a",
        method: METHOD,
        generation: 1,
        bytes: new TextEncoder().encode("a long message body"),
        mimeType: "text/plain",
      });
      put("conn_a", "messages", [
        {
          ...message("m1"),
          content: null,
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: "text/plain",
            size_bytes: blob.sizeBytes,
          },
        },
      ]);
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "claude.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        status: "unavailable",
        reason: "blob_backed_records_unsupported",
        stream: "messages",
        recordCount: 1,
      });
    });
  });

  describe("repeat reads", () => {
    it("is read-only and returns identical bytes and revision until the source changes", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [activity("a1", "2026-08-01")]);
      const calls: string[] = [];
      const spy = new Proxy(store, {
        get(target, key, receiver) {
          const value = Reflect.get(target, key, receiver);
          return typeof value === "function"
            ? (...args: unknown[]) => (
                calls.push(String(key)),
                value.apply(target, args)
              )
            : value;
        },
      });
      const before = writes().n;
      const first = await readCanonicalLegacyScope({
        store: spy,
        scope: "oura.activity",
        selection: a,
      });
      const second = await readCanonicalLegacyScope({
        store: spy,
        scope: "oura.activity",
        selection: a,
      });
      expect(writes().n).toBe(before);
      expect(new Set(calls)).toEqual(
        new Set([
          "readSnapshot",
          "getInstanceBinding",
          "listStreams",
          "listStreamCompletions",
          "listRecords",
        ]),
      );
      expect(JSON.stringify(second)).toBe(JSON.stringify(first));

      // Unrelated connection writes do not move this view; its own writes do.
      connect("conn_other", "oura");
      put("conn_other", "activity", [activity("o1", "2026-08-05")]);
      const unrelated = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
      });
      expect(unrelated.ok && first.ok && unrelated.revision).toBe(
        first.ok && first.revision,
      );
      put(
        "conn_a",
        "activity",
        [activity("a2", "2026-08-02")],
        "2026-09-03T00:00:00.000Z",
      );
      const changed = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
      });
      expect(changed.ok && first.ok && changed.revision).not.toBe(
        first.ok && first.revision,
      );
    });

    it("turns a partial first read into the complete view once the source is repaired", async () => {
      const a = connect("conn_a", "chatgpt");
      const conv = (id: string) => ({
        id,
        title: id,
        create_time: "2026-01-01T00:00:00.000Z",
        update_time: "2026-01-01T00:00:00.000Z",
        current_node: `${id}-m`,
        message_count_on_current_branch: 1,
      });
      const msg = (id: string) => ({
        id: `${id}-m`,
        conversation_id: id,
        parent_id: null,
        children_ids: [],
        role: "user",
        content: "hi",
        content_type: "text",
        create_time: "2026-01-01T00:00:00.000Z",
        on_current_branch: true,
      });
      put("conn_a", "conversations", [conv("good"), conv("gap")]);
      put("conn_a", "messages", [msg("good")]);

      const partial = await readCanonicalLegacyScope({
        store,
        scope: "chatgpt.conversations",
        selection: a,
      });
      expect(partial.ok && partial.complete).toBe(false);
      expect(
        partial.ok && (partial.envelope.data.conversations as unknown[]).length,
      ).toBe(1);

      put("conn_a", "messages", [msg("gap")], "2026-09-04T00:00:00.000Z");
      const complete = await readCanonicalLegacyScope({
        store,
        scope: "chatgpt.conversations",
        selection: a,
      });
      expect(complete.ok && complete.complete).toBe(true);
      expect(
        complete.ok &&
          (complete.envelope.data.conversations as unknown[]).length,
      ).toBe(2);
      expect(complete.ok && partial.ok && complete.revision).not.toBe(
        partial.ok && partial.revision,
      );
    });

    it("excludes tombstoned rows", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "activity", [
        activity("a1", "2026-08-01"),
        activity("a2", "2026-08-02"),
      ]);
      expect(
        store.deleteRecord(
          "conn_a",
          "activity",
          "a2",
          "2026-09-02T00:00:00.000Z",
          "mutable_state",
        ),
      ).toBe(true);
      const read = await readCanonicalLegacyScope({
        store,
        scope: "oura.activity",
        selection: a,
      });
      expect(
        read.ok &&
          (read.envelope.data.days as { id: string }[]).map((d) => d.id),
      ).toEqual(["a1"]);
    });
  });

  describe("completion receipts from a full replace", () => {
    const COLLECTED = "2026-09-10T08:30:00+02:00";
    const COLLECTED_ISO = "2026-09-10T06:30:00.000Z";

    function replace(
      instance: string,
      stream: string,
      rows: Record<string, unknown>[],
      sourceCollectedAt?: string,
      binding: { method?: string; generation?: number } = {},
    ) {
      return store.replaceStream({
        instance,
        stream,
        method: binding.method ?? METHOD,
        generation: binding.generation ?? 1,
        emittedAt: "2026-09-10T07:00:00.000Z",
        primaryKey: ["id"],
        envelopes: rows.map((data) => ({
          instance,
          stream,
          key: String(data.id),
          data,
          emitted_at: "2026-09-10T07:00:00.000Z",
        })),
        ...(sourceCollectedAt === undefined ? {} : { sourceCollectedAt }),
      });
    }

    const receipts = () =>
      db
        .prepare(
          "SELECT instance, stream, method, generation, source_collected_at FROM pdpp_stream_completion ORDER BY instance, stream",
        )
        .all();

    const readOura = (selection: {
      instance: string;
      sourceId: string;
      method: string;
    }) =>
      readCanonicalLegacyScope({ store, scope: "oura.activity", selection });

    it("serves a genuine empty replace as an empty stream stamped with the source time", async () => {
      const a = connect("conn_a", "oura");
      expect(replace("conn_a", "activity", [], COLLECTED).applied).toBe(true);

      const read = await readOura(a);
      expect(read).toMatchObject({ ok: true, complete: true });
      if (!read.ok) return;
      expect(read.envelope.data.days).toEqual([]);
      expect(read.envelope.collectedAt).toBe(COLLECTED_ISO);
      expect(read.diagnostics.sourceRowCounts).toEqual({ activity: 0 });
    });

    it("serves an empty stream next to a nonempty one only with that stream's own receipt", async () => {
      const a = connect("conn_a", "chatgpt");
      const conversation = {
        id: "c1",
        title: "t",
        create_time: "2026-01-01T00:00:00.000Z",
        update_time: "2026-01-01T00:00:00.000Z",
        current_node: null,
        message_count_on_current_branch: 0,
      };
      replace("conn_a", "conversations", [conversation], COLLECTED);
      // The parent's receipt and row count say nothing about messages.
      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "chatgpt.conversations",
          selection: a,
        }),
      ).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["messages"],
      });
    });

    it("keeps a never-collected stream unavailable", async () => {
      const a = connect("conn_a", "oura");
      replace("conn_a", "sleep", [], COLLECTED);
      expect(await readOura(a)).toMatchObject({
        ok: false,
        reason: "no_synced_data",
      });
      put("conn_a", "sleep", [{ id: "s1", day: "2026-08-01" }]);
      expect(await readOura(a)).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["activity"],
      });
    });

    it("writes no receipt for a replace without a source time and drops the older one", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "sleep", [{ id: "s1", day: "2026-08-01" }]);
      expect(replace("conn_a", "activity", []).applied).toBe(true);
      expect(receipts()).toEqual([]);
      expect(await readOura(a)).toMatchObject({
        reason: "stream_completion_unknown",
      });

      replace("conn_a", "activity", [], COLLECTED);
      expect(receipts()).toHaveLength(1);
      // An old client's later replace is a newer collection with no time:
      // the older receipt must not stand as proof of it.
      expect(replace("conn_a", "activity", []).applied).toBe(true);
      expect(receipts()).toEqual([]);
      expect(await readOura(a)).toMatchObject({
        reason: "stream_completion_unknown",
      });
    });

    it("refuses an invalid source time and keeps the rows and the prior receipt", () => {
      connect("conn_a", "oura");
      replace("conn_a", "activity", [activity("a1", "2026-08-01")], COLLECTED);
      const before = {
        receipts: receipts(),
        rows: db.prepare("SELECT * FROM pdpp_records").all(),
      };
      for (const bad of [
        "",
        "yesterday",
        "2026-09-10",
        "2026-09-10 08:30:00Z",
        "2026-02-30T00:00:00Z",
        "2026-09-10T24:00:00Z",
        "2026-09-10T08:30:00+25:00",
      ]) {
        expect(() => replace("conn_a", "activity", [], bad)).toThrow(
          "invalid_source_collected_at",
        );
      }
      expect({
        receipts: receipts(),
        rows: db.prepare("SELECT * FROM pdpp_records").all(),
      }).toEqual(before);
    });

    it("rolls back rows and the prior receipt together when the replace is rejected", () => {
      connect("conn_a", "oura");
      replace("conn_a", "activity", [activity("a1", "2026-08-01")], COLLECTED);
      const before = {
        receipts: receipts(),
        rows: db.prepare("SELECT * FROM pdpp_records").all(),
      };
      const rejected = replace(
        "conn_a",
        "activity",
        [activity("a2", "2026-08-02"), { day: "2026-08-03" }],
        "2026-09-11T00:00:00Z",
      );
      expect(rejected.applied).toBe(false);
      expect(() =>
        replace("conn_a", "activity", [], "2026-09-11T00:00:00Z", {
          generation: 2,
        }),
      ).toThrow("binding_generation_mismatch");
      expect(() =>
        replace("conn_a", "activity", [], "2026-09-11T00:00:00Z", {
          method: "other_method",
        }),
      ).toThrow("instance_bound_to_other_method");
      expect({
        receipts: receipts(),
        rows: db.prepare("SELECT * FROM pdpp_records").all(),
      }).toEqual(before);

      // A fault after the rows are written, at the receipt insert, rolls the
      // rows and the dropped prior receipt back together.
      db.exec(`CREATE TRIGGER fail_receipt BEFORE INSERT ON pdpp_stream_completion
        BEGIN SELECT RAISE(ABORT, 'injected receipt fault'); END`);
      expect(() =>
        replace(
          "conn_a",
          "activity",
          [activity("a2", "2026-08-02")],
          "2026-09-11T00:00:00Z",
        ),
      ).toThrow("injected receipt fault");
      db.exec("DROP TRIGGER fail_receipt");
      expect({
        receipts: receipts(),
        rows: db.prepare("SELECT * FROM pdpp_records").all(),
      }).toEqual(before);
    });

    it("erases receipts on reset and delete, and ignores a receipt from another generation or method", async () => {
      const a = connect("conn_a", "oura");
      replace("conn_a", "activity", [], COLLECTED);
      store.resetInstanceBinding({
        instance: "conn_a",
        expectedMethod: METHOD,
        expectedGeneration: 1,
        nextMethod: METHOD,
      });
      expect(receipts()).toEqual([]);
      expect(await readOura(a)).toMatchObject({ reason: "no_synced_data" });

      // A row left behind by another generation or method is not evidence.
      const insert = db.prepare(
        "INSERT INTO pdpp_stream_completion (instance, stream, method, generation, source_collected_at, write_seq, live_count) VALUES (?, 'activity', ?, ?, ?, 0, 0)",
      );
      insert.run("conn_a", METHOD, 1, COLLECTED);
      expect(await readOura(a)).toMatchObject({ reason: "no_synced_data" });
      db.prepare("DELETE FROM pdpp_stream_completion").run();
      insert.run("conn_a", "other_method", 2, COLLECTED);
      expect(await readOura(a)).toMatchObject({ reason: "no_synced_data" });
      db.prepare("DELETE FROM pdpp_stream_completion").run();

      replace("conn_a", "activity", [], COLLECTED, { generation: 2 });
      expect((await readOura(a)).ok).toBe(true);
      store.deleteConnection("conn_a");
      expect(receipts()).toEqual([]);
    });

    it("does not let incremental writes or deletes stand in for a full refresh", async () => {
      const a = connect("conn_a", "oura");
      put("conn_a", "sleep", [{ id: "s1", day: "2026-08-01" }]);

      // An empty or unchanged ingest is not a completion.
      store.ingestBatch(
        [],
        () => "mutable_state",
        () => ["id"],
        {
          method: METHOD,
          generation: 1,
        },
      );
      expect(receipts()).toEqual([]);

      replace("conn_a", "activity", [activity("a1", "2026-08-01")], COLLECTED);
      expect(receipts()).toHaveLength(1);
      // An unchanged replay writes nothing, so the receipt still describes
      // the stream.
      put(
        "conn_a",
        "activity",
        [activity("a1", "2026-08-01")],
        "2026-09-10T07:00:00.000Z",
      );
      expect(receipts()).toHaveLength(1);

      // A changed ingest, then a tombstone, empties the stream outside any
      // replace: that is not a collected empty stream.
      put("conn_a", "activity", [activity("a1", "2026-08-01", 90)]);
      expect(receipts()).toEqual([]);
      replace(
        "conn_a",
        "activity",
        [activity("a1", "2026-08-01", 90)],
        COLLECTED,
      );
      store.deleteRecord(
        "conn_a",
        "activity",
        "a1",
        "2026-09-12T00:00:00.000Z",
        "mutable_state",
      );
      expect(receipts()).toEqual([]);
      expect(await readOura(a)).toMatchObject({
        reason: "stream_completion_unknown",
        streams: ["activity"],
      });

      // A rejected ingest writes no receipt either.
      const rejected = store.ingestBatch(
        [
          {
            instance: "conn_a",
            stream: "activity",
            key: "x",
            data: { day: "2026-08-02" },
            emitted_at: "2026-09-12T00:00:00.000Z",
          },
        ],
        () => "mutable_state",
        () => ["id"],
        { method: METHOD, generation: 1 },
      );
      expect(rejected.rejected).toHaveLength(1);
      expect(receipts()).toEqual([]);
    });

    it("never lends one account's receipt to another", async () => {
      connect("conn_a", "oura");
      const b = connect("conn_b", "oura");
      replace("conn_a", "activity", [], COLLECTED);
      put("conn_b", "sleep", [{ id: "s1", day: "2026-08-01" }]);
      expect(await readOura(b)).toMatchObject({
        reason: "stream_completion_unknown",
        streams: ["activity"],
      });
    });

    it("keeps bytes and revision stable across wall-clock changes and unrelated writes", async () => {
      const a = connect("conn_a", "oura");
      replace("conn_a", "activity", [], COLLECTED);
      vi.useFakeTimers();
      try {
        vi.setSystemTime(new Date("2030-01-01T00:00:00.000Z"));
        const first = await readOura(a);
        vi.setSystemTime(new Date("2031-06-01T00:00:00.000Z"));
        connect("conn_b", "oura");
        replace("conn_b", "activity", [], "2026-09-20T00:00:00Z");
        put("conn_a", "sleep", [{ id: "s1", day: "2026-08-01" }]);
        const second = await readOura(a);
        expect(first.ok && first.envelope.collectedAt).toBe(COLLECTED_ISO);
        expect(JSON.stringify(second)).toBe(JSON.stringify(first));

        // A new collection of this stream is new evidence.
        replace("conn_a", "activity", [], "2026-09-21T00:00:00Z");
        const third = await readOura(a);
        expect(third.ok && third.envelope.collectedAt).toBe(
          "2026-09-21T00:00:00.000Z",
        );
        expect(third.ok && first.ok && third.revision).not.toBe(
          first.ok && first.revision,
        );
      } finally {
        vi.useRealTimers();
      }
    });

    describe("freshness of a nonempty stream", () => {
      const SEPT_1 = "2026-09-01T09:00:00.000Z";
      const SEPT_11 = "2026-09-11T09:00:00.000Z";

      /** One full replace whose rows are stamped with the collection time. */
      function collect(
        instance: string,
        stream: string,
        rows: Record<string, unknown>[],
        collectedAt: string,
        /** `null` sends no source time, like an older client. */
        sourceCollectedAt: string | null = collectedAt,
      ) {
        const result = store.replaceStream({
          instance,
          stream,
          method: METHOD,
          generation: 1,
          emittedAt: collectedAt,
          primaryKey: ["id"],
          envelopes: rows.map((data) => ({
            instance,
            stream,
            key: String(data.id),
            data,
            emitted_at: collectedAt,
          })),
          ...(sourceCollectedAt === null ? {} : { sourceCollectedAt }),
        });
        expect(result.applied).toBe(true);
        return result;
      }

      const nativeState = () => ({
        rows: db.prepare("SELECT * FROM pdpp_records ORDER BY 1, 2, 3").all(),
        history: db
          .prepare("SELECT * FROM pdpp_record_changes ORDER BY id")
          .all(),
      });

      const days = [activity("a1", "2026-08-01"), activity("a2", "2026-08-02")];

      it("advances collectedAt and revision when an unchanged full replace is collected again", async () => {
        const a = connect("conn_a", "oura");
        collect("conn_a", "activity", days, SEPT_1);
        const first = await readOura(a);
        expect(first.ok && first.envelope.collectedAt).toBe(SEPT_1);
        const native = nativeState();

        expect(collect("conn_a", "activity", days, SEPT_11)).toMatchObject({
          accepted: 0,
          unchanged: 2,
          deleted: 0,
        });
        // The unchanged rows keep their own versions and emittedAt.
        expect(nativeState()).toEqual(native);

        const second = await readOura(a);
        expect(second).toMatchObject({ ok: true, complete: true });
        if (!first.ok || !second.ok) return;
        expect(second.envelope.collectedAt).toBe(SEPT_11);
        expect(second.envelope.data).toEqual(first.envelope.data);
        expect(second.revision).not.toBe(first.revision);
      });

      it("keeps bytes and revision when the same collection is replayed, also after another account's writes", async () => {
        const a = connect("conn_a", "oura");
        connect("conn_b", "oura");
        collect("conn_a", "activity", days, SEPT_11);
        const first = await readOura(a);

        // Other accounts move the shared write clock.
        collect("conn_b", "activity", [activity("b1", "2026-08-05")], SEPT_11);
        collect("conn_a", "activity", days, SEPT_11);
        put("conn_b", "activity", [activity("b1", "2026-08-05", 10)]);
        expect(JSON.stringify(await readOura(a))).toBe(JSON.stringify(first));
      });

      it("uses only a receipt of the current method and generation that counts the live rows", async () => {
        const a = connect("conn_a", "oura");
        collect("conn_a", "activity", days, SEPT_1);
        const insert = db.prepare(
          "INSERT INTO pdpp_stream_completion (instance, stream, method, generation, source_collected_at, write_seq, live_count) VALUES ('conn_a', 'activity', ?, ?, ?, 0, ?)",
        );
        for (const [method, generation, liveCount] of [
          ["other_method", 1, 2],
          [METHOD, 2, 2],
          [METHOD, 1, 1],
          [METHOD, 1, 3],
        ] as const) {
          db.prepare("DELETE FROM pdpp_stream_completion").run();
          insert.run(method, generation, SEPT_11, liveCount);
          const read = await readOura(a);
          expect(read.ok && read.envelope.collectedAt).toBe(SEPT_1);
        }
      });

      it("falls back to row timestamps for an older client that sends no source time", async () => {
        const a = connect("conn_a", "oura");
        collect("conn_a", "activity", days, SEPT_1, null);
        const first = await readOura(a);
        expect(first.ok && first.envelope.collectedAt).toBe(SEPT_1);

        // A receipted collection, then an old client's unchanged replace:
        // the receipt is gone and nothing claims the newer collection.
        collect("conn_a", "activity", days, SEPT_11);
        collect("conn_a", "activity", days, "2026-09-20T09:00:00.000Z", null);
        expect(receipts()).toEqual([]);
        expect(JSON.stringify(await readOura(a))).toBe(JSON.stringify(first));
      });

      it("takes the newest stream collection across nonempty and empty streams", async () => {
        const a = connect("conn_a", "claude");
        const profile = {
          id: "org1",
          organization_id: "org1",
          full_name: "N",
          plan: null,
          name_source: "none",
          metadata_status: "valid",
        };
        const conversation = {
          id: "cv1",
          title: "T",
          create_time: null,
          update_time: null,
          project_id: null,
          message_count: 0,
          is_starred: false,
        };
        const readClaude = () =>
          readCanonicalLegacyScope({
            store,
            scope: "claude.conversations",
            selection: a,
          });
        collect("conn_a", "account_profile", [profile], SEPT_1);
        collect("conn_a", "conversations", [conversation], SEPT_1);
        collect("conn_a", "messages", [], "2026-09-05T09:00:00.000Z");
        const first = await readClaude();
        expect(first.ok && first.envelope.collectedAt).toBe(
          "2026-09-05T09:00:00.000Z",
        );

        collect("conn_a", "conversations", [conversation], SEPT_11);
        const second = await readClaude();
        expect(second.ok && second.envelope.collectedAt).toBe(SEPT_11);
        expect(second.ok && first.ok && second.revision).not.toBe(
          first.ok && first.revision,
        );
      });

      it("keeps omission diagnostics: a receipt does not prove every row mapped", async () => {
        const a = connect("conn_a", "oura");
        collect(
          "conn_a",
          "activity",
          [activity("a1", "2026-08-01"), { ...activity("a2", "x"), day: null }],
          SEPT_1,
        );
        collect(
          "conn_a",
          "activity",
          [activity("a1", "2026-08-01"), { ...activity("a2", "x"), day: null }],
          SEPT_11,
        );
        const read = await readOura(a);
        expect(read).toMatchObject({
          ok: true,
          complete: false,
          envelope: { collectedAt: SEPT_11 },
          diagnostics: { omissions: [{ stream: "activity", count: 1 }] },
        });
      });
    });
  });

  describe("ChatGPT read edge cases", () => {
    const COLLECTED = "2026-09-10T06:30:00.000Z";

    function replace(
      instance: string,
      stream: string,
      rows: Record<string, unknown>[],
      withReceipt = true,
    ) {
      return store.replaceStream({
        instance,
        stream,
        method: METHOD,
        generation: 1,
        emittedAt: COLLECTED,
        primaryKey: ["id"],
        envelopes: rows.map((data) => ({
          instance,
          stream,
          key: String(data.id),
          data,
          emitted_at: COLLECTED,
        })),
        ...(withReceipt ? { sourceCollectedAt: COLLECTED } : {}),
      });
    }

    const conversation = (
      id: string,
      update_time: string,
      extras: Record<string, unknown> = {},
    ) => ({
      id,
      title: id,
      create_time: "2026-09-01T00:00:00.000Z",
      update_time,
      current_node: null,
      message_count_on_current_branch: 0,
      ...extras,
    });

    it("returns valid peers with omissions for a bad timestamp and missing title", async () => {
      const selection = connect("conn_chatgpt", "chatgpt");
      replace("conn_chatgpt", "conversations", [
        conversation("valid", "2026-09-03T00:00:00.000Z"),
        conversation("bad-time", "2026-09-02T00:00:00.000Z", {
          create_time: 17,
        }),
        conversation("missing-title", "2026-09-01T00:00:00.000Z", {
          title: undefined,
        }),
      ]);
      replace("conn_chatgpt", "messages", []);

      const read = await readCanonicalLegacyScope({
        store,
        scope: "chatgpt.conversations",
        selection,
      });

      expect(read).toMatchObject({
        ok: true,
        complete: false,
        envelope: {
          data: {
            conversations: [
              { id: "valid", title: "valid", messages: [] },
              { id: "missing-title", title: "Untitled", messages: [] },
            ],
            total: 2,
          },
        },
        diagnostics: {
          sourceRowCounts: { conversations: 3, messages: 0 },
          omissions: [
            {
              stream: "conversations",
              count: 1,
              reasons: [
                "Conversation timestamps must be strings, null, or absent",
              ],
            },
          ],
        },
      });
    });

    it("returns stream_completion_unknown for an empty memories stream without its receipt", async () => {
      const selection = connect("conn_memories", "chatgpt");
      // Activity on another bound source stream rules out the no-data case,
      // but cannot prove that this empty memories stream completed.
      replace(
        "conn_memories",
        "conversations",
        [conversation("other-stream", "2026-09-01T00:00:00.000Z")],
        false,
      );
      replace("conn_memories", "memories", [], false);

      expect(
        await readCanonicalLegacyScope({
          store,
          scope: "chatgpt.memories",
          selection,
        }),
      ).toMatchObject({
        ok: false,
        reason: "stream_completion_unknown",
        streams: ["memories"],
      });
    });

    it("orders reverse-supplied conversations newest update first", async () => {
      const selection = connect("conn_order", "chatgpt");
      replace("conn_order", "conversations", [
        conversation("older", "2026-09-01T00:00:00.000Z"),
        conversation("newer", "2026-09-03T00:00:00.000Z"),
      ]);
      replace("conn_order", "messages", []);

      const read = await readCanonicalLegacyScope({
        store,
        scope: "chatgpt.conversations",
        selection,
      });

      expect(
        read.ok &&
          (read.envelope.data.conversations as { id: string }[]).map(
            ({ id }) => id,
          ),
      ).toEqual(["newer", "older"]);
    });
  });
});
