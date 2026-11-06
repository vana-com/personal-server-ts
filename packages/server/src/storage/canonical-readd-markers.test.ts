import Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import type { ScopeTombstone } from "@opendatalabs/personal-server-ts-core/sync";
import {
  canonicalReaddVersion,
  createCanonicalReaddMarkers,
} from "./canonical-readd-markers.js";

const SCOPE = "chatgpt.conversations";
const STREAMS = ["conversations", "messages"] as const;
const INSTANCE = "chatgpt:0xowner";

function setup(known: Record<string, ScopeTombstone | null> = {}) {
  const db = new Database(":memory:");
  const history = new Map<string, ScopeTombstone>();
  const deletions = {
    knownDeletion: (scope: string) => known[scope] ?? null,
    deletionHistory: {
      remember: (scope: string, tombstone: ScopeTombstone) =>
        void history.set(scope, tombstone),
      get: (scope: string) => history.get(scope) ?? null,
    },
  };
  const markers = createCanonicalReaddMarkers(db, deletions);
  const receipt = (stream: string, generation = 1, writeSeq = 10) => ({
    instance: INSTANCE,
    stream,
    method: "chatgpt",
    generation,
    writeSeq,
  });
  /** The scope is deleted now: the tracker and the history both hold it. */
  const deleteNow = (tombstone: ScopeTombstone) => {
    known[SCOPE] = tombstone;
    history.set(SCOPE, tombstone);
  };
  return { db, history, markers, receipt, deleteNow };
}

describe("canonical re-add markers", () => {
  it("acknowledges nothing while no tombstone is known", () => {
    const { db, markers, receipt } = setup();
    const intent = markers.acknowledge("chatgpt", STREAMS);
    expect(intent.acknowledged).toEqual([]);
    markers.record(
      intent,
      STREAMS.map((stream) => receipt(stream)),
    );
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 1, STREAMS)).toBeNull();
  });

  it("never acknowledges a tombstone of unknown version", () => {
    const { db, markers, receipt } = setup({
      [SCOPE]: { deletedAt: "2026-10-14T00:00:00Z", version: null },
    });
    const intent = markers.acknowledge("chatgpt", STREAMS);
    expect(intent.acknowledged).toEqual([]);
    markers.record(
      intent,
      STREAMS.map((stream) => receipt(stream)),
    );
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 1, STREAMS)).toBeNull();
  });

  it("requires a marker for every stream backing the scope", () => {
    const { db, deleteNow, markers, receipt } = setup();
    deleteNow({ deletedAt: "2026-10-14T00:00:00Z", version: "4" });
    const intent = markers.acknowledge("chatgpt", ["conversations"]);
    markers.record(intent, [receipt("conversations")]);
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 1, STREAMS)).toBeNull();
    expect(
      canonicalReaddVersion(db, SCOPE, INSTANCE, 1, ["conversations"]),
    ).toBe("4");

    markers.record(markers.acknowledge("chatgpt", ["messages"]), [
      receipt("messages"),
    ]);
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 1, STREAMS)).toBe("4");
  });

  it("answers the lowest acknowledged version across streams and never lowers one", () => {
    const { db, deleteNow, markers, receipt } = setup();
    deleteNow({ deletedAt: "2026-10-14T00:00:00Z", version: "2" });
    markers.record(
      markers.acknowledge("chatgpt", STREAMS),
      STREAMS.map((stream) => receipt(stream)),
    );
    deleteNow({ deletedAt: "2026-10-20T00:00:00Z", version: "5" });
    markers.record(markers.acknowledge("chatgpt", ["messages"]), [
      receipt("messages"),
    ]);
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 1, STREAMS)).toBe("2");

    deleteNow({ deletedAt: "2026-10-14T00:00:00Z", version: "2" });
    markers.record(markers.acknowledge("chatgpt", ["messages"]), [
      receipt("messages"),
    ]);
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 1, ["messages"])).toBe(
      "5",
    );
  });

  it("acknowledges only the tombstone the scope currently stands under, never the history alone", () => {
    // The gateway shows the scope live again (a file re-add elsewhere): the
    // durable history keeps tombstone 3, but the write is not on top of it.
    const live = setup();
    live.history.set(SCOPE, {
      deletedAt: "2026-10-14T00:00:00Z",
      version: "3",
    });
    expect(live.markers.acknowledge("chatgpt", STREAMS).acknowledged).toEqual(
      [],
    );

    const deleted = setup({
      [SCOPE]: { deletedAt: "2026-10-20T00:00:00Z", version: "7" },
    });
    deleted.history.set(SCOPE, {
      deletedAt: "2026-10-20T00:00:00Z",
      version: "7",
    });
    deleted.markers.record(
      deleted.markers.acknowledge("chatgpt", STREAMS),
      STREAMS.map((stream) => deleted.receipt(stream)),
    );
    expect(canonicalReaddVersion(deleted.db, SCOPE, INSTANCE, 1, STREAMS)).toBe(
      "7",
    );
  });

  it("keys markers by connection generation and by the writing method", () => {
    const { db, deleteNow, markers, receipt } = setup();
    deleteNow({ deletedAt: "2026-10-14T00:00:00Z", version: "1" });
    markers.record(
      markers.acknowledge("chatgpt", STREAMS),
      STREAMS.map((stream) => receipt(stream, 1)),
    );
    // A reset connection's new generation has proven nothing yet.
    expect(canonicalReaddVersion(db, SCOPE, INSTANCE, 2, STREAMS)).toBeNull();
    // A method that does not serve the scope acknowledges nothing for it.
    expect(markers.acknowledge("github-browser", STREAMS).acknowledged).toEqual(
      [],
    );
    // A receipt of another method does not satisfy this intent.
    const other = setup();
    other.deleteNow({
      deletedAt: "2026-10-14T00:00:00Z",
      version: "1",
    });
    other.markers.record(
      other.markers.acknowledge("chatgpt", STREAMS),
      STREAMS.map((stream) => ({ ...other.receipt(stream), method: "other" })),
    );
    expect(
      canonicalReaddVersion(other.db, SCOPE, INSTANCE, 1, STREAMS),
    ).toBeNull();
  });

  it("holds no marker in a database that never created the table", () => {
    expect(
      canonicalReaddVersion(new Database(":memory:"), SCOPE, INSTANCE, 1, [
        ...STREAMS,
      ]),
    ).toBeNull();
  });
});
