import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { createRecordQuery, type RecordQuery } from "../localdb/index.js";
import type { PdppTokenContext } from "../ports/pdpp-auth.js";
import type { StreamDeclarationRegistry } from "../storage/pdpp-records/stream-declaration.js";
import {
  listPdppRecords,
  type PdppRecordListPorts,
} from "./pdpp-records-list.js";

const owner: PdppTokenContext = {
  active: true,
  tokenKind: "owner",
  subjectId: "owner",
};

const declaration = { name: "posts" } as never;
const declarations: StreamDeclarationRegistry = {
  get: () => declaration,
  forInstance: () => declaration,
  declares: () => true,
  list: () => [declaration],
};

const open: Database.Database[] = [];
afterEach(() => {
  for (const db of open.splice(0)) db.close();
});

/** A real `records` table, so the count runs as SQL over the page's own filter. */
function seeded(
  rows: Record<string, number>,
  other: Record<string, number>,
  /** Runs after each statement has read, before its caller resumes. */
  afterStatement?: (sql: string, db: Database.Database) => void,
) {
  const db = new Database(":memory:");
  open.push(db);
  db.exec(`CREATE TABLE records (
    connection_id TEXT NOT NULL, stream TEXT NOT NULL, pk_hash TEXT NOT NULL,
    record_key TEXT NOT NULL, stamp_o INTEGER NOT NULL, stamp_r TEXT NOT NULL,
    body TEXT NOT NULL, body_sha256 TEXT NOT NULL, first_o INTEGER, seen_o INTEGER, seen_r TEXT,
    PRIMARY KEY (connection_id, stream, pk_hash)) WITHOUT ROWID;`);
  const insert = db.prepare(
    "INSERT INTO records VALUES (?, ?, ?, ?, 1, 'r', '{}', 'h', NULL, NULL, NULL)",
  );
  const add = (stream: string, counts: Record<string, number>) => {
    for (const [connection, count] of Object.entries(counts))
      for (let i = 0; i < count; i++) {
        const key = `${connection}-${String(i).padStart(3, "0")}`;
        insert.run(connection, stream, `pk-${key}`, key);
      }
  };
  add("posts", rows);
  add("comments", other);
  return createRecordQuery({
    query: async (sql, params = []) => {
      const result = db.prepare(sql).all(...params) as never;
      afterStatement?.(sql, db);
      return result;
    },
  });
}

function ports(
  recordQuery: RecordQuery,
  instances: string[],
): PdppRecordListPorts {
  return {
    accountMode: { read: () => "switched" },
    recordQuery,
    declarations,
    ownerInstances: () => instances,
  };
}

async function list(
  p: PdppRecordListPorts,
  query: string,
  prefer: string | undefined,
  context = owner,
) {
  const { body } = await listPdppRecords(p, {
    url: `https://ps.test/v1/streams/posts/records?${query}`,
    stream: "posts",
    context,
    prefer,
  });
  return body as {
    data: unknown[];
    has_more: boolean;
    next_cursor?: string;
    meta?: Record<string, unknown>;
  };
}

describe("local record list count", () => {
  it("states the stream's full total on every page when exact is preferred", async () => {
    const query = seeded({ a: 7, b: 5 }, { a: 4 });
    const p = ports(query, ["a", "b"]);
    const seen: Array<unknown> = [];
    let cursor: string | undefined;
    let rows = 0;
    do {
      const page = await list(
        p,
        `limit=5${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        "count=exact",
      );
      seen.push(page.meta?.count);
      rows += page.data.length;
      cursor = page.next_cursor;
    } while (cursor);
    expect(rows).toBe(12);
    expect(seen).toHaveLength(3);
    expect(seen).toEqual(Array(3).fill({ kind: "exact", value: 12 }));
  });

  it("states a total of zero for an empty stream", async () => {
    const page = await list(ports(seeded({}, {}), ["a"]), "", "count=exact");
    expect(page.meta?.count).toEqual({ kind: "exact", value: 0 });
  });

  it("reads count among other Prefer tokens, and states none unasked", async () => {
    const p = ports(seeded({ a: 3 }, {}), ["a"]);
    expect(
      (await list(p, "", "return=minimal, count=exact")).meta?.count,
    ).toEqual({ kind: "exact", value: 3 });
    for (const prefer of [undefined, "", "count=none", "return=minimal"]) {
      expect((await list(p, "", prefer)).meta).toBeUndefined();
    }
  });

  it("counts the rows its page lists when a row is admitted mid-read", async () => {
    let admitted = false;
    const query = seeded({ a: 1 }, {}, (sql, db) => {
      // The first read that counts has finished; a writer lands before the
      // caller can issue its next read.
      if (admitted || !/count\(\*\)/i.test(sql)) return;
      admitted = true;
      db.prepare(
        "INSERT INTO records VALUES ('a', 'posts', 'pk-late', 'a-late', 1, 'r', '{}', 'h', NULL, NULL, NULL)",
      ).run();
    });
    const page = await list(ports(query, ["a"]), "limit=100", "count=exact");
    expect(admitted).toBe(true);
    expect(page.meta?.count).toEqual({
      kind: "exact",
      value: page.data.length,
    });
  });

  it("downgrades with a warning where it cannot count the whole stream", async () => {
    const query = {
      ...seeded({ a: 3 }, {}),
      changesSince: async () => ({ changes: [], nextCursor: null }),
    };
    // A change session reads the frozen history port.
    const page = await list(
      {
        ...ports(query, ["a"]),
        recordHistory: async () => ({ data: [], hasMore: false }),
      },
      "changes_since=beginning",
      "count=exact",
    );
    expect(page.meta?.count).toBeUndefined();
    expect(page.meta?.warnings).toEqual([
      expect.objectContaining({ code: "count_downgraded", param: "count" }),
    ]);
  });
});
