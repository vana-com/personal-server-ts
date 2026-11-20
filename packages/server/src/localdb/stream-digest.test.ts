import { afterEach, describe, expect, it, vi } from "vitest";
import { sha256 } from "@noble/hashes/sha2";
import {
  canonicalJson,
  toHex,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createLocalListing } from "../../../core/src/localdb/listing.js";
import { openLocalDb } from "../../../core/src/localdb/open.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import type { SqlDriver } from "../../../core/src/localdb/driver.js";
import {
  deleteRunRecords,
  mergeIncoming,
  withOrigin,
} from "../../../core/src/localdb/merge.js";
import {
  STREAM_DIGEST_PAGE_ROWS,
  streamDigest,
} from "../../../core/src/localdb/stream-digest.js";
import { liveStreamCounts } from "../../../core/src/stream-sync-read/service.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { addConnection, addStream } from "./local-state-fixture.js";

/**
 * Two devices that hold the same live records report the same count and the
 * same digest, whatever order, batching or stamps the records came with.
 */
const CONNECTION = "c1";
const STREAM = "items";
const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const hex = (text: string) => toHex(sha256(new TextEncoder().encode(text)));
const record = (id: number, version = 1) => {
  const body = canonicalJson({ id: `r${id}`, version });
  return { pkHash: hex(`pk-${id}`), key: `r${id}`, body, bodySha: hex(body) };
};
const records = (n: number) => Array.from({ length: n }, (_, i) => record(i));

/** A deterministic shuffle, so a failure reproduces. */
function shuffled<T>(items: readonly T[], seed: number): T[] {
  const out = [...items];
  let state = seed;
  for (let i = out.length - 1; i > 0; i--) {
    state = (state * 1103515245 + 12345) & 0x7fffffff;
    const j = state % (i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out;
}

const opened: SqlDriver[] = [];
afterEach(async () => {
  for (const db of opened.splice(0)) await db.close();
});

async function device(deviceId: string) {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId,
  });
  opened.push(db);
  await addConnection(db, CONNECTION, "fixture-source");
  await addStream(db, CONNECTION, STREAM, { records: 0 });
  return db;
}

/** Pulled rows, as a download applies them, in batches of `chunk`. */
async function arrive(
  db: SqlDriver,
  rows: readonly ReturnType<typeof record>[],
  options: { chunk: number; stampO: number; stampR: string },
) {
  for (let at = 0; at < rows.length; at += options.chunk) {
    const op = `op-${at}`;
    await db.batch(
      withOrigin("remote", [
        ...rows.slice(at, at + options.chunk).map((row) => ({
          sql: "INSERT INTO incoming (op, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
          params: [
            op,
            STREAM,
            row.pkHash,
            row.key,
            options.stampO,
            options.stampR,
            row.body,
            row.bodySha,
          ],
        })),
        ...mergeIncoming(op, CONNECTION),
      ]),
    );
  }
}

/** An explicit delete, as a run end commits it. */
async function explicitDelete(db: SqlDriver, pkHash: string, key: string) {
  await db.batch([
    {
      sql: "INSERT INTO run_rows (run_id, stream, pk_hash, record_key, body, body_sha256, op) VALUES ('run-del', ?, ?, ?, '{}', ?, 'delete')",
      params: [STREAM, pkHash, key, hex("{}")],
    },
    ...deleteRunRecords(CONNECTION, STREAM, "run-del", 9000, 0),
    { sql: "DELETE FROM run_rows WHERE run_id = 'run-del'" },
  ]);
}

async function summary(db: SqlDriver) {
  const listing = createLocalListing({
    db,
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 9000,
  } as unknown as LocalSyncDeps);
  const status = await listing.status({ audit: true });
  const [row] = liveStreamCounts(status);
  const direct = await streamDigest(db, CONNECTION, STREAM);
  // The status field and the function agree, and the count is the row count.
  expect(row!.digest).toBe(direct.fingerprint);
  expect(row!.records).toBe(direct.rows);
  return { records: row!.records, digest: row!.digest };
}

describe("per-stream count and digest", () => {
  it("is equal for two devices that received the same records in different orders", async () => {
    const all = records(60);
    const a = await device("a");
    const b = await device("b");
    const c = await device("c");
    await arrive(a, all, { chunk: 7, stampO: 1000, stampR: "run-a" });
    await arrive(b, shuffled(all, 1), {
      chunk: 1,
      stampO: 2500,
      stampR: "run-b",
    });
    // Two partial arrivals with a repeat of the first batch, as a retried pull.
    const second = shuffled(all, 2);
    await arrive(c, second.slice(0, 40), {
      chunk: 13,
      stampO: 3000,
      stampR: "run-c",
    });
    await arrive(c, second, { chunk: 60, stampO: 3000, stampR: "run-c" });
    const [sa, sb, sc] = [await summary(a), await summary(b), await summary(c)];
    expect(sa.records).toBe(60);
    expect(sb).toEqual(sa);
    expect(sc).toEqual(sa);
    expect(sa.digest).toMatch(/^[0-9a-f]{64}$/);
    expect(sa.digest).not.toBe(EMPTY_SHA256);
  });

  it("is equal for many shuffles of the same set", async () => {
    const all = records(25);
    const reference = await device("ref");
    await arrive(reference, all, { chunk: 25, stampO: 1, stampR: "r" });
    const expected = await summary(reference);
    for (let seed = 10; seed < 16; seed++) {
      const db = await device(`d${seed}`);
      await arrive(db, shuffled(all, seed), {
        chunk: 1 + (seed % 5),
        stampO: seed,
        stampR: `r${seed}`,
      });
      expect(await summary(db)).toEqual(expected);
    }
  });

  it("changes both count and digest when one record is missing", async () => {
    const all = records(30);
    const full = await device("full");
    const short = await device("short");
    await arrive(full, all, { chunk: 10, stampO: 1000, stampR: "r" });
    await arrive(short, all.slice(1), { chunk: 10, stampO: 1000, stampR: "r" });
    const [f, s] = [await summary(full), await summary(short)];
    expect(s.records).toBe(f.records! - 1);
    expect(s.digest).not.toBe(f.digest);
  });

  it("changes the digest and not the count when one record has another body", async () => {
    const all = records(30);
    const same = await device("same");
    const other = await device("other");
    await arrive(same, all, { chunk: 10, stampO: 1000, stampR: "r" });
    await arrive(other, [record(0, 2), ...all.slice(1)], {
      chunk: 10,
      stampO: 1000,
      stampR: "r",
    });
    const [s, o] = [await summary(same), await summary(other)];
    expect(o.records).toBe(s.records);
    expect(o.digest).not.toBe(s.digest);
  });

  it("leaves an explicitly deleted record out, as a device that never held it does", async () => {
    const all = records(20);
    const deleter = await device("deleter");
    const never = await device("never");
    await arrive(deleter, all, { chunk: 5, stampO: 1000, stampR: "run-a" });
    const gone = all[7]!;
    await explicitDelete(deleter, gone.pkHash, gone.key);
    await arrive(
      never,
      shuffled(
        all.filter((r) => r !== gone),
        3,
      ),
      {
        chunk: 4,
        stampO: 2000,
        stampR: "run-b",
      },
    );
    const [d, n] = [await summary(deleter), await summary(never)];
    expect(d.records).toBe(19);
    expect(d).toEqual(n);
  });

  it("ignores the local tombstone tables", async () => {
    const all = records(10);
    const clean = await device("clean");
    const marked = await device("marked");
    await arrive(clean, all, { chunk: 10, stampO: 1000, stampR: "r" });
    await arrive(marked, all, { chunk: 10, stampO: 1000, stampR: "r" });
    await marked.batch([
      {
        sql: "INSERT INTO record_tombstones (connection_id, stream, pk_hash, stamp_o, stamp_r) VALUES (?, ?, ?, 9000, 'r')",
        params: [CONNECTION, STREAM, hex("never-held")],
      },
      {
        sql: "INSERT INTO log_tombstones (connection_id, stream, pk_hash, stamp_o, stamp_r, rank) VALUES (?, ?, ?, 9000, 'r', 1)",
        params: [CONNECTION, STREAM, hex("never-held-2")],
      },
    ]);
    expect(await summary(marked)).toEqual(await summary(clean));
  });

  it("pages: a stream larger than a page digests the same as one read at once", async () => {
    const all = records(45);
    const db = await device("paged");
    await arrive(db, shuffled(all, 4), {
      chunk: 45,
      stampO: 1,
      stampR: "r",
    });
    const whole = await streamDigest(db, CONNECTION, STREAM, 1000);
    for (const pageRows of [1, 2, 7, 45, 46]) {
      expect(await streamDigest(db, CONNECTION, STREAM, pageRows)).toEqual(
        whole,
      );
    }
  });

  it("digests an empty stream as the empty hash", async () => {
    const db = await device("empty");
    expect(await streamDigest(db, CONNECTION, STREAM)).toEqual({
      rows: 0,
      fingerprint: EMPTY_SHA256,
    });
  });
});

describe("status reporting", () => {
  async function listingOf(db: SqlDriver) {
    return createLocalListing({
      db,
      queue: connectionQueue(),
      ownerAddress: "0xabc",
      logger: { info: vi.fn(), warn: vi.fn() },
      now: () => 9000,
    } as unknown as LocalSyncDeps);
  }

  /**
   * The database, with one write committed the first time a query matches
   * `when` returns: a write that lands between the audit's reads.
   */
  function interleaved(
    db: SqlDriver,
    when: (sql: string) => boolean,
    write: () => Promise<unknown>,
  ): SqlDriver {
    let fired = false;
    return {
      info: db.info,
      batch: (statements) => db.batch(statements),
      close: () => db.close(),
      query: async (sql, params) => {
        const rows = await db.query(sql, params);
        if (!fired && when(sql)) {
          fired = true;
          await write();
        }
        return rows as never;
      },
    };
  }

  it("reports the state before or after a write that lands between its reads, never a mix", async () => {
    // The write lands after the stream's state is read and before its rows are.
    const db = await device("between");
    await arrive(db, records(3), { chunk: 3, stampO: 1, stampR: "r" });
    const before = await streamDigest(db, CONNECTION, STREAM);
    const listing = await listingOf(
      interleaved(
        db,
        (sql) => sql.includes("FROM stream_state"),
        () => arrive(db, [record(50)], { chunk: 1, stampO: 2, stampR: "r2" }),
      ),
    );
    const [row] = liveStreamCounts(await listing.status({ audit: true }));
    const after = await streamDigest(db, CONNECTION, STREAM);
    expect(after.rows).toBe(4);
    expect([before.fingerprint, after.fingerprint]).toContain(row!.digest);
    // The count and the digest are of the same state.
    expect(row!.digest).toBe(
      row!.records === 3 ? before.fingerprint : after.fingerprint,
    );
  });

  it("reports the state before or after a write that lands between two pages of one stream", async () => {
    const all = records(STREAM_DIGEST_PAGE_ROWS + 20);
    const db = await device("pages");
    await arrive(db, all, { chunk: 500, stampO: 1, stampR: "r" });
    const before = await streamDigest(db, CONNECTION, STREAM);
    // One row in the first page and one in the last change: a digest read
    // from the first page before them and the second after them is neither.
    const byKey = [...all].sort((a, b) => (a.pkHash < b.pkHash ? -1 : 1));
    const changed = [byKey[0]!, byKey[byKey.length - 1]!].map((r) =>
      record(Number(r.key.slice(1)), 2),
    );
    const listing = await listingOf(
      interleaved(
        db,
        (sql) => sql.includes("ORDER BY pk_hash LIMIT"),
        () => arrive(db, changed, { chunk: 2, stampO: 5, stampR: "r2" }),
      ),
    );
    const [row] = liveStreamCounts(await listing.status({ audit: true }));
    const after = await streamDigest(db, CONNECTION, STREAM);
    expect(after.fingerprint).not.toBe(before.fingerprint);
    expect([before.fingerprint, after.fingerprint]).toContain(row!.digest);
  });

  it("reports no digest for a connection that keeps changing, and says so", async () => {
    const db = await device("busy");
    await arrive(db, records(3), { chunk: 3, stampO: 1, stampR: "r" });
    let n = 100;
    const warn = vi.fn();
    const busy: SqlDriver = {
      info: db.info,
      batch: (statements) => db.batch(statements),
      close: () => db.close(),
      query: async (sql, params) => {
        const rows = await db.query(sql, params);
        if (sql.includes("FROM stream_state"))
          await arrive(db, [record(n++)], {
            chunk: 1,
            stampO: n,
            stampR: "busy",
          });
        return rows as never;
      },
    };
    const listing = createLocalListing({
      db: busy,
      queue: connectionQueue(),
      ownerAddress: "0xabc",
      logger: { info: vi.fn(), warn },
      now: () => 9000,
    } as unknown as LocalSyncDeps);
    const [row] = liveStreamCounts(await listing.status({ audit: true }));
    expect(row!.digest).toBeNull();
    expect(warn).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining("kept changing"),
    );
  });

  it("carries no digest unless an audit is asked for", async () => {
    const db = await device("plain");
    await arrive(db, records(3), { chunk: 3, stampO: 1, stampR: "r" });
    const listing = await listingOf(db);
    const rows = liveStreamCounts(await listing.status());
    expect(rows).toEqual([
      { connector: "fixture-source", ns: "", stream: STREAM, records: 3 },
    ]);
    expect(Object.keys(rows[0]!)).not.toContain("digest");
  });

  it("reports no digest for a stream that is not live or not complete", async () => {
    const db = await device("states");
    await addStream(db, CONNECTION, "loading", {
      records: 0,
      complete: false,
    });
    await addConnection(db, "c-deleted", "gone", { control: "deleted" });
    await addStream(db, "c-deleted", "old", { records: 0 });
    const listing = await listingOf(db);
    const byStream = Object.fromEntries(
      liveStreamCounts(await listing.status({ audit: true })).map((row) => [
        `${row.connector}/${row.stream}`,
        row.digest,
      ]),
    );
    expect(byStream["fixture-source/loading"]).toBeNull();
    expect(byStream["gone/old"]).toBeNull();
    expect(byStream["fixture-source/items"]).toBe(EMPTY_SHA256);
  });
});
