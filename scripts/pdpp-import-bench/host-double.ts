/**
 * An in-process double of the phone's native import store
 * (unity-surfaces `lib/ps/native_import_store.dart`): canonical entries and a
 * job's staged entries in SQLite, read the way the Dart store answers
 * `import.entries.read` / `import.entries.scan` (staged over canonical, staged
 * deletions hidden, pages of at most 100 entries and 512 KiB), plus the
 * batched `import.entries.readMany` / `import.entries.scanMany` the encoder
 * prefetches with.
 *
 * Each call is counted. A call's modeled bridge time is a fixed cost per call
 * (the stdio bridge measured 0.31 ms per read and 0.50 ms per scan) plus the
 * SQLite time this double spends answering it. A value over 256 KiB also
 * counts the chunk calls (`value`) that read it.
 */
import Database from "better-sqlite3";
import type { LiteStoragePage } from "../../packages/lite/src/canonical-persistence.js";
import type { LiteCanonicalReadView } from "../../packages/lite/src/import-job.js";

const PAGE_ENTRIES = 100;
const PAGE_BYTES = 512 * 1024;
/** Larger values are answered `{large}` and read in chunks of `CHUNK_UNITS`. */
const INLINE_BYTES = 256 * 1024;
const CHUNK_UNITS = 131_072;
const utf8 = new TextEncoder();

export interface CallStats {
  calls: number;
  items: number;
  sqliteMs: number;
}

export function createImportHostDouble(path: string, callMs: number) {
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = OFF");
  db.exec(`
    CREATE TABLE IF NOT EXISTS canonical_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS staged (job_id TEXT NOT NULL, k TEXT NOT NULL, v TEXT, PRIMARY KEY (job_id, k)) WITHOUT ROWID;
  `);
  const getCanonical = db.prepare("SELECT v FROM canonical_kv WHERE k = ?");
  const getStaged = db.prepare(
    "SELECT v FROM staged WHERE job_id = ? AND k = ?",
  );
  const putCanonical = db.prepare(
    "INSERT INTO canonical_kv (k, v) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET v = excluded.v",
  );
  const deleteCanonical = db.prepare("DELETE FROM canonical_kv WHERE k = ?");
  const putStaged = db.prepare(
    "INSERT INTO staged (job_id, k, v) VALUES (?, ?, ?) ON CONFLICT (job_id, k) DO UPDATE SET v = excluded.v",
  );
  // As the Dart store: an index range [prefix, upper) after the cursor.
  // One bound pair, so SQLite seeks: keys hold no NUL, so `k > after` is
  // `k >= after + "\0"`.
  const range = `k >= ? AND k < ? ORDER BY k LIMIT ${PAGE_ENTRIES + 1}`;
  const rangeCanonical = db.prepare(
    `SELECT k, v FROM canonical_kv WHERE ${range}`,
  );
  const rangeStaged = db.prepare(
    `SELECT k, v FROM staged WHERE job_id = ? AND ${range}`,
  );
  /** Keys here are ASCII paths, so the next code unit bounds the prefix. */
  const upperBound = (prefix: string) =>
    prefix
      ? prefix.slice(0, -1) +
        String.fromCharCode(prefix.charCodeAt(prefix.length - 1) + 1)
      : "\uffff";
  const stats = new Map<string, CallStats>();
  const shapes = new Map<string, { n: number; ms: number; entries: number }>();

  function count<T>(op: string, items: number, run: () => T): T {
    const started = performance.now();
    try {
      return run();
    } finally {
      const s = stats.get(op) ?? { calls: 0, items: 0, sqliteMs: 0 };
      s.calls += 1;
      s.items += items;
      s.sqliteMs += performance.now() - started;
      stats.set(op, s);
    }
  }

  function read(jobId: string, key: string): string | undefined {
    const staged = getStaged.get(jobId, key) as
      { v: string | null } | undefined;
    if (staged) return chunked(staged.v ?? undefined);
    return chunked((getCanonical.get(key) as { v: string } | undefined)?.v);
  }
  /** Counts the `import.entries.value` calls a large value costs. */
  function chunked<T extends string | undefined>(value: T): T {
    if (
      value !== undefined &&
      value.length * 3 > INLINE_BYTES &&
      utf8.encode(value).byteLength > INLINE_BYTES
    ) {
      const s = stats.get("value") ?? { calls: 0, items: 0, sqliteMs: 0 };
      s.calls += Math.ceil(value.length / CHUNK_UNITS);
      s.items += 1;
      stats.set("value", s);
    }
    return value;
  }

  /** `after` is exclusive; the empty string sorts before every key. */
  function page(
    jobId: string,
    prefix: string,
    after?: string,
  ): LiteStoragePage {
    let cursor = after;
    for (;;) {
      const args = [
        cursor === undefined ? prefix : `${cursor}\0`,
        upperBound(prefix),
      ] as const;
      const staged = rangeStaged.all(jobId, ...args) as {
        k: string;
        v: string | null;
      }[];
      const canonical = rangeCanonical.all(...args) as {
        k: string;
        v: string;
      }[];
      let horizon: string | undefined;
      for (const rows of [staged, canonical]) {
        if (rows.length <= PAGE_ENTRIES) continue;
        const end = rows.at(-1)!.k;
        if (horizon === undefined || end < horizon) horizon = end;
      }
      const merged = new Map<string, string | null>();
      for (const row of canonical) merged.set(row.k, row.v);
      for (const row of staged) merged.set(row.k, row.v);
      const keys = [...merged.keys()].sort();
      const entries: { key: string; value: string }[] = [];
      let bytes = 0;
      let more = horizon !== undefined;
      let last: string | undefined;
      for (const key of keys) {
        if (horizon !== undefined && key > horizon) break;
        const value = merged.get(key);
        if (value != null) {
          const size = utf8.encode(value).byteLength;
          if (
            entries.length === PAGE_ENTRIES ||
            (entries.length > 0 && bytes + size > PAGE_BYTES)
          ) {
            more = true;
            break;
          }
          bytes += size;
          entries.push({ key, value: chunked(value) });
        }
        last = key;
      }
      if (!more) return { entries };
      if (entries.length) return { entries, after: last! };
      cursor = last!;
    }
  }

  /** The encoder's view of one job, with or without the batched reads. */
  function view(jobId: string, batched: boolean): LiteCanonicalReadView {
    // As `stagedView` in native-import-jobs.js: answers kept for one batch.
    const values = new Map<string, string | undefined>();
    const pages = new Map<string, LiteStoragePage>();
    const plain: LiteCanonicalReadView = {
      get: async (key) => {
        if (!values.has(key))
          values.set(
            key,
            count("read", 1, () => read(jobId, key)),
          );
        return values.get(key);
      },
      scan: async (prefix, after) => {
        const id = `${prefix}\0${after ?? ""}`;
        if (!pages.has(id)) pages.set(id, await uncachedScan(prefix, after));
        return pages.get(id)!;
      },
    };
    const uncached = {
      scan: async (prefix: string, after?: string) =>
        count("scan", 1, () => {
          if (!process.env.BENCH_SHAPES) return page(jobId, prefix, after);
          const t = performance.now();
          const result = page(jobId, prefix, after);
          const shape =
            prefix.replace(/[0-9a-f]{64}/g, "#") + (after ? "+after" : "");
          const s = shapes.get(shape) ?? { n: 0, ms: 0, entries: 0 };
          s.n++;
          s.ms += performance.now() - t;
          s.entries += result.entries.length;
          shapes.set(shape, s);
          return result;
        }),
    };
    const uncachedScan = uncached.scan;
    if (!batched) return plain;
    return {
      ...plain,
      getMany: async (keys) =>
        count("readMany", keys.length, () =>
          keys.map((key) => read(jobId, key)),
        ),
      scanMany: async (scans) =>
        count("scanMany", scans.length, () =>
          scans.map((scan) => page(jobId, scan.prefix, scan.after)),
        ),
    };
  }

  const stage = db.transaction(
    (jobId: string, entries: { key: string; value: string | null }[]) => {
      for (const entry of entries) putStaged.run(jobId, entry.key, entry.value);
    },
  );
  // As the Dart publish: one set-based copy, then the staged deletions.
  const publish = db.transaction((jobId: string) => {
    db.prepare(
      "INSERT INTO canonical_kv (k, v) SELECT k, v FROM staged WHERE job_id = ? AND v IS NOT NULL ON CONFLICT (k) DO UPDATE SET v = excluded.v",
    ).run(jobId);
    db.prepare(
      "DELETE FROM canonical_kv WHERE k IN (SELECT k FROM staged WHERE job_id = ? AND v IS NULL)",
    ).run(jobId);
    db.prepare("DELETE FROM staged WHERE job_id = ?").run(jobId);
  });
  const writeCanonical = db.transaction(
    (writes: Map<string, string | null>) => {
      for (const [key, value] of writes)
        if (value === null) deleteCanonical.run(key);
        else putCanonical.run(key, value);
    },
  );

  return {
    db,
    view,
    stage,
    publish,
    /** Canonical entries outside any job, for setting up the connection. */
    canonical: {
      get: (key: string) =>
        (getCanonical.get(key) as { v: string } | undefined)?.v,
      page: (prefix: string, after?: string) => page("", prefix, after),
      write: writeCanonical,
    },
    stats,
    /** Modeled bridge time of every view call so far. */
    bridgeMs() {
      let ms = 0;
      for (const s of stats.values()) ms += s.calls * callMs + s.sqliteMs;
      return ms;
    },
    resetStats: () => stats.clear(),
    shapes,
  };
}
