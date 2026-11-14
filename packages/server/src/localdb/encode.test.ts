import { createHash, randomBytes } from "node:crypto";
import { createMemoryStreamSyncBlobs } from "../../../core/src/stream-sync/memory-registry.js";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  openLocalDb,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  frameOfBody,
  framesOfParts,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  FrozenRowsChanged,
  dropSpool,
  encodePrefixes,
  freezePrefixRows,
  uploadFrozenParts,
  type EncodedPart,
} from "../../../core/src/localdb/encode.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
import { newPublishMeter } from "../../../core/src/localdb/publish-meter.js";
import {
  openBytes,
  sealBytes,
} from "../../../core/src/stream-sync/stream-aead.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

const hash = async (bytes: Uint8Array) =>
  new Uint8Array(createHash("sha256").update(bytes).digest());
const hex = (bytes: Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");
const keyHash = (prefix: string) => prefix.padEnd(64, "0");
const input = {
  connectionId: "connection",
  stream: "items",
  scope: "pdpp.source.items",
  generation: 3,
  changedPrefixes: [""],
  upToSeq: 0,
} as const;

const drivers: SqlDriver[] = [];
const dirs: string[] = [];
afterEach(async () => {
  for (const driver of drivers.splice(0)) await driver.close();
  for (const dir of dirs.splice(0))
    rmSync(dir, { recursive: true, force: true });
});

async function fresh(partTargetBytes?: number) {
  const dir = mkdtempSync(join(process.cwd(), ".encode-test-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const identity = { owner: "0xabc", network: "test", deviceId: "encode-test" };
  const driver = openBetterSqlite3(path);
  drivers.push(driver);
  const db = await openLocalDb(driver, identity);
  const blobs = new Map<string, Uint8Array>();
  const testKey = new Uint8Array(32).fill(17);
  const encryptPart = vi.fn(async (_scope: string, clear: Uint8Array) =>
    sealBytes(testKey, clear, (n) => randomBytes(n)),
  );
  const get = vi.fn(async (key: string) => blobs.get(key) ?? null);
  const exists = vi.fn(async (key: string) => blobs.has(key));
  const put = vi.fn(async (key: string, bytes: Uint8Array) => {
    blobs.set(key, bytes.slice());
  });
  // Encoding must not call registry, queue, signer, or another PS-2 body.
  const deps = {
    db,
    blobs: {
      governor: createMemoryStreamSyncBlobs().governor,
      get,
      exists,
      put,
    },
    keys: { encryptPart },
    ...(partTargetBytes === undefined ? {} : { partTargetBytes }),
  } as LocalSyncDeps;

  const insert = async (
    rows: readonly {
      k: string;
      o?: number;
      r?: string;
      f?: number | null;
      value?: string;
      connectionId?: string;
      stream?: string;
    }[],
  ) => {
    const fixtures = rows.map((row) => {
      const body = JSON.stringify({ id: row.k, value: row.value ?? "sample" });
      const bytes = new TextEncoder().encode(body);
      const envelope = {
        h: hex(bytes),
        k: row.k,
        n: bytes.length,
        o: row.o ?? 10,
        r: row.r ?? "run",
        f: row.f ?? null,
      };
      return { row, body, envelope, frame: frameOfBody(envelope, bytes) };
    });
    await db.batch(
      fixtures.map(({ row, body, envelope }) => ({
        sql: "INSERT INTO records (connection_id, stream, pk_hash, record_key, stamp_o, stamp_r, body, body_sha256, first_o) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        params: [
          row.connectionId ?? input.connectionId,
          row.stream ?? input.stream,
          row.k,
          row.k,
          envelope.o,
          envelope.r,
          body,
          envelope.h,
          envelope.f,
        ],
      })),
    );
    return fixtures;
  };
  const read = async (parts: readonly EncodedPart[]) => {
    const summaries: { k: string; o: number; r: string; f: number | null }[] =
      [];
    for await (const frame of framesOfParts(
      hash,
      parts.map((part) => ({
        prefix: part.prefix,
        hash: part.partHash,
        bytes: part.bytes,
        count: part.count,
      })),
      async (_part, index) => {
        const cipher = blobs.get(input.scope + "/" + parts[index]!.blobName);
        if (!cipher) throw new Error("missing fixture blob");
        return openBytes(testKey, cipher);
      },
      { generation: "v3" },
    )) {
      const digest = createHash("sha256");
      for await (const piece of frame.body()) digest.update(piece);
      expect(digest.digest("hex")).toBe(frame.envelope.h);
      const { k, o, r, f } = frame.envelope;
      summaries.push({ k, o, r, f: f ?? null });
    }
    return summaries;
  };
  return {
    db,
    deps,
    blobs,
    get,
    exists,
    put,
    encryptPart,
    insert,
    read,
    path,
    identity,
  };
}

describe("encodePrefixes", () => {
  it("an identical repeat uploads nothing and returns the same part hashes", async () => {
    const f = await fresh();
    const low = keyHash("2");
    const high = keyHash("a");
    await f.insert([
      { k: high },
      { k: low, value: "unicode-\u00e9", f: 7 },
      { k: keyHash("1"), connectionId: "another-connection" },
      { k: keyHash("b"), stream: "another-stream" },
    ]);
    const query = vi.spyOn(f.db, "query");
    const headExtras = Object.freeze({
      checkpoint: Object.freeze({ cursor: "opaque" }),
    });
    const request = { ...input, changedPrefixes: ["1", "0", "1"], headExtras };
    const first = await encodePrefixes(f.deps, request);
    expect(first.map((part) => [part.prefix, part.seq, part.count])).toEqual([
      ["0", 0, 1],
      ["1", 0, 1],
    ]);
    expect(f.put).toHaveBeenCalledTimes(2);
    expect(await f.read(first)).toEqual([
      { k: low, o: 10, r: "run", f: 7 },
      { k: high, o: 10, r: "run", f: null },
    ]);
    f.put.mockClear();
    f.encryptPart.mockClear();
    const second = await encodePrefixes(f.deps, request);
    expect(second.map((part) => part.partHash)).toEqual(
      first.map((part) => part.partHash),
    );
    expect(second).toEqual(first);
    expect(f.put).not.toHaveBeenCalled();
    expect(f.encryptPart).not.toHaveBeenCalled();
    // Per call and prefix: one query for a page's keys and sizes, one for its
    // bodies (the copy into the spool is a batch, not a query).
    expect(query).toHaveBeenCalledTimes(8);
    expect(
      query.mock.calls.every(([sql]) => sql.includes("ORDER BY pk_hash")),
    ).toBe(true);
    // The first of the two never reads a body.
    expect(
      query.mock.calls.filter(([sql]) => sql.includes("body_bytes")),
    ).toHaveLength(4);
    expect(request.headExtras).toBe(headExtras);
  });

  it("cuts at partTargetBytes (default 4 MiB) and skips an existing part", async () => {
    const small = await fresh();
    const smallFrames = await small.insert([
      { k: keyHash("1") },
      { k: keyHash("2") },
      { k: keyHash("3") },
    ]);
    const exact = smallFrames[0]!.frame.length + smallFrames[1]!.frame.length;
    const packed = await encodePrefixes(
      { ...small.deps, partTargetBytes: exact },
      input,
    );
    expect(packed.map((part) => part.bytes)).toEqual([
      exact,
      smallFrames[2]!.frame.length,
    ]);
    expect(packed.map((part) => part.count)).toEqual([2, 1]);
    expect(await small.read(packed)).toEqual(
      smallFrames.map(({ envelope }) => ({
        k: envelope.k,
        o: envelope.o,
        r: envelope.r,
        f: null,
      })),
    );

    for (const configured of [undefined, 512]) {
      const target = configured ?? 4 * 1024 * 1024;
      const f = await fresh(configured);
      const fixtures = await f.insert([
        { k: keyHash("1") },
        { k: keyHash("2"), value: "x".repeat(target + 31) },
        { k: keyHash("3") },
      ]);
      const first = fixtures[0]!;
      const existingName = "g3-p-" + hex(first.frame);
      const existingCipher = await f.encryptPart(input.scope, first.frame);
      f.blobs.set(input.scope + "/" + existingName, existingCipher);
      f.encryptPart.mockClear();

      const parts = await encodePrefixes(f.deps, input);
      const longSize = fixtures[1]!.frame.length;
      expect(parts.map((part) => part.bytes)).toEqual([
        first.frame.length,
        target,
        longSize - target,
        fixtures[2]!.frame.length,
      ]);
      expect(parts.map((part) => part.count)).toEqual([1, 1, 0, 1]);
      expect(parts.map((part) => part.seq)).toEqual([0, 1, 2, 3]);
      expect(parts.every((part) => part.bytes <= target)).toBe(true);
      expect(parts[0]!.blobName).toBe(existingName);
      expect(f.blobs.get(input.scope + "/" + existingName)).toBe(
        existingCipher,
      );
      // The existence probe is a HEAD: it asks about each part and reads none.
      expect(f.exists.mock.calls.map(([key]) => key)).toEqual(
        parts.map((part) => input.scope + "/" + part.blobName),
      );
      expect(f.get).not.toHaveBeenCalled();
      expect(f.put).toHaveBeenCalledTimes(3);
      expect(f.encryptPart).toHaveBeenCalledTimes(3);
      expect(f.put.mock.calls.some(([key]) => key.endsWith(existingName))).toBe(
        false,
      );
      expect(await f.read(parts)).toEqual(
        fixtures.map(({ envelope }) => ({
          k: envelope.k,
          o: envelope.o,
          r: envelope.r,
          f: null,
        })),
      );
    }
  });

  it("replaceBelow leaves out rows with a stamp below the run stamp", async () => {
    const f = await fresh();
    await f.insert([
      { k: keyHash("bf"), o: 11, r: "a", f: null },
      { k: keyHash("ae"), o: 10, r: "z", f: null },
      { k: keyHash("a2"), o: 10, r: "m", f: null },
      { k: keyHash("a1"), o: 10, r: "a" },
      { k: keyHash("a0"), o: 9, r: "z" },
      { k: keyHash("9f"), o: 11 },
      { k: keyHash("c0"), o: 11 },
      { k: keyHash("a3"), o: 11, stream: "another-stream" },
    ]);
    const query = vi.spyOn(f.db, "query");
    const parts = await encodePrefixes(f.deps, {
      ...input,
      changedPrefixes: ["101"],
      replaceBelow: { o: 10, r: "m" },
    });
    expect(parts.reduce((count, part) => count + part.count, 0)).toBe(3);
    expect(await f.read(parts)).toEqual([
      { k: keyHash("a2"), o: 10, r: "m", f: null },
      { k: keyHash("ae"), o: 10, r: "z", f: null },
      { k: keyHash("bf"), o: 11, r: "a", f: null },
    ]);
    expect(query).toHaveBeenCalledTimes(2);
    expect(
      await f.db.query<{ n: number }>("SELECT count(*) AS n FROM records"),
    ).toEqual([{ n: 8 }]);
  });
});

describe("a transfer reads the spool the snapshot made", () => {
  const prefixes = { ...input, changedPrefixes: [""], attempt: "attempt-1" };
  const upload = (f: Awaited<ReturnType<typeof fresh>>, frozen: never) =>
    uploadFrozenParts(f.deps, { ...prefixes, frozen });

  async function frozen(f: Awaited<ReturnType<typeof fresh>>) {
    return (await freezePrefixRows(f.deps, prefixes)) as never;
  }
  const spooled = async (f: Awaited<ReturnType<typeof fresh>>) =>
    (
      await f.db.query<{ n: number }>("SELECT count(*) AS n FROM publish_spool")
    )[0]!.n;

  it("encodes the same parts whether the stream fits one page or spans many", async () => {
    const f = await fresh();
    await f.insert(
      Array.from({ length: 150 }, (_, i) => ({
        k: String(i).padStart(3, "0").padEnd(64, "0"),
      })),
    );
    const parts = await upload(f, await frozen(f));
    expect(parts.reduce((n, part) => n + part.count, 0)).toBe(150);
    expect((await f.read(parts)).map((row) => row.k)).toEqual(
      Array.from({ length: 150 }, (_, i) =>
        String(i).padStart(3, "0").padEnd(64, "0"),
      ),
    );
  });

  it("keeps a count per prefix in memory and the rows in the spool", async () => {
    const f = await fresh();
    await f.insert([
      { k: keyHash("1") },
      { k: keyHash("2") },
      { k: keyHash("1"), connectionId: "another-connection" },
    ]);
    const [only, ...rest] = await freezePrefixRows(f.deps, prefixes);
    expect(rest).toEqual([]);
    expect(only).toEqual({ prefix: "", rows: 2 });
    expect(await spooled(f)).toBe(2);
  });

  it("sends the snapshot's rows whatever later writes do to records", async () => {
    const f = await fresh();
    await f.insert([
      { k: keyHash("1") },
      { k: keyHash("2"), f: 9 },
      { k: keyHash("3") },
    ]);
    const froze = await frozen(f);
    await f.db.batch([
      {
        sql: "UPDATE records SET stamp_o = 11, stamp_r = 'late', body_sha256 = ? WHERE pk_hash = ?",
        params: ["f".repeat(64), keyHash("2")],
      },
      { sql: "DELETE FROM records WHERE pk_hash = ?", params: [keyHash("3")] },
    ]);
    await f.insert([{ k: keyHash("4") }]);
    const parts = await upload(f, froze);
    expect(await f.read(parts)).toEqual([
      { k: keyHash("1"), o: 10, r: "run", f: null },
      { k: keyHash("2"), o: 10, r: "run", f: 9 },
      { k: keyHash("3"), o: 10, r: "run", f: null },
    ]);
  });

  it("throws when the spool lost rows after the snapshot", async () => {
    const f = await fresh();
    await f.insert([{ k: keyHash("1") }, { k: keyHash("2") }]);
    const froze = await frozen(f);
    await f.db.batch([
      {
        sql: "DELETE FROM publish_spool WHERE pk_hash = ?",
        params: [keyHash("2")],
      },
    ]);
    await expect(upload(f, froze)).rejects.toBeInstanceOf(FrozenRowsChanged);
    expect(f.put).not.toHaveBeenCalledWith(
      expect.stringContaining("-p-"),
      expect.anything(),
    );
  });

  it("drops one attempt's rows and no other's", async () => {
    const f = await fresh();
    await f.insert([{ k: keyHash("1") }, { k: keyHash("2") }]);
    await freezePrefixRows(f.deps, prefixes);
    await freezePrefixRows(f.deps, { ...prefixes, attempt: "attempt-2" });
    expect(await spooled(f)).toBe(4);
    await dropSpool(f.deps, "attempt-1", prefixes.changedPrefixes);
    expect(
      await f.db.query("SELECT DISTINCT attempt FROM publish_spool"),
    ).toEqual([{ attempt: "attempt-2" }]);
  });

  it("is empty after a simulated crash and restart", async () => {
    const f = await fresh();
    await f.insert([{ k: keyHash("1") }, { k: keyHash("2") }]);
    await freezePrefixRows(f.deps, prefixes);
    expect(await spooled(f)).toBe(2);
    // The process stopped mid-publish: no drop. A new process opens the file.
    await f.db.close();
    drivers.splice(drivers.indexOf(f.db), 1);
    const driver = openBetterSqlite3(f.path);
    drivers.push(driver);
    const reopened = await openLocalDb(driver, f.identity);
    expect(
      await reopened.query("SELECT count(*) AS n FROM publish_spool"),
    ).toEqual([{ n: 0 }]);
    // The records are untouched: only the copy went.
    expect(await reopened.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 2 },
    ]);
  });
});

describe("encodePrefixes under writes and large bodies", () => {
  /** Spy on db.query: total body characters per result, and a hook per result. */
  function watch(
    f: Awaited<ReturnType<typeof fresh>>,
    onBodies?: (calls: number) => Promise<void>,
  ) {
    const real = f.db.query.bind(f.db);
    const seen = { maxBodyChars: 0, bodyPages: 0 };
    vi.spyOn(f.db, "query").mockImplementation((async (
      sql: string,
      params?: never,
    ) => {
      const rows = (await real(sql, params)) as { body?: string }[];
      const chars = rows.reduce(
        (n, row) => n + (typeof row.body === "string" ? row.body.length : 0),
        0,
      );
      if (chars > 0) {
        seen.bodyPages += 1;
        seen.maxBodyChars = Math.max(seen.maxBodyChars, chars);
        await onBodies?.(seen.bodyPages);
      }
      return rows;
    }) as never);
    return seen;
  }

  it("encodes the snapshot when a row of a later page is rewritten between pages", async () => {
    const f = await fresh();
    const keys = Array.from({ length: 150 }, (_, i) =>
      String(i).padStart(3, "0").padEnd(64, "0"),
    );
    await f.insert(keys.map((k) => ({ k })));
    watch(f, async (page) => {
      // After the first page is read, a collector re-emits a row not yet read.
      if (page === 1) {
        await f.db.batch([
          {
            sql: "UPDATE records SET stamp_o = 99, stamp_r = 'later' WHERE pk_hash = ?",
            params: [keys[140]!],
          },
        ]);
      }
    });
    const parts = await encodePrefixes(f.deps, input);
    const rows = await f.read(parts);
    expect(rows).toHaveLength(150);
    expect(rows.every((row) => row.o === 10 && row.r === "run")).toBe(true);
  });

  it("keeps a page of bodies under the byte cap", async () => {
    const f = await fresh();
    const big = "x".repeat(600 * 1024);
    await f.insert(
      Array.from({ length: 12 }, (_, i) => ({
        k: String(i).padStart(2, "0").padEnd(64, "0"),
        value: big,
      })),
    );
    const seen = watch(f);
    const parts = await encodePrefixes(f.deps, input);
    expect(parts.reduce((n, part) => n + part.count, 0)).toBeGreaterThan(0);
    expect((await f.read(parts)).map((row) => row.k)).toHaveLength(12);
    // Twelve rows are 7 MiB; a page holds what fits in 2 MiB (three rows).
    expect(seen.maxBodyChars).toBeLessThanOrEqual(2 * 1024 * 1024);
    expect(seen.bodyPages).toBeGreaterThanOrEqual(4);
  });

  it("reads a body larger than the cap as a page of its own", async () => {
    const f = await fresh();
    await f.insert([
      { k: keyHash("1"), value: "y".repeat(3 * 1024 * 1024) },
      { k: keyHash("2"), value: "z" },
    ]);
    const seen = watch(f);
    const parts = await encodePrefixes(f.deps, input);
    expect((await f.read(parts)).map((row) => row.k)).toEqual([
      keyHash("1"),
      keyHash("2"),
    ]);
    expect(seen.maxBodyChars).toBeGreaterThan(3 * 1024 * 1024);
    expect(seen.maxBodyChars).toBeLessThan(3 * 1024 * 1024 + 1024);
    expect(seen.bodyPages).toBe(2);
  });
});

describe("a freeze over many prefixes, one batch each, copies the same spool", () => {
  // Prefix-free; together they cover every key nibble. Two keys per nibble.
  const prefixes = ["0000", "0001", "001", "01", "1"];
  const nibbles = "0123456789abcdef";
  const expectedKeys = [...nibbles].flatMap((d) => [
    keyHash(`${d}1`),
    keyHash(`${d}f`),
  ]);
  const spoolRows = (f: Awaited<ReturnType<typeof fresh>>, attempt: string) =>
    f.db.query<{ pk_hash: string; body: string; stamp_o: number }>(
      `SELECT pk_hash, body, stamp_o FROM publish_spool
        WHERE attempt = ? ORDER BY pk_hash`,
      [attempt],
    );

  it("spools exactly the prefixes' rows, with the per-prefix counts, and publishes the same rows", async () => {
    const f = await fresh();
    await f.insert([
      ...expectedKeys.map((k) => ({ k })),
      { k: keyHash("1"), connectionId: "another-connection" },
      { k: keyHash("2"), stream: "another-stream" },
    ]);
    const frozen = await freezePrefixRows(f.deps, {
      ...input,
      changedPrefixes: prefixes,
      attempt: "attempt-1",
    });
    expect(frozen).toEqual([
      { prefix: "0000", rows: 2 },
      { prefix: "0001", rows: 2 },
      { prefix: "001", rows: 4 },
      { prefix: "01", rows: 8 },
      { prefix: "1", rows: 16 },
    ]);
    const spooled = await spoolRows(f, "attempt-1");
    expect(spooled.map((row) => row.pk_hash)).toEqual([...expectedKeys].sort());
    const records = await f.db.query<{ pk_hash: string; body: string }>(
      `SELECT pk_hash, body FROM records
        WHERE connection_id = ? AND stream = ? ORDER BY pk_hash`,
      [input.connectionId, input.stream],
    );
    expect(spooled.map(({ pk_hash, body }) => ({ pk_hash, body }))).toEqual(
      records.filter((row) => expectedKeys.includes(row.pk_hash)),
    );
    const parts = await uploadFrozenParts(f.deps, {
      attempt: "attempt-1",
      scope: input.scope,
      generation: input.generation,
      frozen,
    });
    expect(parts.map((part) => part.prefix)).toEqual(prefixes);
    expect((await f.read(parts)).map((row) => row.k)).toEqual(
      [...expectedKeys].sort(),
    );
  });

  it("a part already in storage is probed through the metered port and downloads no body", async () => {
    const f = await fresh();
    await f.insert(expectedKeys.map((k) => ({ k })));
    const request = { ...input, changedPrefixes: prefixes };
    const attempt = { ...request, attempt: "attempt-1" };
    const frozenPrefixes = (await freezePrefixRows(f.deps, attempt)) as never;
    const first = await uploadFrozenParts(f.deps, {
      attempt: "attempt-1",
      scope: input.scope,
      generation: input.generation,
      frozen: frozenPrefixes,
    });
    // Every part is now stored. Count the body bytes a second transfer reads.
    let bytesServed = 0;
    const served = f.get.getMockImplementation()!;
    f.get.mockImplementation(async (key: string) => {
      const body = await served(key);
      bytesServed += body?.length ?? 0;
      return body;
    });
    f.put.mockClear();
    f.exists.mockClear();
    const meter = newPublishMeter();
    const again = await uploadFrozenParts(
      { ...f.deps, now: Date.now },
      {
        attempt: "attempt-1",
        scope: input.scope,
        generation: input.generation,
        frozen: frozenPrefixes,
        meter,
      },
    );
    expect(again).toEqual(first);
    expect(f.exists).toHaveBeenCalledTimes(first.length);
    expect(f.get).not.toHaveBeenCalled();
    expect(bytesServed).toBe(0);
    expect(f.put).not.toHaveBeenCalled();
    expect(meter.blobGets).toBe(first.length);
    expect(meter.partsUploaded).toBe(0);
  });

  it("drops exactly one attempt's rows across its prefixes", async () => {
    const f = await fresh();
    await f.insert(expectedKeys.map((k) => ({ k })));
    const request = { ...input, changedPrefixes: prefixes };
    await freezePrefixRows(f.deps, { ...request, attempt: "attempt-1" });
    await freezePrefixRows(f.deps, { ...request, attempt: "attempt-2" });
    expect(await spoolRows(f, "attempt-1")).toHaveLength(32);
    await dropSpool(f.deps, "attempt-1", prefixes);
    expect(await spoolRows(f, "attempt-1")).toEqual([]);
    expect(await spoolRows(f, "attempt-2")).toHaveLength(32);
    // The records themselves are untouched.
    expect(await f.db.query("SELECT count(*) AS n FROM records")).toEqual([
      { n: 32 },
    ]);
  });
});
