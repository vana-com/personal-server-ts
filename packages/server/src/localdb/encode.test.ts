import { createHash, randomBytes } from "node:crypto";
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
  encodePrefixes,
  freezePrefixRows,
  uploadFrozenParts,
  type EncodedPart,
} from "../../../core/src/localdb/encode.js";
import type { LocalSyncDeps } from "../../../core/src/localdb/deps.js";
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
  const driver = openBetterSqlite3(join(dir, "db.sqlite"));
  drivers.push(driver);
  const db = await openLocalDb(driver, {
    owner: "0xabc",
    network: "test",
    deviceId: "encode-test",
  });
  const blobs = new Map<string, Uint8Array>();
  const testKey = new Uint8Array(32).fill(17);
  const encryptPart = vi.fn(async (_scope: string, clear: Uint8Array) =>
    sealBytes(testKey, clear, (n) => randomBytes(n)),
  );
  const get = vi.fn(async (key: string) => blobs.get(key) ?? null);
  const put = vi.fn(async (key: string, bytes: Uint8Array) => {
    blobs.set(key, bytes.slice());
  });
  // Encoding must not call registry, queue, signer, or another PS-2 body.
  const deps = {
    db,
    blobs: { get, put },
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
  return { db, deps, blobs, get, put, encryptPart, insert, read };
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
    // Per call and prefix: one page to freeze the identities, one to encode.
    expect(query).toHaveBeenCalledTimes(8);
    expect(
      query.mock.calls.every(([sql]) => sql.includes("ORDER BY pk_hash")),
    ).toBe(true);
    // The freeze never reads a body.
    expect(
      query.mock.calls.filter(([sql]) => !sql.includes("body,")),
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
      expect(f.get.mock.calls.map(([key]) => key)).toEqual(
        parts.map((part) => input.scope + "/" + part.blobName),
      );
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

describe("a transfer reads the rows the snapshot froze", () => {
  const prefixes = { ...input, changedPrefixes: [""] };
  const upload = (f: Awaited<ReturnType<typeof fresh>>, frozen: never) =>
    uploadFrozenParts(f.deps, { ...prefixes, frozen });

  async function frozen(f: Awaited<ReturnType<typeof fresh>>) {
    return (await freezePrefixRows(f.deps, prefixes)) as never;
  }

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

  it("keeps a count and a digest per prefix, not the rows", async () => {
    const f = await fresh();
    await f.insert([{ k: keyHash("1") }, { k: keyHash("2") }]);
    const [only, ...rest] = await freezePrefixRows(f.deps, prefixes);
    expect(rest).toEqual([]);
    expect(Object.keys(only!).sort()).toEqual(["digest", "prefix", "rows"]);
    expect(only).toMatchObject({ prefix: "", rows: 2 });
  });

  it.each([
    [
      "a row got a newer stamp",
      "UPDATE records SET stamp_o = 11, body_sha256 = '" +
        "f".repeat(64) +
        "' WHERE pk_hash = ?",
    ],
    [
      "a row's first checkpoint moved under the same stamp",
      "UPDATE records SET first_o = 3 WHERE pk_hash = ?",
    ],
    ["a row was removed", "DELETE FROM records WHERE pk_hash = ?"],
  ])("throws when %s after the freeze", async (_name, sql) => {
    const f = await fresh();
    await f.insert([{ k: keyHash("1") }, { k: keyHash("2"), f: 9 }]);
    const froze = await frozen(f);
    await f.db.batch([{ sql, params: [keyHash("2")] }]);
    await expect(upload(f, froze)).rejects.toBeInstanceOf(FrozenRowsChanged);
    expect(f.put).not.toHaveBeenCalledWith(
      expect.stringContaining("-p-"),
      expect.anything(),
    );
  });

  it("throws when a row was added after the freeze", async () => {
    const f = await fresh();
    await f.insert([{ k: keyHash("1") }]);
    const froze = await frozen(f);
    await f.insert([{ k: keyHash("2") }]);
    await expect(upload(f, froze)).rejects.toBeInstanceOf(FrozenRowsChanged);
  });
});
