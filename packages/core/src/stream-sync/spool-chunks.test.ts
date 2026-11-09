/**
 * Allocation cut 1. Reference bytes intentionally retain the old joined form.
 * Production must not: observe the encoder and append port, not V8 heap usage.
 *
 * Mutants: RESTORE_FLUSH_JOIN, RESTORE_COMPACTION_JOIN, SPLIT_SURROGATE_PAIR,
 * UTF16_DERIVE_BUDGET, ALLOCATING_COUNT, PER_PATH_BUDGET, LAST_SEEN_COMPACTION,
 * FLIP_COMPACTION_OBSERVED_AT, FIXED_STEP_GROWTH.
 */
import assert from "node:assert/strict";
import v8 from "node:v8";
import vm from "node:vm";
import { describe, it } from "vitest";
import {
  ENVELOPE_LIMIT_BYTES,
  encodeLine,
  frameBytes,
  utf8Length,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncFiles } from "./memory-files.js";
import type { StreamSyncFiles } from "./ports.js";
import {
  SpoolWriter,
  compactShard,
  countShard,
  deriveShards,
  inlineSpoolLine,
  readSpool,
  shardPath,
  spoolLogPath,
  type SpoolEntry,
} from "./spool.js";

const encoder = new TextEncoder();
const hash = (n: number, second = 0) =>
  "00" +
  second.toString(16).padStart(2, "0") +
  n.toString(16).padStart(60, "0");
const corpus = [
  "ASCII",
  "é".repeat(23),
  "中".repeat(23),
  "🐟𝄞".repeat(17),
  "x".repeat(47) + "🐟" + "y".repeat(47),
  "left\u2028middle\u2029right",
  "\ud800",
  "\udc00",
  "",
];
const body = (value: string, o = 2, r = "run") =>
  encodeLine({ o, r, v: { value } });
/** A format-2 spool line: key, envelope and inline body. */
const spoolLine = (key: string, text: string, o = 2, r = "run") =>
  inlineSpoolLine(
    { h: "0".repeat(64), k: key, n: utf8Length(text), o, r },
    text,
  );
const frameSize = (key: string, text: string, o = 2, r = "run") =>
  frameBytes({ h: "0".repeat(64), k: key, n: utf8Length(text), o, r });
type Row = { key: string; text: string; o?: number; r?: string };
const wire = (rows: readonly Row[]) =>
  encoder.encode(
    rows
      .map(({ key, text, o, r }) => `${spoolLine(key, text, o, r)}\n`)
      .join(""),
  );
const lineBytes = (key: string, text: string, o?: number, r?: string) =>
  utf8Length(spoolLine(key, text, o, r)) + 1;

function filesWithWrites(chunkBytes = 7) {
  const files = createMemoryStreamSyncFiles(chunkBytes);
  const writes: {
    path: string;
    bytes: number;
    buffer: number;
    batch: number;
  }[] = [];
  const port: StreamSyncFiles = {
    ...files,
    async appendMany(entries) {
      const batch = entries.reduce((n, entry) => n + entry.bytes.byteLength, 0);
      for (const entry of entries)
        writes.push({
          path: entry.path,
          bytes: entry.bytes.byteLength,
          buffer: entry.bytes.buffer.byteLength,
          batch,
        });
      await files.appendMany(entries);
    },
  };
  return { files: port, writes };
}

async function observeEncoding<T>(action: () => Promise<T>) {
  const encode = TextEncoder.prototype.encode;
  const encodeInto = TextEncoder.prototype.encodeInto;
  const calls: { kind: string; input: number; buffer: number }[] = [];
  TextEncoder.prototype.encode = function (this: TextEncoder, text = "") {
    const bytes = encode.call(this, text);
    calls.push({
      kind: "encode",
      input: utf8Length(text),
      buffer: bytes.buffer.byteLength,
    });
    return bytes;
  };
  TextEncoder.prototype.encodeInto = function (
    this: TextEncoder,
    text,
    destination,
  ) {
    calls.push({
      kind: "encodeInto",
      input: utf8Length(text),
      buffer: destination.buffer.byteLength,
    });
    return encodeInto.call(this, text, destination);
  };
  try {
    return { result: await action(), calls };
  } finally {
    TextEncoder.prototype.encode = encode;
    TextEncoder.prototype.encodeInto = encodeInto;
  }
}

function assertBound(
  calls: { kind: string; input: number; buffer: number }[],
  writes: { bytes: number; buffer: number; batch: number }[],
  chunkBytes: number,
  longestLine: number,
) {
  // Kills RESTORE_*_JOIN even when the joined batch happens to fit the bound.
  // A line's envelope is parsed or built by `encode`; it is a few hundred
  // bytes. No payload or batch may go through it.
  assert.equal(
    calls.filter((c) => c.kind === "encode" && c.input > ENVELOPE_LIMIT_BYTES)
      .length,
    0,
  );
  for (const call of calls) {
    assert.ok(
      call.input <= longestLine,
      `whole-batch string passed to encoder: ${call.input}`,
    );
    assert.ok(
      call.buffer <= chunkBytes + longestLine,
      `oversized encoder buffer: ${call.buffer}`,
    );
  }
  for (const write of writes) {
    assert.ok(
      write.batch <= chunkBytes + longestLine,
      `oversized append batch: ${write.batch}`,
    );
    assert.ok(
      write.bytes <= chunkBytes + longestLine,
      `oversized append: ${write.bytes}`,
    );
    assert.ok(
      write.buffer <= chunkBytes + longestLine,
      `oversized backing buffer: ${write.buffer}`,
    );
  }
}

/** Live heap plus ArrayBuffer stores, after GC has settled. */
function settledLiveBytes(): number {
  // `gc` is not a global in a vitest worker; expose it for this process only.
  v8.setFlagsFromString("--expose-gc");
  const gc = vm.runInNewContext("gc") as () => void;
  let prev = Infinity;
  let cur = Infinity;
  for (let i = 0; i < 8; i += 1) {
    gc();
    const m = process.memoryUsage();
    prev = cur;
    cur = m.heapUsed + m.arrayBuffers;
    if (cur >= prev) break;
  }
  return cur;
}

describe("spool allocation chunks", () => {
  // One valid line of 256 KiB, delivered one byte per chunk, read by a reader
  // that holds the open line until its newline. The reader must hold about
  // the line's size, not one allocation per chunk. Mutant it kills: an open
  // line kept as a list of per-chunk fragments (the head before this test).
  it("keeps a long line fed in one-byte chunks near its own size", async () => {
    const LINE_BYTES = 256 * 1024;
    const text = "t".repeat(LINE_BYTES);
    const bytes = encoder.encode(`${spoolLine(hash(7), text)}\n`);
    let retained = -1;
    const source: StreamSyncFiles = {
      ...createMemoryStreamSyncFiles(),
      async *readChunks() {
        const baseline = settledLiveBytes();
        for (let i = 0; i < bytes.length - 1; i += 1) {
          yield bytes.slice(i, i + 1);
        }
        // Every byte but the newline is now held by the reader.
        retained = settledLiveBytes() - baseline;
        yield bytes.slice(bytes.length - 1);
      },
    };
    const read: SpoolEntry[] = [];
    for await (const row of readSpool(source, "long.log")) read.push(row);
    assert.equal(read.length, 1);
    assert.equal(read[0]!.envelope.k, hash(7));
    assert.deepEqual(read[0]!.body, { kind: "inline", text });
    // Capacity is at most twice the line, so 3 x the line is a loose bound
    // for the reader's own state. Fragment lists measure tens of MB here.
    assert.ok(
      retained < 3 * LINE_BYTES,
      `reader held ${retained} bytes for a ${LINE_BYTES}-byte line`,
    );
  });

  // A pre-format-2 line (space at offset 64) read through the growable open
  // line buffer keeps its old size measure: line bytes + 1 of the text after
  // the key, and an envelope derived from the body.
  it("parses a legacy line assembled from one-byte chunks with its legacy size", async () => {
    const text = body("中🐟".repeat(40));
    const legacy = `${hash(3)} ${text}\n`;
    const bytes = encoder.encode(legacy);
    const source: StreamSyncFiles = {
      ...createMemoryStreamSyncFiles(),
      async *readChunks() {
        for (let i = 0; i < bytes.length; i += 1) yield bytes.slice(i, i + 1);
      },
    };
    const read: SpoolEntry[] = [];
    for await (const row of readSpool(source, "legacy.log")) read.push(row);
    assert.equal(read.length, 1);
    assert.equal(read[0]!.envelope.k, hash(3));
    assert.equal(read[0]!.size, utf8Length(text) + 1);
  });

  it("flush bytes match the joined reference across UTF-8 widths and surrogate boundaries", async () => {
    const { files, writes } = filesWithWrites(1);
    const rows = corpus.map((value, i) => ({
      key: hash(i),
      text: body(value),
    }));
    const expected = wire(rows);
    const chunkBytes = 113;
    const longest = Math.max(...rows.map((r) => lineBytes(r.key, r.text)));
    const writer = new SpoolWriter(files, chunkBytes);
    const { calls } = await observeEncoding(async () => {
      for (const row of rows)
        await writer.add("run.log", spoolLine(row.key, row.text));
      await writer.flush();
    });
    assert.deepEqual(await files.read("run.log"), expected);
    assertBound(calls, writes, chunkBytes, longest);
    const read = [];
    for await (const row of readSpool(files, "run.log"))
      read.push(row.body.kind === "inline" ? row.body.text : "");
    assert.deepEqual(
      read,
      rows.map((r) => r.text),
    );
    // Canonical JSON escapes lone units; changing that would break base parity.
    assert.ok(rows[6]!.text.includes("\\ud800"));
    assert.ok(rows[7]!.text.includes("\\udc00"));
  });

  it("bounds aggregate append bytes across multiple spool paths", async () => {
    const { files, writes } = filesWithWrites(3);
    const rows = Array.from({ length: 60 }, (_, i) => ({
      key: hash(i),
      text: body("中🐟".repeat(12)),
      path: `run${i % 6}.log`,
    }));
    const chunkBytes = 900;
    const longest = Math.max(...rows.map((r) => lineBytes(r.key, r.text)));
    const writer = new SpoolWriter(files, chunkBytes);
    const { calls } = await observeEncoding(async () => {
      for (const row of rows)
        await writer.add(row.path, spoolLine(row.key, row.text));
      await writer.flush();
    });
    for (const path of new Set(rows.map((row) => row.path)))
      assert.deepEqual(
        await files.read(path),
        wire(rows.filter((row) => row.path === path)),
      );
    assertBound(calls, writes, chunkBytes, longest); // Kills PER_PATH_BUDGET.
  });

  it("derivation bounds UTF-8 bytes rather than UTF-16 code units", async () => {
    const { files, writes } = filesWithWrites(3);
    const dir = "spool";
    // 3 UTF-8 bytes per CJK code unit. A line is ~833 bytes but ~467 UTF-16
    // units. A UTF-16 counter would flush three lines (~2.5 KB) where the
    // bound allows one chunk plus one line (~1.8 KB). The old 80-character
    // payload had a ratio low enough for that overshoot to fit the bound.
    const rows = Array.from({ length: 30 }, (_, i) => ({
      key: hash(i),
      text: body("中".repeat(200)),
    }));
    const expected = wire(rows);
    await files.write(spoolLogPath(dir), expected);
    const chunkBytes = 1024;
    const longest = Math.max(...rows.map((r) => lineBytes(r.key, r.text)));
    const { calls } = await observeEncoding(() =>
      deriveShards(files, dir, chunkBytes),
    );
    assert.deepEqual(await files.read(shardPath(dir, 0)), expected);
    assertBound(calls, writes, chunkBytes, longest); // Kills UTF16_DERIVE_BUDGET.
  });

  it("compaction writes bounded sorted winners identical to the old joined shard", async () => {
    const { files, writes } = filesWithWrites(1);
    const path = shardPath("spool", 0);
    // Each winner has a distinct observedAt (o) and run (r) stamp. Its losers
    // are: an equal-stamp loser that comes earlier in input, and an OLDER
    // candidate that comes AFTER the winner. The older candidate has a larger
    // run string, so run-before-observedAt ordering would also pick it. Each
    // one only wins if compaction keeps the last-seen line or compares the
    // stamps the wrong way round.
    const winners: Row[] = corpus.map((value, i) => ({
      key: hash(i),
      text: body(value, 100 + i, "run-b"),
      o: 100 + i,
      r: "run-b",
    }));
    const input: Row[] = corpus
      .map((_, i) => i)
      .reverse()
      .flatMap((i) => {
        const key = hash(i);
        const tie = {
          key,
          text: body("tie loser", 100 + i, "run-b"),
          o: 100 + i,
          r: "run-b",
        };
        const older = {
          key,
          text: body("older", 50 + i, "run-z"),
          o: 50 + i,
          r: "run-z",
        };
        return [tie, winners[i]!, older];
      });
    await files.write(path, wire(input));
    const expected = wire(winners);
    const chunkBytes = 113;
    const longest = Math.max(
      ...winners.map((w) => lineBytes(w.key, w.text, w.o, w.r)),
    );
    const { result, calls } = await observeEncoding(() =>
      compactShard(files, path, 0, 1_000_000, chunkBytes),
    );
    assert.equal(
      result,
      winners.reduce((n, w) => n + frameSize(w.key, w.text, w.o, w.r), 0),
    );
    assert.deepEqual(await files.read(path), expected);
    assert.ok(
      writes.length > 1,
      "winner shard must be appended in bounded batches",
    );
    assertBound(calls, writes, chunkBytes, longest);
  });

  it("copies only linear bytes while assembling a long line from small chunks", async () => {
    // A line that spans many 64-byte chunks is assembled in OpenLine. Growth by
    // doubling copies each byte O(1) times. Growth by a fixed step copies
    // O(n^2 / step) bytes, far over this budget.
    const text = "t".repeat(256 * 1024);
    const line = spoolLine(hash(7), text);
    const bytes = encoder.encode(`${line}\n`);
    const lineLength = bytes.length - 1;
    const chunkBytes = 64;
    const source: StreamSyncFiles = {
      ...createMemoryStreamSyncFiles(),
      async *readChunks() {
        for (let i = 0; i < lineLength; i += chunkBytes) {
          // Views keep input preparation out of the observed copy budget.
          yield bytes.subarray(i, Math.min(i + chunkBytes, lineLength));
        }
        yield bytes.subarray(lineLength);
      },
    };
    const set = Uint8Array.prototype.set;
    let copiedBytes = 0;
    const read: string[] = [];
    Uint8Array.prototype.set = function (this: Uint8Array, array, offset) {
      copiedBytes += array.length;
      return set.call(this, array, offset);
    };
    try {
      for await (const entry of readSpool(source, "long.log"))
        read.push(entry.line);
    } finally {
      Uint8Array.prototype.set = set;
    }
    assert.deepEqual(read, [line]);
    // Count both input appends (1 x the line) and growth copies (< 2 x).
    assert.ok(
      copiedBytes <= 3 * lineLength,
      `reader copied ${copiedBytes} bytes for a ${lineLength}-byte line`,
    );
  });

  it("countShard counts exact UTF-8 bytes without encoding payloads", async () => {
    const { files } = filesWithWrites(1);
    const rows = corpus.map((value, i) => ({
      key: hash(i, i % 2),
      text: body(value),
    }));
    await files.write("a", wire(rows.slice(0, 4)));
    await files.write("b", wire(rows.slice(4)));
    const expected = new Array<number>(256).fill(0);
    for (const row of rows)
      expected[parseInt(row.key.slice(2, 4), 16)]! += frameSize(
        row.key,
        row.text,
      );
    const { result, calls } = await observeEncoding(() =>
      countShard(files, ["a", "b"]),
    );
    assert.deepEqual(result, expected);
    // Only envelopes are decoded; no payload is encoded (kills ALLOCATING_COUNT).
    assert.ok(
      calls.every(
        (c) => c.kind === "encode" && c.input <= ENVELOPE_LIMIT_BYTES,
      ),
    );
  });

  it("empty flush, derivation, compaction and counting allocate no output buffers", async () => {
    const { files, writes } = filesWithWrites();
    const { result, calls } = await observeEncoding(async () => {
      await new SpoolWriter(files, 113).flush();
      await deriveShards(files, "empty", 113);
      assert.equal(
        await compactShard(files, shardPath("empty", 0), 0, 1000, 113),
        null,
      );
      return countShard(files, []);
    });
    assert.deepEqual(result, new Array<number>(256).fill(0));
    assert.deepEqual(calls, []);
    assert.deepEqual(writes, []);
    assert.equal(await files.read("empty.log"), null);
  });

  it("does not rewrite a unique shard or an over-budget shard", async () => {
    for (const budget of [0, 1_000_000]) {
      const { files, writes } = filesWithWrites();
      const path = shardPath("spool", 0);
      const expected = wire([{ key: hash(1), text: body("中🐟") }]);
      await files.write(path, expected);
      assert.equal(await compactShard(files, path, 0, budget, 113), null);
      assert.deepEqual(await files.read(path), expected);
      assert.deepEqual(writes, []);
    }
  });

  it("rejects malformed UTF-8 encoding of a lone surrogate while preserving canonical escaped ones", async () => {
    const { files } = filesWithWrites(1);
    // ED A0 80 encodes surrogate U+D800, forbidden by UTF-8. Canonical JSON's
    // literal backslash-u spelling is valid and covered in the identity tests.
    await files.write("invalid", Uint8Array.from([0xed, 0xa0, 0x80, 0x0a]));
    await assert.rejects(async () => {
      for await (const row of readSpool(files, "invalid")) void row;
    }, TypeError);
  });
});
