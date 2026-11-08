/**
 * Allocation cut 1. Reference bytes intentionally retain the old joined form.
 * Production must not: observe the encoder and append port, not V8 heap usage.
 *
 * Mutants: RESTORE_FLUSH_JOIN, RESTORE_COMPACTION_JOIN, SPLIT_SURROGATE_PAIR,
 * UTF16_DERIVE_BUDGET, ALLOCATING_COUNT, PER_PATH_BUDGET and RESTORE_EXCLUDED_JOIN.
 */
import assert from "node:assert/strict";
import { describe, it } from "vitest";
import {
  RECORD_LINE_LIMIT_BYTES,
  encodeLine,
  pkHash,
  utf8Length,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createMemoryStreamSyncFiles } from "./memory-files.js";
import type { StreamSyncFiles } from "./ports.js";
import {
  SpoolWriter,
  compactShard,
  countShard,
  deriveShards,
  readSpool,
  shardPath,
  spoolLogPath,
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
const line = (value: string, o = 2, r = "run") =>
  encodeLine({ o, r, v: { value } });
const wire = (rows: readonly { key: string; text: string }[]) =>
  encoder.encode(rows.map(({ key, text }) => `${key} ${text}\n`).join(""));

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
  assert.equal(calls.filter((c) => c.kind === "encode").length, 0);
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

describe("spool allocation chunks", () => {
  it("flush bytes match the joined reference across UTF-8 widths and surrogate boundaries", async () => {
    const { files, writes } = filesWithWrites(1);
    const rows = corpus.map((value, i) => ({
      key: hash(i),
      text: line(value),
    }));
    const expected = wire(rows);
    const chunkBytes = 113;
    const longest = Math.max(...rows.map((r) => utf8Length(r.text) + 66));
    const writer = new SpoolWriter(files, chunkBytes);
    const { calls } = await observeEncoding(async () => {
      for (const row of rows)
        await writer.add("run.log", row.key, row.text, utf8Length(row.text));
      await writer.flush();
    });
    assert.deepEqual(await files.read("run.log"), expected);
    assertBound(calls, writes, chunkBytes, longest);
    const read = [];
    for await (const row of readSpool(files, "run.log")) read.push(row.text);
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
      text: line("中🐟".repeat(12)),
      path: `run${i % 6}.log`,
    }));
    const chunkBytes = 900;
    const longest = Math.max(...rows.map((r) => utf8Length(r.text) + 66));
    const writer = new SpoolWriter(files, chunkBytes);
    const { calls } = await observeEncoding(async () => {
      for (const row of rows)
        await writer.add(row.path, row.key, row.text, utf8Length(row.text));
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
    const rows = Array.from({ length: 30 }, (_, i) => ({
      key: hash(i),
      text: line("中".repeat(80)),
    }));
    const expected = wire(rows);
    await files.write(spoolLogPath(dir), expected);
    const chunkBytes = 1024;
    const longest = Math.max(...rows.map((r) => utf8Length(r.text) + 66));
    const { calls } = await observeEncoding(() =>
      deriveShards(files, dir, chunkBytes),
    );
    assert.deepEqual(await files.read(shardPath(dir, 0)), expected);
    assertBound(calls, writes, chunkBytes, longest); // Kills UTF16_DERIVE_BUDGET.
  });

  it("compaction writes bounded sorted winners identical to the old joined shard", async () => {
    const { files, writes } = filesWithWrites(1);
    const path = shardPath("spool", 0);
    const winners = corpus.map((value, i) => ({
      key: hash(i),
      text: line(value),
    }));
    // Reverse input order and include a losing older value and an equal-stamp
    // loser. The later equal stamp wins, exactly as before this cut.
    const input = [...winners]
      .reverse()
      .flatMap((w) => [
        { key: w.key, text: line("older", 1) },
        { key: w.key, text: line("tie loser") },
        w,
      ]);
    await files.write(path, wire(input));
    const expected = wire(winners);
    const chunkBytes = 113;
    const longest = Math.max(...winners.map((w) => utf8Length(w.text) + 66));
    const { result, calls } = await observeEncoding(() =>
      compactShard(files, path, 0, 1_000_000, chunkBytes),
    );
    assert.equal(
      result,
      winners.reduce((n, w) => n + utf8Length(w.text) + 1, 0),
    );
    assert.deepEqual(await files.read(path), expected);
    assert.ok(
      writes.length > 1,
      "winner shard must be appended in bounded batches",
    );
    assertBound(calls, writes, chunkBytes, longest);
  });

  it("excluded-record text lines use bounded encoding without a joined batch", async () => {
    const { files, writes } = filesWithWrites();
    const rows = corpus.map((value) =>
      JSON.stringify({ stream: value, pkHash: hash(1), bytes: 9_000_000 }),
    );
    const expected = encoder.encode(rows.map((r) => r + "\n").join(""));
    const chunkBytes = 113;
    const longest = Math.max(...rows.map((r) => utf8Length(r) + 1));
    const writer = new SpoolWriter(files, chunkBytes);
    const { calls } = await observeEncoding(async () => {
      for (const row of rows)
        await writer.addLine("excluded.ndjson", row, utf8Length(row));
      await writer.flush();
    });
    assert.deepEqual(await files.read("excluded.ndjson"), expected);
    assertBound(calls, writes, chunkBytes, longest);
  });

  it("finishRun flushes excluded records in configured bounded batches", async () => {
    const { StreamSyncWriter } = await import("./writer.js");
    const { bindStreamSyncHome } = await import("./home.js");
    const { streamSyncHashes } = await import("./crypto.js");
    const memory = createMemoryStreamSyncFiles();
    const runId = "excluded-chunks";
    const stream = "rows-漢🐟";
    const path = `runs/${runId}/excluded.ndjson`;
    const threshold = 128;
    const batches: number[] = [];
    const events: string[] = [];
    const files: StreamSyncFiles = {
      ...memory,
      async appendMany(entries) {
        const bytes = entries
          .filter((entry) => entry.path === path)
          .reduce((sum, entry) => sum + entry.bytes.length, 0);
        if (bytes > 0) {
          batches.push(bytes);
          events.push("append");
        }
        await memory.appendMany(entries);
      },
      async sync(prefix) {
        events.push(`sync:${prefix}`);
        await memory.sync(prefix);
      },
    };
    const unexpected = async (): Promise<never> => {
      throw new Error("intake-only test unexpectedly invoked publication");
    };
    const ownerAddress = "0x1111111111111111111111111111111111111111";
    const writer = new StreamSyncWriter({
      ownerAddress,
      home: bindStreamSyncHome({
        ownerAddress,
        network: "test",
        open: () => files,
      }),
      registry: {
        // declareStream reads the stream's control row (not a publication).
        read: async () => ({ found: false }),
        post: unexpected,
        listControlRows: unexpected,
      },
      blobs: { get: unexpected, put: unexpected },
      keys: {
        namespaceHmac: async () => new Uint8Array(32),
        encrypt: unexpected,
        decrypt: unexpected,
      },
      signer: { signAddData: unexpected },
      spoolFlushBytes: threshold,
      now: () => 1,
    });
    await writer.beginRun({
      runId,
      connector: "test",
      userConnect: false,
      observedAt: 1,
    });
    await writer.declareStream(runId, stream, {
      primaryKey: ["id"],
      profile: { key: null, version: "1" },
    });

    const payload = "x".repeat(RECORD_LINE_LIMIT_BYTES);
    let expected = "";
    let largestLine = 0;
    for (let id = 0; id < 5; id += 1) {
      const record = { id, payload };
      const bytes =
        payload.length +
        utf8Length(encodeLine({ o: 1, r: runId, v: { id, payload: "" } }));
      const digest = await pkHash(streamSyncHashes.sha256, record, ["id"]);
      const excluded = `${JSON.stringify({ stream, pkHash: digest, bytes })}\n`;
      expected += excluded;
      largestLine = Math.max(largestLine, utf8Length(excluded));
      assert.equal(await writer.append(runId, stream, record), "too_large");
    }

    assert.deepEqual(batches, []);
    const status = await writer.finishRun(runId, { checkpointCandidate: null });
    assert.equal(status.phase, "ready");
    assert.equal(status.streams[stream]?.recordTooLarge, 5);
    assert.ok(utf8Length(expected) > threshold + largestLine);
    assert.ok(batches.length > 1); // Kills RESTORE_EXCLUDED_JOIN in the writer.
    for (const bytes of batches) assert.ok(bytes <= threshold + largestLine);
    assert.deepEqual(await memory.read(path), encoder.encode(expected));
    assert.deepEqual(events, [
      ...batches.map(() => "append"),
      `sync:runs/${runId}`,
    ]);
  });

  it("countShard counts exact UTF-8 bytes without encoding payloads", async () => {
    const { files } = filesWithWrites(1);
    const rows = corpus.map((value, i) => ({
      key: hash(i, i % 2),
      text: line(value),
    }));
    await files.write("a", wire(rows.slice(0, 4)));
    await files.write("b", wire(rows.slice(4)));
    const expected = new Array<number>(256).fill(0);
    for (const row of rows)
      expected[parseInt(row.key.slice(2, 4), 16)]! +=
        encoder.encode(row.text).length + 1;
    const { result, calls } = await observeEncoding(() =>
      countShard(files, ["a", "b"]),
    );
    assert.deepEqual(result, expected);
    assert.deepEqual(calls, []); // Kills ALLOCATING_COUNT.
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
      const expected = wire([{ key: hash(1), text: line("中🐟") }]);
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
