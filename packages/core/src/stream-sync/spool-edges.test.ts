import { describe, expect, it } from "vitest";
import { createMemoryStreamSyncFiles } from "./memory-files.js";
import type { StreamSyncFiles } from "./ports.js";
import { readSpool, type SpoolLine } from "./spool.js";

// Same size as the filesystem adapter's read chunk (fs-files.ts CHUNK_BYTES).
const CHUNK = 1024 * 1024;
const encoder = new TextEncoder();
const hashOf = (n: number) => n.toString(16).padStart(64, "0");

/**
 * Reference split: decode the whole file at once, split on "\n", parse each
 * complete line. The parse is written out here rather than reused from spool.ts
 * so the reference does not share code with the reader under test.
 */
function reference(bytes: Uint8Array) {
  const parts = new TextDecoder("utf-8", { fatal: true })
    .decode(bytes)
    .split("\n");
  const unterminated = parts.pop() !== "";
  const lines: SpoolLine[] = parts.map((raw) => {
    if (raw[64] !== " ") throw new Error("reference: malformed line");
    return { pkHash: raw.slice(0, 64), text: raw.slice(65) };
  });
  return { lines, unterminated };
}

/** Stores the file as one chunk; the adapter then yields exact CHUNK-byte reads. */
async function fileOf(bytes: Uint8Array, chunk = CHUNK) {
  const base = createMemoryStreamSyncFiles(chunk);
  const path = "runs/r/spool/s0/edges.log";
  await base.write(path, bytes);
  const sizes: number[] = [];
  const files: StreamSyncFiles = {
    ...base,
    async *readChunks(p) {
      for await (const chunk of base.readChunks(p)) {
        sizes.push(chunk.length);
        yield chunk;
      }
    },
  };
  return { files, path, sizes };
}

async function readAll(files: StreamSyncFiles, path: string) {
  const lines: SpoolLine[] = [];
  try {
    for await (const line of readSpool(files, path)) lines.push(line);
  } catch (error) {
    return { lines, error: error as Error };
  }
  return { lines, error: undefined };
}

/** Asserts readSpool yields exactly the reference lines, at the real chunk size. */
async function expectMatchesReference(bytes: Uint8Array, chunk = CHUNK) {
  const ref = reference(bytes);
  const { files, path, sizes } = await fileOf(bytes, chunk);
  const got = await readAll(files, path);

  expect(sizes[0]).toBe(Math.min(chunk, bytes.length));
  expect(sizes.reduce((n, s) => n + s, 0)).toBe(bytes.length);
  expect(got.lines).toEqual(ref.lines);
  if (ref.unterminated) {
    expect(got.error?.message).toContain("ends mid-line");
  } else {
    expect(got.error).toBeUndefined();
  }
  return { ref, sizes };
}

/**
 * Line 1 is ASCII and sized so that line 2's character starts at byte
 * CHUNK - split. The first `split` bytes of the character fall in chunk 1 and
 * the rest in chunk 2.
 */
function straddleFile(ch: string, split: number) {
  // Line 1 is 65 + k bytes plus "\n"; line 2's header is 65 bytes.
  const k = CHUNK - split - 131;
  return `${hashOf(1)} ${"a".repeat(k)}\n${hashOf(2)} ${ch}tail\n${hashOf(3)} after 😀€ end\n`;
}

describe("readSpool at 1 MiB chunk edges", () => {
  // (a) multi-byte characters straddle the boundary at each possible split.
  it.each([
    ["€ (3 bytes), split 1|2", "€", 1],
    ["€ (3 bytes), split 2|1", "€", 2],
    ["😀 (4 bytes), split 1|3", "😀", 1],
    ["😀 (4 bytes), split 2|2", "😀", 2],
    ["😀 (4 bytes), split 3|1", "😀", 3],
  ])("(a) %s", async (_name, ch, split) => {
    const bytes = encoder.encode(straddleFile(ch, split));
    const at = CHUNK - split;
    expect(bytes.subarray(at, at + encoder.encode(ch).length)).toEqual(
      encoder.encode(ch),
    );
    const { ref } = await expectMatchesReference(bytes);
    expect(ref.lines[1]?.text).toContain(ch);
  });

  // (b) one line is longer than two chunks and crosses two boundaries.
  it("(b) one line spans more than two chunks", async () => {
    const unit = "é€😀"; // 2 + 3 + 4 bytes
    const long = unit.repeat(Math.ceil((2.5 * CHUNK) / 9));
    const bytes = encoder.encode(
      `${hashOf(1)} short\n${hashOf(2)} ${long}\n${hashOf(3)} after\n`,
    );
    expect(encoder.encode(long).length).toBeGreaterThan(2 * CHUNK);
    const { ref } = await expectMatchesReference(bytes);
    expect(ref.lines[1]?.text).toBe(long);
  });

  // (c) a line ends exactly at a boundary, in two positions.
  it.each([
    ["newline is the last byte of chunk 1", CHUNK - 1],
    ["last content byte is the last byte of chunk 1", CHUNK],
  ])("(c) a line ends at the boundary: %s", async (_name, newlineAt) => {
    // Line 1 is ASCII: its header is 65 bytes, then k content bytes, then "\n".
    const k = newlineAt - 65;
    const bytes = encoder.encode(
      `${hashOf(1)} ${"a".repeat(k)}\n${hashOf(2)} 😀 tail\n${hashOf(3)} last\n`,
    );
    expect(bytes[newlineAt]).toBe(0x0a);
    await expectMatchesReference(bytes);
  });

  // (d) the last line has no "\n": complete lines are yielded, then the error.
  it("(d) the file has no trailing newline", async () => {
    const bytes = encoder.encode(
      `${hashOf(1)} ${"x".repeat(CHUNK + 100)}\n${hashOf(2)} tail 😀`,
    );
    const { ref } = await expectMatchesReference(bytes);
    expect(ref.unterminated).toBe(true);
    expect(ref.lines).toHaveLength(1);
  });
});

// The whole-file decoder strips a U+FEFF only at the very start of the file.
// Decoding each line on its own must match that rule exactly.
const BOM = "\uFEFF";

/** Line 1 is ASCII and ends so that line 2 starts at `start` with a BOM. */
function lineStartBomFile(start: number) {
  // Line 1 is 66 + k bytes including its "\n".
  const k = start - 66;
  return `${hashOf(1)} ${"a".repeat(k)}\n${BOM}${hashOf(2)} two\n`;
}

describe("readSpool and the byte order mark", () => {
  it("strips a BOM at the start of the file", async () => {
    await expectMatchesReference(
      encoder.encode(`${BOM}${hashOf(1)} one\n${hashOf(2)} two\n`),
    );
  });

  it("strips a BOM at the start of the file across 1-byte reads", async () => {
    await expectMatchesReference(
      encoder.encode(`${BOM}${hashOf(1)} one\n${hashOf(2)} two\n`),
      1,
    );
  });

  it("keeps a U+FEFF inside a line", async () => {
    const bytes = encoder.encode(`${hashOf(1)} a${BOM}b\n${hashOf(2)} two\n`);
    const { ref } = await expectMatchesReference(bytes);
    expect(ref.lines[0]?.text).toBe(`a${BOM}b`);
  });

  it.each([1, 2])(
    "keeps a U+FEFF inside a line that straddles the 1 MiB boundary (split %i)",
    async (split) => {
      const bytes = encoder.encode(straddleFile(BOM, split));
      const at = CHUNK - split;
      expect(bytes.subarray(at, at + 3)).toEqual(encoder.encode(BOM));
      const { ref } = await expectMatchesReference(bytes);
      expect(ref.lines[1]?.text).toContain(BOM);
    },
  );

  // Red on the per-line decode: each line used to lose a leading U+FEFF.
  it.each([
    ["a small file", 100],
    ["a line that starts at the 1 MiB boundary", CHUNK - 1],
  ])("does not strip a U+FEFF at a line start: %s", async (_name, start) => {
    const bytes = encoder.encode(lineStartBomFile(start));
    expect(bytes[start]).toBe(0xef);
    const { files, path } = await fileOf(bytes);
    const got = await readAll(files, path);
    expect(got.lines).toEqual([
      { pkHash: hashOf(1), text: "a".repeat(start - 66) },
    ]);
    expect(got.error?.message).toBe("malformed spool line");
  });

  // Red on the per-line decode: the file has no lines, so no error either.
  it.each([
    ["in one read", CHUNK],
    ["across 1-byte reads", 1],
  ])(
    "a file that is only a BOM has no lines and no error: %s",
    async (_name, chunk) => {
      await expectMatchesReference(encoder.encode(BOM), chunk);
    },
  );

  it("reads a file with no BOM unchanged", async () => {
    await expectMatchesReference(
      encoder.encode(`${hashOf(1)} one\n${hashOf(2)} two\n`),
    );
  });
});
