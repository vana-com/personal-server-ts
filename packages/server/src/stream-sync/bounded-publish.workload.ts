/**
 * Lane P1 workload: a real StreamSyncWriter (fs spool, disk-backed blobs)
 * publishes a repeated-key NDJSON source. Two halves:
 *
 * - `publishWorkload` runs in a fresh child (see packages/core/src/test-support/memory-oracle.ts). It does the
 *   publish and nothing else, so its kernel peak is the publish's peak.
 * - `verifyPublished` runs in the test process after the child exits. It reads
 *   the published head, then every part one at a time, and checks that every
 *   key is present exactly once, that its `seq` is the last version and its
 *   `pad` is right. Completeness is a bitmap over keys, not a body map.
 *
 * Records: record i has id `k<i % distinct>` and seq `i`, so the last version of
 * key k is at index k + floor((records - 1 - k) / distinct) * distinct.
 */

import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import {
  type StreamSyncBlobs,
  StreamSyncWriter,
  createStreamSyncKeyPorts,
  streamSyncHashes,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  PART_LIMIT_BYTES,
  decodeHead,
  linesOfParts,
  partBlobName,
  streamScope,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createFsStreamSyncFiles } from "./fs-files.js";
import {
  OWNER,
  OWNER_SIGNATURE,
  SERVER_KEY,
  SHAPE,
  accountSigner,
  createFakeStreamSyncRegistry,
  finishedOutcome,
  testStreamSyncHome,
} from "./bounded-publish.harness.js";

export const NS = "";
export const CONNECTOR = "p1-bounded";
export const STREAM = "items";
export const P = PART_LIMIT_BYTES;

export interface SourceCase {
  /** Bytes per record line, newline included. */
  readonly recordBytes: number;
  readonly records: number;
  /** Distinct keys. Key k's last version is its winner. */
  readonly distinct: number;
}

export interface WriterKnobs {
  readonly partTargetBytes?: number;
  readonly reduceBudgetBytes?: number;
  readonly spoolFlushBytes?: number;
}

const PROBE = `{"id":"k00000000","pad":"","seq":"000000000"}`;

/** The pad string every record of this size carries. */
export function recordPad(recordBytes: number): string {
  return "p".repeat(recordBytes - 1 - Buffer.byteLength(PROBE));
}

export function recordIdOf(index: number, distinct: number): string {
  return `k${String(index % distinct).padStart(8, "0")}`;
}

/** Deterministic NDJSON; every line is exactly `recordBytes` including "\n". */
export async function ensureSource(path: string, c: SourceCase): Promise<void> {
  const expectedSize = c.records * c.recordBytes;
  try {
    if ((await stat(path)).size === expectedSize) return;
  } catch {
    // Missing: generate below.
  }
  const pad = recordPad(c.recordBytes);
  const out = createWriteStream(path);
  for (let i = 0; i < c.records; i += 1) {
    const line = `${JSON.stringify({
      id: recordIdOf(i, c.distinct),
      seq: String(i).padStart(9, "0"),
      pad,
    })}\n`;
    if (!out.write(line)) await new Promise((r) => out.once("drain", r));
  }
  await new Promise<void>((resolve, reject) => {
    out.end((error?: Error | null) => (error ? reject(error) : resolve()));
  });
  const size = (await stat(path)).size;
  if (size !== expectedSize) {
    throw new Error(
      `source ${path} is ${size} bytes, expected ${expectedSize}`,
    );
  }
}

/** Disk-backed blob store: ciphertext lives in files, not in the heap. */
export function diskBlobs(dir: string): StreamSyncBlobs {
  const file = (key: string) => join(dir, encodeURIComponent(key));
  return {
    async put(key, bytes) {
      await writeFile(file(key), bytes);
    },
    async get(key) {
      try {
        return new Uint8Array(await readFile(file(key)));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw error;
      }
    },
  };
}

export interface PublishArgs {
  readonly source: string;
  readonly root: string;
  readonly records: number;
  readonly distinct: number;
  readonly writer?: WriterKnobs;
}

export interface PublishResult {
  readonly scope: string;
  /** Lowercase hex of the head's Keccak-256 (`h-<hex>` is its blob name). */
  readonly headHex: string;
  readonly blobDir: string;
  readonly generation: number;
}

/** Child side: publish the source through the real writer. No read-back. */
export async function publishWorkload(args: unknown): Promise<PublishResult> {
  const a = args as PublishArgs;
  const registry = createFakeStreamSyncRegistry();
  const blobDir = join(a.root, "blobs");
  await mkdir(blobDir, { recursive: true });
  const files = createFsStreamSyncFiles(join(a.root, "device"));
  const writer = new StreamSyncWriter({
    ownerAddress: OWNER,
    registry,
    blobs: diskBlobs(blobDir),
    home: testStreamSyncHome(files),
    keys: createStreamSyncKeyPorts(OWNER_SIGNATURE),
    signer: accountSigner(SERVER_KEY),
    declaredStreams: () => [],
    ...a.writer,
  });
  const runId = `run-${a.distinct}-${a.records}`;
  await writer.refreshControls();
  await writer.beginRun({
    runId,
    connector: CONNECTOR,
    userConnect: false,
    observedAt: Date.UTC(2026, 10, 1),
    identity: "none",
    checkpointUsed: null,
  });
  await writer.declareStream(runId, STREAM, SHAPE);
  const lines = createInterface({
    input: createReadStream(a.source, { highWaterMark: 64 * 1024 }),
    crlfDelay: Infinity,
  });
  for await (const line of lines) {
    await writer.append(
      runId,
      STREAM,
      JSON.parse(line) as Record<string, unknown>,
    );
  }
  await writer.finishRun(runId, { checkpointCandidate: { cursor: runId } });
  await writer.publishPending();

  const finished = finishedOutcome(await writer.status(), runId)?.outcome;
  if (
    !finished ||
    finished.kind !== "checkpointed" ||
    finished.generation !== 1
  ) {
    throw new Error(`publish did not checkpoint: ${JSON.stringify(finished)}`);
  }
  const scope = streamScope(CONNECTOR, NS, STREAM);
  const row = await registry.read(scope);
  if (!row.found) throw new Error("stream not published");
  return {
    scope,
    headHex: row.dataHash.toLowerCase().replace(/^0x/, ""),
    blobDir,
    generation: finished.generation,
  };
}

/** The last version's index for key k. */
export function lastIndexOf(k: number, c: SourceCase): number {
  return k + Math.floor((c.records - 1 - k) / c.distinct) * c.distinct;
}

/**
 * Parent side, after the measured child has exited. Reads the head, then each
 * part one at a time. Throws on the first violation, with the key or part.
 */
export async function verifyPublished(
  out: PublishResult,
  c: SourceCase,
): Promise<{ parts: number; maxPartBytes: number; keys: number }> {
  const blobs = diskBlobs(out.blobDir);
  const keys = createStreamSyncKeyPorts(OWNER_SIGNATURE);
  const headCipher = await blobs.get(`${out.scope}/h-${out.headHex}`);
  if (!headCipher) throw new Error("head blob is missing");
  const decoded = decodeHead(await keys.decrypt(out.scope, headCipher));
  if (decoded.kind !== "ok") throw new Error(`head: ${decoded.kind}`);
  const head: Head = decoded.head;

  if (!head.complete) throw new Error("head is not complete");
  if (head.recordCount !== c.distinct) {
    throw new Error(`recordCount ${head.recordCount}, expected ${c.distinct}`);
  }
  if (head.parts.length < 2) throw new Error("expected more than one part");
  if (head.parts.reduce((n, p) => n + p.count, 0) !== c.distinct) {
    throw new Error("part counts do not sum to the distinct keys");
  }

  const pad = recordPad(c.recordBytes);
  const seen = new Uint8Array(c.distinct);
  let seenCount = 0;
  let maxPartBytes = 0;
  const sizes = new Map<string, number>();
  for (const part of head.parts) {
    if (part.bytes > P) throw new Error(`part ${part.hash} exceeds P`);
    maxPartBytes = Math.max(maxPartBytes, part.bytes);
    sizes.set(part.hash, part.bytes);
  }
  const loadPart = async (part: Head["parts"][number]) => {
    const name = `${out.scope}/${partBlobName(out.generation, part.hash)}`;
    const cipher = await blobs.get(name);
    if (!cipher) throw new Error(`part ${part.hash} is missing`);
    return keys.decrypt(out.scope, cipher);
  };
  {
    for await (const line of linesOfParts(
      streamSyncHashes.sha256,
      head,
      loadPart,
    )) {
      const id = line.v.id;
      if (typeof id !== "string" || !/^k\d{8}$/.test(id)) {
        throw new Error(`record id ${JSON.stringify(id)} is not a key`);
      }
      const k = Number(id.slice(1));
      if (k >= c.distinct) throw new Error(`key ${id} is out of range`);
      if (seen[k]) throw new Error(`key ${id} appears in two parts`);
      seen[k] = 1;
      seenCount += 1;
      const expectedSeq = String(lastIndexOf(k, c)).padStart(9, "0");
      if (line.v.seq !== expectedSeq) {
        throw new Error(
          `key ${id}: seq ${JSON.stringify(line.v.seq)}, expected last version ${expectedSeq}`,
        );
      }
      if (line.v.pad !== pad) {
        throw new Error(
          `key ${id}: pad has ${String(line.v.pad).length} bytes, expected ${pad.length}`,
        );
      }
    }
  }
  if (seenCount !== c.distinct) {
    throw new Error(
      `${c.distinct - seenCount} keys are missing from the parts`,
    );
  }
  return { parts: head.parts.length, maxPartBytes, keys: seenCount };
}
