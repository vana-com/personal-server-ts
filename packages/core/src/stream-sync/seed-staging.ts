/**
 * Portable seed staging for Desktop and Lite (design revision 4.1, §2.9).
 *
 * Desktop keeps the retained rows of its own runs. Before the first
 * generation-1 publish of a connection, it hands them to its sidecar through
 * the seed route, one (connector, stream) at a time. This module stages each
 * upload through its host files port and serves the staged rows to the writer as its
 * `StreamSyncSeedSource`. The writer merges them into the first publish to
 * (seed target, generation 1) and records a receipt per stream; after that
 * the staged rows are dropped.
 *
 * Layout under the files port:
 *
 *   install-id                          stable id of this install
 *   uploads/<id>/rows.ndjson            one record per line
 *   staged/<hex connector>/<hex stream>.json   the current upload of a stream
 *
 * An upload becomes visible only when its pointer is written, after every
 * line arrived and the count matched. A replaced or dropped upload is
 * removed by the next `streams()` call, which the writer makes before it
 * reads any rows, so a read never loses its file.
 *
 * Memory is bounded by one record plus one write batch, whatever the upload
 * size. A record has the same acceptance rules as run intake.
 */

import {
  isPlainObject,
  pkHash,
  streamScope,
  type HeadProfile,
  type JsonObject,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { streamSyncHashes } from "./crypto.js";
import type {
  SeedReceipt,
  StreamSyncFiles,
  StreamSyncSeedSource,
} from "./ports.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const NEWLINE = 0x0a;
const BATCH_BYTES = 1024 * 1024;
/** A ns of the longest form, to check that every stream name fits (§2.1). */
const LONGEST_NS = "0".repeat(16);

/** First line of an upload. */
export interface SeedDescriptor {
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  /** Record lines that follow; a different count rejects the upload. */
  readonly records: number;
}

export interface StagedSeed {
  readonly upload: string;
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  /** Rows staged for the seed. */
  readonly records: number;
  /** Lines that were not a JSON object with every primary-key field. */
  readonly invalid: number;
}

export class SeedUploadError extends Error {
  constructor(
    readonly errorCode:
      "SEED_BAD_NAME" | "SEED_BAD_DESCRIPTOR" | "SEED_COUNT_MISMATCH",
    message: string,
  ) {
    super(message);
    this.name = "SeedUploadError";
  }
}

export type SeedStreamState =
  | { readonly state: SeedReceipt }
  | ({ readonly state: "staged" } & Omit<
      StagedSeed,
      "upload" | "profile" | "primaryKey"
    >);

/** Receipts of the writer for `connector` on this install. */
export interface SeedReceiptLookupResult {
  /** Receipt per stream for the current seed target. */
  readonly receipts: Readonly<Record<string, SeedReceipt>>;
  /** Staged uploads a delete retired. A new upload for the stream is not one. */
  readonly skipped: readonly {
    readonly stream: string;
    readonly upload: string;
  }[];
}

export type SeedReceiptLookup = (
  connector: string,
) => Promise<SeedReceiptLookupResult>;

export interface SeedStaging {
  /** The stable id of this install, created on first use. */
  installId(): Promise<string>;
  /**
   * The writer's seed source. `receipts` reads the writer's receipts; a
   * stream with a receipt is never offered again and its rows are dropped.
   */
  source(installId: string, receipts: SeedReceiptLookup): StreamSyncSeedSource;
  /** Stage one upload; the previous upload of the stream is replaced. */
  stage(
    connector: string,
    stream: string,
    body: AsyncIterable<Uint8Array>,
    validate?: (descriptor: SeedDescriptor) => void | Promise<void>,
  ): Promise<StagedSeed>;
  /** The staged streams of `connector`. */
  staged(connector: string): Promise<Record<string, StagedSeed>>;
  /**
   * Remove the staged rows of a stream that holds a receipt. Only call it
   * for such a stream: the writer reads staged rows only before the receipt.
   */
  drop(connector: string, stream: string): Promise<void>;
}

function hex(name: string): string {
  return bytesToHex(encoder.encode(name));
}

function unhex(text: string): string {
  return decoder.decode(hexToBytes(text));
}

/** Throws `SEED_BAD_NAME` unless (connector, stream) makes a valid scope. */
export function checkSeedNames(connector: string, stream: string): void {
  try {
    streamScope(connector, LONGEST_NS, stream);
  } catch (error) {
    throw new SeedUploadError("SEED_BAD_NAME", (error as Error).message);
  }
  if (connector.includes("|") || stream.includes("|")) {
    throw new SeedUploadError("SEED_BAD_NAME", "names may not contain '|'");
  }
}

function parseDescriptor(text: string): SeedDescriptor {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new SeedUploadError(
      "SEED_BAD_DESCRIPTOR",
      "the first line is not JSON",
    );
  }
  const bad = (why: string) => new SeedUploadError("SEED_BAD_DESCRIPTOR", why);
  if (!isPlainObject(value)) throw bad("the first line is not an object");
  const { primaryKey, profile, records } = value as Record<string, unknown>;
  if (
    !Array.isArray(primaryKey) ||
    primaryKey.length === 0 ||
    !primaryKey.every((f) => typeof f === "string" && f !== "")
  ) {
    throw bad("primaryKey must be a non-empty array of field names");
  }
  if (
    !isPlainObject(profile) ||
    !(profile.key === null || typeof profile.key === "string") ||
    typeof profile.version !== "string" ||
    profile.version === ""
  ) {
    throw bad("profile must be {key: string|null, version: string}");
  }
  if (
    typeof records !== "number" ||
    !Number.isSafeInteger(records) ||
    records < 0
  ) {
    throw bad("records must be a non-negative integer");
  }
  return {
    primaryKey: primaryKey as string[],
    profile: { key: profile.key as string | null, version: profile.version },
    records,
  };
}

/**
 * Split a byte stream into lines. A line is held whole while it is parsed, so
 * a very large record costs about its size here; the rows file is the only
 * other place the seed keeps it.
 */
async function* lines(
  body: AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  let pending: Uint8Array[] = [];
  let pendingBytes = 0;
  const take = (tail: Uint8Array): Uint8Array => {
    const out = new Uint8Array(pendingBytes + tail.length);
    let at = 0;
    for (const piece of pending) {
      out.set(piece, at);
      at += piece.length;
    }
    out.set(tail, at);
    pending = [];
    pendingBytes = 0;
    return out;
  };
  for await (const chunk of body) {
    let start = 0;
    for (;;) {
      const end = chunk.indexOf(NEWLINE, start);
      if (end < 0) break;
      yield take(chunk.subarray(start, end));
      start = end + 1;
    }
    if (start < chunk.length) {
      const rest = chunk.subarray(start);
      pending.push(rest.slice());
      pendingBytes += rest.length;
    }
  }
  if (pendingBytes > 0) yield take(new Uint8Array());
}

function randomId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

export function createSeedStaging(files: StreamSyncFiles): SeedStaging {
  /** Uploads being written by this process; never collected. */
  const active = new Set<string>();
  let installIdPromise: Promise<string> | null = null;

  const pointerPath = (connector: string, stream: string) =>
    `staged/${hex(connector)}/${hex(stream)}.json`;

  async function readPointer(path: string): Promise<StagedSeed | null> {
    const bytes = await files.read(path);
    return bytes ? (JSON.parse(decoder.decode(bytes)) as StagedSeed) : null;
  }

  async function staged(
    connector: string,
  ): Promise<Record<string, StagedSeed>> {
    const out: Record<string, StagedSeed> = {};
    const prefix = `staged/${hex(connector)}`;
    for (const path of await files.list(prefix)) {
      const match = /^staged\/[0-9a-f]+\/([0-9a-f]*)\.json$/.exec(path);
      if (!match) continue;
      const pointer = await readPointer(path);
      if (pointer) out[unhex(match[1]!)] = pointer;
    }
    return out;
  }

  /** Remove uploads that no pointer names and no request is writing. */
  async function collect(): Promise<void> {
    const referenced = new Set<string>();
    for (const path of await files.list("staged")) {
      const pointer = await readPointer(path);
      if (pointer) referenced.add(pointer.upload);
    }
    const uploads = new Set<string>();
    for (const path of await files.list("uploads")) {
      const match = /^uploads\/([0-9a-f]+)\//.exec(path);
      if (match) uploads.add(match[1]!);
    }
    for (const id of uploads) {
      if (!referenced.has(id) && !active.has(id)) {
        await files.remove(`uploads/${id}`);
      }
    }
  }

  return {
    installId() {
      installIdPromise ??= (async () => {
        const existing = await files.read("install-id");
        if (existing) return decoder.decode(existing).trim();
        const id = randomId();
        await files.write("install-id", encoder.encode(id));
        return id;
      })();
      return installIdPromise;
    },

    source(installId, receipts) {
      return {
        installId,
        async streams(connector) {
          const { receipts: done, skipped } = await receipts(connector);
          const out = [];
          for (const [stream, seed] of Object.entries(
            await staged(connector),
          )) {
            if (
              done[stream] !== undefined ||
              skipped.some(
                (s) => s.stream === stream && s.upload === seed.upload,
              )
            ) {
              await files.remove(pointerPath(connector, stream));
              continue;
            }
            out.push({
              stream,
              upload: seed.upload,
              primaryKey: seed.primaryKey,
              profile: seed.profile,
            });
          }
          await collect();
          return out.sort((a, b) => (a.stream < b.stream ? -1 : 1));
        },
        async *records(connector, stream) {
          const pointer = await readPointer(pointerPath(connector, stream));
          if (!pointer) return;
          const chunks = files.readChunks(
            `uploads/${pointer.upload}/rows.ndjson`,
          );
          for await (const line of lines(chunks)) {
            if (line.length === 0) continue;
            yield JSON.parse(decoder.decode(line)) as Record<string, unknown>;
          }
        },
      };
    },

    async stage(connector, stream, body, validate) {
      checkSeedNames(connector, stream);
      const upload = randomId();
      active.add(upload);
      const rowsPath = `uploads/${upload}/rows.ndjson`;
      try {
        let descriptor: SeedDescriptor | null = null;
        let seen = 0;
        let records = 0;
        let invalid = 0;
        let batch: string[] = [];
        let batchBytes = 0;
        const flush = async () => {
          if (batch.length === 0) return;
          await files.appendMany([
            { path: rowsPath, bytes: encoder.encode(batch.join("")) },
          ]);
          batch = [];
          batchBytes = 0;
        };
        for await (const line of lines(body)) {
          if (descriptor === null) {
            descriptor = parseDescriptor(decoder.decode(line));
            await validate?.(descriptor);
            continue;
          }
          if (line.length === 0) continue;
          seen += 1;
          const text = decoder.decode(line);
          let value: unknown;
          try {
            value = JSON.parse(text);
            if (!isPlainObject(value)) throw new Error("not an object");
            await pkHash(
              streamSyncHashes.sha256,
              value as JsonObject,
              descriptor.primaryKey,
            );
          } catch {
            invalid += 1;
            continue;
          }
          records += 1;
          batch.push(`${text}\n`);
          batchBytes += line.length + 1;
          if (batchBytes >= BATCH_BYTES) await flush();
        }
        if (descriptor === null) {
          throw new SeedUploadError("SEED_BAD_DESCRIPTOR", "the body is empty");
        }
        if (seen !== descriptor.records) {
          throw new SeedUploadError(
            "SEED_COUNT_MISMATCH",
            `expected ${descriptor.records} record lines, got ${seen}`,
          );
        }
        await flush();
        // The rows are durable before the pointer names them.
        await files.sync(`uploads/${upload}`);
        const seed: StagedSeed = {
          upload,
          primaryKey: [...descriptor.primaryKey],
          profile: descriptor.profile,
          records,
          invalid,
        };
        await files.write(
          pointerPath(connector, stream),
          encoder.encode(JSON.stringify(seed)),
        );
        return seed;
      } catch (error) {
        // A pointer write can commit before its acknowledgement is lost. Never
        // erase rows that the durable pointer may already name. Reconcile the
        // committed write now, or let the next collection settle an unknown one.
        let committed: StagedSeed | null;
        try {
          committed = await readPointer(pointerPath(connector, stream));
        } catch {
          throw error;
        }
        if (committed?.upload === upload) return committed;
        await files.remove(`uploads/${upload}`);
        throw error;
      } finally {
        active.delete(upload);
      }
    },

    staged,

    async drop(connector, stream) {
      const path = pointerPath(connector, stream);
      const pointer = await readPointer(path);
      if (!pointer) return;
      await files.remove(path);
      await files.remove(`uploads/${pointer.upload}`);
    },
  };
}
