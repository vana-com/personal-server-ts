/**
 * Publisher-backed fixture for the stream-sync read side. Moved out of
 * `stream-sync-read/memory.test.ts` so that gate tests can share it.
 *
 * Fixtures use identity encryption. The real publisher, codec and hashes are
 * kept. Encryption is not what these tests measure.
 */

import type { JsonObject } from "@opendatalabs/personal-server-ts-stream-sync";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { streamSyncReadHashes } from "../stream-sync-read/keys.js";
import { createMemoryStreamSyncReadFiles } from "../stream-sync-read/memory-files.js";
import type { MirrorFeedRow } from "../stream-sync-read/mirror.js";
import type {
  StreamSyncOverlayEntry,
  StreamSyncReadFiles,
} from "../stream-sync-read/ports.js";
import {
  StreamSyncReadService,
  type StreamSyncReadOptions,
} from "../stream-sync-read/service.js";
import {
  buildTestHead,
  type TestOwnerKey,
} from "../stream-sync-read/testing.js";

export const KiB = 1024;
export const MiB = 1024 * KiB;
export const META = `0x${"ab".repeat(32)}`;
export const CONNECTOR = "acme";
export const silent = { info() {}, warn() {}, error() {} };

export const ask = (scope: string) => ({
  scope,
  connection: null,
  cursor: null,
  legacyFile: false,
});

export function masterKey(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, i) => (seed * 31 + i) & 0xff);
}

/** Bit prefixes of length `bits`: every head part is one of these, so parts stay small. */
export function prefixesFor(bits: number): string[] {
  return Array.from({ length: 2 ** bits }, (_, i) =>
    i.toString(2).padStart(bits, "0"),
  );
}

/** Prefix length that keeps parts near 128 KiB for `n` records of about 500 bytes. */
export function bitsFor(n: number): number {
  return Math.log2(n / 128);
}

/** Fixed-width IDs and a padded value: encoded lines of 384 to 768 bytes. */
export function recordsOf(n: number): JsonObject[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `r${String(i).padStart(8, "0")}`,
    seq: i,
    body: "x".repeat(300 + (i % 300)),
  }));
}

/** Read keys for the identity fixture: decryption is the identity. */
export function identityReadKeys(owner: TestOwnerKey) {
  return {
    hashes: streamSyncReadHashes,
    keyCheck: owner.keyCheck,
    decrypt: async (_scope: string, cipher: Uint8Array) => cipher.slice(),
  };
}

export class Fixture {
  readonly blobs = new Map<string, Uint8Array>();
  readonly rows = new Map<string, MirrorFeedRow>();
  readonly files: StreamSyncReadFiles & {
    readonly files: Map<string, Uint8Array>;
  } = createMemoryStreamSyncReadFiles();
  overlay: StreamSyncOverlayEntry[] = [];
  private clock = Date.parse("2026-11-01T00:00:00Z");
  /** Publishes with identity encryption. */
  readonly identity: TestOwnerKey;

  constructor(readonly owner: TestOwnerKey) {
    this.identity = {
      ...owner,
      encrypt: async (_scope, clear) => clear.slice(),
    };
  }

  private row(scope: string, dataHash: string, metadataHash: string) {
    const previous = this.rows.get(scope);
    const version = previous ? Number(previous.expectedVersion) + 1 : 1;
    this.clock += 1000;
    this.rows.set(scope, {
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      addedAt: new Date(this.clock).toISOString(),
      deletedAt: null,
    });
    return version;
  }

  async activate(connector: string, ns: string): Promise<void> {
    const { active } = await this.owner.control();
    this.row(controlScope(connector, ns), active.dataHash, active.metadataHash);
  }

  async publish(input: {
    connector: string;
    ns: string;
    stream: string;
    generation: number;
    records: JsonObject[];
    prefixes?: string[];
    observedAt?: number;
  }): Promise<void> {
    const built = await buildTestHead({
      key: this.identity,
      connector: input.connector,
      ns: input.ns,
      stream: input.stream,
      generation: input.generation,
      primaryKey: ["id"],
      records: input.records,
      observedAt: input.observedAt ?? this.clock,
      prefixes: input.prefixes,
    });
    for (const [k, v] of built.blobs) this.blobs.set(k, v);
    this.row(built.scope, built.dataHash, META);
  }

  options(
    overrides: Partial<StreamSyncReadOptions> = {},
  ): Partial<StreamSyncReadOptions> {
    return {
      files: this.files,
      blobs: {
        get: async (k) => this.blobs.get(k)?.slice() ?? null,
      },
      keys: identityReadKeys(this.owner),
      logger: silent,
      overlay: { entries: async () => this.overlay },
      now: () => new Date("2026-11-02T00:00:00Z"),
      ...overrides,
    };
  }

  async service(
    overrides: Partial<StreamSyncReadOptions> = {},
  ): Promise<StreamSyncReadService> {
    return StreamSyncReadService.open(
      this.options(overrides) as StreamSyncReadOptions,
    );
  }

  async sync(service: StreamSyncReadService): Promise<void> {
    await service.observe([...this.rows.values()], {
      fromStart: true,
      lastPage: true,
    });
    await service.importPending();
  }
}
