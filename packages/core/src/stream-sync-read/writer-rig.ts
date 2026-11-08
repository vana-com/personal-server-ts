/**
 * Test rig for the writer-parity tests: the real `StreamSyncWriter` publishes
 * to a registry fake, and the real `StreamSyncReadService` reads through the
 * writer's own overlay source, so every plan the reader reads is the one the
 * production producer emits.
 */

import {
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  createStreamSyncKeyPorts,
  StreamSyncWriter,
  type RegistryPostResult,
  type SignedRegistryPost,
  type StreamSyncBlobs,
  type StreamSyncRegistry,
  type StreamSyncRunStatus,
} from "../stream-sync/index.js";
import { createWriterOverlaySource } from "../stream-sync/writer.js";
import {
  decodeHead,
  parseScope,
  streamMasterKeyFromSignature,
  streamScope,
  type ControlRead,
  type Head,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createStreamSyncReadKeys } from "./keys.js";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { MirrorFeedRow } from "./mirror.js";
import { StreamSyncReadService } from "./service.js";
import type { StreamSyncOverlaySnapshotSource } from "./ports.js";

const OWNER = `0x${"11".repeat(20)}` as const;
const SIGNATURE = `0x${"1f".repeat(32)}${"2a".repeat(32)}1b` as const;
export const CONNECTOR = "acme";
export const T0 = Date.UTC(2026, 10, 1);
const silent = { info() {}, warn() {}, error() {} };

class Gateway implements StreamSyncRegistry {
  private readonly versions = new Map<
    string,
    { dataHash: string; metadataHash: string; at: string }[]
  >();

  async read(scope: string): Promise<ControlRead> {
    const rows = this.versions.get(scope);
    if (!rows?.length) return { found: false };
    const head = rows[rows.length - 1]!;
    return {
      found: true,
      version: rows.length,
      dataHash: head.dataHash,
      metadataHash: head.metadataHash,
      deleted: false,
    };
  }

  async post(request: SignedRegistryPost): Promise<RegistryPostResult> {
    const rows = this.versions.get(request.scope) ?? [];
    if (Number(request.expectedVersion) !== rows.length + 1) {
      return { kind: "conflict", latestVersion: String(rows.length) };
    }
    rows.push({
      dataHash: request.dataHash,
      metadataHash: request.metadataHash,
      at: new Date(T0 + rows.length * 1000).toISOString(),
    });
    this.versions.set(request.scope, rows);
    return { kind: "committed" };
  }

  async listControlRows() {
    const out: { scope: string; read: ControlRead }[] = [];
    for (const scope of this.versions.keys()) {
      if (parseScope(scope)?.kind === "control") {
        out.push({ scope, read: await this.read(scope) });
      }
    }
    return out;
  }

  feed(): MirrorFeedRow[] {
    return [...this.versions].map(([scope, rows]) => {
      const head = rows[rows.length - 1]!;
      return {
        scope,
        dataHash: head.dataHash,
        metadataHash: head.metadataHash,
        expectedVersion: String(rows.length),
        addedAt: head.at,
        deletedAt: null,
      };
    });
  }
}

/** One stream of a run. */
export interface StreamSpec {
  /** Default `items`. */
  readonly stream?: string;
  readonly key: string;
  readonly version: string;
  /** The legacy projector's profile key; default null. */
  readonly profileKey?: string | null;
  readonly rows: readonly Record<string, unknown>[];
  /** The stream is not incremental: the run reads it whole. */
  readonly fullStream?: boolean;
}

/** One run, as a connector would deliver it. */
export interface RunSpec extends StreamSpec {
  readonly runId: string;
  /** A full read; otherwise it resumes from a checkpoint. */
  readonly full: boolean;
  /** Resume from a checkpoint of another namespace (writer.ts:1465). */
  readonly otherNamespace?: boolean;
  /** More streams the same run delivers. */
  readonly also?: readonly StreamSpec[];
  /** observedAt, in ms after T0; default: collection order, 1 s apart. */
  readonly at?: number;
  /** Collect and publish on a second device of the same owner. */
  readonly otherDevice?: boolean;
}

export interface SeedRows {
  /** Default `items`. */
  readonly stream?: string;
  readonly key: string;
  readonly version: string;
  readonly rows: readonly Record<string, unknown>[];
}

export class Rig {
  readonly gateway = new Gateway();
  readonly blobMap = new Map<string, Uint8Array>();
  readonly files = createMemoryStreamSyncFiles();
  readonly writer: StreamSyncWriter;
  /** A second device: its own home, the same owner, registry and blobs. */
  readonly other: StreamSyncWriter;
  readonly overlay: StreamSyncOverlaySnapshotSource;
  service!: StreamSyncReadService;
  /** Every run is identity-less: one namespace, the empty one. */
  readonly ns = "";
  private order = 0;

  constructor(
    seed?: SeedRows,
    readonly connector: string = CONNECTOR,
  ) {
    this.writer = this.device(this.files, seed);
    this.other = this.device(createMemoryStreamSyncFiles());
    this.overlay = createWriterOverlaySource(this.writer);
  }

  private device(
    files: ReturnType<typeof createMemoryStreamSyncFiles>,
    seed?: SeedRows,
  ): StreamSyncWriter {
    const blobs: StreamSyncBlobs = {
      put: async (key, bytes) => void this.blobMap.set(key, bytes.slice()),
      get: async (key) => this.blobMap.get(key) ?? null,
    };
    return new StreamSyncWriter({
      ownerAddress: OWNER,
      registry: this.gateway,
      blobs,
      home: bindStreamSyncHome({
        ownerAddress: OWNER,
        network: "test",
        open: () => files,
      }),
      keys: createStreamSyncKeyPorts(SIGNATURE),
      signer: { signAddData: async () => `0x${"22".repeat(65)}` },
      now: () => T0 + 3_600_000,
      ...(seed
        ? {
            seed: {
              installId: "install-1",
              streams: async () => [
                {
                  stream: seed.stream ?? "items",
                  primaryKey: [seed.key],
                  profile: { key: null, version: seed.version },
                },
              ],
              records: async function* () {
                for (const row of seed.rows) yield row;
              },
            },
          }
        : {}),
    });
  }

  async open(): Promise<void> {
    this.service = await StreamSyncReadService.open({
      files: createMemoryStreamSyncReadFiles(),
      blobs: { get: async (key) => this.blobMap.get(key) ?? null },
      keys: await createStreamSyncReadKeys(
        streamMasterKeyFromSignature(SIGNATURE),
      ),
      logger: silent,
      overlay: this.overlay,
      durable: true,
      now: () => new Date(T0 + 7_200_000),
    });
  }

  async sync(): Promise<void> {
    await this.service.observe(this.gateway.feed(), {
      fromStart: true,
      lastPage: true,
    });
    await this.service.importPending();
  }

  /** A finished run whose publish has not started; a second device's run is published at once. */
  async collect(spec: RunSpec): Promise<void> {
    const writer = spec.otherDevice ? this.other : this.writer;
    this.order += 1;
    const observedAt = T0 + (spec.at ?? this.order * 1000);
    await writer.refreshControls();
    await writer.beginRun({
      runId: spec.runId,
      connector: this.connector,
      userConnect: false,
      observedAt,
      identity: "none",
      checkpointUsed: spec.full
        ? null
        : {
            ns: spec.otherNamespace ? "0123456789abcdef" : this.ns,
            generation: 1,
          },
    });
    for (const stream of [spec, ...(spec.also ?? [])]) {
      const name = stream.stream ?? "items";
      await writer.declareStream(spec.runId, name, {
        primaryKey: [stream.key],
        profile: { key: stream.profileKey ?? null, version: stream.version },
        ...(stream.fullStream ? { incremental: false } : {}),
      });
      for (const row of stream.rows) {
        await writer.append(spec.runId, name, { ...row });
      }
    }
    await writer.finishRun(spec.runId, {
      checkpointCandidate: { cursor: spec.runId },
    });
    if (spec.otherDevice) await writer.publishPending();
  }

  /** The head the registry holds now for `stream`, decrypted; null when none. */
  async registeredHead(stream = "items"): Promise<Head | null> {
    const scope = streamScope(this.connector, this.ns, stream);
    const row = await this.gateway.read(scope);
    if (!row.found) return null;
    const name = `h-${row.dataHash.toLowerCase().replace(/^0x/, "")}`;
    const cipher = this.blobMap.get(`${scope}/${name}`);
    if (!cipher) throw new Error(`head blob ${name} is missing`);
    const decoded = decodeHead(
      await createStreamSyncKeyPorts(SIGNATURE).decrypt(scope, cipher),
    );
    if (decoded.kind !== "ok") throw new Error(`head ${name}: ${decoded.kind}`);
    return decoded.head;
  }

  /** The registry version of `stream`; 0 when none. */
  async registeredVersion(stream = "items"): Promise<number> {
    const row = await this.gateway.read(
      streamScope(this.connector, this.ns, stream),
    );
    return row.found ? row.version : 0;
  }

  /** Publish every ready run and say what the writer did with each. */
  async publish(): Promise<StreamSyncRunStatus[]> {
    return [...(await this.writer.publishPending()).runs];
  }
}
