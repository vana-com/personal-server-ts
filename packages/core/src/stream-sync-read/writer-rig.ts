/**
 * Test rig for the writer-parity tests: the real `StreamSyncWriter` publishes
 * to a registry fake, and the real `StreamSyncReadService` reads with a
 * snapshot overlay whose runs the test describes the way an overlay source
 * would describe the writer's pending runs.
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
import {
  parseScope,
  streamMasterKeyFromSignature,
  type ControlRead,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { createStreamSyncReadKeys } from "./keys.js";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { MirrorFeedRow } from "./mirror.js";
import { StreamSyncReadService } from "./service.js";
import { FakeOverlay, type FakeRun } from "./service-fixture.js";

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

/** One run of the `items` stream, as a connector would deliver it. */
export interface RunSpec {
  readonly runId: string;
  readonly key: string;
  readonly version: string;
  readonly rows: readonly Record<string, unknown>[];
  /** A full read; otherwise it resumes from a checkpoint. */
  readonly full: boolean;
  /** Resume from a checkpoint of another namespace (writer.ts:1465). */
  readonly otherNamespace?: boolean;
  /** The run's `complete` as an overlay source reports it (default `full`). */
  readonly complete?: boolean;
}

export interface SeedRows {
  readonly key: string;
  readonly version: string;
  readonly rows: readonly Record<string, unknown>[];
}

export class Rig {
  readonly gateway = new Gateway();
  readonly blobMap = new Map<string, Uint8Array>();
  readonly files = createMemoryStreamSyncFiles();
  readonly overlay = new FakeOverlay();
  readonly writer: StreamSyncWriter;
  service!: StreamSyncReadService;
  /** Every run is identity-less: one namespace, the empty one. */
  readonly ns = "";
  private order = 0;
  private readonly observed = new Map<string, number>();

  constructor(seed?: SeedRows) {
    const blobs: StreamSyncBlobs = {
      put: async (key, bytes) => void this.blobMap.set(key, bytes.slice()),
      get: async (key) => this.blobMap.get(key) ?? null,
    };
    this.writer = new StreamSyncWriter({
      ownerAddress: OWNER,
      registry: this.gateway,
      blobs,
      home: bindStreamSyncHome({
        ownerAddress: OWNER,
        network: "test",
        open: () => this.files,
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
                  stream: "items",
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

  /** A finished run of `items` whose publish has not started. */
  async collect(spec: RunSpec): Promise<void> {
    const observedAt = T0 + (this.order += 1) * 1000;
    this.observed.set(spec.runId, observedAt);
    await this.writer.refreshControls();
    await this.writer.beginRun({
      runId: spec.runId,
      connector: CONNECTOR,
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
    await this.writer.declareStream(spec.runId, "items", {
      primaryKey: [spec.key],
      profile: { key: null, version: spec.version },
    });
    for (const row of spec.rows) {
      await this.writer.append(spec.runId, "items", { ...row });
    }
    await this.writer.finishRun(spec.runId, {
      checkpointCandidate: { cursor: spec.runId },
    });
  }

  /** The overlay's description of a pending run. */
  describe(spec: RunSpec): FakeRun {
    const observedAt = this.observed.get(spec.runId)!;
    return {
      runId: spec.runId,
      ns: this.ns,
      generation: 1,
      observedAt,
      streams: [
        {
          name: "items",
          primaryKey: [spec.key],
          version: spec.version,
          complete: spec.complete ?? spec.full,
          ...(spec.otherNamespace ? { incompleteOverBase: true } : {}),
          rows: spec.rows.map((v) => ({
            o: observedAt,
            r: spec.runId,
            v: v as never,
          })),
        },
      ],
    };
  }

  /** Publish every ready run and say what the writer did with each. */
  async publish(): Promise<StreamSyncRunStatus[]> {
    return [...(await this.writer.publishPending()).runs];
  }
}
