import type {
  JsonObject,
  Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { controlScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { hexToBytes, keccak256, parseSignature, toBytes, toHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { createStreamSyncReadKeys } from "./keys.js";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import type { MirrorFeedRow } from "./mirror.js";
import type {
  StreamSyncImportedCoverage,
  StreamSyncOverlayRun,
  StreamSyncOverlaySnapshot,
  StreamSyncOverlaySnapshotSource,
  StreamSyncPublishReceipt,
} from "./ports.js";
import {
  StreamSyncReadService,
  type ReadDecision,
  type StreamSyncReadOptions,
} from "./service.js";
import { buildTestHead, type TestOwnerKey } from "./testing.js";
import {
  NO_FLOOR,
  planStream,
  type PlanRun,
} from "../stream-sync/publish-plan.js";

const META = `0x${"ab".repeat(32)}`;
const silent = { info() {}, warn() {}, error() {} };

/**
 * The owner signature of test owner `seed`: a real secp256k1 signature over
 * the master-key message, made with a test key derived from the seed. It is in
 * canonical form (v = 27/28, low s), the form the reader's normalization maps
 * to itself, so the fixture keys equal the keys of the raw bytes.
 */
export async function masterKey(seed: number): Promise<Uint8Array> {
  const account = privateKeyToAccount(
    keccak256(toBytes(`pdpp-test-owner-key:${seed}`)),
  );
  const sig = parseSignature(
    await account.sign({ hash: keccak256(toBytes("vana-master-key-v1")) }),
  );
  const out = new Uint8Array(65);
  out.set(hexToBytes(toHex(BigInt(sig.r), { size: 32 })), 0);
  out.set(hexToBytes(toHex(BigInt(sig.s), { size: 32 })), 32);
  out[64] = 27 + (sig.yParity ?? 0);
  return out;
}

export class Fixture {
  readonly blobs = new Map<string, Uint8Array>();
  readonly rows = new Map<string, MirrorFeedRow>();
  readonly files = createMemoryStreamSyncReadFiles();
  readonly blobGets: string[] = [];
  readonly overlay = new FakeOverlay();
  /** Passed to the service as `durable`. */
  durable = true;
  private clock = Date.parse("2026-11-01T00:00:00Z");

  constructor(readonly key: TestOwnerKey) {}

  private row(
    scope: string,
    dataHash: string,
    metadataHash: string,
    deleted = false,
  ) {
    const previous = this.rows.get(scope);
    const version = previous ? Number(previous.expectedVersion) + 1 : 1;
    this.clock += 1000;
    this.rows.set(scope, {
      scope,
      dataHash,
      metadataHash,
      expectedVersion: String(version),
      addedAt: new Date(this.clock).toISOString(),
      deletedAt: deleted ? new Date(this.clock).toISOString() : null,
    });
    return version;
  }

  async activate(
    connector: string,
    ns: string,
    key = this.key,
  ): Promise<number> {
    const { active } = await key.control();
    return this.row(
      controlScope(connector, ns),
      active.dataHash,
      active.metadataHash,
    );
  }

  async deleteConnection(connector: string, ns: string): Promise<number> {
    const { tombstone } = await this.key.control();
    return this.row(
      controlScope(connector, ns),
      tombstone.dataHash,
      tombstone.metadataHash,
      true,
    );
  }

  async publish(input: {
    connector: string;
    ns: string;
    stream: string;
    generation: number;
    records: JsonObject[];
    primaryKey?: string[];
    complete?: boolean;
    observedAt?: number;
    profileKey?: string | null;
    profileVersion?: string;
    prefixes?: string[];
    key?: TestOwnerKey;
    encryptWith?: TestOwnerKey;
    withholdBlobs?: boolean;
  }) {
    const built = await buildTestHead({
      key: input.key ?? this.key,
      connector: input.connector,
      ns: input.ns,
      stream: input.stream,
      generation: input.generation,
      primaryKey: input.primaryKey ?? ["id"],
      records: input.records,
      observedAt: input.observedAt ?? this.clock,
      complete: input.complete,
      ...(input.profileKey !== undefined
        ? { profileKey: input.profileKey }
        : {}),
      ...(input.profileVersion ? { profileVersion: input.profileVersion } : {}),
      prefixes: input.prefixes,
      encryptWith: input.encryptWith,
    });
    if (!input.withholdBlobs) {
      for (const [k, v] of built.blobs) this.blobs.set(k, v);
    }
    this.row(built.scope, built.dataHash, META);
    return built;
  }

  async service(
    extra: Partial<StreamSyncReadOptions> = {},
  ): Promise<StreamSyncReadService> {
    return StreamSyncReadService.open({
      files: this.files,
      blobs: {
        get: async (k) => {
          this.blobGets.push(k);
          return this.blobs.get(k) ?? null;
        },
      },
      keys: await createStreamSyncReadKeys(this.key.masterKey),
      logger: silent,
      overlay: this.overlay,
      durable: this.durable,
      now: () => new Date("2026-11-02T00:00:00Z"),
      ...extra,
    });
  }

  async sync(service: StreamSyncReadService): Promise<void> {
    await service.observe([...this.rows.values()], {
      fromStart: true,
      lastPage: true,
    });
    await service.importPending();
  }
}

export async function body(
  decision: ReadDecision,
): Promise<Record<string, any>> {
  if (decision.kind !== "view" && decision.kind !== "local_pending")
    throw new Error(`expected view, got ${decision.kind}`);
  return JSON.parse(await new Response(decision.body).text());
}

export const ask = (
  scope: string,
  extra: Partial<Parameters<StreamSyncReadService["resolve"]>[0]> = {},
) => ({
  scope,
  connection: null,
  cursor: null,
  legacyFile: false,
  isOwnerView: true,
  ...extra,
});

export interface FakeStream {
  readonly name: string;
  readonly rows: readonly Line[];
  readonly complete?: boolean;
  /** The run resumed from another namespace's checkpoint (the plan's `foreignCheckpoint`). */
  readonly incompleteOverBase?: boolean;
  readonly contentRevision?: string;
  readonly receipt?: StreamSyncPublishReceipt;
  /** Default `["id"]`. */
  readonly primaryKey?: readonly string[];
  /** The writing connector's version. Default `1.0.0`. */
  readonly version?: string;
  /** The writing connector's profile key. Default none. */
  readonly profileKey?: string | null;
}

export interface FakeRun {
  readonly runId: string;
  readonly ns: string | null;
  readonly generation: number | null;
  /** The recorded start. Default: absent when `generation` is null, else active(generation). */
  readonly start?: StreamSyncOverlayRun["start"];
  readonly userConnect?: boolean;
  readonly full?: boolean;
  readonly state?: StreamSyncOverlayRun["state"];
  readonly observedAt?: number;
  readonly streams: readonly FakeStream[];
}

/** The plan facts of a fake stream: the descriptor read as a writer run. */
function fakePlanRun(run: StreamSyncOverlayRun, s: FakeStream): PlanRun {
  const primaryKey = s.primaryKey ?? ["id"];
  const profile = { key: s.profileKey ?? null, version: s.version ?? "1.0.0" };
  return {
    runId: run.runId,
    observedAt: run.observedAt,
    generation: run.generation,
    primaryKey,
    profile,
    full: s.complete ?? false,
    foreignCheckpoint: s.incompleteOverBase ?? false,
    empty: s.rows.length === 0,
    seed: "none",
    ...(s.receipt
      ? {
          executed: {
            kind: "publish" as const,
            head: {
              generation: s.receipt.generation,
              primaryKey,
              profile,
              complete: s.complete ?? false,
            },
            replacesBase: false,
          },
        }
      : {}),
  };
}

/** A snapshot source that counts what the reader does with it. */
export class FakeOverlay implements StreamSyncOverlaySnapshotSource {
  runs: FakeRun[] = [];
  /** `snapshot()` calls. */
  snapshots = 0;
  /** Snapshots taken and not yet released. */
  open = 0;
  /** `release()` calls that took effect. */
  released = 0;
  /** Everything `acknowledge` was called with, in order. */
  readonly acks: StreamSyncImportedCoverage[] = [];
  /** Runs before a snapshot is taken. */
  beforeSnapshot?: () => Promise<void> | void;
  /** Runs before a pinned log is read. */
  beforeLines?: () => void;

  private describe(run: FakeRun, connector: string): StreamSyncOverlayRun {
    return {
      runId: run.runId,
      connector,
      ns: run.ns,
      generation: run.generation,
      start:
        run.start ??
        (run.generation === null
          ? { kind: "absent" }
          : { kind: "active", generation: run.generation }),
      userConnect: run.userConnect ?? false,
      full: run.full ?? true,
      state: run.state ?? "pending",
      observedAt: run.observedAt ?? Date.parse("2026-11-01T00:00:00.000Z"),
      streams: run.streams.map((s) => ({
        name: s.name,
        primaryKey: s.primaryKey ?? ["id"],
        profile: { key: s.profileKey ?? null, version: s.version ?? "1.0.0" },
        complete: (s.complete ?? false) && !(s.incompleteOverBase ?? false),
        contentRevision: s.contentRevision ?? "r1",
        state: s.receipt
          ? "published"
          : (run.state ?? "pending") === "failed"
            ? "failed"
            : "pending",
        ...(s.receipt ? { receipt: s.receipt } : {}),
      })),
    };
  }

  /** Connector of every fake run. */
  connector = "acme";

  async snapshot(connector: string): Promise<StreamSyncOverlaySnapshot> {
    await this.beforeSnapshot?.();
    this.snapshots++;
    this.open++;
    const taken = this.runs.map((r) => ({
      run: r,
      described: this.describe(r, this.connector),
    }));
    let released = false;
    return {
      runs: taken
        .filter(() => connector === this.connector)
        .map((t) => t.described),
      plan: (ns, stream, head, ids) =>
        connector !== this.connector
          ? []
          : planStream(
              head,
              NO_FLOOR,
              taken.flatMap(({ run, described }) => {
                const s = run.streams.find((x) => x.name === stream);
                if (run.ns !== ns || !s || !ids.includes(run.runId)) return [];
                return [fakePlanRun(described, s)];
              }),
            ),
      lines: (entry, stream) => {
        this.beforeLines?.();
        const found =
          this.runs.length === 0
            ? undefined
            : taken.find((t) => t.run.runId === entry.runId);
        const rows = found?.run.streams.find((s) => s.name === stream)?.rows;
        if (!rows) throw new Error("overlay log is missing");
        return (async function* () {
          for (const row of rows) yield row;
        })();
      },
      release: () => {
        if (released) return;
        released = true;
        this.open--;
        this.released++;
      },
    };
  }

  async acknowledge(coverage: StreamSyncImportedCoverage): Promise<void> {
    this.acks.push(coverage);
  }
}
