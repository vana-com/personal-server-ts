/**
 * Stream-sync read side of one Personal Server (§2.9, §2.10).
 *
 * - The download worker hands it every physical registry row it lists
 *   (`observe`), before its cursor moves, then lets it import (`importPending`).
 * - A data GET asks `resolve` what to serve for a requested name: a stream
 *   view, the existing legacy path, or a refusal. The decision is the
 *   package's one `eligible` rule; nothing here re-derives it.
 *
 * Requested names are logical: `pdpp.<c>.<s>` or a legacy binding name. A
 * caller may pick a connection with `connection=<ns>`; grants never name
 * one. Physical `~` names are never accepted as a requested name.
 */

import {
  admitStart,
  canonicalBytes32,
  classifyStreamRow,
  controlHashes,
  eligible,
  IDENTITYLESS_NS,
  isHeadLive,
  selectConnection,
  streamScope,
  type ConnectionView,
  type ControlState,
  type Eligibility,
  type Line,
  type StreamHeadView,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  type LegacyScopeBinding,
} from "../legacy-projection/index.js";
import {
  foldPlan,
  planHeadOf,
  type Contribution,
  type Fold,
  type WithheldContribution,
  type WithheldReason,
} from "./fold.js";
import { StreamSyncImporter, type ImportIssue } from "./importer.js";
import {
  NO_OVERLAY,
  overlayWinners,
  viewLines,
  type OverlayWinners,
} from "./lines.js";
import {
  RegistryMirror,
  toControlRead,
  type MirrorRow,
  type MirrorFeedRow,
} from "./mirror.js";
import type {
  StreamSyncBlobReader,
  StreamSyncImportedCoverage,
  StreamSyncOverlaySnapshot,
  StreamSyncOverlaySnapshotSource,
  StreamSyncPublishReceipt,
  StreamSyncReadFiles,
  StreamSyncReadKeys,
  StreamSyncReadLogger,
} from "./ports.js";
import { planProjection, ProjectionFailedError } from "./projection.js";
import { isPhysicalScope, logicalStreamScopeParts } from "./routing.js";
import {
  ViewStore,
  type ImportedVersion,
  type ViewKey,
  type ViewLease,
} from "./view-store.js";

export interface StreamSyncReadOptions {
  readonly files: StreamSyncReadFiles;
  readonly blobs: StreamSyncBlobReader;
  readonly keys: StreamSyncReadKeys;
  readonly logger: StreamSyncReadLogger;
  /** Own-writes overlay: local runs whose rows the imported views may not hold yet. */
  readonly overlay?: StreamSyncOverlaySnapshotSource;
  /**
   * The read files survive a restart. Only then does an import acknowledge
   * its coverage to the overlay source, which may retire what it covers.
   * Default false: a reader that cannot prove durability never acknowledges.
   */
  readonly durable?: boolean;
  /** Byte budget of a non-windowed legacy projection; above it `too_large`. */
  readonly arrayProjectionBudgetBytes?: number;
  readonly now?: () => Date;
}

export interface ResolveInput {
  readonly scope: string;
  /** `connection=<ns>`; `null` when absent. */
  readonly connection: string | null;
  /** `cursor=` of an earlier response; `null` when absent. */
  readonly cursor: string | null;
  /** The existing path holds a legacy or raw body of `scope`. */
  readonly legacyFile: boolean;
  /** The caller reads as the owner (`isOwnerView`), not as a grantee. */
  readonly isOwnerView: boolean;
}

/**
 * A local run whose rows the view does not show, and why (fold.ts): the
 * writer's publish plan refuses or defers it, or the read does not show it
 * before it is imported. Carried to the owner only.
 */
export interface WithheldRun {
  readonly runId: string;
  readonly stream: string;
  readonly reason: WithheldReason;
}

/**
 * What only the owner is told of this device's local runs when the answer
 * serves no stream view: the existing path or a refusal answers instead.
 */
export interface OwnerNotes {
  /** Runs the writer will not publish; absent when none. */
  readonly withheld?: readonly WithheldRun[];
  /**
   * A legacy body answers while local runs are not published: `runs` counts
   * distinct runs with a requested stream that has no publish receipt, with
   * or without records, shown or withheld. The legacy body's own time is an
   * ingest stamp, not comparable with a run's, so nothing decides which is
   * newer: the owner is told.
   */
  readonly pending?: { readonly runs: number };
  /**
   * A legacy body answers while published local runs wait for import: the
   * body does not reflect them. `runs` counts distinct runs with a stream the
   * writer published and the reader has not imported yet. Cleared by import
   * coverage, not by the publish receipt.
   */
  readonly awaitingImport?: { readonly runs: number };
  /**
   * A stored body answers while the reader holds a live imported head for a
   * requested stream: a complete head would have served its own view, so the
   * body does not reflect this one (an incomplete head). Derived from the
   * response and the stream's head, not from runs: it outlives import and run
   * retirement. `streams` counts distinct streams.
   */
  readonly notReflected?: { readonly streams: number };
}

export type ReadDecision =
  /** Not a stream-sync read: the existing path answers, unchanged. */
  | ({ readonly kind: "pass" } & OwnerNotes)
  /** §2.10 step 3: serve the legacy or raw file through the existing path. */
  | ({ readonly kind: "legacy" } & OwnerNotes)
  | ({
      readonly kind: "unavailable";
      readonly reason: "deleted" | "no_data" | "connection_not_found";
    } & OwnerNotes)
  /** The connector's only connections were written with another owner key. */
  | ({ readonly kind: "key_mismatch" } & OwnerNotes)
  /** The cursor names a version this server no longer holds. */
  | { readonly kind: "cursor_stale" }
  | { readonly kind: "invalid_cursor" }
  | { readonly kind: "invalid_connection" }
  | { readonly kind: "too_large"; readonly bytes: number }
  /**
   * Imports or writer publications into the streams this read touched kept
   * changing under it. Nothing is wrong with the data: ask again.
   */
  | { readonly kind: "busy"; readonly retryAfterSeconds: number }
  /**
   * The owner's partial view, built on this device: the live imported heads,
   * complete or not, and the local runs the writer will publish on them, when
   * no complete view serves (a first run made offline, an incomplete head, a
   * pending key reset). Owner-only, no registry entry to bind: nothing to
   * bill. The body marks the data `"origin":"local-pending"` and says whether
   * it is `"complete"`.
   */
  | {
      readonly kind: "local_pending";
      readonly connector: string;
      readonly ns: string;
      readonly cursor: string;
      /** The view holds everything the writer will publish, and that is complete. */
      readonly complete: boolean;
      /** Owner only; absent when none. */
      readonly withheld?: readonly WithheldRun[];
      readonly body: ReadableStream<Uint8Array>;
    }
  | {
      readonly kind: "view";
      readonly connector: string;
      readonly ns: string;
      /** Pins `(stream → head version)` of every input head. */
      readonly cursor: string;
      /**
       * The registered stream head a paid read's access record binds: the
       * window's parent stream of a windowed legacy name, else the first
       * stream read. Physical name and registry version. `null` for an
       * owner-only view with an input stream that has no imported head: there
       * is no registry entry to bind or charge.
       */
      readonly served: {
        readonly scope: string;
        readonly version: number;
      } | null;
      /** Owner only; absent when none. */
      readonly withheld?: readonly WithheldRun[];
      readonly body: ReadableStream<Uint8Array>;
    };

/** See `StreamSyncReadService.retireBasis`. */
export interface RetireBasis {
  readonly covered: boolean;
  readonly ambiguous: boolean;
  /**
   * Every read target of the scope is deleted right now and none was
   * re-collected: the published side serves no view because the owner deleted
   * the source, not because data is missing. `covered` is false then.
   */
  readonly deleted: boolean;
  /**
   * Every connector that can serve the scope (`readTargets`) is one the
   * registry mirror has seen. False when an alternate was never connected:
   * it may hold local data nobody published, so no delete of the registry
   * can explain a missing entity.
   */
  readonly allTargetsKnown: boolean;
  readonly throughMs: number;
  readonly streams: readonly {
    readonly connector: string;
    readonly stream: string;
    /** Version of the stream's last delete; 0 = never deleted. */
    readonly deleteVersion: number;
    /**
     * Registry time (ms) of that delete, or null when unknown (a delete
     * learned from a head, not from a listed tombstone row).
     */
    readonly deleteAtMs: number | null;
  }[];
}

export interface StreamSyncConnectionStatus {
  readonly connector: string;
  readonly ns: string;
  readonly control: ControlState["kind"];
  readonly streams: Readonly<
    Record<
      string,
      StreamHeadView & {
        readonly version: number | null;
        readonly records: number | null;
      }
    >
  >;
}

export interface StreamSyncReadStatus {
  readonly listed: boolean;
  readonly connections: readonly StreamSyncConnectionStatus[];
  readonly issues: readonly ImportIssue[];
}

/**
 * One row per stream the read side knows, for owner diagnostics. `records` is
 * the imported head's record count only while that head is live (§2.4). A
 * pending (unimported), tombstoned, superseded-generation or
 * deleted-connection head counts `null`. Logical connection selection, a
 * legacy-file fallback and rows from the local outbox overlay are outside
 * this count.
 */
export function liveStreamCounts(status: StreamSyncReadStatus): {
  readonly connector: string;
  readonly ns: string;
  readonly stream: string;
  readonly records: number | null;
}[] {
  return status.connections.flatMap((connection) =>
    Object.entries(connection.streams).map(([stream, head]) => ({
      connector: connection.connector,
      ns: connection.ns,
      stream,
      records: head.live ? head.records : null,
    })),
  );
}

interface Target {
  readonly connector: string;
  readonly streams: readonly string[];
  /** Absent for `pdpp.<c>.<s>`: a `{records}` body. */
  readonly binding?: LegacyScopeBinding;
}

/** What a cursor pins of one input stream. */
interface CursorStream {
  /** Imported registry version, or null: the stream had no imported head. */
  readonly b: number | null;
  /**
   * The overlay members it served, `[runId, contentRevision]`. Absent in a
   * cursor from before overlay pins: it pinned no member.
   */
  readonly m?: readonly (readonly [string, string])[];
  /**
   * The whole fold the response was built from: every run the writer would
   * publish, in publish order, `[runId, contentRevision]`, including those a
   * later key change replaced. Absent in a cursor from before fold pins.
   */
  readonly p?: readonly (readonly [string, string])[];
  /**
   * A cursor from before the plan: the fold replaced the imported base. Such
   * a cursor replays only when this is false.
   */
  readonly d?: boolean;
  /**
   * The key, profile and completeness of the head the response showed (the
   * projection's input). Absent in a cursor from before shape pins.
   */
  readonly h?: string;
}

interface Cursor {
  readonly c: string;
  readonly ns: string;
  readonly s: Readonly<Record<string, CursorStream>>;
}

const NS = /^(?:[0-9a-f]{16})?$/;
const DEFAULT_ARRAY_BUDGET = 64 * 1024 * 1024;
const encoder = new TextEncoder();

function legacyConnectorKey(pdppSource: string): string {
  return pdppSource.slice(pdppSource.lastIndexOf("/") + 1);
}

/** The connectors and streams a logical name reads. */
export function readTargets(scope: string): Target[] {
  if (isPhysicalScope(scope)) return [];
  const targets = new Map<string, Target>();
  const plain = logicalStreamScopeParts(scope);
  if (plain) {
    targets.set(plain.connector, {
      connector: plain.connector,
      streams: [plain.stream],
    });
  }
  const original = LEGACY_SCOPE_BINDINGS.get(scope);
  if (original) {
    const connector = legacyConnectorKey(original.pdppSource);
    targets.set(connector, {
      connector,
      streams: original.pdppStreams,
      binding: original,
    });
  }
  for (const [profileKey, binding] of alternateLegacyBindingsForScope(scope)) {
    targets.set(profileKey, {
      connector: profileKey,
      streams: binding.pdppStreams,
      binding,
    });
  }
  return [...targets.values()];
}

/** Whether the imported view holds everything the published stream holds. */
function covers(
  base: ImportedVersion,
  receipt: StreamSyncPublishReceipt,
): boolean {
  if (base.head.generation !== receipt.generation) return false;
  if (base.version > receipt.registryVersion) return true;
  return (
    base.version === receipt.registryVersion &&
    sameBytes32(base.dataHash, receipt.dataHash)
  );
}

/** Digests compare in the one spelling the writer uses; a malformed one never matches. */
function sameBytes32(a: string, b: string): boolean {
  try {
    return canonicalBytes32(a) === canonicalBytes32(b);
  } catch {
    return false;
  }
}

function encodeCursor(cursor: Cursor): string {
  const json = JSON.stringify(cursor);
  let binary = "";
  for (const byte of encoder.encode(json)) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function decodeCursor(text: string): Cursor | null {
  try {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as {
      c?: unknown;
      ns?: unknown;
      v?: unknown;
      s?: unknown;
    };
    if (typeof parsed?.c !== "string" || typeof parsed.ns !== "string") {
      return null;
    }
    const streams: Record<string, CursorStream> = {};
    if (typeof parsed.s === "object" && parsed.s !== null) {
      for (const [name, pin] of Object.entries(parsed.s)) {
        const { b, m, p, d, h } = (pin ?? {}) as {
          b?: unknown;
          m?: unknown;
          p?: unknown;
          d?: unknown;
          h?: unknown;
        };
        if (b !== null && !Number.isSafeInteger(b)) return null;
        const pairs = (x: unknown) =>
          Array.isArray(x) &&
          x.every(
            (y) =>
              Array.isArray(y) &&
              y.length === 2 &&
              typeof y[0] === "string" &&
              typeof y[1] === "string",
          );
        if (m !== undefined && !pairs(m)) return null;
        if (p !== undefined && !pairs(p)) return null;
        if (d !== undefined && typeof d !== "boolean") return null;
        if (h !== undefined && typeof h !== "string") return null;
        streams[name] = {
          b: b as number | null,
          ...(m ? { m: m as [string, string][] } : {}),
          ...(p ? { p: p as [string, string][] } : {}),
          ...(d !== undefined ? { d } : {}),
          ...(h !== undefined ? { h } : {}),
        };
      }
    } else if (typeof parsed.v === "object" && parsed.v !== null) {
      // A cursor from before overlay pins: registry versions only.
      for (const [name, version] of Object.entries(parsed.v)) {
        if (!Number.isSafeInteger(version)) return null;
        streams[name] = { b: version as number };
      }
    } else {
      return null;
    }
    return { c: parsed.c, ns: parsed.ns, s: streams };
  } catch {
    return null;
  }
}

function toStream(
  chunks: AsyncIterable<string>,
  done: () => void,
): ReadableStream<Uint8Array> {
  const iterator = chunks[Symbol.asyncIterator]();
  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    done();
  };
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        let buffer = "";
        while (buffer.length < 64 * 1024) {
          const next = await iterator.next();
          if (next.done) {
            if (buffer) controller.enqueue(encoder.encode(buffer));
            controller.close();
            finish();
            return;
          }
          buffer += next.value;
        }
        controller.enqueue(encoder.encode(buffer));
      } catch (error) {
        finish();
        controller.error(error);
      }
    },
    async cancel() {
      finish();
      await iterator.return?.(undefined);
    },
  });
}

/** What a read sees when no overlay source is configured. */
const NO_SNAPSHOT: StreamSyncOverlaySnapshot = {
  runs: [],
  plan: () => [],
  lines: () => {
    throw new Error("no overlay source");
  },
  release() {},
};

/** Reads start over this many times when an import lands under them. */
const MAX_COHERENCE_ATTEMPTS = 8;
const BUSY_RETRY_AFTER_SECONDS = 1;

export class StreamSyncReadService {
  private spoolCounter = 0;

  private constructor(
    private readonly options: StreamSyncReadOptions,
    private readonly mirror: RegistryMirror,
    private readonly views: ViewStore,
    private readonly importer: StreamSyncImporter,
    private changed: Set<string>,
  ) {}

  static async open(
    options: StreamSyncReadOptions,
  ): Promise<StreamSyncReadService> {
    const hashes = await controlHashes(
      options.keys.hashes.keccak256,
      options.keys.keyCheck,
    );
    const mirror = await RegistryMirror.open(
      options.files,
      (row) => classifyStreamRow(toControlRead(row), hashes) === "tombstoned",
    );
    const views = await ViewStore.open(options.files);
    await options.files.remove("spool");
    const importer = new StreamSyncImporter({
      mirror,
      views,
      blobs: options.blobs,
      keys: options.keys,
      controlHashes: hashes,
      logger: options.logger,
      // Only durable files may let the source retire what they cover.
      ...(options.durable && options.overlay
        ? {
            acknowledge: (coverage: StreamSyncImportedCoverage) =>
              options.overlay!.acknowledge(coverage),
          }
        : {}),
    });
    // Every durable current view is covered already: say so, so a restart
    // retires what an interrupted acknowledgment left behind.
    if (options.durable && options.overlay) {
      for (const { key, version } of views.views()) {
        await importer.acknowledge(key, {
          version: version.version,
          dataHash: version.dataHash,
          generation: version.head.generation,
        });
      }
    }
    // Import whatever the mirror holds that a crash left unimported.
    const service = new StreamSyncReadService(
      options,
      mirror,
      views,
      importer,
      new Set(mirror.connectors()),
    );
    await service.forwardDeletes();
    return service;
  }

  /** True when the next listing must start from the registry's first page. */
  wantsListingFromStart(): boolean {
    return this.mirror.wantsListingFromStart();
  }

  /** Record one listed page. Call before the listing cursor moves. */
  async observe(
    rows: readonly MirrorFeedRow[],
    page: { readonly fromStart: boolean; readonly lastPage: boolean },
  ): Promise<void> {
    for (const connector of await this.mirror.observe(rows, page)) {
      this.changed.add(connector);
    }
    await this.forwardDeletes();
  }

  /** Import changed connectors and retry those with a retried problem. */
  async importPending(): Promise<void> {
    const connectors = new Set([
      ...this.changed,
      ...this.importer.retryConnectors(),
    ]);
    this.changed = new Set();
    await this.importer.run([...connectors].sort());
    await this.forwardDeletes();
  }

  private async forwardDeletes(): Promise<void> {
    await this.options.overlay?.observeDeletes?.(
      this.mirror.deleteObservations(),
    );
  }

  status(): StreamSyncReadStatus {
    const connections: StreamSyncConnectionStatus[] = [];
    for (const connector of this.mirror.connectors()) {
      for (const view of this.connectionViews(connector)) {
        const streams: Record<
          string,
          StreamHeadView & { version: number | null; records: number | null }
        > = {};
        for (const [stream, head] of Object.entries(view.streams)) {
          const imported = this.importer.servableView({
            connector,
            ns: view.ns,
            stream,
          });
          streams[stream] = {
            ...head,
            version: imported?.version ?? null,
            records: imported?.head.recordCount ?? null,
          };
        }
        connections.push({
          connector,
          ns: view.ns,
          control: view.control.kind,
          streams,
        });
      }
    }
    return {
      listed: !this.mirror.needsFullListing(),
      connections,
      issues: this.importer.listIssues(),
    };
  }

  /**
   * The local runs whose rows `stream` of `(connector, ns)` shows on top of
   * `base`, read from the writer's publish plan (`foldPlan`). Each run is
   * judged by the start-to-current rule alone, `admitStart(run.start, control,
   * run)`: a pending read shows the runs the rule publishes or waits on, and a
   * published read shows only the runs it publishes. A foreign control
   * withholds every run of the key with reason `key_mismatch`. A tombstoned
   * stream row shows nothing. A run at or below the stream's deletion floor,
   * or one that `base` already covers, adds nothing. Whether a connection
   * serves a view at all is decided by `eligible()`, not here.
   *
   * `pending` reads this device's own rows the rule does not yet publish, for
   * the owner's pending view. `steps`, from a cursor, replays the plan of
   * exactly those runs; the withheld and unpublished runs are still every
   * such run now.
   */
  private contributions(
    snapshot: StreamSyncOverlaySnapshot | undefined,
    connector: string,
    ns: string,
    stream: string,
    control: ControlState,
    tombstoned: boolean,
    base: ImportedVersion | null,
    options: {
      readonly pending?: boolean;
      readonly steps?: readonly (readonly [string, string])[];
    } = {},
  ): Fold {
    const { pending = false, steps } = options;
    const head = base && planHeadOf(base.head);
    const none = foldPlan(head, [], []);
    if (!snapshot || tombstoned) return none;
    // A foreign key holds every local run pending, as the writer does: none is
    // shown, and each is named withheld with the reason.
    if (control.kind === "foreign") {
      const held: WithheldContribution[] = [];
      for (const run of snapshot.runs) {
        if (run.connector !== connector || run.ns !== ns) continue;
        const local = run.streams.find((s) => s.name === stream);
        if (local) held.push({ run, stream: local, reason: "key_mismatch" });
      }
      return { ...none, withheld: held };
    }
    // A receipt at or below the stream's deletion floor was published before
    // the owner deleted the stream: the same rule servableView applies to
    // imported views, on every overlay path (owner, pending and overlay-only).
    const floor = this.mirror.deletionFloor(streamScope(connector, ns, stream));
    const candidates: Contribution[] = [];
    for (const run of snapshot.runs) {
      if (run.connector !== connector || run.ns !== ns) continue;
      const local = run.streams.find((s) => s.name === stream);
      if (!local) continue;
      // The same rule decide() applies, on the run's recorded start and flags:
      // a pending read shows publish and wait, a published read shows publish
      // only. The rule holds for a published run too, including the window
      // where this mirror still reads the deleted control the writer left.
      const verdict = admitStart(run.start, control, run);
      if (verdict === "discard" || (verdict === "wait" && !pending)) continue;
      if (!local.receipt && (local.collectedAt ?? 0) < floor) continue;
      if (local.receipt && local.receipt.registryVersion <= floor) continue;
      if (local.receipt && base && covers(base, local.receipt)) continue;
      candidates.push({ run, stream: local });
    }
    const fold = (runs: readonly Contribution[]) =>
      foldPlan(
        head,
        runs,
        snapshot.plan(
          ns,
          stream,
          head,
          runs.map((c) => c.run.runId),
        ),
      );
    const all = fold(candidates);
    if (!steps) return all;
    const replay = fold(
      candidates.filter((c) =>
        steps.some(
          ([runId, revision]) =>
            runId === c.run.runId && revision === c.stream.contentRevision,
        ),
      ),
    );
    return {
      ...replay,
      withheld: all.withheld,
      unpublished: all.unpublished,
      awaiting: all.awaiting,
    };
  }

  /**
   * What a legacy delete asks about `scope`, from the PUBLISHED side only
   * (imported heads; this device's spool and overlay never count).
   * `null` when the mirror does not hold a whole listing or no read target of
   * the scope is a connector the mirror knows. `covered` is false while any target stream lacks a live,
   * complete head in the one active connection of its connector (more than
   * one active connection is `ambiguous`). `throughMs` is the oldest
   * `observedAt` of the heads used: a legacy row collected after it may hold
   * data the views lack. `streams` lists every target stream with the
   * version and registry time of its last delete (0 = never deleted), read
   * from the mirror's deletion floor. `deleted` holds when every target is
   * deleted and none was re-collected.
   */
  retireBasis(scope: string): RetireBasis | null {
    // As `resolve` does: a connector the registry mirror has never seen is no
    // target. A scope may be served by alternate connectors; one that was
    // never connected holds nothing and must not leave the scope "uncovered".
    const known = new Set(this.mirror.connectors());
    const allTargets = readTargets(scope);
    const targets = allTargets.filter((t) => known.has(t.connector));
    if (targets.length === 0 || this.mirror.needsFullListing()) return null;
    const streams: RetireBasis["streams"][number][] = [];
    for (const target of targets) {
      for (const stream of target.streams) {
        streams.push({
          connector: target.connector,
          stream,
          ...this.lastDelete(target.connector, stream),
        });
      }
    }
    let throughMs = Infinity;
    let covered = true;
    let ambiguous = false;
    let deletedTargets = 0;
    for (const target of targets) {
      const connections = this.connectionViews(target.connector);
      if (connections.filter((c) => c.control.kind === "active").length > 1) {
        ambiguous = true;
        covered = false;
        break;
      }
      const eligibility = eligible({
        connections,
        target: { kind: "logical", streams: target.streams },
        legacyFile: true,
      });
      if (eligibility.kind !== "view") {
        covered = false;
        if (
          eligibility.kind === "unavailable" &&
          eligibility.reason === "deleted"
        ) {
          deletedTargets += 1;
        }
        continue;
      }
      for (const stream of target.streams) {
        const imported = this.importer.servableView({
          connector: target.connector,
          ns: eligibility.ns,
          stream,
        });
        if (!imported) {
          covered = false;
          continue;
        }
        throughMs = Math.min(throughMs, imported.head.observedAt);
      }
    }
    return {
      covered: covered && Number.isFinite(throughMs),
      ambiguous,
      deleted: !ambiguous && deletedTargets === targets.length,
      allTargetsKnown: targets.length === allTargets.length,
      throughMs: Number.isFinite(throughMs) ? throughMs : 0,
      streams,
    };
  }

  /**
   * The highest delete version the mirror holds for a stream, in any
   * namespace, and the registry time of the EARLIEST such delete (null when
   * any of them has no known time). A local write is "before the delete" only
   * if it predates every delete of the stream.
   */
  private lastDelete(
    connector: string,
    stream: string,
  ): { deleteVersion: number; deleteAtMs: number | null } {
    const rows = this.mirror.rowsFor(connector);
    const namespaces = new Set([
      IDENTITYLESS_NS,
      ...rows.controls.keys(),
      ...rows.streams.keys(),
    ]);
    let deleteVersion = 0;
    let deleteAtMs: number | null = null;
    let unknown = false;
    for (const ns of namespaces) {
      const scope = streamScope(connector, ns, stream);
      const floor = this.mirror.deletionFloor(scope);
      if (floor === 0) continue;
      deleteVersion = Math.max(deleteVersion, floor);
      const at = this.mirror.deletionTime(scope);
      if (at === null) unknown = true;
      else deleteAtMs = deleteAtMs === null ? at : Math.min(deleteAtMs, at);
    }
    return { deleteVersion, deleteAtMs: unknown ? null : deleteAtMs };
  }

  /**
   * The legacy body the PUBLISHED view of `scope` serves, as a grant would
   * read it: imported heads only, never an unpublished local run. `null` only
   * when the read decided that no complete view serves it. A failed read
   * (storage error, wrong key, a body that does not parse) THROWS: it is not
   * the answer "no view". A readback compares a local legacy file with this
   * body.
   */
  async publishedBody(scope: string): Promise<unknown | null> {
    const decision = await this.resolve({
      scope,
      connection: null,
      cursor: null,
      legacyFile: true,
      isOwnerView: false,
    });
    if (decision.kind !== "view") {
      if ("body" in decision) await decision.body.cancel();
      return null;
    }
    const parsed = JSON.parse(await new Response(decision.body).text()) as {
      data?: unknown;
    };
    return parsed.data ?? null;
  }

  /** Changes whenever an imported view of one of the scope's streams changes. */
  viewRevision(scope: string): string {
    return readTargets(scope)
      .flatMap((t) => t.streams.map((s) => this.views.revision(t.connector, s)))
      .join(",");
  }

  /** §2.10 inputs for connector c: every connection this server knows. */
  connectionViews(
    connector: string,
    snapshot?: StreamSyncOverlaySnapshot,
  ): ConnectionView[] {
    const rows = this.mirror.rowsFor(connector);
    const namespaces = new Set([
      ...rows.controls.keys(),
      ...rows.streams.keys(),
    ]);
    const out: ConnectionView[] = [];
    for (const ns of [...namespaces].sort()) {
      const control = this.importer.controlState(rows.controls.get(ns));
      const streams: Record<string, StreamHeadView> = {};
      let latest: number | null = null;
      const mirrored = rows.streams.get(ns) ?? new Map<string, MirrorRow>();
      const names = new Set(mirrored.keys());
      for (const run of snapshot?.runs ?? []) {
        if (run.ns !== ns) continue;
        for (const s of run.streams) names.add(s.name);
      }
      for (const stream of [...names].sort()) {
        const row = mirrored.get(stream);
        const imported = this.importer.servableView({ connector, ns, stream });
        const kind = row ? this.importer.streamRowKind(row) : null;
        const live =
          imported !== null &&
          kind !== null &&
          isHeadLive(control, kind, imported.head.generation);
        const local = this.contributions(
          snapshot,
          connector,
          ns,
          stream,
          control,
          kind === "tombstoned",
          live ? imported : null,
        );
        streams[stream] = {
          tombstoned: kind === "tombstoned",
          live: live || local.merged.length > 0,
          complete: local.complete,
        };
        // Q6: the registry time of the connection's newest live stream head.
        if (live && row && row.addedAtMs !== null) {
          latest =
            latest === null ? row.addedAtMs : Math.max(latest, row.addedAtMs);
        }
      }
      out.push({ ns, control, latestHeadRegistration: latest, streams });
    }
    return out;
  }

  async resolve(input: ResolveInput): Promise<ReadDecision> {
    if (input.connection !== null && !NS.test(input.connection)) {
      return { kind: "invalid_connection" };
    }
    let cursor: Cursor | null = null;
    if (input.cursor !== null) {
      cursor = decodeCursor(input.cursor);
      if (!cursor) return { kind: "invalid_cursor" };
    }
    const known = new Set(this.mirror.connectors());
    const all = readTargets(input.scope);
    const targets = all.filter((t) => known.has(t.connector));
    // A connector the registry mirror has never seen can still hold the
    // owner's local runs (a first run made offline).
    const candidates =
      this.options.overlay && input.isOwnerView
        ? all.filter((t) => !known.has(t.connector))
        : [];
    if (targets.length === 0 && candidates.length === 0) {
      return input.connection !== null
        ? { kind: "unavailable", reason: "connection_not_found" }
        : { kind: "pass" };
    }
    // One pinned snapshot per connector, taken BEFORE any imported view is
    // leased: whatever an import retires after this point stays readable
    // from the pin. The chosen view keeps its snapshot until the body ends.
    //
    // The snapshot's plan knows the writer's commits up to the snapshot. An
    // import that lands after it carries commits the plan does not know, so
    // pairing that base with this plan could show a run the writer refuses.
    // The read starts over when an import lands before the decision is made.
    // Only the streams this read touches can invalidate it: the import
    // revisions of the target streams are its basis. The snapshot pins the
    // writer state of those streams (a publication in flight is part of it),
    // so a later writer change alone cannot pair a base with another plan.
    const touched = [...targets, ...candidates];
    const basis = () =>
      touched
        .flatMap((t) =>
          t.streams.map((s) => this.views.revision(t.connector, s)),
        )
        .join(",");
    for (let attempt = 1; ; attempt += 1) {
      const before = basis();
      const snapshots = new Map<string, StreamSyncOverlaySnapshot>();
      let decision: ReadDecision;
      try {
        for (const target of [...targets, ...candidates]) {
          snapshots.set(
            target.connector,
            // Only the owner view reads local runs. A grant is answered from
            // the imported heads, as if no local run existed.
            input.isOwnerView
              ? await this.snapshot(target.connector)
              : NO_SNAPSHOT,
          );
        }
        decision = await this.decide(
          input,
          cursor,
          targets,
          candidates,
          snapshots,
        );
      } finally {
        for (const snapshot of snapshots.values()) snapshot.release();
      }
      if (basis() === before) return decision;
      if ("body" in decision) await decision.body.cancel();
      if (attempt >= MAX_COHERENCE_ATTEMPTS) {
        return { kind: "busy", retryAfterSeconds: BUSY_RETRY_AFTER_SECONDS };
      }
    }
  }

  private snapshot(connector: string): Promise<StreamSyncOverlaySnapshot> {
    return this.options.overlay
      ? this.options.overlay.snapshot(connector)
      : Promise.resolve(NO_SNAPSHOT);
  }

  private async decide(
    input: ResolveInput,
    cursor: Cursor | null,
    targets: readonly Target[],
    candidates: readonly Target[],
    snapshots: Map<string, StreamSyncOverlaySnapshot>,
  ): Promise<ReadDecision> {
    const evaluated = targets.map((target) => {
      const connections = this.connectionViews(
        target.connector,
        snapshots.get(target.connector),
      );
      const eligibility = this.eligibility(input, target, connections);
      return { target, connections, eligibility };
    });

    // The owner never reads fewer records than a grant. When the stored body
    // answers a grant (no published view of the imported heads), it answers
    // the owner too, whatever the owner's own overlay would show: a complete
    // overlay does not contain a different stored body.
    const grantReadsFile =
      input.isOwnerView &&
      input.legacyFile &&
      input.connection === null &&
      !targets.some(
        (target) =>
          this.eligibility(
            input,
            target,
            this.connectionViews(target.connector),
          ).kind === "view",
      );

    const views = evaluated
      .filter((e) => !grantReadsFile && e.eligibility.kind === "view")
      .map((e) => {
        const ns = (e.eligibility as { ns: string }).ns;
        const selected = e.connections.find((c) => c.ns === ns)!;
        return {
          ...e,
          ns,
          registered: selected.latestHeadRegistration ?? -Infinity,
        };
      })
      .sort(
        (a, b) =>
          b.registered - a.registered ||
          (a.target.connector < b.target.connector ? -1 : 1),
      );
    if (views.length > 0) {
      const best = views[0]!;
      // The view owns its snapshot from here: it releases it with the body.
      const snapshot = snapshots.get(best.target.connector)!;
      snapshots.delete(best.target.connector);
      return this.serveView(
        input.scope,
        best.target,
        best.ns,
        cursor,
        snapshot,
        input.isOwnerView,
      );
    }
    const deleted = evaluated.some(
      (e) =>
        e.eligibility.kind === "unavailable" &&
        e.eligibility.reason === "deleted",
    );
    // The owner's partial view. A deleted connection still gets the scan: the
    // rule admits only a full connect the writer will publish, and nothing
    // else is shown. The owner never reads fewer rows than a grant: when a
    // grant would read the legacy body, the owner reads it too, with the notes.
    let notes: OwnerNotes = {};
    if (input.isOwnerView) {
      const scan = this.pendingScan(
        input,
        [...targets, ...candidates],
        snapshots,
      );
      if (scan.best && !grantReadsFile) {
        const snapshot = snapshots.get(scan.best.target.connector)!;
        snapshots.delete(scan.best.target.connector);
        try {
          return await this.serveView(
            input.scope,
            scan.best.target,
            scan.best.ns,
            cursor,
            snapshot,
            true,
            "pending",
          );
        } catch (error) {
          // The projector refuses the partial input (a legacy name whose
          // rows are not all there yet). No partial view serves; the answer
          // below does, with the notes. serveView released the snapshot.
          if (!(error instanceof ProjectionFailedError)) throw error;
          this.options.logger.info(
            { connector: scan.best.target.connector },
            "stream-sync read: the partial view cannot be projected",
          );
          // The writer will publish these runs, but the requested name cannot
          // show them: the owner is told, whatever answer follows.
          scan.withheld = uniqueWithheld([
            ...scan.withheld,
            ...scan.best.shown,
          ]);
        }
      }
      // No view is served: the runs the writer will not publish still reach
      // the owner, with the answer that is.
      if (scan.withheld.length > 0) {
        this.logWithheld(scan.connectors, scan.withheld.length);
        notes = { withheld: scan.withheld };
      }
      // The legacy body answers, as before own-writes; unpublished runs are
      // counted, never compared by time.
      if (input.legacyFile && scan.unpublished > 0) {
        this.options.logger.info(
          { connector: scan.connectors.join(","), pending: scan.unpublished },
          "stream-sync read: legacy body served over pending local runs",
        );
        notes = { ...notes, pending: { runs: scan.unpublished } };
      }
      // Published is not reflected: until import covers a published run, the
      // legacy body does not show it either.
      if (input.legacyFile && scan.awaiting > 0) {
        notes = { ...notes, awaitingImport: { runs: scan.awaiting } };
      }
      // A live imported head the stored body does not reflect, whatever the
      // runs say: import and retirement do not end this note, reflection does.
      if (input.legacyFile && scan.notReflected > 0) {
        notes = { ...notes, notReflected: { streams: scan.notReflected } };
      }
    }
    if (cursor) return { kind: "cursor_stale" };
    if (deleted) {
      return { kind: "unavailable", reason: "deleted" };
    }
    // A named connection is served only from its own view: a legacy file
    // records no connection.
    if (input.connection !== null) {
      const foreign = evaluated.some((e) =>
        e.connections.some(
          (c) => c.ns === input.connection && c.control.kind === "foreign",
        ),
      );
      return foreign
        ? { kind: "key_mismatch", ...notes }
        : { kind: "unavailable", reason: "connection_not_found", ...notes };
    }
    if (evaluated.some((e) => e.eligibility.kind === "legacy")) {
      return { kind: "legacy", ...notes };
    }
    if (
      evaluated.some(
        (e) =>
          selectConnection(e.connections) === null &&
          e.connections.some((c) => c.control.kind === "foreign"),
      )
    ) {
      return { kind: "key_mismatch", ...notes };
    }
    return { kind: "pass", ...notes };
  }

  /** §2.10 for one target over `connections`. */
  private eligibility(
    input: ResolveInput,
    target: Target,
    connections: readonly ConnectionView[],
  ): Eligibility {
    return eligible({
      connections: [...connections],
      target:
        input.connection !== null
          ? {
              kind: "physical",
              ns: input.connection,
              streams: target.streams,
            }
          : { kind: "logical", streams: target.streams },
      legacyFile: input.legacyFile,
    });
  }

  /** The imported view of a stream while its head is live, else null. */
  private liveImported(
    connector: string,
    ns: string,
    stream: string,
    control: ControlState,
    row: MirrorRow | undefined,
  ): ImportedVersion | null {
    const imported = this.importer.servableView({ connector, ns, stream });
    const kind = row ? this.importer.streamRowKind(row) : null;
    return imported !== null &&
      kind !== null &&
      isHeadLive(control, kind, imported.head.generation)
      ? imported
      : null;
  }

  /**
   * The target and connection the owner's partial view serves: every needed
   * stream has a live imported head (complete or not) or local runs the
   * writer will publish; `at` is the newest stamp among them. Also every run
   * withheld, and the distinct runs not published yet, among all the
   * connections looked at, whether or not any of them can be served.
   */
  private pendingScan(
    input: ResolveInput,
    targets: readonly Target[],
    snapshots: ReadonlyMap<string, StreamSyncOverlaySnapshot>,
  ): {
    best: {
      target: Target;
      ns: string;
      at: number;
      /** The runs whose rows its view shows, per stream. */
      shown: WithheldRun[];
    } | null;
    withheld: WithheldRun[];
    unpublished: number;
    awaiting: number;
    notReflected: number;
    connectors: string[];
  } {
    let best: {
      target: Target;
      ns: string;
      at: number;
      shown: WithheldRun[];
    } | null = null;
    const withheld: WithheldRun[] = [];
    const unpublished = new Set<string>();
    const awaiting = new Set<string>();
    const notReflected = new Set<string>();
    const connectors = new Set<string>();
    for (const target of targets) {
      const snapshot = snapshots.get(target.connector);
      if (!snapshot) continue;
      const rows = this.mirror.rowsFor(target.connector);
      const namespaces = new Set<string>([
        ...rows.controls.keys(),
        ...rows.streams.keys(),
      ]);
      for (const run of snapshot.runs)
        if (run.ns !== null) namespaces.add(run.ns);
      for (const ns of [...namespaces].sort()) {
        if (input.connection !== null && input.connection !== ns) continue;
        const control = this.importer.controlState(rows.controls.get(ns));
        let at = 0;
        const shown: WithheldRun[] = [];
        // Every stream is scanned, whether or not an earlier one can be
        // served: a withheld or unpublished run is reported either way.
        const covered = target.streams.map((stream) => {
          const row = rows.streams.get(ns)?.get(stream);
          const live = this.liveImported(
            target.connector,
            ns,
            stream,
            control,
            row,
          );
          if (live !== null) {
            notReflected.add(JSON.stringify([target.connector, ns, stream]));
          }
          const local = this.contributions(
            snapshot,
            target.connector,
            ns,
            stream,
            control,
            row !== undefined &&
              this.importer.streamRowKind(row) === "tombstoned",
            live,
            { pending: true },
          );
          if (local.withheld.length > 0 || local.unpublished.length > 0) {
            connectors.add(target.connector);
          }
          withheld.push(...withheldRuns([{ stream, fold: local }]));
          for (const c of local.merged) {
            shown.push({
              runId: c.run.runId,
              stream,
              reason: "projection_unavailable",
            });
          }
          for (const runId of local.unpublished) {
            unpublished.add(JSON.stringify([target.connector, ns, runId]));
          }
          for (const runId of local.awaiting) {
            awaiting.add(JSON.stringify([target.connector, ns, runId]));
          }
          at = Math.max(
            at,
            live?.head.observedAt ?? 0,
            ...local.merged.map((c) => c.run.observedAt),
          );
          return live !== null || local.merged.length > 0;
        });
        if (!covered.every(Boolean)) continue;
        if (
          !best ||
          at > best.at ||
          (at === best.at && target.connector < best.target.connector)
        ) {
          best = { target, ns, at, shown };
        }
      }
    }
    return {
      best,
      withheld: uniqueWithheld(withheld),
      unpublished: unpublished.size,
      awaiting: awaiting.size,
      notReflected: notReflected.size,
      connectors: [...connectors],
    };
  }

  /** One log line per read: a count, never a row. */
  private logWithheld(connectors: readonly string[], count: number): void {
    this.options.logger.warn(
      { connector: connectors.join(","), withheld: count },
      "stream-sync read: local runs withheld from the view",
    );
  }

  private async serveView(
    scope: string,
    target: Target,
    ns: string,
    cursor: Cursor | null,
    snapshot: StreamSyncOverlaySnapshot,
    isOwnerView: boolean,
    mode: "view" | "pending" = "view",
  ): Promise<ReadDecision> {
    const pending = mode === "pending";
    const leases: ViewLease[] = [];
    // Snapshot and leases are released together, once, with the body.
    let released = false;
    const releaseAll = () => {
      if (released) return;
      released = true;
      for (const lease of leases) lease.release();
      snapshot.release();
    };
    try {
      if (cursor && (cursor.c !== target.connector || cursor.ns !== ns)) {
        releaseAll();
        return { kind: "cursor_stale" };
      }
      const rows = this.mirror.rowsFor(target.connector);
      const control = this.importer.controlState(rows.controls.get(ns));
      const inputs: StreamInput[] = [];
      for (const stream of target.streams) {
        const key: ViewKey = { connector: target.connector, ns, stream };
        const pin = cursor ? cursor.s[stream] : undefined;
        if (cursor && !pin) {
          releaseAll();
          return { kind: "cursor_stale" };
        }
        const row = rows.streams.get(ns)?.get(stream);
        const kind = row ? this.importer.streamRowKind(row) : null;
        const current = this.importer.servableView(key);
        const currentLive =
          current !== null &&
          kind !== null &&
          isHeadLive(control, kind, current.head.generation);
        // A partial view leases the live head too, complete or not: the
        // owner's rows stay readable after the run that wrote them retires.
        let lease: ViewLease | null = null;
        if (cursor) {
          if (pin!.b === null) {
            // The cursor saw no imported head; one has appeared since.
            if (currentLive) {
              releaseAll();
              return { kind: "cursor_stale" };
            }
          } else {
            lease = this.views.lease(key, pin!.b);
            if (!lease) {
              releaseAll();
              return { kind: "cursor_stale" };
            }
          }
        } else if (currentLive) {
          lease = this.views.lease(key);
        }
        if (lease) leases.push(lease);
        // Replay the plan a cursor recorded: a retired or changed run makes
        // the cursor stale, and a new run does not join. A cursor from before
        // fold pins recorded the shown members alone.
        const steps = cursor ? (pin!.p ?? pin!.m ?? []) : undefined;
        const fold = this.contributions(
          snapshot,
          target.connector,
          ns,
          stream,
          control,
          kind === "tombstoned",
          lease?.version ?? null,
          { pending, ...(steps ? { steps } : {}) },
        );
        if (cursor && !replaysPin(fold, pin!)) {
          releaseAll();
          return { kind: "cursor_stale" };
        }
        if (!lease && fold.merged.length === 0) {
          // Not a view after all: nothing imported and nothing local.
          releaseAll();
          return { kind: "cursor_stale" };
        }
        inputs.push({ stream, lease, fold });
      }
      // A stream without an imported head has no registry entry: only the
      // owner reads it. Everyone else gets the existing path, with its own
      // billing, grants and access record.
      if (pending && !isOwnerView) {
        releaseAll();
        return { kind: "pass" };
      }
      if (!isOwnerView && inputs.some((i) => !i.lease)) {
        releaseAll();
        return { kind: "pass" };
      }
      const byStream = new Map(inputs.map((i) => [i.stream, i]));
      const overlays = new Map<string, OverlayWinners>();
      let observedAt = 0;
      for (const input of inputs) {
        const { fold } = input;
        const overlay = fold.merged.length
          ? await overlayWinners(snapshot, this.options.keys, {
              runs: fold.merged.map((c) => c.run),
              stream: input.stream,
              primaryKey: fold.shape!.primaryKey,
            })
          : NO_OVERLAY;
        overlays.set(input.stream, overlay);
        observedAt = Math.max(
          observedAt,
          input.lease?.version.head.observedAt ?? 0,
          overlay.newestObservedAt ?? 0,
          ...fold.merged.map((c) => c.run.observedAt),
        );
      }
      const lines = (stream: string): AsyncIterable<Line> => {
        const input = byStream.get(stream)!;
        return viewLines(
          this.views,
          this.options.keys,
          input.lease,
          overlays.get(stream)!,
          input.fold.shape!.primaryKey,
        );
      };
      const nextCursor = encodeCursor({
        c: target.connector,
        ns,
        s: Object.fromEntries(
          inputs.map((i) => [
            i.stream,
            {
              b: i.lease ? i.lease.version.version : null,
              m: i.fold.merged
                .map((c) => [c.run.runId, c.stream.contentRevision] as const)
                .sort(),
              p: i.fold.chain.map(
                (c) => [c.run.runId, c.stream.contentRevision] as const,
              ),
              h: shapePin(i.fold),
            },
          ]),
        ),
      });
      // Runs the writer will not publish are never shown and never dropped
      // silently: the log gets a count, the owner gets the runs.
      const withheldAll = uniqueWithheld(withheldRuns(inputs));
      if (withheldAll.length > 0) {
        this.logWithheld([target.connector], withheldAll.length);
      }
      const withheld = isOwnerView ? withheldAll : [];
      const complete = inputs.every((i) => i.fold.complete);
      const open = `{"version":"1.0","scope":${JSON.stringify(scope)},"collectedAt":${JSON.stringify(new Date(observedAt).toISOString())},${pending ? `"origin":"local-pending","complete":${complete},` : ""}${withheld.length > 0 ? `"withheld":${JSON.stringify(withheld)},` : ""}"data":`;
      let payload: AsyncIterable<string>;
      if (!target.binding) {
        payload = recordsPayload(lines(target.streams[0]!));
      } else {
        const first = inputs[0]!;
        const plan = await planProjection({
          scope,
          binding: target.binding,
          // The head the writer leaves, not the base the runs built on.
          profileKey: first.fold.shape?.profile.key ?? undefined,
          lines,
          streamBytes: (stream) =>
            (byStream.get(stream)!.lease?.version.head.parts ?? []).reduce(
              (sum, p) => sum + p.bytes,
              0,
            ),
          sha256: this.options.keys.hashes.sha256,
          spool: this.options.files,
          spoolId: `${Date.now().toString(36)}-${(this.spoolCounter++).toString(36)}`,
          budgetBytes:
            this.options.arrayProjectionBudgetBytes ?? DEFAULT_ARRAY_BUDGET,
          now: (this.options.now?.() ?? new Date()).toISOString(),
        });
        if (plan.kind === "too_large") {
          releaseAll();
          return plan;
        }
        payload = plan.payload;
      }
      const servedStream =
        target.binding?.window?.parentStream ?? target.streams[0]!;
      const servedBase = byStream.get(servedStream)!.lease;
      const body = toStream(envelope(open, payload), releaseAll);
      if (pending) {
        return {
          kind: "local_pending",
          connector: target.connector,
          ns,
          cursor: nextCursor,
          complete,
          ...(withheld.length > 0 ? { withheld } : {}),
          body,
        };
      }
      return {
        kind: "view",
        connector: target.connector,
        ns,
        cursor: nextCursor,
        // A view with an input that has no registered head has no registry
        // entry to bind a paid read to.
        served:
          servedBase && inputs.every((i) => i.lease)
            ? {
                scope: streamScope(target.connector, ns, servedStream),
                version: servedBase.version.version,
              }
            : null,
        ...(withheld.length > 0 ? { withheld } : {}),
        body,
      };
    } catch (error) {
      releaseAll();
      throw error;
    }
  }
}

interface StreamInput {
  readonly stream: string;
  /** The leased imported view, or null for an overlay-only stream. */
  readonly lease: ViewLease | null;
  /** The local runs the view shows, as the writer will publish them. */
  readonly fold: Fold;
}

/** The runs the view does not show, one per run and stream. */
function withheldRuns(
  inputs: readonly { readonly stream: string; readonly fold: Fold }[],
): WithheldRun[] {
  return inputs.flatMap((i) =>
    i.fold.withheld.map((c): WithheldRun => ({
      runId: c.run.runId,
      stream: i.stream,
      reason: c.reason,
    })),
  );
}

/** The projection input a cursor pins: the shown head's key, profile and completeness. */
function shapePin(fold: Fold): string {
  return JSON.stringify([
    fold.shape?.primaryKey ?? null,
    fold.shape?.profile.key ?? null,
    fold.shape?.profile.version ?? null,
    fold.complete,
  ]);
}

function uniqueWithheld(runs: readonly WithheldRun[]): WithheldRun[] {
  const seen = new Set<string>();
  return runs
    .filter((w) => {
      const key = `${w.runId}\0${w.stream}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) =>
      a.runId === b.runId
        ? a.stream < b.stream
          ? -1
          : a.stream > b.stream
            ? 1
            : 0
        : a.runId < b.runId
          ? -1
          : 1,
    );
}

const stepKey = (c: Contribution) =>
  `${c.run.runId}\0${c.stream.contentRevision}`;
const pairKey = ([runId, revision]: readonly [string, string]) =>
  `${runId}\0${revision}`;

/**
 * The replayed fold is the one the cursor recorded: the same published runs
 * in the same order, the same shown members, the same head shape. Otherwise
 * a replay would mix rows the first response had replaced, or project them
 * under another profile.
 */
function replaysPin(fold: Fold, pin: CursorStream): boolean {
  if (pin.d === true) return false;
  if (pin.h !== undefined && pin.h !== shapePin(fold)) return false;
  const members = (pin.m ?? []).map(pairKey).sort();
  const shown = fold.merged.map(stepKey).sort();
  if (
    members.length !== shown.length ||
    members.some((key, i) => key !== shown[i])
  ) {
    return false;
  }
  if (pin.p) {
    const chain = fold.chain.map(stepKey);
    if (
      pin.p.length !== chain.length ||
      pin.p.some((pair, i) => pairKey(pair) !== chain[i])
    ) {
      return false;
    }
  }
  return true;
}

/**
 * `{records}` of a stream with no legacy binding (`pdpp.<c>.<s>`).
 *
 * Record order is unspecified. The file read this replaces serves records in
 * the order its writer chose, and no writer uses a record field: one pages
 * the records route by import time and key, another keeps arrival order.
 * A stream keeps no write order, so a view serves its parts in pkHash order
 * and makes no promise about it. Readers that need an order sort by a field.
 */
async function* recordsPayload(
  lines: AsyncIterable<Line>,
): AsyncGenerator<string> {
  yield '{"records":[';
  let first = true;
  for await (const line of lines) {
    yield (first ? "" : ",") + JSON.stringify(line.v);
    first = false;
  }
  yield "]}";
}

async function* envelope(
  open: string,
  payload: AsyncIterable<string>,
): AsyncGenerator<string> {
  yield open;
  yield* payload;
  yield "}";
}
