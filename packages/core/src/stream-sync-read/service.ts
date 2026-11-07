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
  controlHashes,
  eligible,
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
import { StreamSyncImporter, type ImportIssue } from "./importer.js";
import {
  NO_OVERLAY,
  overlayWinners,
  viewLines,
  type OverlayWinners,
} from "./lines.js";
import {
  RegistryMirror,
  type MirrorRow,
  type MirrorFeedRow,
} from "./mirror.js";
import type {
  StreamSyncBlobReader,
  StreamSyncImportedCoverage,
  StreamSyncOverlayRun,
  StreamSyncOverlaySnapshot,
  StreamSyncOverlaySnapshotSource,
  StreamSyncOverlayStream,
  StreamSyncPublishReceipt,
  StreamSyncReadFiles,
  StreamSyncReadKeys,
  StreamSyncReadLogger,
} from "./ports.js";
import { planProjection } from "./projection.js";
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

export type ReadDecision =
  /** Not a stream-sync read: the existing path answers, unchanged. */
  | { readonly kind: "pass" }
  /** §2.10 step 3: serve the legacy or raw file through the existing path. */
  | { readonly kind: "legacy" }
  | {
      readonly kind: "unavailable";
      readonly reason: "deleted" | "no_data" | "connection_not_found";
    }
  /** The connector's only connections were written with another owner key. */
  | { readonly kind: "key_mismatch" }
  /** The cursor names a version this server no longer holds. */
  | { readonly kind: "cursor_stale" }
  | { readonly kind: "invalid_cursor" }
  | { readonly kind: "invalid_connection" }
  | { readonly kind: "too_large"; readonly bytes: number }
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
      readonly body: ReadableStream<Uint8Array>;
    };

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
function covers(base: ImportedVersion, receipt: StreamSyncPublishReceipt): boolean {
  if (base.head.generation !== receipt.generation) return false;
  if (base.version > receipt.registryVersion) return true;
  return (
    base.version === receipt.registryVersion &&
    normalizeHash(base.dataHash) === normalizeHash(receipt.dataHash)
  );
}

function normalizeHash(hash: string): string {
  const lower = hash.toLowerCase();
  return lower.startsWith("0x") ? lower.slice(2) : lower;
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
        const { b, m } = (pin ?? {}) as { b?: unknown; m?: unknown };
        if (b !== null && !Number.isSafeInteger(b)) return null;
        if (
          m !== undefined &&
          !(
            Array.isArray(m) &&
            m.every(
              (x) =>
                Array.isArray(x) &&
                x.length === 2 &&
                typeof x[0] === "string" &&
                typeof x[1] === "string",
            )
          )
        ) {
          return null;
        }
        streams[name] = {
          b: b as number | null,
          ...(m ? { m: m as [string, string][] } : {}),
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
  lines: () => {
    throw new Error("no overlay source");
  },
  release() {},
};

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
    const mirror = await RegistryMirror.open(options.files);
    const views = await ViewStore.open(options.files);
    await options.files.remove("spool");
    const importer = new StreamSyncImporter({
      mirror,
      views,
      blobs: options.blobs,
      keys: options.keys,
      controlHashes: await controlHashes(
        options.keys.hashes.keccak256,
        options.keys.keyCheck,
      ),
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
    return new StreamSyncReadService(
      options,
      mirror,
      views,
      importer,
      new Set(mirror.connectors()),
    );
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
  }

  /** Import changed connectors and retry those with a retried problem. */
  async importPending(): Promise<void> {
    const connectors = new Set([
      ...this.changed,
      ...this.importer.retryConnectors(),
    ]);
    this.changed = new Set();
    await this.importer.run([...connectors].sort());
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
          const imported = this.views.get({ connector, ns: view.ns, stream });
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
   * `base`. A run counts only under a verified active control state of this
   * key and its own generation (never the one active at read time), and never
   * over a tombstoned stream row. A published stream that `base` already
   * covers adds nothing: its rows are in the view.
   */
  private contributions(
    snapshot: StreamSyncOverlaySnapshot | undefined,
    connector: string,
    ns: string,
    stream: string,
    control: ControlState,
    tombstoned: boolean,
    base: ImportedVersion | null,
  ): { run: StreamSyncOverlayRun; stream: StreamSyncOverlayStream }[] {
    if (!snapshot || control.kind !== "active" || tombstoned) return [];
    const out: { run: StreamSyncOverlayRun; stream: StreamSyncOverlayStream }[] =
      [];
    for (const run of snapshot.runs) {
      if (
        run.connector !== connector ||
        run.ns !== ns ||
        run.generation !== control.generation
      ) {
        continue;
      }
      const local = run.streams.find((s) => s.name === stream);
      if (!local) continue;
      if (local.receipt && base && covers(base, local.receipt)) continue;
      out.push({ run, stream: local });
    }
    // Rows merge only under one primary key: the base's, else the newest
    // run's. A run of an unrelated key shape is not hashed against it.
    const reference =
      base?.head.primaryKey ??
      [...out].sort(
        (a, b) =>
          b.run.observedAt - a.run.observedAt ||
          (a.run.runId < b.run.runId ? 1 : -1),
      )[0]?.stream.primaryKey;
    return out.filter(
      (c) => JSON.stringify(c.stream.primaryKey) === JSON.stringify(reference),
    );
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
        const imported = this.views.get({ connector, ns, stream });
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
          live: live || local.length > 0,
          complete:
            (imported?.head.complete ?? false) ||
            local.some((c) => c.stream.complete),
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
    const targets = readTargets(input.scope).filter((t) =>
      known.has(t.connector),
    );
    if (targets.length === 0) {
      return input.connection !== null
        ? { kind: "unavailable", reason: "connection_not_found" }
        : { kind: "pass" };
    }
    // One pinned snapshot per connector, taken BEFORE any imported view is
    // leased: whatever an import retires after this point stays readable
    // from the pin. The chosen view keeps its snapshot until the body ends.
    const snapshots = new Map<string, StreamSyncOverlaySnapshot>();
    try {
      for (const target of targets) {
        snapshots.set(target.connector, await this.snapshot(target.connector));
      }
      return await this.decide(input, cursor, targets, snapshots);
    } finally {
      for (const snapshot of snapshots.values()) snapshot.release();
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
    snapshots: Map<string, StreamSyncOverlaySnapshot>,
  ): Promise<ReadDecision> {
    const evaluated = targets.map((target) => {
      const connections = this.connectionViews(
        target.connector,
        snapshots.get(target.connector),
      );
      const eligibility: Eligibility = eligible({
        connections,
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
      return { target, connections, eligibility };
    });

    const views = evaluated
      .filter((e) => e.eligibility.kind === "view")
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
    if (cursor) return { kind: "cursor_stale" };
    if (
      evaluated.some(
        (e) =>
          e.eligibility.kind === "unavailable" &&
          e.eligibility.reason === "deleted",
      )
    ) {
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
        ? { kind: "key_mismatch" }
        : { kind: "unavailable", reason: "connection_not_found" };
    }
    if (evaluated.some((e) => e.eligibility.kind === "legacy")) {
      return { kind: "legacy" };
    }
    if (
      evaluated.some(
        (e) =>
          selectConnection(e.connections) === null &&
          e.connections.some((c) => c.control.kind === "foreign"),
      )
    ) {
      return { kind: "key_mismatch" };
    }
    return { kind: "pass" };
  }

  private async serveView(
    scope: string,
    target: Target,
    ns: string,
    cursor: Cursor | null,
    snapshot: StreamSyncOverlaySnapshot,
    isOwnerView: boolean,
  ): Promise<ReadDecision> {
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
        const current = this.views.get(key);
        const currentLive =
          current !== null &&
          kind !== null &&
          isHeadLive(control, kind, current.head.generation);
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
        let local = this.contributions(
          snapshot,
          target.connector,
          ns,
          stream,
          control,
          kind === "tombstoned",
          lease?.version ?? null,
        );
        if (cursor) {
          // Replay exactly the recorded members: a retired or changed one
          // makes the cursor stale, and a new run does not join.
          const wanted = pin!.m ?? [];
          local = local.filter((c) =>
            wanted.some(
              ([runId, revision]) =>
                runId === c.run.runId && revision === c.stream.contentRevision,
            ),
          );
          if (local.length !== wanted.length) {
            releaseAll();
            return { kind: "cursor_stale" };
          }
        }
        if (!lease && local.length === 0) {
          // Not a view after all: nothing imported and nothing local.
          releaseAll();
          return { kind: "cursor_stale" };
        }
        inputs.push({ stream, lease, local });
      }
      // A stream without an imported head has no registry entry: only the
      // owner reads it. Everyone else gets the existing path, with its own
      // billing, grants and access record.
      if (!isOwnerView && inputs.some((i) => !i.lease)) {
        releaseAll();
        return { kind: "pass" };
      }
      const byStream = new Map(inputs.map((i) => [i.stream, i]));
      const overlays = new Map<string, OverlayWinners>();
      let observedAt = 0;
      for (const input of inputs) {
        const shape = input.lease
          ? input.lease.version.head
          : newestShape(input.local);
        const overlay = input.local.length
          ? await overlayWinners(snapshot, this.options.keys, {
              runs: input.local.map((c) => c.run),
              stream: input.stream,
              primaryKey: shape.primaryKey,
            })
          : NO_OVERLAY;
        overlays.set(input.stream, overlay);
        observedAt = Math.max(
          observedAt,
          input.lease?.version.head.observedAt ?? 0,
          overlay.newestObservedAt ?? 0,
          ...input.local.map((c) => c.run.observedAt),
        );
      }
      const lines = (stream: string): AsyncIterable<Line> => {
        const input = byStream.get(stream)!;
        return viewLines(
          this.views,
          this.options.keys,
          input.lease,
          overlays.get(stream)!,
          (input.lease
            ? input.lease.version.head
            : newestShape(input.local)
          ).primaryKey,
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
              m: i.local
                .map((c) => [c.run.runId, c.stream.contentRevision] as const)
                .sort(),
            },
          ]),
        ),
      });
      const open = `{"version":"1.0","scope":${JSON.stringify(scope)},"collectedAt":${JSON.stringify(new Date(observedAt).toISOString())},"data":`;
      let payload: AsyncIterable<string>;
      if (!target.binding) {
        payload = recordsPayload(lines(target.streams[0]!));
      } else {
        const first = inputs[0]!;
        const plan = await planProjection({
          scope,
          binding: target.binding,
          profileKey:
            (first.lease
              ? first.lease.version.head.profile.key
              : newestShape(first.local).profile.key) ?? undefined,
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
  readonly local: readonly {
    run: StreamSyncOverlayRun;
    stream: StreamSyncOverlayStream;
  }[];
}

/** Primary key and profile of an overlay-only stream: its newest run's. */
function newestShape(local: StreamInput["local"]): StreamSyncOverlayStream {
  const newest = [...local].sort(
    (a, b) =>
      b.run.observedAt - a.run.observedAt ||
      (a.run.runId < b.run.runId ? 1 : -1),
  )[0]!;
  return newest.stream;
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
