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
import { overlayWinners, viewLines, type OverlayWinners } from "./lines.js";
import { RegistryMirror, type MirrorFeedRow } from "./mirror.js";
import type {
  StreamSyncBlobReader,
  StreamSyncOverlaySource,
  StreamSyncReadFiles,
  StreamSyncReadKeys,
  StreamSyncReadLogger,
} from "./ports.js";
import { planProjection } from "./projection.js";
import { isPhysicalScope } from "./routing.js";
import { ViewStore, type ViewKey, type ViewLease } from "./view-store.js";

export interface StreamSyncReadOptions {
  readonly files: StreamSyncReadFiles;
  readonly blobs: StreamSyncBlobReader;
  readonly keys: StreamSyncReadKeys;
  readonly logger: StreamSyncReadLogger;
  readonly overlay?: StreamSyncOverlaySource;
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

interface Target {
  readonly connector: string;
  readonly streams: readonly string[];
  /** Absent for `pdpp.<c>.<s>`: a `{records}` body. */
  readonly binding?: LegacyScopeBinding;
}

interface Cursor {
  readonly c: string;
  readonly ns: string;
  readonly v: Readonly<Record<string, number>>;
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
  const plain = /^pdpp\.([^.~]+)\.([^~]+)$/.exec(scope);
  if (plain) {
    targets.set(plain[1]!, { connector: plain[1]!, streams: [plain[2]!] });
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
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as Cursor;
    if (
      typeof parsed?.c !== "string" ||
      typeof parsed.ns !== "string" ||
      typeof parsed.v !== "object" ||
      parsed.v === null
    ) {
      return null;
    }
    for (const version of Object.values(parsed.v)) {
      if (!Number.isSafeInteger(version)) return null;
    }
    return parsed;
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
    });
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

  /** §2.10 inputs for connector c: every connection this server knows. */
  connectionViews(connector: string): ConnectionView[] {
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
      for (const [stream, row] of rows.streams.get(ns) ?? []) {
        const imported = this.views.get({ connector, ns, stream });
        const live =
          imported !== null &&
          isHeadLive(
            control,
            row.deleted ? "tombstoned" : "present",
            imported.head.generation,
          );
        streams[stream] = { live, complete: imported?.head.complete ?? false };
        // Q6: the registry time of the connection's newest live stream head.
        if (live && row.addedAtMs !== null) {
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
    const evaluated = targets.map((target) => {
      const connections = this.connectionViews(target.connector);
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
      return this.serveView(input.scope, best.target, best.ns, cursor);
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
  ): Promise<ReadDecision> {
    if (cursor && (cursor.c !== target.connector || cursor.ns !== ns)) {
      return { kind: "cursor_stale" };
    }
    const leases: ViewLease[] = [];
    const releaseAll = () => {
      for (const lease of leases) lease.release();
    };
    for (const stream of target.streams) {
      const key: ViewKey = { connector: target.connector, ns, stream };
      const at = cursor ? cursor.v[stream] : undefined;
      if (cursor && at === undefined) {
        releaseAll();
        return { kind: "cursor_stale" };
      }
      const lease = this.views.lease(key, at);
      if (!lease) {
        releaseAll();
        return { kind: "cursor_stale" };
      }
      leases.push(lease);
    }
    try {
      const byStream = new Map(leases.map((l) => [l.key.stream, l]));
      const overlays = new Map<string, OverlayWinners>();
      let observedAt = 0;
      for (const lease of leases) {
        const overlay = await overlayWinners(
          this.options.overlay,
          this.options.keys,
          lease,
        );
        overlays.set(lease.key.stream, overlay);
        observedAt = Math.max(
          observedAt,
          lease.version.head.observedAt,
          overlay.newestObservedAt ?? 0,
        );
      }
      const lines = (stream: string): AsyncIterable<Line> =>
        viewLines(
          this.views,
          this.options.keys,
          byStream.get(stream)!,
          overlays.get(stream)!,
        );
      const nextCursor = encodeCursor({
        c: target.connector,
        ns,
        v: Object.fromEntries(
          leases.map((l) => [l.key.stream, l.version.version]),
        ),
      });
      const open = `{"version":"1.0","scope":${JSON.stringify(scope)},"collectedAt":${JSON.stringify(new Date(observedAt).toISOString())},"data":`;
      let payload: AsyncIterable<string>;
      if (!target.binding) {
        payload = recordsPayload(lines(target.streams[0]!));
      } else {
        const plan = await planProjection({
          scope,
          binding: target.binding,
          profileKey: leases[0]!.version.head.profile.key ?? undefined,
          lines,
          streamBytes: (stream) =>
            byStream
              .get(stream)!
              .version.head.parts.reduce((sum, p) => sum + p.bytes, 0),
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
      const body = toStream(envelope(open, payload), releaseAll);
      return {
        kind: "view",
        connector: target.connector,
        ns,
        cursor: nextCursor,
        body,
      };
    } catch (error) {
      releaseAll();
      throw error;
    }
  }
}

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
