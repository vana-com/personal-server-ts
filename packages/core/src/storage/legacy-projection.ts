/**
 * Serve legacy scope bodies from stored PDPP records.
 *
 * PDPP connectors store one envelope per stream, body `{records: [row, …]}`,
 * under `<source>.<stream>`. Apps that predate PDPP read legacy bodies such
 * as `chatgpt.conversations` = `{conversations, total}`. `withLegacyProjection`
 * wraps the raw storage port: when the latest stored body of a projected
 * scope is `{records}`, reads return the legacy body projected from that
 * stream and its sibling streams. Every other body is served exactly as
 * stored. Writes, listings and the sync-facing methods pass through.
 *
 * Give the wrapped ("served") port to every reader of data: the HTTP data
 * route, MCP, derivatives and the job worker. Give the raw port to sync
 * upload/download, so canonical bytes (and their hashes) never change.
 */

import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
  type PdppRecord,
  type ProjectionDiagnostic,
  type ProjectionError,
} from "../legacy-projection/index.js";
import type { DataStoragePort } from "../ports/index.js";
import { isBinaryEnvelope } from "../contracts/binary.js";
import type { IndexEntry } from "./index/types.js";
import { buildDataBlocksAsync } from "./blocks/build.js";
import { readBuiltScopeBlocks } from "./blocks/page.js";
import type { DataBlockManifest, DataScopeBlock } from "./blocks/types.js";
import { previewEnvelopeValue } from "./preview.js";

/**
 * Sources whose `{records}` bodies are projected. Other sources either emit
 * legacy wrappers themselves (GitHub, Strava) or have no real-shape parity
 * evidence yet (Oura), so their stored bodies are served as stored.
 */
const PROJECTED_SOURCES: ReadonlySet<string> = new Set(["chatgpt", "claude"]);

/** Keys the server stamps into `data`; they are not part of the body. */
const SERVER_STAMP_KEYS: ReadonlySet<string> = new Set([
  "$writtenBy",
  "$lineage",
]);

/**
 * - `legacy`: anything that is not exactly `{records: [...]}`. Served as stored.
 * - `pdpp-projected`: `{records}` of plain rows under a scope with a legacy
 *   binding of a projected source. Served as the projected legacy body.
 * - `pdpp-unprojected`: `{records}` under any other scope (for example
 *   `chatgpt.messages`, which has no legacy form), or `{records}` holding a
 *   tagged `{stream, data}` row, which is not one stream's rows. Served as
 *   stored.
 */
export type StoredBodyForm = "legacy" | "pdpp-projected" | "pdpp-unprojected";

export function classifyStoredBody(
  scope: string,
  data: unknown,
): StoredBodyForm {
  if (!isRecordsBody(data)) return "legacy";
  return isProjectedScope(scope) && !data.records.some(isTaggedRecord)
    ? "pdpp-projected"
    : "pdpp-unprojected";
}

export type LegacyProjectionIssue =
  | {
      kind: "projection_failed";
      scope: string;
      collectedAt: string;
      error: ProjectionError;
    }
  | {
      kind: "projection_diagnostics";
      scope: string;
      collectedAt: string;
      diagnostics: ProjectionDiagnostic[];
    };

export interface LegacyProjectionOptions {
  /**
   * Called when a projection fails (the stored body is then served as
   * stored) or succeeds with dropped rows or a missing join stream.
   */
  onIssue?: (issue: LegacyProjectionIssue) => void;
}

const SERVED = Symbol.for("personal-server-ts.legacy-projection.served");
/** A served port's own projected view of one stored version, for supersede. */
const PROJECTED_VIEW = Symbol.for(
  "personal-server-ts.legacy-projection.projected-view",
);

interface Projected {
  /** Identifies the inputs; block cursors carry it so a page from one
   * projection never resumes into another. */
  view?: string;
  envelope: DataFileEnvelope;
  bytes: Uint8Array;
  built?: { manifest: DataBlockManifest; blocks: DataScopeBlock[] };
  /** Rows left out or join streams missing; absent for a complete view. */
  diagnostics?: ProjectionDiagnostic[];
}

const textEncoder = new TextEncoder();

/** How many stored versions' body forms one served port remembers. */
const FORM_CACHE_SIZE = 64;

/**
 * Wrap a raw storage port so reads of projected scopes return legacy bodies.
 * Wrapping an already wrapped port returns it unchanged.
 */
export function withLegacyProjection(
  raw: DataStoragePort,
  options: LegacyProjectionOptions = {},
): DataStoragePort {
  if ((raw as { [SERVED]?: true })[SERVED]) return raw;

  // One entry, keyed by the versions of every input. It saves re-projecting
  // on repeated reads of the same data; it is not a persistent cache.
  let memo: { key: string; value: Projected | null } | null = null;
  // The body form of each stored version read so far, so a version that is
  // not projected (most often a legacy body) is parsed to classify it once,
  // not on every read. Bounded; the oldest entry goes first.
  const forms = new Map<string, StoredBodyForm>();
  const rememberForm = (version: string, form: StoredBodyForm) => {
    forms.set(version, form);
    if (forms.size > FORM_CACHE_SIZE) {
      forms.delete(forms.keys().next().value!);
    }
  };

  /**
   * The projected view of a stored version, or null when it is served as
   * stored. `own` is the stored envelope when it had to be read to decide.
   */
  async function resolve(
    scope: string,
    collectedAt: string,
  ): Promise<{ view: Projected | null; own?: DataFileEnvelope }> {
    if (!isProjectedScope(scope)) return { view: null };
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const source = scope.slice(0, scope.indexOf("."));
    // The latest version joins the latest siblings, whatever order one run
    // wrote its streams in. A historical version joins, of the sibling
    // versions written before the next version of `scope`, the one nearest
    // in time: the one its own run wrote, before or after it.
    const supersededAt = nextVersionTime(raw, scope, collectedAt);
    const inputs = binding.pdppStreams.map((stream) => {
      const storedScope = `${source}.${stream}`;
      const entry =
        storedScope === scope
          ? raw.findEntry({ scope, at: collectedAt })
          : supersededAt === undefined
            ? raw.findEntry({ scope: storedScope })
            : nearestBefore(raw, storedScope, collectedAt, supersededAt);
      return {
        stream,
        storedScope,
        collectedAt: storedScope === scope ? collectedAt : entry?.collectedAt,
        // The index row id changes when a version is deleted and written
        // again under the same collectedAt, so it identifies the content.
        version: entry ? `${entry.id}@${entry.collectedAt}` : null,
      };
    });
    const ownVersion = inputs.find(
      (input) => input.storedScope === scope,
    )?.version;
    if (ownVersion) {
      const form = forms.get(ownVersion);
      if (form !== undefined && form !== "pdpp-projected") {
        return { view: null };
      }
    }
    const key = JSON.stringify([scope, inputs.map((input) => input.version)]);
    if (memo?.key === key) return { view: memo.value };

    const own = await raw.readEnvelope(scope, collectedAt);
    const form = classifyStoredBody(scope, own.data);
    if (ownVersion) rememberForm(ownVersion, form);
    let value: Projected | null = null;
    if (form === "pdpp-projected") {
      value = await project(scope, collectedAt, own, inputs);
      if (value) value.view = key;
    }
    memo = { key, value };
    return { view: value, own };
  }

  async function projected(
    scope: string,
    collectedAt: string,
  ): Promise<Projected | null> {
    return (await resolve(scope, collectedAt)).view;
  }

  async function project(
    scope: string,
    collectedAt: string,
    own: DataFileEnvelope,
    inputs: { stream: string; storedScope: string; collectedAt?: string }[],
  ): Promise<Projected | null> {
    const records: PdppRecord[] = [];
    const fetchedStreams: string[] = [];
    // The projection time is the newest input version, so the same stored
    // data always projects to the same bytes.
    let now = collectedAt;
    for (const input of inputs) {
      if (!input.collectedAt) continue;
      const envelope =
        input.storedScope === scope
          ? own
          : await raw.readEnvelope(input.storedScope, input.collectedAt);
      if (classifyStoredBody(input.storedScope, envelope.data) === "legacy") {
        continue;
      }
      const rows = (envelope.data as { records: Record<string, unknown>[] })
        .records;
      if (rows.some(isTaggedRecord)) continue;
      fetchedStreams.push(input.stream);
      if (input.collectedAt > now) now = input.collectedAt;
      for (const row of rows) {
        records.push({ stream: input.stream, data: row });
      }
    }

    const result = projectPdppRecordsToLegacyPayload(scope, records, {
      fetchedStreams,
      now,
      orderByPrimaryKey: true,
      allowMissingJoinStreams: true,
    });
    if (!result.ok) {
      options.onIssue?.({
        kind: "projection_failed",
        scope,
        collectedAt,
        error: result.error,
      });
      return null;
    }
    if (result.diagnostics?.length) {
      options.onIssue?.({
        kind: "projection_diagnostics",
        scope,
        collectedAt,
        diagnostics: result.diagnostics,
      });
    }
    // Server stamps signed the stored records, not this view, so they are
    // not carried over. `?view=stored` returns them with the stored body.
    const envelope = { ...own, data: result.payload } as DataFileEnvelope;
    return {
      envelope,
      bytes: textEncoder.encode(JSON.stringify(envelope)),
      ...(result.diagnostics?.length
        ? { diagnostics: result.diagnostics }
        : {}),
    };
  }

  async function builtBlocks(
    scope: string,
    view: Projected,
  ): Promise<{ manifest: DataBlockManifest; blocks: DataScopeBlock[] }> {
    view.built ??= await buildDataBlocksAsync({
      scope,
      collectedAt: view.envelope.collectedAt,
      ...(typeof (view.envelope as { schemaId?: unknown }).schemaId === "string"
        ? { schemaId: (view.envelope as { schemaId: string }).schemaId }
        : {}),
      content: view.envelope,
    });
    return view.built;
  }

  const overrides: Partial<DataStoragePort> & {
    [SERVED]: true;
    [PROJECTED_VIEW]: typeof projected;
  } = {
    [SERVED]: true,
    [PROJECTED_VIEW]: projected,
    async readEnvelope(scope, collectedAt) {
      const { view, own } = await resolve(scope, collectedAt);
      return view?.envelope ?? own ?? raw.readEnvelope(scope, collectedAt);
    },
    readStoredEnvelope(scope, collectedAt) {
      return raw.readEnvelope(scope, collectedAt);
    },
  };
  if (raw.readEnvelopeBytes) {
    const rawBytes = raw.readEnvelopeBytes.bind(raw);
    overrides.readEnvelopeBytes = async (scope, collectedAt) =>
      (await projected(scope, collectedAt))?.bytes ??
      rawBytes(scope, collectedAt);
  }
  if (raw.readEnvelopeStream) {
    const rawStream = raw.readEnvelopeStream.bind(raw);
    overrides.readEnvelopeStream = async (scope, collectedAt) => {
      const view = await projected(scope, collectedAt);
      if (!view) return rawStream(scope, collectedAt);
      const bytes = view.bytes;
      return new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
    };
  }
  if (raw.readEnvelopePreview) {
    const rawPreview = raw.readEnvelopePreview.bind(raw);
    overrides.readEnvelopePreview = async (scope, collectedAt, previewOpts) => {
      const view = await projected(scope, collectedAt);
      return view
        ? previewEnvelopeValue(view.envelope, previewOpts.maxBytes)
        : rawPreview(scope, collectedAt, previewOpts);
    };
  }
  if (raw.readScopeBlocks) {
    const rawBlocks = raw.readScopeBlocks.bind(raw);
    overrides.readScopeBlocks = async (scope, collectedAt, blockOpts) => {
      const view = await projected(scope, collectedAt);
      return view
        ? readBuiltScopeBlocks(await builtBlocks(scope, view), {
            ...blockOpts,
            cursorView: view.view,
          })
        : rawBlocks(scope, collectedAt, blockOpts);
    };
  }
  if (raw.readBlockManifest) {
    const rawManifest = raw.readBlockManifest.bind(raw);
    overrides.readBlockManifest = async (scope, collectedAt) => {
      const view = await projected(scope, collectedAt);
      return view
        ? (await builtBlocks(scope, view)).manifest
        : rawManifest(scope, collectedAt);
    };
  }
  // A stored sidecar answers "yes" for either form (a projected view can
  // always be split into blocks), so the stored body is only read when the
  // raw port has no sidecar yet.
  if (raw.hasScopeBlocks) {
    const rawHas = raw.hasScopeBlocks.bind(raw);
    overrides.hasScopeBlocks = async (scope, collectedAt) =>
      (await rawHas(scope, collectedAt)) ||
      (await projected(scope, collectedAt)) !== null;
  }
  if (raw.canReadScopeBlocks) {
    const rawCan = raw.canReadScopeBlocks.bind(raw);
    overrides.canReadScopeBlocks = async (scope, collectedAt) =>
      (await rawCan(scope, collectedAt)) ||
      (await projected(scope, collectedAt)) !== null;
  }

  return new Proxy(raw, {
    get(target, property) {
      if (Object.prototype.hasOwnProperty.call(overrides, property)) {
        return overrides[property as keyof typeof overrides];
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
    has(target, property) {
      return (
        Object.prototype.hasOwnProperty.call(overrides, property) ||
        Reflect.has(target, property)
      );
    },
  });
}

/**
 * The projected legacy scopes whose served body is built from `scope`'s
 * stored stream, other than `scope` itself: `chatgpt.messages` →
 * `["chatgpt.conversations"]`. Anything that caches a read of a projected
 * scope must treat a change to these streams as a change to it.
 */
export function legacyScopesProjectedFrom(scope: string): string[] {
  const dot = scope.indexOf(".");
  if (dot <= 0) return [];
  const source = scope.slice(0, dot);
  const stream = scope.slice(dot + 1);
  return [...LEGACY_SCOPE_BINDINGS.values()]
    .filter(
      (binding) =>
        binding.scope !== scope &&
        binding.scope.startsWith(`${source}.`) &&
        isProjectedScope(binding.scope) &&
        binding.pdppStreams.includes(stream),
    )
    .map((binding) => binding.scope);
}

function isProjectedScope(scope: string): boolean {
  const dot = scope.indexOf(".");
  return (
    dot > 0 &&
    PROJECTED_SOURCES.has(scope.slice(0, dot)) &&
    LEGACY_SCOPE_BINDINGS.has(scope)
  );
}

const VERSION_PAGE_SIZE = 100;

/** Versions of `scope`, newest first, until `stop` returns true. */
function walkVersions(
  raw: DataStoragePort,
  scope: string,
  stop: (entry: IndexEntry) => boolean,
): IndexEntry | undefined {
  for (let offset = 0; ; offset += VERSION_PAGE_SIZE) {
    const page = raw.listVersions(scope, { limit: VERSION_PAGE_SIZE, offset });
    const found = page.find(stop);
    if (found || page.length < VERSION_PAGE_SIZE) return found;
  }
}

/**
 * When the version of `scope` after the one at `collectedAt` was collected,
 * or undefined when that version is the latest (or not indexed).
 */
function nextVersionTime(
  raw: DataStoragePort,
  scope: string,
  collectedAt: string,
): number | undefined {
  const at = Date.parse(collectedAt);
  const latest = raw.findEntry({ scope });
  if (!latest || !(Date.parse(latest.collectedAt) > at)) return undefined;
  let next = Date.parse(latest.collectedAt);
  walkVersions(raw, scope, (entry) => {
    const time = Date.parse(entry.collectedAt);
    if (time > at) next = time;
    return !(time > at);
  });
  return next;
}

/**
 * The version of `scope` collected nearest to `collectedAt`, among those
 * collected before `bound` (epoch ms).
 */
function nearestBefore(
  raw: DataStoragePort,
  scope: string,
  collectedAt: string,
  bound: number,
): IndexEntry | undefined {
  const at = Date.parse(collectedAt);
  // Newest first: remember the last version after `at`, stop at the first
  // one at or before it, and take whichever of the two is nearer.
  let after: IndexEntry | undefined;
  const notAfter = walkVersions(raw, scope, (entry) => {
    const time = Date.parse(entry.collectedAt);
    if (time > at) {
      if (time < bound) after = entry;
      return false;
    }
    return true;
  });
  if (!after || !notAfter) return after ?? notAfter;
  return Date.parse(after.collectedAt) - at <
    at - Date.parse(notAfter.collectedAt)
    ? after
    : notAfter;
}

/** A `{stream, data}` row: a record tagged with its stream, not a stream row. */
function isTaggedRecord(row: unknown): boolean {
  if (row === null || typeof row !== "object" || Array.isArray(row)) {
    return false;
  }
  const { stream, data } = row as { stream?: unknown; data?: unknown };
  return (
    typeof stream === "string" &&
    data !== null &&
    typeof data === "object" &&
    !Array.isArray(data)
  );
}

function isRecordsBody(
  data: unknown,
): data is { records: Record<string, unknown>[] } {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return false;
  }
  const keys = Object.keys(data).filter((key) => !SERVER_STAMP_KEYS.has(key));
  return (
    keys.length === 1 &&
    keys[0] === "records" &&
    Array.isArray((data as { records: unknown }).records)
  );
}

export interface SupersedeResult {
  /** `collectedAt` of every deleted version. */
  superseded: string[];
  /** Why nothing was deleted, when superseding was refused. */
  refused?: string;
}

/**
 * After a `{records}` version of a projected scope is committed, delete the
 * scope's older owner-written legacy versions: the new version serves the
 * same legacy view, so they are a second copy.
 *
 * It deletes nothing unless `storage` is a served port (see
 * `withLegacyProjection`) whose projection of the new version is complete:
 * no join stream missing and no row left out. It also deletes nothing when
 * the projection holds fewer items than the newest legacy version, or lacks
 * any item id that version holds, so an empty or time-windowed run cannot
 * replace a full history. For Claude scopes it also deletes nothing when an
 * item holds fewer nested messages or documents than the legacy item. A legacy version must carry the scope's legacy
 * collection key (`conversations` for `chatgpt.conversations`); PDPP
 * versions, other bodies, binary uploads, versions a builder wrote
 * (`$writtenBy`) and newer versions are kept.
 *
 * Local only: the deletes are not sent to the gateway. Copies that sync
 * already uploaded, and copies other replicas already downloaded, remain.
 */
export async function supersedeLegacyVersions(
  storage: DataStoragePort,
  scope: string,
  committedAt: string,
): Promise<SupersedeResult> {
  const refuse = (refused: string): SupersedeResult => ({
    superseded: [],
    refused,
  });
  const readStored = (storage.readStoredEnvelope ?? storage.readEnvelope).bind(
    storage,
  );
  const committed = await readStored(scope, committedAt);
  if (classifyStoredBody(scope, committed.data) !== "pdpp-projected") {
    return refuse("the new version is not PDPP records of a projected scope");
  }
  const projectedView = (
    storage as {
      [PROJECTED_VIEW]?: (s: string, c: string) => Promise<Projected | null>;
    }
  )[PROJECTED_VIEW];
  const view = projectedView ? await projectedView(scope, committedAt) : null;
  if (!view) return refuse("the new version cannot be projected");
  if (view.diagnostics?.length) {
    const kinds = [...new Set(view.diagnostics.map((d) => d.kind))];
    return refuse(`the projection is partial (${kinds.join(", ")})`);
  }
  const collection = legacyCollectionKey(scope);
  const projectedItems = (view.envelope.data as Record<string, unknown>)[
    collection
  ] as unknown[];
  const projectedCount = projectedItems.length;

  const committedMs = Date.parse(committedAt);
  const older: string[] = [];
  const pageSize = 100;
  for (let offset = 0; ; offset += pageSize) {
    const page = storage.listVersions(scope, { limit: pageSize, offset });
    for (const entry of page) {
      // Compare instants, not strings: "…00.500Z" sorts before "…00Z".
      if (Date.parse(entry.collectedAt) < committedMs) {
        older.push(entry.collectedAt);
      }
    }
    if (page.length < pageSize) break;
  }

  const legacy: {
    collectedAt: string;
    count: number;
    ids: string[];
    items: unknown[];
  }[] = [];
  for (const collectedAt of older) {
    const envelope = await readStored(scope, collectedAt);
    // A binary upload under the scope is not a legacy body.
    if (isBinaryEnvelope(envelope)) continue;
    const items = legacyCollection(scope, envelope.data);
    if (items === null) continue;
    legacy.push({
      collectedAt,
      count: items.length,
      ids: items.map(itemId).filter((id) => id !== undefined),
      items,
    });
  }
  const newest = legacy.reduce<(typeof legacy)[number] | undefined>(
    (best, version) =>
      !best || Date.parse(version.collectedAt) > Date.parse(best.collectedAt)
        ? version
        : best,
    undefined,
  );
  if (newest && projectedCount < newest.count) {
    return refuse(
      `the projection has ${projectedCount} ${collection}; the newest legacy version has ${newest.count}`,
    );
  }
  if (newest) {
    const projectedIds = new Set(
      projectedItems.map(itemId).filter((id) => id !== undefined),
    );
    const missing = newest.ids.filter((id) => !projectedIds.has(id));
    if (missing.length > 0) {
      return refuse(
        `the projection lacks ${missing.length} of the ${collection} in the newest legacy version`,
      );
    }
    const shortfall = nestedShortfall(scope, newest.items, projectedItems);
    if (shortfall) return refuse(shortfall);
  }

  const superseded: string[] = [];
  for (const { collectedAt } of legacy) {
    if (await storage.deleteVersion(scope, collectedAt)) {
      superseded.push(collectedAt);
    }
  }
  return { superseded };
}

/**
 * Nested rows a Claude item holds, per scope. The PDPP rows carry no source
 * count the binding can check them against (a conversation's `message_count`
 * is optional; a project has none), so the projection cannot vouch for them.
 * Compare them with the legacy item instead. ChatGPT is not listed: its
 * binding checks the source count itself, and a shorter current branch there
 * is a reviewed difference.
 *
 * A project also keeps its source `raw_docs`. A raw doc with a uuid must be
 * a projected doc; one without a uuid survives only in `raw_docs`, so it
 * counts as a projected doc too.
 */
const NESTED_ITEMS: Record<
  string,
  (item: unknown) => { held: number; selfShort: boolean }
> = {
  "claude.conversations": (item) => ({
    held: arrayLength(field(item, "messages")),
    selfShort: false,
  }),
  "claude.projects": (item) => {
    const detail = field(item, "detail");
    const rawDocs = field(detail, "raw_docs");
    const raw = Array.isArray(rawDocs) ? rawDocs : [];
    const withId = raw.filter((doc) => typeof field(doc, "uuid") === "string");
    const docs = arrayLength(field(detail, "docs"));
    return {
      held: docs + raw.length - withId.length,
      selfShort: docs < withId.length,
    };
  },
};

function field(value: unknown, key: string): unknown {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

function arrayLength(value: unknown): number {
  return Array.isArray(value) ? value.length : 0;
}

/** Why the projection holds fewer nested rows than it should, if so. */
function nestedShortfall(
  scope: string,
  legacyItems: unknown[],
  projectedItems: unknown[],
): string | undefined {
  const nested = NESTED_ITEMS[scope];
  if (!nested) return undefined;
  const projectedById = new Map(
    projectedItems.map((item) => [itemId(item), nested(item).held]),
  );
  const short = legacyItems.filter(
    (item) => (projectedById.get(itemId(item)) ?? 0) < nested(item).held,
  );
  // A project whose own source lists docs the projection lacks.
  const incomplete = projectedItems.filter((item) => nested(item).selfShort);
  const count = short.length + incomplete.length;
  return count > 0
    ? `the projection holds fewer nested rows than the source or the newest legacy version for ${count} of the ${legacyCollectionKey(scope)}`
    : undefined;
}

/** `chatgpt.conversations` → `conversations`: the array a legacy body holds. */
function legacyCollectionKey(scope: string): string {
  return scope.slice(scope.indexOf(".") + 1);
}

/**
 * The items of an owner-written legacy body of `scope`, or null when the
 * body is not one: it must hold the scope's collection array, must not be
 * PDPP records, and must not carry a builder's `$writtenBy` stamp.
 */
function legacyCollection(scope: string, data: unknown): unknown[] | null {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    return null;
  }
  if (isRecordsBody(data) || "$writtenBy" in data) return null;
  const items = (data as Record<string, unknown>)[legacyCollectionKey(scope)];
  return Array.isArray(items) ? items : null;
}

/** A legacy item's `id` (or `uuid`), when it has a string one. */
function itemId(item: unknown): string | undefined {
  if (item === null || typeof item !== "object") return undefined;
  const { id, uuid } = item as { id?: unknown; uuid?: unknown };
  return typeof id === "string"
    ? id
    : typeof uuid === "string"
      ? uuid
      : undefined;
}
