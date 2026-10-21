/**
 * Serve legacy scope bodies from stored PDPP records.
 *
 * PDPP connectors store one envelope per stream, body `{records: [row, …]}`,
 * under `<source>.<stream>`. Apps that predate PDPP read legacy bodies such
 * as `chatgpt.conversations` = `{conversations, total}`. `withLegacyProjection`
 * wraps the raw storage port: when the latest stored body of a projected
 * scope is `{records}`, reads return the legacy body projected from that
 * stream and its sibling streams. Legacy-shaped bodies are served as stored;
 * raw bodies that cannot be projected fail the served read. Writes, listings
 * and the sync-facing methods pass through.
 *
 * Give the wrapped ("served") port to every reader of data: the HTTP data
 * route, MCP, derivatives and the job worker. Give the raw port to sync
 * upload/download, so canonical bytes (and their hashes) never change.
 */

import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
  type LegacyScopeBinding,
  type PdppRecord,
  type ProjectionDiagnostic,
  type ProjectionError,
} from "../legacy-projection/index.js";
import type { DataStoragePort } from "../ports/index.js";
import { ProtocolError } from "../errors/catalog.js";
import { isBinaryEnvelope } from "../contracts/binary.js";
import type { IndexEntry } from "./index/types.js";
import { buildDataBlocksAsync } from "./blocks/build.js";
import { blockRepresentationMetadata } from "./blocks/representation.js";
import { readBuiltScopeBlocks } from "./blocks/page.js";
import type { DataBlockManifest, DataScopeBlock } from "./blocks/types.js";
import { previewEnvelopeValue } from "./preview.js";
import {
  GRANTEE_VIEW,
  isGuarded,
  withDisclosurePolicy,
} from "./disclosure-policy.js";

/** Keys the server stamps into `data`; they are not part of the body. */
const SERVER_STAMP_KEYS: ReadonlySet<string> = new Set([
  "$writtenBy",
  "$lineage",
]);

/**
 * - `legacy`: anything that is not exactly `{records: [...]}`. Served as stored.
 * - `pdpp-projected`: `{records}` of plain rows under a scope with a legacy
 *   binding. Served as the projected legacy body.
 * - `pdpp-unprojected`: `{records}` under any other scope (for example
 *   `chatgpt.messages`, which has no legacy form), or `{records}` holding a
 *   tagged `{stream, data}` row, which is not one stream's rows. A bound
 *   scope rejects this form; an unbound scope is served as stored.
 */
export type StoredBodyForm = "legacy" | "pdpp-projected" | "pdpp-unprojected";

interface CachedForm {
  form: StoredBodyForm;
  selected?: { binding: LegacyScopeBinding; profileKey?: string } | null;
}

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
   * Called when a projection fails or succeeds with dropped rows or a missing
   * join stream.
   */
  onIssue?: (issue: LegacyProjectionIssue) => void;
}

const SERVED = Symbol.for("personal-server-ts.legacy-projection.served");
/** A served port's own projected view of one stored version, for supersede. */
const PROJECTED_VIEW = Symbol.for(
  "personal-server-ts.legacy-projection.projected-view",
);

/** How many stored versions' body forms one served port remembers. */
const FORM_CACHE_SIZE = 64;

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
  // Classification is safe to reuse only for the same immutable stored
  // version. The requested version is classified before the projection cache.
  const forms = new Map<string, CachedForm>();
  const rememberForm = (key: string, value: CachedForm) => {
    forms.set(key, value);
    if (forms.size > FORM_CACHE_SIZE) {
      forms.delete(forms.keys().next().value!);
    }
  };
  function failProjection(
    scope: string,
    collectedAt: string,
    error: ProjectionError,
  ): never {
    options.onIssue?.({ kind: "projection_failed", scope, collectedAt, error });
    throw new ProtocolError(
      409,
      "LEGACY_PROJECTION_UNAVAILABLE",
      `Cannot serve the legacy view for scope "${scope}"`,
      {
        scope,
        collectedAt,
        reason: "reason" in error ? error.reason : error.kind,
        projectionError: error.kind,
      },
    );
  }
  /**
   * The projected view of a stored version, or null when it is served as
   * stored. `own` is the stored envelope when it had to be read to decide.
   */
  async function resolve(
    scope: string,
    collectedAt: string,
  ): Promise<{ view: Projected | null; own?: DataFileEnvelope }> {
    if (!isProjectedScope(scope)) return { view: null };
    const requestedEntry = raw.findEntry({ scope, at: collectedAt });
    const ownVersion = requestedEntry
      ? `${requestedEntry.id}@${requestedEntry.collectedAt}`
      : `unindexed@${collectedAt}`;
    const formKey = JSON.stringify([scope, ownVersion]);
    let cached = forms.get(formKey);
    let own: DataFileEnvelope | undefined;
    if (!cached) {
      own = await raw.readEnvelope(scope, collectedAt);
      const form = classifyStoredBody(scope, own.data);
      cached = {
        form,
        ...(form === "pdpp-projected"
          ? {
              selected: selectProjectionBinding(
                scope,
                (own.data as { records: Record<string, unknown>[] }).records,
              ),
            }
          : {}),
      };
      rememberForm(formKey, cached);
    }
    if (cached.form === "legacy") return { view: null, own };
    if (cached.form === "pdpp-unprojected") {
      failProjection(scope, collectedAt, {
        kind: "incomplete_scope",
        scope,
        reason: "Stored records are not rows of one stream",
      });
    }
    if (!cached.selected) {
      failProjection(scope, collectedAt, {
        kind: "incomplete_scope",
        scope,
        reason:
          "Stored records do not identify one compatible connector profile",
      });
    }

    const { binding, profileKey } = cached.selected;
    const source = scope.slice(0, scope.indexOf("."));
    // The latest version joins the latest siblings, whatever order one run
    // wrote its streams in. A historical version joins, of the sibling
    // versions written before the next version of `scope`, the one nearest
    // in time: the one its own run wrote, before or after it.
    const supersededAt = nextVersionTime(raw, scope, collectedAt);
    const inputs = binding.pdppStreams.map((stream) => {
      const canonicalScope = `${source}.${stream}`;
      // For a single-stream alias, prefer the exact requested version when
      // it exists. This keeps alias writes, body classification and cursors
      // tied to the version the caller asked to read.
      let storedScope =
        binding.pdppStreams.length === 1 && requestedEntry
          ? scope
          : canonicalScope;
      let entry =
        storedScope === scope
          ? requestedEntry
          : supersededAt === undefined
            ? raw.findEntry({ scope: storedScope })
            : nearestBefore(raw, storedScope, collectedAt, supersededAt);
      // Some PDPP streams have a legacy scope alias (for example,
      // youtube.history -> youtube.watch_history). Lite stores the stream
      // envelope under that alias, so use it as the single stream input when
      // no canonical stream-scope entry exists.
      if (!entry && binding.pdppStreams.length === 1 && storedScope !== scope) {
        storedScope = scope;
        entry = requestedEntry;
      }
      return {
        stream,
        storedScope,
        collectedAt: storedScope === scope ? collectedAt : entry?.collectedAt,
        // The index row id changes when a version is deleted and written
        // again under the same collectedAt, so it identifies the content.
        version: entry ? `${entry.id}@${entry.collectedAt}` : null,
      };
    });
    const key = JSON.stringify([
      scope,
      ownVersion,
      profileKey,
      inputs.map(({ storedScope, version }) => [storedScope, version]),
    ]);
    if (memo?.key === key) return { view: memo.value, own };

    own ??= await raw.readEnvelope(scope, collectedAt);

    const value = await project(
      scope,
      collectedAt,
      own,
      inputs,
      binding,
      profileKey,
    );
    if (value) value.view = key;
    memo = { key, value };
    return { view: value, own };
  }

  async function projected(
    scope: string,
    collectedAt: string,
  ): Promise<Projected | null> {
    return (await resolve(scope, collectedAt)).view;
  }

  async function projectedForSupersede(
    scope: string,
    collectedAt: string,
  ): Promise<Projected | null> {
    try {
      return await projected(scope, collectedAt);
    } catch (error) {
      if (
        error instanceof ProtocolError &&
        error.errorCode === "LEGACY_PROJECTION_UNAVAILABLE"
      ) {
        return null;
      }
      throw error;
    }
  }

  async function project(
    scope: string,
    collectedAt: string,
    own: DataFileEnvelope,
    inputs: { stream: string; storedScope: string; collectedAt?: string }[],
    binding: LegacyScopeBinding,
    profileKey?: string,
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
      if (Date.parse(input.collectedAt) > Date.parse(now)) {
        now = input.collectedAt;
      }
      for (const row of rows) {
        records.push({ stream: input.stream, data: row });
      }
    }

    if (
      !recordsMatchBindingSource(
        records,
        binding,
        alternateLegacyBindingsForScope(scope).size > 0,
      )
    ) {
      failProjection(scope, collectedAt, {
        kind: "incomplete_scope",
        scope,
        reason: "Joined streams have conflicting connector identities",
      });
    }

    // Connector identity is storage metadata, not part of an app's legacy row.
    const projectionRecords = records.map((record) => {
      const data = { ...record.data };
      delete data.$pdpp;
      return { ...record, data };
    });
    const result = projectPdppRecordsToLegacyPayload(scope, projectionRecords, {
      fetchedStreams,
      now,
      ...(profileKey ? { profileKey } : {}),
      orderByPrimaryKey: binding.rowOrder !== "arrival",
      allowMissingJoinStreams: true,
    });
    if (!result.ok) {
      failProjection(scope, collectedAt, result.error);
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
    [PROJECTED_VIEW]: projectedForSupersede,
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
    overrides.readBlockManifest = async (scope, collectedAt, options) => {
      const view = await projected(scope, collectedAt);
      if (!view) return rawManifest(scope, collectedAt, options);
      const manifest = (await builtBlocks(scope, view)).manifest;
      return {
        ...manifest,
        ...blockRepresentationMetadata(
          manifest,
          isGuarded(raw) ? "grantee" : "stored",
          view.view,
        ),
      };
    };
  }
  // Inventory inherits raw metadata readiness. Projection belongs to reads.
  if (raw.canReadScopeBlocks) {
    const rawCan = raw.canReadScopeBlocks.bind(raw);
    overrides.canReadScopeBlocks = async (scope, collectedAt) =>
      (await rawCan(scope, collectedAt)) ||
      (await projected(scope, collectedAt)) !== null;
  }

  const served: DataStoragePort = new Proxy(raw, {
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
  // A non-owner's view projects from the guarded raw port, so the requested
  // version and every joined sibling version are authorized on their bytes.
  // Built once per served port, so it keeps its own projection caches.
  let granteeView: DataStoragePort | undefined;
  (overrides as Record<symbol, unknown>)[GRANTEE_VIEW] = isGuarded(raw)
    ? () => served
    : () =>
        (granteeView ??= withLegacyProjection(
          withDisclosurePolicy(raw),
          options,
        ));
  return served;
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
  return LEGACY_SCOPE_BINDINGS.has(scope);
}

function selectProjectionBinding(
  scope: string,
  rows: Record<string, unknown>[],
): { binding: LegacyScopeBinding; profileKey?: string } | null {
  const original = LEGACY_SCOPE_BINDINGS.get(scope)!;
  const alternates = alternateLegacyBindingsForScope(scope);
  const identities = rows.map(recordSourceId);
  if (identities.includes(null)) return null;
  if (alternates.size > 0 && identities.includes(undefined)) return null;
  const sources = new Set(identities.filter((id): id is string => !!id));
  if (sources.size > 1) return null;
  if (sources.size === 0) {
    return alternates.size === 0 ? { binding: original } : null;
  }

  const sourceId = [...sources][0];
  const connectorKey = sourceId.slice(sourceId.lastIndexOf("/") + 1);
  const alternate = alternates.get(connectorKey);
  if (alternate && sourceIdForBinding(alternate) === sourceId) {
    return { binding: alternate, profileKey: connectorKey };
  }
  return sourceIdForBinding(original) === sourceId
    ? { binding: original }
    : null;
}

function recordSourceId(data: unknown): string | null | undefined {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    return null;
  }
  if (!("$pdpp" in data)) return undefined;
  const metadata = data.$pdpp;
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    return null;
  }
  const sourceId = (metadata as { sourceId?: unknown }).sourceId;
  return typeof sourceId === "string" && sourceId ? sourceId : null;
}

function sourceIdForBinding(binding: LegacyScopeBinding): string {
  return binding.pdppSource.replace("/connectors/", "/sources/");
}

function recordsMatchBindingSource(
  records: PdppRecord[],
  binding: LegacyScopeBinding,
  requireIdentity: boolean,
): boolean {
  const expected = sourceIdForBinding(binding);
  return records.every(({ data }) => {
    const actual = recordSourceId(data);
    return actual === expected || (!requireIdentity && actual === undefined);
  });
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
 * same legacy view, so they are a second copy. This explicit supersede path
 * remains available only for the original ChatGPT and Claude sources. Other
 * bound sources retain legacy versions and replace them only in the read view.
 *
 * It deletes nothing unless `storage` is a served port (see
 * `withLegacyProjection`) whose projection of the new version is complete:
 * no join stream missing and no row left out. It also deletes nothing when
 * the projection holds fewer items than a legacy version, or lacks
 * any item identity that version holds, so an empty or time-windowed run cannot
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
  if (scope.startsWith("youtube.")) {
    return refuse(
      "YouTube legacy versions are retained for read-time projection",
    );
  }
  if (
    isProjectedScope(scope) &&
    !scope.startsWith("chatgpt.") &&
    !scope.startsWith("claude.")
  ) {
    return refuse("Legacy versions are retained for read-time projection");
  }
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
  if (!collection) {
    return refuse(`the legacy collection for ${scope} is unsupported`);
  }
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
  const projectedCounts = new Map<string, number>();
  for (const item of projectedItems) {
    const identity = itemIdentity(scope, item);
    if (!identity) continue;
    projectedCounts.set(identity, (projectedCounts.get(identity) ?? 0) + 1);
  }
  for (const version of legacy) {
    const versionLabel =
      version === newest ? "the newest legacy version" : "a legacy version";
    if (projectedCount < version.count) {
      return refuse(
        `the projection has ${projectedCount} ${collection}; ${versionLabel} has ${version.count}`,
      );
    }
    const requiredCounts = new Map<string, number>();
    for (const item of version.items) {
      const identity = itemIdentity(scope, item);
      if (!identity) {
        return refuse(`a legacy ${collection} item has no provable identity`);
      }
      requiredCounts.set(identity, (requiredCounts.get(identity) ?? 0) + 1);
    }
    const missing = [...requiredCounts].reduce(
      (count, [identity, required]) =>
        count + Math.max(0, required - (projectedCounts.get(identity) ?? 0)),
      0,
    );
    if (missing > 0) {
      return refuse(
        `the projection lacks ${missing} of the ${collection} in ${versionLabel}`,
      );
    }
    const shortfall = nestedShortfall(scope, version.items, projectedItems);
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
  "youtube.playlistItems": (item) => ({
    held: arrayLength(field(item, "items")),
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
  const heldByIdentity = (items: unknown[]) => {
    const held = new Map<string, number[]>();
    for (const item of items) {
      const identity = itemIdentity(scope, item);
      if (!identity) continue;
      const values = held.get(identity) ?? [];
      values.push(nested(item).held);
      held.set(identity, values);
    }
    for (const values of held.values())
      values.sort((left, right) => right - left);
    return held;
  };
  const legacyHeld = heldByIdentity(legacyItems);
  const projectedHeld = heldByIdentity(projectedItems);
  let short = 0;
  for (const [identity, required] of legacyHeld) {
    const available = projectedHeld.get(identity) ?? [];
    short += required.filter(
      (count, index) => (available[index] ?? 0) < count,
    ).length;
  }
  // A project whose own source lists docs the projection lacks.
  const incomplete = projectedItems.filter((item) => nested(item).selfShort);
  const count = short + incomplete.length;
  return count > 0
    ? `the projection holds fewer nested rows than the source or a legacy version for ${count} of the ${legacyCollectionKey(scope)}`
    : undefined;
}

const LEGACY_COLLECTION_KEYS: Readonly<Record<string, string | null>> = {
  "youtube.profile": null,
  "youtube.history": "history",
  "youtube.subscriptions": "subscriptions",
  "youtube.playlists": "playlists",
  "youtube.playlistItems": "playlists",
  "youtube.likes": "likedVideos",
  "youtube.watchLater": "watchLater",
};

/** The array a legacy body holds, or null for singleton/unsupported shapes. */
function legacyCollectionKey(scope: string): string | null {
  return scope in LEGACY_COLLECTION_KEYS
    ? LEGACY_COLLECTION_KEYS[scope]!
    : scope.slice(scope.indexOf(".") + 1);
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
  const collection = legacyCollectionKey(scope);
  if (!collection) return null;
  const items = (data as Record<string, unknown>)[collection];
  return Array.isArray(items) ? items : null;
}

/** Stable identity fields for scopes whose legacy keys differ from `id`. */
const IDENTITY_FIELDS: Readonly<Record<string, readonly string[]>> = {
  "youtube.history": ["videoId", "videoUrl"],
  "youtube.subscriptions": ["channelId", "channelUrl"],
  "youtube.playlists": ["playlistId", "url"],
  "youtube.playlistItems": ["playlistId"],
  "youtube.likes": ["videoId", "videoUrl"],
  "youtube.watchLater": ["videoId", "videoUrl"],
};

/** Stable identity used to prove that a projection covers a legacy item. */
function itemIdentity(scope: string, item: unknown): string | undefined {
  for (const key of IDENTITY_FIELDS[scope] ?? []) {
    const value = field(item, key);
    if (typeof value === "string" && value.length > 0) {
      return `${key}:${value}`;
    }
  }
  const id = itemId(item);
  return id === undefined ? undefined : `id:${id}`;
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
