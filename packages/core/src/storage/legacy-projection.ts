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
 * - `pdpp-projected`: `{records}` under a scope with a legacy binding of a
 *   projected source. Served as the projected legacy body.
 * - `pdpp-unprojected`: `{records}` under any other scope (for example
 *   `chatgpt.messages`, which has no legacy form). Served as stored.
 */
export type StoredBodyForm = "legacy" | "pdpp-projected" | "pdpp-unprojected";

export function classifyStoredBody(
  scope: string,
  data: unknown,
): StoredBodyForm {
  if (!isRecordsBody(data)) return "legacy";
  return isProjectedScope(scope) ? "pdpp-projected" : "pdpp-unprojected";
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

interface Projected {
  /** Identifies the inputs; block cursors carry it so a page from one
   * projection never resumes into another. */
  view?: string;
  envelope: DataFileEnvelope;
  bytes: Uint8Array;
  built?: { manifest: DataBlockManifest; blocks: DataScopeBlock[] };
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

  async function projected(
    scope: string,
    collectedAt: string,
  ): Promise<Projected | null> {
    if (!isProjectedScope(scope)) return null;
    const binding = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const source = scope.slice(0, scope.indexOf("."));
    const inputs = binding.pdppStreams.map((stream) => {
      const storedScope = `${source}.${stream}`;
      const entry =
        storedScope === scope
          ? raw.findEntry({ scope, at: collectedAt })
          : raw.findEntry({ scope: storedScope });
      return {
        stream,
        storedScope,
        collectedAt: storedScope === scope ? collectedAt : entry?.collectedAt,
        // The index row id changes when a version is deleted and written
        // again under the same collectedAt, so it identifies the content.
        version: entry ? `${entry.id}@${entry.collectedAt}` : null,
      };
    });
    const key = JSON.stringify([scope, inputs.map((input) => input.version)]);
    if (memo?.key === key) return memo.value;

    const own = await raw.readEnvelope(scope, collectedAt);
    let value: Projected | null = null;
    if (classifyStoredBody(scope, own.data) === "pdpp-projected") {
      value = await project(scope, collectedAt, own, inputs);
      if (value) value.view = key;
    }
    memo = { key, value };
    return value;
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
      const rows = isRecordsBody(envelope.data) ? envelope.data.records : null;
      if (!rows) continue;
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

  const overrides: Partial<DataStoragePort> & { [SERVED]: true } = {
    [SERVED]: true,
    async readEnvelope(scope, collectedAt) {
      return (
        (await projected(scope, collectedAt))?.envelope ??
        raw.readEnvelope(scope, collectedAt)
      );
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
