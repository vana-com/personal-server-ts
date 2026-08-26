/**
 * Derivative data: lineage on the write path.
 *
 * A derivative is an ordinary write whose body names the data points it was
 * computed from. The caller's `lineage` field (top level of a JSON body, or
 * inside the `X-Vana-Metadata` object of a binary write) is a list of data
 * point ids, `keccak256(abi.encode(owner, scope))`. The Personal Server
 * validates it against the owner's own data points and mirrors it into the
 * envelope `data` under the reserved `$lineage` key, the same in-`data`
 * marker idiom as `$writtenBy` and `$binary`, so lineage rides the unchanged
 * encrypt / upload / register path and `metadataHash` commits to it.
 *
 * The caller's `lineage` field is left in the record untouched: for session
 * writes it is inside the bytes the builder signed, so the lineage claim is
 * builder-signed and `$lineage` is the server-validated mirror of it.
 *
 * See docs/derivative-data-api.md for the wire contract.
 */

import {
  LineageInvalidError,
  LineageScopeUnderSourcePrefixError,
  LineageSourceLookupFailedError,
  LineageSourceUnknownError,
  ServerNotConfiguredError,
} from "../errors/catalog.js";
import type { DataStoragePort } from "../ports/index.js";
import { computeDataPointId } from "../sync/data-point-id.js";

/** Reserved key inside the envelope `data` record for validated lineage. */
export const LINEAGE_KEY = "$lineage" as const;

/** The caller-facing field name (JSON body top level / binary metadata). */
export const LINEAGE_FIELD = "lineage" as const;

/** Upper bound on sources per record; keeps validation and hashing bounded. */
export const MAX_LINEAGE_SOURCES = 256;

/**
 * How many local scopes the source resolver hashes before it stops treating
 * the local index as authoritative and defers the remainder to the gateway.
 */
export const LOCAL_SCOPE_SCAN_LIMIT = 5000;

const BYTES32_HEX = /^0x[0-9a-fA-F]{64}$/;

export interface StoredLineage {
  /** Validated, lowercased source data point ids in the order given. */
  sources: `0x${string}`[];
  /** ISO timestamp the Personal Server validated and stamped the lineage. */
  writtenAt: string;
}

/** A source as the resolver saw it (local index or gateway). */
export interface ResolvedLineageSource {
  dataPointId: `0x${string}`;
  scope: string;
  /** Null while the source is only known locally (not registered yet). */
  version: string | null;
  deletedAt: string | null;
}

/** The subset of a gateway data-point record the resolver needs. */
export interface LineageDataPointRecord {
  dataPointId: string;
  ownerAddress: string;
  scope: string;
  version: string;
  deletedAt: string | null;
}

/**
 * Gateway lookup for a source that is not in the local index. Must include
 * deleted (tombstoned) data points: a deleted source is still a valid
 * lineage target, it is only reported as deleted when the lineage is walked.
 */
export interface LineageSourceLookup {
  getDataPoint(dataPointId: string): Promise<LineageDataPointRecord | null>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function hasReservedLineageKey(data: Record<string, unknown>): boolean {
  return Object.prototype.hasOwnProperty.call(data, LINEAGE_KEY);
}

/** Stamp validated lineage into an envelope `data` record. */
export function stampLineage(
  data: Record<string, unknown>,
  lineage: StoredLineage,
): Record<string, unknown> {
  return { ...data, [LINEAGE_KEY]: lineage };
}

/**
 * The stored `$lineage` of a record, or null for a root record. Tolerates
 * hand-crafted envelopes: anything that is not the exact stamped shape is
 * treated as no lineage rather than thrown on.
 */
export function readStoredLineage(
  data: Record<string, unknown> | undefined,
): StoredLineage | null {
  const value = data?.[LINEAGE_KEY];
  if (!isRecord(value)) return null;
  const sources = value.sources;
  if (
    !Array.isArray(sources) ||
    !sources.every((id) => typeof id === "string" && BYTES32_HEX.test(id)) ||
    typeof value.writtenAt !== "string"
  ) {
    return null;
  }
  return {
    sources: sources.map((id) => id.toLowerCase() as `0x${string}`),
    writtenAt: value.writtenAt,
  };
}

/**
 * The caller's `lineage` field from a JSON body or a binary write's parsed
 * metadata. `undefined` when the container is not an object or carries no
 * such field, so a bare-string metadata header or a lineage-less body is a
 * root record.
 */
export function extractLineageField(container: unknown): unknown {
  if (!isRecord(container)) return undefined;
  return container[LINEAGE_FIELD];
}

/**
 * Parse the caller's `lineage` value: an array of distinct 0x-prefixed
 * 32-byte hex strings, at most MAX_LINEAGE_SOURCES long. Ids are lowercased
 * so equal ids compare equal wherever they are stored. Throws
 * LineageInvalidError (400).
 */
export function parseLineageSources(value: unknown): `0x${string}`[] {
  if (!Array.isArray(value)) {
    throw new LineageInvalidError(
      `${LINEAGE_FIELD} must be an array of data point ids (0x-prefixed 32-byte hex)`,
    );
  }
  if (value.length > MAX_LINEAGE_SOURCES) {
    throw new LineageInvalidError(
      `${LINEAGE_FIELD} lists ${value.length} sources; the maximum is ${MAX_LINEAGE_SOURCES}`,
      { max: MAX_LINEAGE_SOURCES, count: value.length },
    );
  }
  const seen = new Set<string>();
  const sources: `0x${string}`[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || !BYTES32_HEX.test(entry)) {
      throw new LineageInvalidError(
        `${LINEAGE_FIELD} entries must be 0x-prefixed 32-byte hex data point ids`,
        { entry: typeof entry === "string" ? entry : typeof entry },
      );
    }
    const id = entry.toLowerCase() as `0x${string}`;
    if (seen.has(id)) {
      throw new LineageInvalidError(
        `${LINEAGE_FIELD} lists the same source twice`,
        { duplicate: id },
      );
    }
    seen.add(id);
    sources.push(id);
  }
  return sources;
}

/** First dot-segment of a scope (`chatgpt` for `chatgpt.conversations`). */
export function scopeNamespace(scope: string): string {
  const dot = scope.indexOf(".");
  return dot === -1 ? scope : scope.slice(0, dot);
}

/**
 * The naming rule. Grant patterns are exact, `prefix.*` or `*`; `prefix.*`
 * covers every scope that starts with `prefix.`. A derived scope and a
 * source scope are both covered by the same non-universal pattern exactly
 * when they share their first segment, and that is the one way the current
 * grammar can leak across a lineage edge (a grant on `chatgpt.*` would read
 * both `chatgpt.conversations` and a derivative named `chatgpt.summary`).
 * `*` reads everything by definition and is not a lineage leak.
 */
export function derivedScopeViolatesNaming(
  derivedScope: string,
  sourceScope: string,
): boolean {
  return scopeNamespace(derivedScope) === scopeNamespace(sourceScope);
}

export function assertDerivedScopeNaming(
  derivedScope: string,
  sourceScopes: readonly string[],
): void {
  for (const sourceScope of sourceScopes) {
    if (derivedScopeViolatesNaming(derivedScope, sourceScope)) {
      throw new LineageScopeUnderSourcePrefixError({
        scope: derivedScope,
        sourceScope,
      });
    }
  }
}

export interface ResolveLineageSourcesInput {
  /** The derived record's scope. */
  scope: string;
  sources: readonly `0x${string}`[];
  serverOwner: `0x${string}`;
  storage: Pick<DataStoragePort, "listScopes">;
  /** Absent = sources must be in the local index. */
  gateway?: LineageSourceLookup;
}

/**
 * Resolve every source id to a data point of this owner. The local index is
 * consulted first (`keccak256(owner, scope)` over the server's own scopes,
 * so an unsynced local scope is a valid source), then the gateway with
 * deleted points included. An id that resolves to nothing, or to another
 * owner's data point, fails the whole write with 422
 * LINEAGE_SOURCE_UNKNOWN listing every offending id; a gateway that cannot
 * be reached fails with 502 so the builder retries instead of being told
 * its source does not exist.
 */
export async function resolveLineageSources(
  input: ResolveLineageSourcesInput,
): Promise<ResolvedLineageSource[]> {
  const ownId = computeDataPointId(input.serverOwner, input.scope);
  const self = input.sources.find((id) => id === ownId);
  if (self) {
    throw new LineageInvalidError(
      "A record cannot list its own data point as a lineage source",
      { dataPointId: self },
    );
  }

  const local = localScopesById(input.storage, input.serverOwner);
  const resolved: ResolvedLineageSource[] = [];
  const unknown: string[] = [];
  for (const dataPointId of input.sources) {
    const localScope = local.get(dataPointId);
    if (localScope !== undefined) {
      resolved.push({
        dataPointId,
        scope: localScope,
        version: null,
        deletedAt: null,
      });
      continue;
    }
    if (!input.gateway) {
      unknown.push(dataPointId);
      continue;
    }
    let record: LineageDataPointRecord | null;
    try {
      record = await input.gateway.getDataPoint(dataPointId);
    } catch (err) {
      throw new LineageSourceLookupFailedError({
        dataPointId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
    if (
      !record ||
      record.ownerAddress.toLowerCase() !== input.serverOwner.toLowerCase()
    ) {
      unknown.push(dataPointId);
      continue;
    }
    resolved.push({
      dataPointId,
      scope: record.scope,
      version: record.version,
      deletedAt: record.deletedAt,
    });
  }
  if (unknown.length > 0) {
    throw new LineageSourceUnknownError({ unknown });
  }
  return resolved;
}

/**
 * `dataPointId -> scope` for the server's own scopes. Bounded by
 * LOCAL_SCOPE_SCAN_LIMIT; scopes beyond it are simply resolved through the
 * gateway like any non-local source.
 */
function localScopesById(
  storage: Pick<DataStoragePort, "listScopes">,
  serverOwner: `0x${string}`,
): Map<string, string> {
  const byId = new Map<string, string>();
  const { scopes } = storage.listScopes({
    limit: LOCAL_SCOPE_SCAN_LIMIT,
    offset: 0,
  });
  for (const summary of scopes) {
    byId.set(computeDataPointId(serverOwner, summary.scope), summary.scope);
  }
  return byId;
}

export interface PrepareLineageInput {
  scope: string;
  /** The raw caller value (`body.lineage` / `metadata.lineage`). */
  field: unknown;
  serverOwner: `0x${string}` | undefined;
  storage: Pick<DataStoragePort, "listScopes">;
  gateway?: LineageSourceLookup;
  now: () => Date;
}

/**
 * Validate a write's lineage end to end (shape, sources, naming rule) and
 * produce the `$lineage` record to stamp. Throws ProtocolErrors; callers on
 * the write path let them propagate before anything is stored.
 */
export async function prepareLineage(
  input: PrepareLineageInput,
): Promise<StoredLineage> {
  const sources = parseLineageSources(input.field);
  if (!input.serverOwner) {
    throw new ServerNotConfiguredError({
      reason: "serverOwner is required to validate lineage sources",
    });
  }
  const resolved = await resolveLineageSources({
    scope: input.scope,
    sources,
    serverOwner: input.serverOwner,
    storage: input.storage,
    gateway: input.gateway,
  });
  assertDerivedScopeNaming(
    input.scope,
    resolved.map((source) => source.scope),
  );
  return { sources, writtenAt: input.now().toISOString() };
}
