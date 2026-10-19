import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  compareLegacyCoverage,
  type LegacyCoverageVerdict,
} from "./legacy-scope-coverage.js";
export type { LegacyCoverageVerdict } from "./legacy-scope-coverage.js";
import { LEGACY_SCOPE_ENTITY_KEYS } from "./legacy-scope-entity-keys.js";
import {
  GITHUB_BROWSER_BINDINGS,
  LEGACY_SCOPE_BINDINGS,
  legacyBindingsForProfile,
  META_040_BINDINGS,
  OURA_BROWSER_BINDINGS,
} from "../legacy-projection/index.js";
import {
  legacyConnectorKey,
  readCanonicalLegacyScope,
  type CanonicalConnectionBinding,
  type CanonicalConnectionSelection,
  type CanonicalLegacyReadFailure,
  type CanonicalLegacyReadOk,
  type CanonicalLegacyReadStore,
  type ReadCanonicalLegacyScopeInput,
  CANONICAL_LEGACY_VIEW_CONTRACT,
} from "./canonical-legacy-projection.js";

/**
 * Decides, per legacy scope, whether the latest body comes from the
 * canonical rows or from the existing legacy file, and reads it.
 *
 * Only a bound scope can move. Its binding names the connector key it was
 * reviewed for (`oura`, `oura-browser`, `github-browser`, `meta`, ...), and
 * that key is the method id a connection is registered with: the operator's
 * trusted method configuration names methods the same way. The store source
 * id is never derived from the key; it is the connection's registered
 * source, and that (source, method) pair must be configured on this boot.
 *
 * A bound scope is canonical-owned for write/refusal safety when a connection
 * of one of its methods has held a row of, or a completion receipt for, one
 * of the scope's streams, or was reset or deleted (both erase the rows that
 * would show this). With a stored legacy head, the first eligible GET checks
 * the projected body against the latest legacy body and records the verdict.
 * A newer legacy version is checked again; a mismatch explicitly returns
 * that file. A regression against an already covered version refuses.
 * Every other scope, unbound ones included, keeps the file.
 *
 * The connection comes only from the registry: the single live connection
 * of the scope's methods that has held any data. A request cannot name one.
 */

/** Every declaration profile the pure module serves a scope from. */
const BINDING_PROFILES = [
  LEGACY_SCOPE_BINDINGS,
  GITHUB_BROWSER_BINDINGS,
  META_040_BINDINGS,
  OURA_BROWSER_BINDINGS,
];

const COVERAGE_RULE_VERSION = 5;

function scopeDeclarationCursor(scope: string): string {
  return JSON.stringify(
    BINDING_PROFILES.flatMap((profile) => [...profile.values()])
      .filter((binding) => binding.scope === scope)
      .map((binding) => ({
        pdppSource: binding.pdppSource,
        pdppStreams: binding.pdppStreams,
        primaryKey: binding.primaryKey,
        fieldsRead: binding.fieldsRead,
        provenance: binding.provenance,
      })),
  );
}

/**
 * Registry facts and takeover diagnostics from the same SQLite database as
 * the rows. Facts must work when the record server is not mounted (its tables
 * may then be absent: no connection, no evidence).
 */
export interface LegacyScopeAuthority {
  /** Connections registered with one of `methods`, deleted ones included. */
  listMethodConnections(
    methods: readonly string[],
  ): CanonicalConnectionBinding[];
  /**
   * True when the instance has held a row (live or tombstoned) of one of
   * `streams`, or holds a completion receipt for one. Null `streams`: any.
   */
  hasHeldData(instance: string, streams: readonly string[] | null): boolean;
  /** See `CanonicalLegacyReadStore.readSnapshot`. Same database connection. */
  readSnapshot<T>(read: () => T): T;
  writeClock(): number;
  /** Monotonic arrival revision, independent of record content writes. */
  arrivalRevision(): number;
  /** Whether a complete canonical read has already superseded the legacy head. */
  hasTakeover(scope: string, instance?: string, generation?: number): boolean;
  hasCoveredHead(
    scope: string,
    head: LegacyScopeHead,
    instance?: string,
  ): boolean;
  isReset(scope: string): boolean;
  cachedVerdict(
    scope: string,
    instance: string,
    generation: number,
    legacyVersionId: number,
    canonicalCursor: string,
  ): LegacyCoverageVerdict | null;
  verdictFor(scope: string): LegacyScopeVerdictRecord[];
  resetTakeover(scope: string): void;
  /** Identity of the latest index entry not owned by a known projector. */
  eligibleLegacyHead(scope: string): LegacyScopeHead | null;
  /**
   * Revalidates the head and connection selection under a write lock, then
   * records the eligible legacy versions. A null head confirms a read that
   * did not observe legacy data and records no takeover.
   */
  confirmRead(
    scope: string,
    expectedHead: LegacyScopeHead | null,
    selectionIsCurrent: () => boolean,
    verdict?: {
      instance: string;
      generation: number;
      writeClock: number;
      arrivalRevision: number;
      canonicalCursor: string;
      coverage: LegacyCoverageVerdict;
      cached: boolean;
    },
  ): boolean;
}

export interface LegacyScopeVerdictRecord {
  scope: string;
  instance: string;
  generation: number;
  legacyVersionId: number;
  canonicalCursor: string;
  verdict: "covered" | "not_covered";
  comparisonCase: "same_time" | "canonical_newer";
  reasonCounts: Record<string, number>;
  appliedExceptions: LegacyCoverageVerdict["appliedExceptions"];
  reason: {
    reason: string;
    missingEntityCount: number;
    mismatchedFieldPaths: string[];
  } | null;
  legacyBytes: number;
  canonicalBytes: number;
  byteDelta: number;
  evaluatedAt: string;
}

export interface LegacyScopeHead {
  id: number;
  path: string;
  version: number;
  casRevision: number;
  collectedAt: string;
}

export type LegacyScopeRefusal =
  | CanonicalLegacyReadFailure
  | {
      status: "unavailable";
      reason: "no_connection" | "ambiguous_connection";
      candidates: number;
    }
  | {
      /** The record server is not mounted, or does not configure the pair. */
      status: "unavailable";
      reason: "connection_unavailable";
      detail: "method_not_configured";
    }
  | {
      status: "incomplete";
      reason: "canonical_view_incomplete";
      diagnostics: {
        stream: string;
        kind: "omitted" | "partial" | "unproven";
        detail: string;
      }[];
    };

export type LegacyScopeLatest =
  /** Not canonical: the existing storage answers, exactly as before. */
  | { kind: "file" }
  | {
      kind: "canonical";
      envelope: DataFileEnvelope;
      /** Opaque, stable while the rows and receipts do not change. */
      revision: string;
    }
  | { kind: "refused"; refusal: LegacyScopeRefusal };

export type LegacyScopeListing =
  | { kind: "file" }
  | { kind: "canonical"; collectedAt: string }
  | { kind: "refused" };

export interface LegacyScopeViewPort {
  /** The latest body of a scope. Never used for an explicit version. */
  readLatest(scope: string): Promise<LegacyScopeLatest>;
  /**
   * Listing metadata from counts and receipts only, without reading rows.
   * A refusal here is also a refusal on read; a read can still refuse what
   * this lists (for example a projection rejection).
   */
  listingFor(scope: string): LegacyScopeListing;
  /** Bound scopes under `scopePrefix` that `listingFor` lists as canonical. */
  listCanonicalScopes(
    scopePrefix: string | undefined,
  ): { scope: string; collectedAt: string }[];
  /** True when canonical history makes a legacy-only deletion unsafe. */
  ownsScope(scope: string): boolean;
  verdictFor(scope: string): LegacyScopeVerdictRecord[];
  resetTakeover(scope: string): void;
  isReset(scope: string): boolean;
}

export interface CreateLegacyScopeViewInput {
  authority: LegacyScopeAuthority;
  /**
   * The mounted record store, over the authority's database connection.
   * Absent when the record server is not mounted: canonical-owned scopes
   * are then refused.
   */
  records?: CanonicalLegacyReadStore;
  /** Current trusted declarations; pass the same registry used by canonical ingest. */
  declarations?: ReadCanonicalLegacyScopeInput["declarations"];
  /** Methods this boot configures for a store source id. */
  configuredMethods(sourceId: string): readonly string[];
  /** Read the exact latest indexed legacy file; omitted by in-memory adapters. */
  readLegacyHead?(head: LegacyScopeHead): Promise<DataFileEnvelope>;
  /** Optional payload growth limits for the takeover check. */
  coverageThresholds?: { maxPayloadRatio?: number; maxExtraBytes?: number };
}

type Decision =
  | { kind: "file" }
  | { kind: "refused"; refusal: LegacyScopeRefusal }
  | {
      kind: "canonical";
      records: CanonicalLegacyReadStore;
      selection: CanonicalConnectionSelection;
      generation: number;
      streams: readonly string[];
    };

export function createLegacyScopeView(
  input: CreateLegacyScopeViewInput,
): LegacyScopeViewPort {
  const { authority, records } = input;
  const coveredProjection = new Map<
    string,
    { key: string; envelope: DataFileEnvelope; revision: string }
  >();

  function decide(scope: string): Decision {
    const streamsByMethod = scopeMethods(scope);
    if (streamsByMethod.size === 0) {
      return authority.hasTakeover(scope)
        ? refused({
            status: "unavailable",
            reason: "connection_unavailable",
            detail: "method_not_configured",
          })
        : { kind: "file" };
    }
    const connections = authority.listMethodConnections([
      ...streamsByMethod.keys(),
    ]);
    const owned =
      authority.hasTakeover(scope) ||
      connections.some(
        (connection) =>
          connection.deletedAt !== null ||
          connection.generation > 1 ||
          authority.hasHeldData(
            connection.instance,
            streamsByMethod.get(connection.method ?? "") ?? [],
          ),
      );
    if (!owned) return { kind: "file" };

    // A connection that never held anything (boot registers one per source)
    // is not a candidate; any other live one is, whatever stream it holds,
    // so two accounts never split one namespace between them.
    const candidates = connections.filter(
      (connection) =>
        connection.deletedAt === null &&
        authority.hasHeldData(connection.instance, null),
    );
    const [only] = candidates;
    if (!only) {
      return refused({
        status: "unavailable",
        reason: "no_connection",
        candidates: 0,
      });
    }
    if (candidates.length > 1) {
      return refused({
        status: "unavailable",
        reason: "ambiguous_connection",
        candidates: candidates.length,
      });
    }
    const { instance, sourceId, method } = only;
    if (
      !records ||
      sourceId === null ||
      method === null ||
      !input.configuredMethods(sourceId).includes(method)
    ) {
      return refused({
        status: "unavailable",
        reason: "connection_unavailable",
        detail: "method_not_configured",
      });
    }
    return {
      kind: "canonical",
      records,
      selection: { instance, sourceId, method },
      generation: only.generation,
      streams: streamsByMethod.get(method) ?? [],
    };
  }

  function canServeLegacyBeforeTakeover(scope: string): boolean {
    const methods = [...scopeMethods(scope).keys()];
    const connections = authority.listMethodConnections(methods);
    if (
      !connections.length ||
      connections.some((connection) => connection.deletedAt !== null)
    ) {
      return false;
    }
    const current = decide(scope);
    if (
      current.kind === "refused" &&
      !(
        current.refusal.status === "unavailable" &&
        current.refusal.reason === "no_connection"
      )
    ) {
      return false;
    }
    return (
      authority.eligibleLegacyHead(scope) !== null &&
      !authority.hasTakeover(
        scope,
        current.kind === "canonical" ? current.selection.instance : undefined,
        current.kind === "canonical" ? current.generation : undefined,
      )
    );
  }

  function listingFor(scope: string): LegacyScopeListing {
    return authority.readSnapshot((): LegacyScopeListing => {
      if (authority.isReset(scope)) return { kind: "file" };
      const decision = decide(scope);
      const legacyHead = authority.eligibleLegacyHead(scope);
      const hasTakeover = authority.hasTakeover(
        scope,
        decision.kind === "canonical" ? decision.selection.instance : undefined,
        decision.kind === "canonical" ? decision.generation : undefined,
      );
      if (
        decision.kind === "refused" &&
        decision.refusal.status === "unavailable" &&
        decision.refusal.reason === "no_connection" &&
        canServeLegacyBeforeTakeover(scope)
      ) {
        return { kind: "file" };
      }
      if (decision.kind !== "canonical") return { kind: decision.kind };
      const hasLegacyHead = legacyHead !== null;
      if (hasLegacyHead && input.readLegacyHead) {
        const verdict = authority
          .verdictFor(scope)
          .find(
            (row) =>
              row.instance === decision.selection.instance &&
              row.generation === decision.generation &&
              row.legacyVersionId === legacyHead.id,
          );
        const coveredHead = authority.hasCoveredHead(scope, legacyHead);
        if (verdict?.verdict !== "covered") {
          return { kind: coveredHead ? "refused" : "file" };
        }
        if (
          !verdict.canonicalCursor.startsWith(
            `${authority.writeClock()}:${authority.arrivalRevision()}:${receiptCursor(decision, input.declarations)}:`,
          )
        ) {
          return { kind: "refused" };
        }
      } else if (hasLegacyHead && !hasTakeover) return { kind: "file" };
      if (
        !input.readLegacyHead &&
        hasLegacyHead &&
        hasTakeover &&
        missingCompletionReceipts(decision).length > 0
      ) {
        return { kind: "refused" };
      }
      const collectedAt = listedCollectedAt(
        decision.records,
        decision.selection.instance,
        decision.streams,
      );
      return collectedAt === null
        ? { kind: "refused" }
        : { kind: "canonical", collectedAt };
    });
  }

  return {
    async readLatest(scope) {
      if (authority.isReset(scope)) return { kind: "file" };
      const initial = authority.readSnapshot(() => {
        const decision = decide(scope);
        return {
          decision,
          legacyHead: authority.eligibleLegacyHead(scope),
          hasTakeover: authority.hasTakeover(
            scope,
            decision.kind === "canonical"
              ? decision.selection.instance
              : undefined,
            decision.kind === "canonical" ? decision.generation : undefined,
          ),
          canServeLegacy: canServeLegacyBeforeTakeover(scope),
          writeClock: authority.writeClock(),
          arrivalRevision: authority.arrivalRevision(),
          receiptCursor:
            decision.kind === "canonical"
              ? receiptCursor(decision, input.declarations)
              : "",
        };
      });
      const { decision, legacyHead, hasTakeover, canServeLegacy } = initial;
      if (
        decision.kind === "refused" &&
        decision.refusal.status === "unavailable" &&
        decision.refusal.reason === "no_connection" &&
        canServeLegacy
      ) {
        return { kind: "file" };
      }
      if (decision.kind !== "canonical") return decision;
      const canonicalCursor = legacyHead
        ? [
            initial.writeClock,
            initial.arrivalRevision,
            initial.receiptCursor,
            decision.generation,
            CANONICAL_LEGACY_VIEW_CONTRACT,
            scopeDeclarationCursor(scope),
            COVERAGE_RULE_VERSION,
            input.coverageThresholds?.maxPayloadRatio ?? 1.5,
            input.coverageThresholds?.maxExtraBytes ?? 256 * 1024,
          ].join(":")
        : "";
      const projectionKey = legacyHead
        ? JSON.stringify([
            decision.selection.instance,
            decision.generation,
            legacyHead.id,
            canonicalCursor,
          ])
        : "";
      const projectionOwner = scope;
      const cachedCoverage =
        legacyHead !== null && input.readLegacyHead
          ? authority.cachedVerdict(
              scope,
              decision.selection.instance,
              decision.generation,
              legacyHead.id,
              canonicalCursor,
            )
          : null;
      const cachedProjection = coveredProjection.get(projectionOwner);
      if (cachedCoverage?.covered && cachedProjection?.key === projectionKey) {
        const confirmed = authority.confirmRead(
          scope,
          legacyHead,
          () =>
            sameSelection(decide(scope), decision) &&
            receiptCursor(decision, input.declarations) ===
              initial.receiptCursor,
          {
            instance: decision.selection.instance,
            generation: decision.generation,
            writeClock: initial.writeClock,
            arrivalRevision: initial.arrivalRevision,
            canonicalCursor,
            coverage: cachedCoverage,
            cached: true,
          },
        );
        if (!confirmed) {
          if (authority.isReset(scope)) return { kind: "file" };
          return {
            kind: "refused",
            refusal: {
              status: "unavailable",
              reason: "store_inconsistent_read",
              detail:
                "legacy head or canonical cursor changed during parity evaluation",
            },
          };
        }
        return {
          kind: "canonical",
          envelope: cachedProjection.envelope,
          revision: cachedProjection.revision,
        };
      }
      if (cachedCoverage && !cachedCoverage.covered && legacyHead) {
        let legacy: DataFileEnvelope;
        try {
          legacy = await input.readLegacyHead!(legacyHead);
        } catch {
          return hasTakeover
            ? {
                kind: "refused",
                refusal: {
                  status: "unavailable",
                  reason: "store_inconsistent_read",
                  detail: "indexed legacy head could not be read",
                },
              }
            : { kind: "file" };
        }
        if (legacy.scope !== scope) {
          return {
            kind: "refused",
            refusal: {
              status: "unavailable",
              reason: "store_inconsistent_read",
              detail: "indexed legacy head has another scope",
            },
          };
        }
        const alreadyCovered = authority.hasCoveredHead(scope, legacyHead);
        const confirmed = authority.confirmRead(
          scope,
          legacyHead,
          () =>
            sameSelection(decide(scope), decision) &&
            receiptCursor(decision, input.declarations) ===
              initial.receiptCursor,
          {
            instance: decision.selection.instance,
            generation: decision.generation,
            writeClock: initial.writeClock,
            arrivalRevision: initial.arrivalRevision,
            canonicalCursor,
            coverage: cachedCoverage,
            cached: true,
          },
        );
        if (!confirmed) {
          if (authority.isReset(scope)) return { kind: "file" };
          return {
            kind: "refused",
            refusal: {
              status: "unavailable",
              reason: "store_inconsistent_read",
              detail:
                "legacy head or canonical cursor changed during parity evaluation",
            },
          };
        }
        return alreadyCovered
          ? {
              kind: "refused",
              refusal: {
                status: "incomplete",
                reason: "canonical_view_incomplete",
                diagnostics: [],
              },
            }
          : { kind: "file" };
      }
      const read = await readCanonicalLegacyScope({
        store: decision.records,
        declarations: input.declarations,
        scope,
        selection: decision.selection,
        profileBy: "method",
        requireCompletionReceipts: legacyHead !== null && !input.readLegacyHead,
        allowUnprovenEmptyStreams:
          legacyHead !== null && !!input.readLegacyHead,
        includeStreamTimes: legacyHead !== null && !!input.readLegacyHead,
        requireClaudeRawBlobs: legacyHead !== null && !!input.readLegacyHead,
        // The rows must come from a state in which this is still the one
        // connection: a second account appearing between the decision and
        // the rows refuses instead of serving a body chosen while ambiguous.
        confirmSelection: () => sameSelection(decide(scope), decision),
      });
      if (!read.ok) {
        if (
          legacyHead !== null &&
          input.readLegacyHead &&
          isProjectionDataFailure(read.reason)
        ) {
          let legacy: DataFileEnvelope;
          try {
            legacy = await input.readLegacyHead(legacyHead);
          } catch {
            const { ok: _ok, ...refusal } = read;
            return { kind: "refused", refusal };
          }
          if (legacy.scope !== scope) {
            return {
              kind: "refused",
              refusal: {
                status: "unavailable",
                reason: "store_inconsistent_read",
                detail: "indexed legacy head has another scope",
              },
            };
          }
          const coveredHead = authority.hasCoveredHead(scope, legacyHead);
          const coverage = projectionUnavailableCoverage(
            legacy.data,
            read.reason === "missing_raw_blob" ? read.recordCount : 0,
          );
          const confirmed = authority.confirmRead(
            scope,
            legacyHead,
            () =>
              sameSelection(decide(scope), decision) &&
              receiptCursor(decision, input.declarations) ===
                initial.receiptCursor,
            {
              instance: decision.selection.instance,
              generation: decision.generation,
              writeClock: initial.writeClock,
              arrivalRevision: initial.arrivalRevision,
              canonicalCursor: `${initial.writeClock}:${initial.arrivalRevision}:${initial.receiptCursor}:unavailable:${read.reason}:${COVERAGE_RULE_VERSION}`,
              coverage,
              cached: false,
            },
          );
          if (!confirmed) {
            if (authority.isReset(scope)) return { kind: "file" };
            return {
              kind: "refused",
              refusal: {
                status: "unavailable",
                reason: "store_inconsistent_read",
                detail:
                  "legacy head or canonical cursor changed during parity evaluation",
              },
            };
          }
          if (coveredHead) {
            const { ok: _ok, ...refusal } = read;
            return { kind: "refused", refusal };
          }
          return { kind: "file" };
        }
        if (
          legacyHead !== null &&
          !hasTakeover &&
          (read.reason === "projection_rejected" ||
            read.reason === "all_rows_rejected" ||
            read.reason === "no_synced_data" ||
            read.reason === "stream_completion_unknown" ||
            read.reason === "blob_read_budget_exceeded" ||
            read.reason === "blob_backed_record_invalid" ||
            read.reason === "missing_raw_blob" ||
            read.reason === "blob_backed_records_unsupported")
        ) {
          const stillLegacyOwned = authority.readSnapshot(() =>
            canServeLegacyBeforeTakeover(scope),
          );
          if (stillLegacyOwned) return { kind: "file" };
        }
        const { ok: _ok, ...refusal } = read;
        return { kind: "refused", refusal };
      }
      if (legacyHead !== null && input.readLegacyHead) {
        let coverage = cachedCoverage;
        const cached = coverage !== null;
        if (!coverage) {
          let legacy: DataFileEnvelope;
          try {
            legacy = await input.readLegacyHead(legacyHead);
          } catch {
            return hasTakeover
              ? {
                  kind: "refused",
                  refusal: {
                    status: "unavailable",
                    reason: "store_inconsistent_read",
                    detail: "indexed legacy head could not be read",
                  },
                }
              : { kind: "file" };
          }
          if (legacy.scope !== scope) {
            return {
              kind: "refused",
              refusal: {
                status: "unavailable",
                reason: "store_inconsistent_read",
                detail: "indexed legacy head has another scope",
              },
            };
          }
          coverage = compareLegacyCoverage(legacy.data, read.envelope.data, {
            scope,
            entityKeys: LEGACY_SCOPE_ENTITY_KEYS[scope],
            projectionOmissions: read.projectionOmissions,
            canonicalNewer: allStreamsNewerThan(
              read,
              decision.streams,
              legacyHead.collectedAt,
            ),
            allowProvenDeletion:
              read.complete &&
              allStreamsProvenAfter(
                read,
                decision.streams,
                legacyHead.collectedAt,
              ),
            ...input.coverageThresholds,
          });
        }
        const alreadyCovered = authority.hasCoveredHead(scope, legacyHead);
        const confirmed = authority.confirmRead(
          scope,
          legacyHead,
          () =>
            sameSelection(decide(scope), decision) &&
            receiptCursor(decision, input.declarations) ===
              initial.receiptCursor,
          {
            instance: decision.selection.instance,
            generation: decision.generation,
            writeClock: initial.writeClock,
            arrivalRevision: initial.arrivalRevision,
            canonicalCursor,
            coverage,
            cached,
          },
        );
        if (!confirmed) {
          if (authority.isReset(scope)) return { kind: "file" };
          return {
            kind: "refused",
            refusal: {
              status: "unavailable",
              reason: "store_inconsistent_read",
              detail:
                "legacy head or canonical cursor changed during parity evaluation",
            },
          };
        }
        if (!coverage.covered) {
          // A newer file is an explicit, recorded rollback. A canonical
          // regression against the same file must still refuse after takeover.
          return alreadyCovered
            ? {
                kind: "refused",
                refusal: {
                  status: "incomplete",
                  reason: "canonical_view_incomplete",
                  diagnostics: [],
                },
              }
            : { kind: "file" };
        }
        coveredProjection.set(projectionOwner, {
          key: projectionKey,
          envelope: read.envelope,
          revision: read.revision,
        });
        return {
          kind: "canonical",
          envelope: read.envelope,
          revision: read.revision,
        };
      }
      if (!read.complete) {
        if (legacyHead !== null && !hasTakeover) {
          const stillLegacyOwned = authority.readSnapshot(() =>
            canServeLegacyBeforeTakeover(scope),
          );
          if (stillLegacyOwned) return { kind: "file" };
        }
        return {
          kind: "refused",
          refusal: {
            status: "incomplete",
            reason: "canonical_view_incomplete",
            diagnostics: incompleteness(read),
          },
        };
      }
      const confirmed = authority.confirmRead(scope, legacyHead, () =>
        sameSelection(decide(scope), decision),
      );
      if (!confirmed) {
        const current = authority.readSnapshot(() => ({
          canServeLegacy: canServeLegacyBeforeTakeover(scope),
          hasTakeover: authority.hasTakeover(
            scope,
            decision.selection.instance,
            decision.generation,
          ),
        }));
        if (current.canServeLegacy && !current.hasTakeover)
          return { kind: "file" };
        return {
          kind: "refused",
          refusal: {
            status: "unavailable",
            reason: "store_inconsistent_read",
            detail:
              "legacy head or connection selection changed during canonical projection",
          },
        };
      }
      return {
        kind: "canonical",
        envelope: read.envelope,
        revision: read.revision,
      };
    },

    listingFor,

    listCanonicalScopes(scopePrefix) {
      const listed: { scope: string; collectedAt: string }[] = [];
      for (const scope of boundScopes()) {
        if (scopePrefix !== undefined && !scope.startsWith(scopePrefix)) {
          continue;
        }
        const listing = listingFor(scope);
        if (listing.kind === "canonical") {
          listed.push({ scope, collectedAt: listing.collectedAt });
        }
      }
      return listed;
    },

    ownsScope(scope) {
      return authority.readSnapshot(() => decide(scope)).kind !== "file";
    },
    verdictFor: (scope) => authority.verdictFor(scope),
    resetTakeover: (scope) => authority.resetTakeover(scope),
    isReset: (scope) => authority.isReset(scope),
  };
}

function missingCompletionReceipts(
  decision: Extract<Decision, { kind: "canonical" }>,
): string[] {
  const binding = decision.records.getInstanceBinding(
    decision.selection.instance,
  );
  const listings = decision.records.listStreams([decision.selection.instance]);
  const receipts = decision.records.listStreamCompletions(
    decision.selection.instance,
  );
  return decision.streams.filter((stream) => {
    const liveCount =
      listings.find((entry) => entry.stream === stream)?.recordCount ?? 0;
    return !receipts.some(
      (receipt) =>
        receipt.stream === stream &&
        receipt.method === binding.method &&
        receipt.generation === binding.generation &&
        receipt.liveCount === liveCount,
    );
  });
}

function isProjectionDataFailure(reason: string): boolean {
  return [
    "projection_rejected",
    "all_rows_rejected",
    "no_synced_data",
    "stream_completion_unknown",
    "invalid_collected_at",
    "blob_read_budget_exceeded",
    "blob_backed_record_invalid",
    "missing_raw_blob",
    "blob_backed_records_unsupported",
  ].includes(reason);
}

function receiptCursor(
  decision: Extract<Decision, { kind: "canonical" }>,
  declarations?: ReadCanonicalLegacyScopeInput["declarations"],
): string {
  const receipts = decision.records
    .listStreamCompletions(decision.selection.instance)
    .filter((receipt) => decision.streams.includes(receipt.stream))
    .map((receipt) => [
      receipt.stream,
      receipt.method,
      receipt.generation,
      receipt.sourceCollectedAt,
      receipt.writeSeq,
      receipt.liveCount,
    ])
    .sort((a, b) => String(a[0]).localeCompare(String(b[0])));
  // A declaration-only change must invalidate covered-body and verdict caches,
  // including while an asynchronous blob digest or legacy file read is pending.
  if (!declarations) return JSON.stringify(receipts);
  return JSON.stringify({
    receipts,
    schemas: decision.streams.map((stream) => [
      stream,
      declarations.forInstance(decision.selection.instance, stream)?.schema ??
        null,
    ]),
  });
}

function projectionUnavailableCoverage(
  legacyPayload: unknown,
  missingRawBlobCount = 0,
): LegacyCoverageVerdict {
  const legacyBytes = new TextEncoder().encode(
    JSON.stringify(legacyPayload),
  ).length;
  return {
    comparisonCase: "same_time",
    covered: false,
    reason:
      missingRawBlobCount > 0 ? "missing_raw_blob" : "projection_unavailable",
    reasonCounts: {
      no_stable_key: 0,
      missing_entity: 0,
      missing_field: 0,
      field_mismatch: 0,
      type_mismatch: 0,
      timestamp_format: 0,
      identity_mismatch: 0,
      creation_mismatch: 0,
      array_order: 0,
      payload_growth: 0,
      missing_raw_blob: missingRawBlobCount,
      projection_unavailable: missingRawBlobCount > 0 ? 0 : 1,
    },
    appliedExceptions: [],
    missingEntityCount: 0,
    mismatchedFieldPaths: [],
    legacyBytes,
    canonicalBytes: 0,
    byteDelta: -legacyBytes,
  };
}

/** A newer scope snapshot requires a newer collection horizon for each input stream. */
function allStreamsNewerThan(
  read: CanonicalLegacyReadOk,
  streams: readonly string[],
  legacyCollectedAt: string,
): boolean {
  const legacyTime = Date.parse(legacyCollectedAt);
  if (!Number.isFinite(legacyTime)) return false;
  return streams.every((stream) => {
    const time = Date.parse(read.streamCollectionTimes?.[stream] ?? "");
    return Number.isFinite(time) && time > legacyTime;
  });
}

/** Only current P7 receipts from every input stream prove a later deletion. */
function allStreamsProvenAfter(
  read: CanonicalLegacyReadOk,
  streams: readonly string[],
  legacyCollectedAt: string,
): boolean {
  const legacyTime = Date.parse(legacyCollectedAt);
  if (!Number.isFinite(legacyTime)) return false;
  return streams.every((stream) => {
    const time = Date.parse(read.streamCompletionTimes?.[stream] ?? "");
    return Number.isFinite(time) && time > legacyTime;
  });
}

function refused(refusal: LegacyScopeRefusal): Decision {
  return { kind: "refused", refusal };
}

function sameSelection(
  again: Decision,
  decision: Extract<Decision, { kind: "canonical" }>,
): boolean {
  return (
    again.kind === "canonical" &&
    again.selection.instance === decision.selection.instance &&
    again.selection.sourceId === decision.selection.sourceId &&
    again.selection.method === decision.selection.method &&
    again.generation === decision.generation
  );
}

/**
 * The methods that may serve a scope, each with the streams its binding
 * reads. A method id is a binding's connector key; its binding is the one
 * the reader will use for that method.
 */
function scopeMethods(scope: string): Map<string, readonly string[]> {
  const methods = new Map<string, readonly string[]>();
  for (const profile of BINDING_PROFILES) {
    const bound = profile.get(scope);
    if (!bound) continue;
    const method = legacyConnectorKey(bound.pdppSource);
    const binding = legacyBindingsForProfile(method).get(scope);
    if (binding) methods.set(method, binding.pdppStreams);
  }
  return methods;
}

function boundScopes(): string[] {
  const scopes = new Set<string>();
  for (const profile of BINDING_PROFILES) {
    for (const scope of profile.keys()) scopes.add(scope);
  }
  return [...scopes].sort();
}

/**
 * The `collectedAt` a read would return, from listing counts and receipts:
 * a stream's valid receipt time, else its newest row time. Null when a bound
 * stream is empty without a valid receipt, which a read refuses.
 */
function listedCollectedAt(
  store: CanonicalLegacyReadStore,
  instance: string,
  streams: readonly string[],
): string | null {
  const binding = store.getInstanceBinding(instance);
  const listing = store.listStreams([instance]);
  const receipts = store.listStreamCompletions(instance);
  let newest = Number.NEGATIVE_INFINITY;
  for (const stream of streams) {
    const entry = listing.find((candidate) => candidate.stream === stream);
    const count = entry?.recordCount ?? 0;
    const receipt = receipts.find(
      (candidate) =>
        candidate.stream === stream &&
        candidate.method === binding.method &&
        candidate.generation === binding.generation &&
        candidate.liveCount === count,
    );
    const stamp = receipt?.sourceCollectedAt ?? entry?.lastUpdated ?? null;
    if (count === 0 && !receipt) return null;
    if (stamp === null) return null;
    const ms = Date.parse(stamp);
    if (Number.isNaN(ms)) return null;
    newest = Math.max(newest, ms);
  }
  return Number.isFinite(newest) ? new Date(newest).toISOString() : null;
}

function incompleteness(
  read: CanonicalLegacyReadOk,
): Extract<
  LegacyScopeRefusal,
  { reason: "canonical_view_incomplete" }
>["diagnostics"] {
  const { omissions, partialRows, unproven } = read.diagnostics;
  return [
    ...omissions.map((entry) => ({
      stream: entry.stream,
      kind: "omitted" as const,
      detail: `${entry.count} rows: ${entry.reasons.join("; ")}`,
    })),
    ...partialRows.map((entry) => ({
      stream: entry.stream,
      kind: "partial" as const,
      detail: `${entry.count} rows: ${entry.reasons.join("; ")}`,
    })),
    // Optional on the canonical-legacy-view/4 contract: omitted when empty.
    ...(unproven ?? []).map((entry) => ({
      stream: entry.stream,
      kind: "unproven" as const,
      detail: `${entry.aspect}: ${entry.reason}`,
    })),
  ];
}
