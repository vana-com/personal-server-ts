import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import {
  GITHUB_BROWSER_BINDINGS,
  LEGACY_SCOPE_BINDINGS,
  META_040_BINDINGS,
  OURA_BROWSER_BINDINGS,
  type LegacyScopeBinding,
} from "../legacy-projection/index.js";
import {
  readCanonicalLegacyScope,
  resolveCanonicalConnection,
  type CanonicalConnectionBinding,
  type CanonicalConnectionSelection,
  type CanonicalLegacyReadFailure,
  type CanonicalLegacyReadOk,
  type CanonicalLegacyReadStore,
} from "./canonical-legacy-projection.js";

/**
 * Decides, per legacy scope, whether the latest body comes from the
 * canonical rows or from the existing legacy file, and reads it.
 *
 * A scope is canonical when its connector source holds owner evidence in the
 * connection registry: a connection that has held rows or a completion
 * receipt, was reset, or was deleted. A connection that boot registered and
 * nothing ever wrote to is not evidence, so a legacy-only owner keeps the
 * file. For a canonical scope the file is never the latest body: any failure
 * is a refusal.
 *
 * The connection comes only from the registry: the single live connection of
 * the scope's sources, with a method configured on this boot. A request
 * cannot name one.
 */

const SOURCE_ID_PREFIX = "https://registry.pdpp.dev/sources/";
const CONNECTOR_ID_PREFIX = "https://registry.pdpp.dev/connectors/";

/** Every declaration profile the pure module serves a scope from. */
const BINDING_PROFILES: readonly ReadonlyMap<string, LegacyScopeBinding>[] = [
  LEGACY_SCOPE_BINDINGS,
  GITHUB_BROWSER_BINDINGS,
  META_040_BINDINGS,
  OURA_BROWSER_BINDINGS,
];

export interface LegacyScopeViewStore extends CanonicalLegacyReadStore {
  /** Every connection registered for the source, deleted ones included. */
  listSourceBindings(sourceId: string): CanonicalConnectionBinding[];
  /** True once the instance has held a record, live or tombstoned. */
  hasRecordHistory(instance: string): boolean;
}

export type LegacyScopeRefusal =
  | CanonicalLegacyReadFailure
  | {
      status: "unavailable";
      reason: "no_connection" | "ambiguous_connection";
      candidates: number;
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
}

export interface CreateLegacyScopeViewInput {
  store: LegacyScopeViewStore;
  /**
   * Methods this boot configures for a canonical source id. A connection
   * bound to another method is refused, never read.
   */
  configuredMethods(sourceId: string): readonly string[];
}

type Decision =
  | { kind: "file" }
  | { kind: "refused"; refusal: LegacyScopeRefusal }
  | {
      kind: "canonical";
      selection: CanonicalConnectionSelection;
      binding: LegacyScopeBinding;
    };

export function createLegacyScopeView(
  input: CreateLegacyScopeViewInput,
): LegacyScopeViewPort {
  const { store } = input;

  function decide(scope: string): Decision {
    const targets = scopeTargets(scope);
    if (targets.length === 0) return { kind: "file" };
    const evidenced = targets.filter((target) =>
      store
        .listSourceBindings(target.sourceId)
        .some((binding) => isEvidence(store, binding)),
    );
    if (evidenced.length === 0) return { kind: "file" };

    const exact = evidenced.filter((target) => target.binding !== null);
    if (exact.length === 0) {
      // A connector namespace the owner collects into, but no binding maps
      // this scope. Its file cannot be told apart from stale connector data.
      return {
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "unbound_scope",
          lookup: { kind: "unknown_scope", scope },
        },
      };
    }

    const chosen: {
      selection: CanonicalConnectionSelection;
      binding: LegacyScopeBinding;
    }[] = [];
    let candidates = 0;
    for (const target of exact) {
      const resolved = resolveCanonicalConnection(store, {
        sourceId: target.sourceId,
      });
      if (resolved.ok) {
        candidates += 1;
        chosen.push({
          selection: resolved.selection,
          binding: target.binding!,
        });
      } else {
        candidates += resolved.candidates;
      }
    }
    if (candidates === 0) {
      return {
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "no_connection",
          candidates: 0,
        },
      };
    }
    const [only] = chosen;
    if (candidates > 1 || !only) {
      return {
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "ambiguous_connection",
          candidates,
        },
      };
    }
    if (
      !input
        .configuredMethods(only.selection.sourceId)
        .includes(only.selection.method)
    ) {
      return {
        kind: "refused",
        refusal: {
          status: "unavailable",
          reason: "connection_unavailable",
          detail: "method_mismatch",
        },
      };
    }
    return { kind: "canonical", ...only };
  }

  return {
    async readLatest(scope) {
      const decision = store.readSnapshot(() => decide(scope));
      if (decision.kind !== "canonical") return decision;
      const read = await readCanonicalLegacyScope({
        store,
        scope,
        selection: decision.selection,
      });
      if (!read.ok) {
        const { ok: _ok, ...refusal } = read;
        return { kind: "refused", refusal };
      }
      if (!read.complete) {
        return {
          kind: "refused",
          refusal: {
            status: "incomplete",
            reason: "canonical_view_incomplete",
            diagnostics: incompleteness(read),
          },
        };
      }
      return {
        kind: "canonical",
        envelope: read.envelope,
        revision: read.revision,
      };
    },

    listingFor(scope) {
      return store.readSnapshot((): LegacyScopeListing => {
        const decision = decide(scope);
        if (decision.kind !== "canonical") return { kind: decision.kind };
        const collectedAt = listedCollectedAt(
          store,
          decision.selection.instance,
          decision.binding.pdppStreams,
        );
        return collectedAt === null
          ? { kind: "refused" }
          : { kind: "canonical", collectedAt };
      });
    },
  };
}

interface ScopeTarget {
  sourceId: string;
  /** Null when the source only shares the scope's namespace. */
  binding: LegacyScopeBinding | null;
}

/**
 * The canonical sources that could hold a scope: every profile binding of
 * the scope, else every source bound anywhere in the scope's namespace.
 */
function scopeTargets(scope: string): ScopeTarget[] {
  const exact = new Map<string, ScopeTarget>();
  for (const profile of BINDING_PROFILES) {
    const binding = profile.get(scope);
    if (binding) {
      const sourceId = canonicalSourceId(binding.pdppSource);
      exact.set(sourceId, { sourceId, binding });
    }
  }
  if (exact.size > 0) return [...exact.values()];

  const namespace = `${scope.split(".", 1)[0]}.`;
  const shared = new Map<string, ScopeTarget>();
  for (const profile of BINDING_PROFILES) {
    for (const [bound, binding] of profile) {
      if (!bound.startsWith(namespace)) continue;
      const sourceId = canonicalSourceId(binding.pdppSource);
      shared.set(sourceId, { sourceId, binding: null });
    }
  }
  return [...shared.values()];
}

function isEvidence(
  store: LegacyScopeViewStore,
  binding: CanonicalConnectionBinding,
): boolean {
  return (
    binding.deletedAt !== null ||
    binding.generation > 1 ||
    store.hasRecordHistory(binding.instance) ||
    store.listStreamCompletions(binding.instance).length > 0
  );
}

/**
 * The `collectedAt` a read would return, from listing counts and receipts:
 * a stream's valid receipt time, else its newest row time. Null when a bound
 * stream is empty without a valid receipt, which a read refuses.
 */
function listedCollectedAt(
  store: LegacyScopeViewStore,
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
    ...unproven.map((entry) => ({
      stream: entry.stream,
      kind: "unproven" as const,
      detail: `${entry.aspect}: ${entry.reason}`,
    })),
  ];
}

/** Binding sources are `connectors/<name>`; the store registers `sources/<name>`. */
function canonicalSourceId(pdppSource: string): string {
  return pdppSource.startsWith(CONNECTOR_ID_PREFIX)
    ? SOURCE_ID_PREFIX + pdppSource.slice(CONNECTOR_ID_PREFIX.length)
    : pdppSource;
}
