import { createHash } from "node:crypto";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  legacyBindingsForProfile,
  type LegacyScopeBinding,
} from "@opendatalabs/personal-server-ts-core/legacy-projection";
import {
  CANONICAL_LEGACY_VIEW_CONTRACT,
  readCanonicalLegacyScope,
  type CanonicalConnectionSelection,
  type CanonicalLegacyReadStore,
  type ReadCanonicalLegacyScopeInput,
} from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import {
  currentVerdictCursorPrefix,
  scopeMethods,
  type LegacyScopeAuthority,
} from "@opendatalabs/personal-server-ts-core/storage/legacy-scope-view";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { NativeStreamCompletionReceipt } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/completion";
import type { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

/**
 * Native canonical facts for one exact legacy scope, read from this server's
 * own record store. Everything here is rechecked synchronously at the stop
 * barrier. These facts do NOT prove grant inventory, global fencing,
 * durable retention, metrics recovery or reader qualification.
 */
export interface LegacyCanonicalInputs {
  scope: string;
  identity: {
    /** `<source id>@<version>#<digest>` of the retained declaration. */
    declaration: string;
    /** Digest-pinned provenance of the reviewed binding. */
    artifact: string;
    /** View contract, method, scope and reviewed binding shape. */
    projection: string;
    /** Selected connection: `<instance>:<method>:<generation>:<reset clock>`. */
    binding: string;
    servingGeneration: string;
  };
  inputs: { instance: string; stream: string; generation: number }[];
  /** Current native full-stream receipts, one per bound stream. */
  receipts: NativeStreamCompletionReceipt[];
  /** Start of first-addition accounting. An observed window, not retention. */
  additionsTrackedSince: string;
  /**
   * Digest of every fact above plus verified blobs, arrival order, the legacy
   * head and its full current parity verdict.
   */
  inputDigest: string;
}

export interface LegacyCanonicalCoverage extends LegacyCanonicalInputs {
  /** Revision of the complete reviewed projection read over these inputs. */
  projectionRevision: string;
  watermark: string;
}

export type LegacyCanonicalAssessment =
  | { ok: true; coverage: LegacyCanonicalInputs }
  | { ok: false; blockers: string[] };
export type LegacyCanonicalQualification =
  | { ok: true; coverage: LegacyCanonicalCoverage }
  | { ok: false; blockers: string[] };

/** The policy's view of native canonical coverage. */
export interface LegacyCanonicalCoveragePort {
  /** Synchronous; safe inside the policy's SQLite transaction. */
  assess(scope: string, servingGeneration: string): LegacyCanonicalAssessment;
  /** Runs the complete reviewed projection; never inside a transaction. */
  qualify(
    scope: string,
    servingGeneration: string,
  ): Promise<LegacyCanonicalQualification>;
  /** Synchronous barrier recheck of every native input of `coverage`. */
  isCurrent(coverage: LegacyCanonicalCoverage): boolean;
}

type NativeRecordStore = CanonicalLegacyReadStore &
  Pick<
    ReturnType<typeof createSqliteRecordStore>,
    | "listConnections"
    | "getInstanceBinding"
    | "assessStreamCompletion"
    | "firstAddedCoverage"
    | "getBlobMeta"
    | "getBlobBytes"
  >;

export interface LegacyCanonicalCoverageDeps {
  /** The record store over the policy's own database connection. */
  store: NativeRecordStore;
  /** Retained declaration snapshots this boot serves. */
  declarations: readonly DeclarationSnapshot[];
  /** The same registry canonical ingest and the legacy view use. */
  streamDeclarations: ReadCanonicalLegacyScopeInput["declarations"];
  /** Methods this boot configures, keyed by store source id. */
  configuredMethods: ReadonlyMap<string, readonly string[]>;
  /** Connection registry and takeover ledger over the same database connection. */
  authority: Pick<
    LegacyScopeAuthority,
    | "listMethodConnections"
    | "hasHeldData"
    | "eligibleLegacyHead"
    | "hasCoveredHead"
    | "verdictFor"
    | "writeClock"
    | "arrivalRevision"
  >;
}

interface Candidate {
  method: string;
  binding: LegacyScopeBinding;
  declaration: DeclarationSnapshot;
  instance: string;
}

const sha256 = (value: unknown) =>
  createHash("sha256").update(canonicalJson(value)).digest("hex");

export function createLegacyCanonicalCoverage(
  deps: LegacyCanonicalCoverageDeps,
): LegacyCanonicalCoveragePort {
  const { store } = deps;

  function candidates(scope: string): Candidate[] | string {
    const streamsByMethod = scopeMethods(scope);
    if (streamsByMethod.size === 0) return "unbound_scope";
    const configured = (sourceId: string | null, method: string | null) =>
      sourceId !== null &&
      method !== null &&
      (deps.configuredMethods.get(sourceId) ?? []).includes(method) &&
      deps.declarations.some(
        (declaration) => declaration.source_id === sourceId,
      );
    // As the legacy view decides: every live connection of any method of the
    // scope that holds data is a candidate, configured or not. A configured
    // method's live connection counts even while it holds nothing.
    const live = deps.authority
      .listMethodConnections([...streamsByMethod.keys()])
      .filter(
        (connection) =>
          connection.deletedAt === null &&
          (deps.authority.hasHeldData(connection.instance, null) ||
            configured(connection.sourceId, connection.method)),
      );
    const [only] = live;
    if (!only) return "no_connection";
    if (live.length > 1) return "ambiguous_connection";
    const binding = legacyBindingsForProfile(only.method ?? "").get(scope);
    if (!binding || !configured(only.sourceId, only.method))
      return "connection_method_not_configured";
    const declarations = deps.declarations.filter(
      (declaration) => declaration.source_id === only.sourceId,
    );
    if (declarations.length !== 1) return "declaration_ambiguous";
    return [
      {
        method: only.method!,
        binding,
        declaration: declarations[0]!,
        instance: only.instance,
      },
    ];
  }

  /** Every live row of one stream, through the store's own paginated reader. */
  function liveRows(instance: string, stream: string) {
    const rows: { recordKey: string; data: Record<string, unknown> }[] = [];
    let cursor: string | undefined;
    for (;;) {
      const page = store.listRecords(stream, {
        instanceIds: [instance],
        limit: 500,
        cursor,
        order: "asc",
      });
      for (const row of page.data) {
        if (row.instance !== instance || row.stream !== stream)
          throw new Error("foreign row");
        rows.push(row);
      }
      if (!page.hasMore) return rows;
      if (!page.nextCursor || page.nextCursor === cursor)
        throw new Error("cursor did not advance");
      cursor = page.nextCursor;
    }
  }

  function assessInSnapshot(
    scope: string,
    servingGeneration: string,
  ):
    | {
        ok: true;
        coverage: LegacyCanonicalInputs;
        selection: CanonicalConnectionSelection;
      }
    | { ok: false; blockers: string[] } {
    const found = candidates(scope);
    if (typeof found === "string") return { ok: false, blockers: [found] };
    const { method, binding, declaration, instance } = found[0]!;
    const connection = store.getInstanceBinding(instance);
    const blockers: string[] = [];
    if (
      connection.deletedAt !== null ||
      connection.method !== method ||
      connection.sourceId !== declaration.source_id
    )
      return { ok: false, blockers: ["connection_changed"] };

    const artifacts = binding.provenance
      .flatMap((entry) =>
        "digest" in entry ? [`${entry.kind}:${entry.ref}@${entry.digest}`] : [],
      )
      .sort();
    if (artifacts.length === 0) blockers.push("projection_artifact_unpinned");

    const receipts: NativeStreamCompletionReceipt[] = [];
    const blobs = new Map<string, string>();
    const arrival: Record<string, string> = {};
    for (const stream of binding.pdppStreams) {
      const declared = declaration.streams.find((item) => item.name === stream);
      if (!declared) {
        blockers.push(`declaration_stream_missing:${stream}`);
        continue;
      }
      if (
        canonicalJson(declared.primary_key) !==
        canonicalJson(binding.primaryKey[stream] ?? null)
      ) {
        blockers.push(`declaration_primary_key_mismatch:${stream}`);
        continue;
      }
      const assessment = store.assessStreamCompletion({
        instance,
        stream,
        sourceId: declaration.source_id,
        primaryKey: declared.primary_key,
      });
      const receipt = assessment.receipt;
      if (assessment.status !== "current" || !receipt) {
        blockers.push(`completion_${assessment.status}:${stream}`);
        continue;
      }
      if (
        receipt.instance !== instance ||
        receipt.method !== method ||
        receipt.generation !== connection.generation
      ) {
        blockers.push(`completion_identity_mismatch:${stream}`);
        continue;
      }
      receipts.push(receipt);
      let rows;
      try {
        rows = liveRows(instance, stream);
      } catch {
        blockers.push(`records_unreadable:${stream}`);
        continue;
      }
      if (rows.length !== receipt.liveCount) {
        blockers.push(`records_inconsistent:${stream}`);
        continue;
      }
      // The completion digest covers blob references, not their bytes.
      for (const row of rows) {
        if (!Object.hasOwn(row.data, "blob_ref")) continue;
        const ref = row.data.blob_ref as Record<string, unknown> | null;
        const blobId = ref?.blob_id;
        if (typeof blobId !== "string") {
          blockers.push(`blob_reference_invalid:${stream}`);
          break;
        }
        const meta = store.getBlobMeta(blobId);
        if (!meta || !store.getBlobBytes(blobId)) {
          blockers.push(`blob_missing:${stream}`);
          break;
        }
        if (
          (ref!.sha256 !== undefined && ref!.sha256 !== meta.sha256) ||
          (ref!.size_bytes !== undefined && ref!.size_bytes !== meta.sizeBytes)
        ) {
          blockers.push(`blob_reference_mismatch:${stream}`);
          break;
        }
        blobs.set(blobId, meta.sha256);
      }
      if (binding.rowOrder === "arrival")
        arrival[stream] = sha256(store.listArrivalOrder(instance, stream));
    }

    // The latest legacy head counts as covered only by a parity read of this
    // exact connection and generation whose covered verdict still describes
    // the current rows, receipts and declarations (the view's own rule).
    const head = deps.authority.eligibleLegacyHead(scope);
    const verdict = head
      ? deps.authority
          .verdictFor(scope)
          .find(
            (row) =>
              row.instance === instance &&
              row.generation === connection.generation &&
              row.legacyVersionId === head.id,
          )
      : undefined;
    if (
      head &&
      (!deps.authority.hasCoveredHead(scope, head, {
        instance,
        generation: connection.generation,
      }) ||
        verdict?.verdict !== "covered" ||
        !verdict.canonicalCursor.startsWith(
          currentVerdictCursorPrefix(
            deps.authority,
            {
              records: store,
              selection: { instance },
              streams: binding.pdppStreams,
            },
            deps.streamDeclarations,
          ),
        ))
    )
      blockers.push("latest_legacy_head_uncovered");
    const trackedSince = store.firstAddedCoverage([instance])[0]?.trackedSince;
    if (!trackedSince) blockers.push("additions_coverage_unavailable");
    if (blockers.length) return { ok: false, blockers };

    const identity = {
      declaration: `${declaration.source_id}@${declaration.version}#${declaration.digest}`,
      artifact: artifacts.join(","),
      projection: `${CANONICAL_LEGACY_VIEW_CONTRACT}:${method}:${scope}:${sha256(
        {
          pdppSource: binding.pdppSource,
          pdppStreams: binding.pdppStreams,
          primaryKey: binding.primaryKey,
          fieldsRead: binding.fieldsRead,
          legacySchemaPath: binding.legacySchemaPath,
          lossy: binding.lossy,
          rowOrder: binding.rowOrder ?? null,
          ancillaryBlobStreams: binding.ancillaryBlobStreams ?? [],
        },
      )}`,
      binding: `${instance}:${method}:${connection.generation}:${connection.resetClock}`,
      servingGeneration,
    };
    return {
      ok: true,
      selection: { instance, sourceId: declaration.source_id, method },
      coverage: {
        scope,
        identity,
        inputs: receipts.map((receipt) => ({
          instance,
          stream: receipt.stream,
          generation: receipt.generation,
        })),
        receipts,
        additionsTrackedSince: trackedSince!,
        inputDigest: sha256({
          identity,
          receipts,
          blobs: [...blobs].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
          arrival,
          head,
          verdict: verdict ?? null,
          trackedSince,
        }),
      },
    };
  }

  function assessWithSelection(scope: string, servingGeneration: string) {
    return store.readSnapshot(() => assessInSnapshot(scope, servingGeneration));
  }
  const watermark = (inputDigest: string, projectionRevision: string) =>
    sha256({ inputDigest, projectionRevision });

  return {
    assess(scope, servingGeneration) {
      const result = assessWithSelection(scope, servingGeneration);
      return result.ok
        ? { ok: true, coverage: result.coverage }
        : { ok: false, blockers: result.blockers };
    },
    async qualify(scope, servingGeneration) {
      const first = assessWithSelection(scope, servingGeneration);
      if (!first.ok) return first;
      let confirmed = false;
      const read = await readCanonicalLegacyScope({
        store,
        declarations: deps.streamDeclarations,
        scope,
        selection: first.selection,
        profileBy: "method",
        requireCompletionReceipts: true,
        requireClaudeRawBlobs: true,
        // The projected rows come from the same snapshot as a matching assessment.
        confirmSelection: () => {
          const again = assessInSnapshot(scope, servingGeneration);
          confirmed =
            again.ok &&
            again.coverage.inputDigest === first.coverage.inputDigest;
          return confirmed;
        },
      });
      if (!read.ok)
        return { ok: false, blockers: [`projection_${read.reason}`] };
      if (!confirmed || !read.complete)
        return { ok: false, blockers: ["projection_incomplete"] };
      return {
        ok: true,
        coverage: {
          ...first.coverage,
          projectionRevision: read.revision,
          watermark: watermark(first.coverage.inputDigest, read.revision),
        },
      };
    },
    isCurrent(coverage) {
      const current = assessWithSelection(
        coverage.scope,
        coverage.identity.servingGeneration,
      );
      return (
        current.ok &&
        current.coverage.inputDigest === coverage.inputDigest &&
        coverage.watermark ===
          watermark(coverage.inputDigest, coverage.projectionRevision)
      );
    },
  };
}
