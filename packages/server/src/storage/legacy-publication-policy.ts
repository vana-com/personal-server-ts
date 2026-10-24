import type Database from "better-sqlite3";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import { z } from "zod";
import { createHash } from "node:crypto";
import { DataFileEnvelopeSchema } from "@opendatalabs/vana-sdk/browser";
import type { ImportReceipt } from "@opendatalabs/personal-server-ts-core/ports";
import {
  canonicalJson,
  type HierarchyManagerOptions,
} from "@opendatalabs/personal-server-ts-core/storage/hierarchy";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import {
  initializeLegacyPublicationPolicy,
  retainCanonicalInputs,
} from "./legacy-publication-fence.js";
import { legacyScopeMayReference } from "./legacy-publication-issuance.js";
import { historyOnlyPredicate, indexDatabase } from "./index-manager.js";
import { createImportOperations } from "./import-operations.js";
import type {
  LegacyCanonicalCoverage,
  LegacyCanonicalCoveragePort,
} from "./legacy-publication-canonical.js";

export interface LegacyPolicyIdentity {
  owner: string;
  serverGeneration: string;
}
export type LegacyPublicationState =
  "mirroring" | "quiescing" | "stopped" | "restoring";
export interface LegacyPublicationPolicy extends LegacyPolicyIdentity {
  scope: string;
  state: LegacyPublicationState;
  epoch: number;
  ownerOptIn: boolean;
  evidence: LegacyShutdownEvidence | null;
  identityMismatch?: boolean;
  blockers: { id: string; kind: string }[];
}

const nonempty = z.string().min(1);
const yes = z.literal(true);
const identitySchema = z.object({
  owner: nonempty,
  serverGeneration: nonempty,
  scope: nonempty,
});
const evidenceSchema = identitySchema.extend({
  contractVersion: z.literal(1),
  epoch: z.number().int().positive(),
  legacyCasRevision: z.number().int().nonnegative(),
  localIntentIds: z.array(nonempty),
  inventory: z.object({
    authoritative: yes,
    complete: yes,
    revision: nonempty,
    aliasesResolved: yes,
    paginationComplete: yes,
    issuersConnected: yes,
    // These are *all effective references* after authoritative alias,
    // wildcard and delegation resolution, not a Desktop listGrants result.
    credentials: z.array(
      z.object({
        id: nonempty,
        state: z.enum(["revoked-final", "expired-final", "publication-final"]),
        scopesResolved: yes,
      }),
    ),
    // Includes credentials that were signed but never submitted locally.
    localIntentIds: z.array(nonempty),
  }),
  globalFence: z.object({
    id: nonempty,
    allIssuers: yes,
    renewals: yes,
    durable: yes,
    writerAdmission: yes,
    remotePublicationDrained: yes,
  }),
  canonical: z.object({
    identity: z.object({
      declaration: nonempty,
      artifact: nonempty,
      projection: nonempty,
      binding: nonempty,
      servingGeneration: nonempty,
    }),
    watermark: nonempty,
    inputs: z
      .array(
        z.object({
          instance: nonempty,
          stream: nonempty,
          generation: z.number().int().positive(),
        }),
      )
      .min(1),
    completeBaseline: yes,
    pagination: yes,
    joins: yes,
    blobs: yes,
    incrementalAndDeletion: yes,
    latestLegacyResolved: yes,
    noFailedIngest: yes,
    noForeignOrHeldHeads: yes,
  }),
  retention: z.object({
    legacyHistoryReadable: yes,
    canonicalHistoryDurable: yes,
    ownerReadersQualified: yes,
    metricsRecoveryQualified: yes,
    noLegacyWritingRecovery: yes,
    restartReadbackPassed: yes,
    rollbackCompatibilityPassed: yes,
  }),
});
export type LegacyShutdownEvidence = z.infer<typeof evidenceSchema>;
export interface LegacyQualificationContext extends LegacyPolicyIdentity {
  scope: string;
  epoch: number;
  legacyCasRevision: number;
  localIntentIds: string[];
  /** Native canonical coverage the evidence must echo exactly. */
  canonical: LegacyCanonicalCoverage;
}
/**
 * Trusted host capability, never supplied by HTTP callers. freezeAndQualify
 * must acquire a durable cross-issuer issuance/renewal fence BEFORE taking
 * its complete inventory snapshot. It must remain fenced after timeouts,
 * failed local commits, restart and server handoff; there is no TTL release.
 * assertCurrent must synchronously verify retention and the external fence
 * receipt at this SQLite snapshot. The policy itself rechecks the native
 * canonical inputs (context.canonical) in the same transaction.
 * An async check, cached declaration, latest-only store or unversioned grant
 * listing cannot implement this port. No production implementation exists yet.
 */
export interface LegacyShutdownQualification {
  freezeAndQualify(context: LegacyQualificationContext): Promise<unknown>;
  assertCurrent(evidence: LegacyShutdownEvidence): boolean;
}

const restorationProjectionSchema = identitySchema.extend({
  contractVersion: z.literal(1),
  canonicalRevision: nonempty,
  canonicalIdentity: evidenceSchema.shape.canonical.shape.identity,
  completeCurrentProjection: yes,
  blobsHydrated: yes,
  historyRecoveryQualified: yes,
  envelope: DataFileEnvelopeSchema.passthrough().extend({
    producer: z.literal("pdpp-projector"),
  }),
});
export type LegacyRestorationProjection = z.infer<
  typeof restorationProjectionSchema
>;
const remoteConfirmationSchema = identitySchema.extend({
  epoch: z.number().int().positive(),
  canonicalRevision: nonempty,
  operation: nonempty,
  bodySha256: nonempty,
  headGeneration: nonempty,
  remoteRevision: nonempty,
  visible: yes,
  historyRecoveryQualified: yes,
});
export type LegacyRestorationConfirmation = z.infer<
  typeof remoteConfirmationSchema
>;
export interface LegacyRestorationCommit {
  projection: LegacyRestorationProjection;
  receipt: ImportReceipt;
  epoch: number;
  headGeneration: string;
}
/** Trusted recovery adapter. It must use the complete current canonical view,
 * including unchanged streams, hydration and the retained-history adapter.
 * assertCurrent reads this DB's canonical snapshot synchronously.
 * confirmRemote must reconcile uncertain delivery by operation and digest.
 * commitReopen must synchronously record a durable issuer reopening decision
 * in THIS SQLite transaction (e.g. a globally honored transactional outbox).
 * It must not reopen an issuer before this transaction commits. A network
 * call or best-effort notification cannot implement commitReopen.
 */
export interface LegacyRestorationAdapter {
  prepare(
    context: LegacyPolicyIdentity & { scope: string; epoch: number },
  ): Promise<unknown>;
  assertCurrent(projection: LegacyRestorationProjection): boolean;
  confirmRemote(commit: LegacyRestorationCommit): Promise<unknown>;
  commitReopen(
    commit: LegacyRestorationCommit & {
      confirmation: LegacyRestorationConfirmation;
    },
  ): boolean;
}

interface PolicyRow {
  owner: string;
  server_generation: string;
  scope: string;
  state: LegacyPublicationState;
  epoch: number;
  owner_opt_in: number;
  evidence_json: string | null;
}

const exactScope = /^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+$/;
function validateScope(scope: string): void {
  if (!exactScope.test(scope))
    throw new ProtocolError(
      400,
      "INVALID_LEGACY_SCOPE",
      "An exact legacy scope is required",
    );
}
function fail(code: string, message: string): never {
  throw new ProtocolError(409, code, message);
}
function sameSet(a: string[], b: string[]): boolean {
  return (
    a.length === b.length &&
    new Set(a).size === a.length &&
    [...a].sort().every((value, i) => value === [...b].sort()[i])
  );
}

export function createLegacyPublicationPolicy(
  db: Database.Database,
  options: LegacyPolicyIdentity & {
    enabled: () => boolean;
    qualification?: LegacyShutdownQualification;
    canonical?: LegacyCanonicalCoveragePort;
    restoration?: LegacyRestorationAdapter;
    storage?: {
      indexManager: IndexManager;
      hierarchyOptions: HierarchyManagerOptions;
    };
    now?: () => number;
    maxRestorationBytes?: number;
  },
) {
  initializeLegacyPublicationPolicy(db);
  const identity = {
    owner: options.owner.toLowerCase(),
    serverGeneration: options.serverGeneration,
  };
  const immediate = <T>(run: () => T): T => db.transaction(run).immediate();
  function rowFor(scope: string): PolicyRow | undefined {
    // A fence from *any* identity wins. Switching owner/generation never
    // creates an unfenced default and never transfers consent or evidence.
    return db
      .prepare(
        `SELECT * FROM legacy_publication_policy WHERE scope = ?
      ORDER BY (state != 'mirroring') DESC, epoch DESC LIMIT 1`,
      )
      .get(scope) as PolicyRow | undefined;
  }
  function read(scope: string): LegacyPublicationPolicy {
    validateScope(scope);
    const blockers = db
      .prepare(
        "SELECT id, kind FROM legacy_publication_holds WHERE scope=? ORDER BY id",
      )
      .all(scope) as { id: string; kind: string }[];
    const row = rowFor(scope);
    if (!row)
      return {
        ...identity,
        scope,
        state: "mirroring",
        epoch: 0,
        ownerOptIn: false,
        evidence: null,
        blockers,
      };
    const mismatch =
      row.owner !== identity.owner ||
      row.server_generation !== identity.serverGeneration;
    return {
      ...identity,
      scope,
      state: row.state,
      blockers,
      epoch: row.epoch,
      ownerOptIn: !mismatch && row.owner_opt_in === 1,
      evidence:
        !mismatch && row.evidence_json
          ? evidenceSchema.parse(JSON.parse(row.evidence_json))
          : null,
      ...(mismatch ? { identityMismatch: true } : {}),
    };
  }
  function check(
    scope: string,
    expectedEpoch: number,
  ): LegacyPublicationPolicy {
    const policy = read(scope);
    if (policy.identityMismatch)
      fail(
        "LEGACY_POLICY_IDENTITY_MISMATCH",
        "An earlier owner/generation policy requires explicit recovery; its fence remains active",
      );
    if (!Number.isSafeInteger(expectedEpoch) || policy.epoch !== expectedEpoch)
      fail(
        "LEGACY_POLICY_EPOCH_MISMATCH",
        "Read the current policy epoch before requesting a transition",
      );
    return policy;
  }
  function revision(scope: string): number {
    return (
      (
        db
          .prepare("SELECT cas_revision FROM scope_revisions WHERE scope = ?")
          .get(scope) as { cas_revision: number } | undefined
      )?.cas_revision ?? 0
    );
  }
  function intents(scope: string): string[] {
    return (
      db
        .prepare(
          "SELECT id, scopes_json FROM legacy_publication_issuance WHERE owner = ? ORDER BY id",
        )
        .all(identity.owner) as { id: string; scopes_json: string }[]
    )
      .filter((row) => {
        try {
          const scopes: unknown = JSON.parse(row.scopes_json);
          return (
            !Array.isArray(scopes) ||
            !scopes.every((scope) => typeof scope === "string") ||
            legacyScopeMayReference(scopes, scope)
          );
        } catch {
          return true;
        }
      })
      .map((row) => row.id);
  }
  function persist(
    scope: string,
    state: LegacyPublicationState,
    epoch: number,
    evidence: LegacyShutdownEvidence | null,
  ): void {
    db.pragma("user_version = 17");
    db.prepare(
      `INSERT INTO legacy_publication_policy(owner, server_generation, scope, state, epoch, owner_opt_in, evidence_json)
      VALUES (?, ?, ?, ?, ?, 1, ?)
      ON CONFLICT(owner, server_generation, scope) DO UPDATE SET state=excluded.state, epoch=excluded.epoch, owner_opt_in=1, evidence_json=excluded.evidence_json`,
    ).run(
      identity.owner,
      identity.serverGeneration,
      scope,
      state,
      epoch,
      evidence ? JSON.stringify(evidence) : null,
    );
    db.prepare(
      "INSERT OR IGNORE INTO legacy_publication_transitions(owner, server_generation, scope, state, epoch, evidence_json) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(
      identity.owner,
      identity.serverGeneration,
      scope,
      state,
      epoch,
      evidence ? JSON.stringify(evidence) : null,
    );
  }
  function capabilities() {
    const rollback = !!options.restoration && !!options.storage;
    return {
      enrollmentEnabled: options.enabled(),
      shutdown: !!options.qualification && !!options.canonical,
      // Real local facts only: receipts, projection, blobs, legacy head.
      nativeCanonicalCoverage: !!options.canonical,
      rollback,
      missing: [
        ...(!options.qualification
          ? [
              "authoritative_inventory_and_global_issuance_fence",
              "qualified_canonical_retention_and_recovery",
            ]
          : []),
        ...(!options.canonical ? ["native_canonical_coverage"] : []),
        ...(!rollback
          ? ["canonical_projection_restore_and_remote_reopen"]
          : []),
      ],
    };
  }
  function blocked(blockers: string[]): never {
    throw new ProtocolError(
      409,
      "LEGACY_SHUTDOWN_BLOCKED",
      "Native canonical coverage is incomplete or changed",
      { blockers },
    );
  }
  return {
    read,
    capabilities,
    /** Native canonical facts for owner readback; null without a record store. */
    canonicalCoverage(scope: string) {
      validateScope(scope);
      return (
        options.canonical?.assess(scope, identity.serverGeneration) ?? null
      );
    },
    async stop(
      scope: string,
      input: { ownerOptIn: boolean; expectedEpoch: number },
    ): Promise<LegacyPublicationPolicy> {
      const context = immediate(
        (): Omit<LegacyQualificationContext, "canonical"> | undefined => {
          const current = check(scope, input.expectedEpoch);
          if (current.state === "stopped") return undefined;
          if (current.state === "restoring")
            fail(
              "LEGACY_POLICY_TRANSITION",
              "Rollback must finish before another shutdown",
            );
          if (current.blockers.length)
            fail(
              "LEGACY_SHUTDOWN_BLOCKED",
              "Held legacy changes require explicit recovery before qualification",
            );
          if (!options.enabled())
            fail(
              "LEGACY_SHUTDOWN_DISABLED",
              "Legacy write shutdown enrollment is disabled",
            );
          if (input.ownerOptIn !== true)
            fail(
              "LEGACY_OWNER_OPT_IN_REQUIRED",
              "The owner must opt in to this exact scope and generation",
            );
          if (!options.qualification || !options.canonical)
            throw new ProtocolError(
              503,
              "LEGACY_SHUTDOWN_UNAVAILABLE",
              "Authoritative shutdown qualification is unavailable",
              { missing: capabilities().missing },
            );
          if (
            db
              .prepare(
                "SELECT 1 FROM owner_import_operations WHERE scope = ? AND state = 'prepared' LIMIT 1",
              )
              .get(scope)
          )
            fail(
              "LEGACY_SHUTDOWN_BLOCKED",
              "Accepted legacy imports must drain before quiescing",
            );
          if (
            db
              .prepare(
                // Same publishability as the upload queue (findUnsynced).
                `SELECT 1 FROM data_files AS entry WHERE entry.scope = ? AND entry.data_point_id IS NULL
          AND NOT (${historyOnlyPredicate}) LIMIT 1`,
              )
              .get(scope)
          )
            fail(
              "LEGACY_SHUTDOWN_BLOCKED",
              "Queued legacy publications must drain before quiescing",
            );
          // Refuse before fencing when this server's own canonical inputs fail.
          const native = options.canonical.assess(
            scope,
            identity.serverGeneration,
          );
          if (!native.ok) blocked(native.blockers);
          const epoch =
            current.state === "quiescing" ? current.epoch : current.epoch + 1;
          persist(scope, "quiescing", epoch, null);
          return {
            ...identity,
            scope,
            epoch,
            legacyCasRevision: revision(scope),
            localIntentIds: intents(scope),
          };
        },
      );
      if (!context) return read(scope);
      // This asynchronous gap is deliberate. Local writes and credential
      // signatures are already fenced durably; a losing stop stays quiescing.
      const native = await options.canonical!.qualify(
        scope,
        identity.serverGeneration,
      );
      if (!native.ok) blocked(native.blockers);
      const canonical = native.coverage;
      const raw = await options.qualification!.freezeAndQualify({
        ...context,
        canonical,
      });
      const parsed = evidenceSchema.safeParse(raw);
      if (!parsed.success)
        throw new ProtocolError(
          409,
          "LEGACY_SHUTDOWN_BLOCKED",
          "Incomplete or non-terminal shutdown evidence",
          {
            blockers: parsed.error.issues.map((issue) => issue.path.join(".")),
          },
        );
      const evidence = parsed.data;
      return immediate(() => {
        const current = check(scope, context.epoch);
        if (current.state !== "quiescing")
          fail(
            "LEGACY_POLICY_TRANSITION",
            "The stop barrier is no longer quiescing",
          );
        if (current.blockers.length)
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "Held legacy changes require explicit recovery before qualification",
          );
        if (!options.enabled())
          fail(
            "LEGACY_SHUTDOWN_DISABLED",
            "Shutdown was disabled while qualification was running; the fence remains active",
          );
        if (
          evidence.owner !== identity.owner ||
          evidence.serverGeneration !== identity.serverGeneration ||
          evidence.scope !== scope ||
          evidence.epoch !== context.epoch ||
          evidence.canonical.identity.servingGeneration !==
            identity.serverGeneration
        )
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "Shutdown evidence belongs to a different owner, generation, scope or epoch",
          );
        if (
          evidence.legacyCasRevision !== context.legacyCasRevision ||
          revision(scope) !== context.legacyCasRevision
        )
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "A legacy commit changed the captured barrier",
          );
        if (
          !sameSet(evidence.localIntentIds, context.localIntentIds) ||
          !sameSet(evidence.inventory.localIntentIds, intents(scope))
        )
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "The authoritative inventory did not resolve every local issuance intent",
          );
        const local = db
          .prepare(
            "SELECT id, kind FROM legacy_publication_issuance WHERE owner = ?",
          )
          .all(identity.owner) as { id: string; kind: string }[];
        if (
          local
            .filter((intent) => intents(scope).includes(intent.id))
            .some(
              (intent) =>
                !evidence.inventory.credentials.some(
                  (credential) =>
                    credential.id === intent.id &&
                    (intent.kind === "publication"
                      ? credential.state === "publication-final"
                      : credential.state !== "publication-final"),
                ),
            )
        )
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "A signed or submitted local credential has no authoritative terminal resolution",
          );
        if (
          canonicalJson(evidence.canonical.identity) !==
            canonicalJson(canonical.identity) ||
          evidence.canonical.watermark !== canonical.watermark ||
          canonicalJson(evidence.canonical.inputs) !==
            canonicalJson(canonical.inputs)
        )
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "Shutdown evidence does not bind this server's native canonical coverage",
          );
        // Same transaction as the stopped write: no await, no cached readiness.
        if (!options.canonical!.isCurrent(canonical))
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "Native canonical inputs changed before commit",
          );
        if (options.qualification!.assertCurrent(evidence) !== true)
          fail(
            "LEGACY_SHUTDOWN_BLOCKED",
            "Canonical coverage, retention or the global fence changed before commit",
          );
        db.prepare(
          "INSERT OR IGNORE INTO legacy_publication_retained_versions SELECT id FROM data_files WHERE scope = ?",
        ).run(scope);
        retainCanonicalInputs(db, evidence.canonical.inputs);
        persist(scope, "stopped", current.epoch + 1, evidence);
        return read(scope);
      });
    },
    async rollback(
      scope: string,
      input: { expectedEpoch: number },
    ): Promise<LegacyPublicationPolicy> {
      const restoring = immediate(() => {
        const current = check(scope, input.expectedEpoch);
        if (current.state === "mirroring")
          fail("LEGACY_POLICY_TRANSITION", "This scope is already mirroring");
        if (current.state !== "restoring")
          persist(scope, "restoring", current.epoch + 1, current.evidence);
        return read(scope);
      });
      if (restoring.blockers.length)
        fail(
          "LEGACY_RESTORE_BLOCKED",
          "Held legacy changes require explicit recovery before restoration",
        );
      const adapter = options.restoration;
      const storage = options.storage;
      if (!adapter || !storage || indexDatabase(storage.indexManager) !== db)
        throw new ProtocolError(
          503,
          "LEGACY_RESTORE_UNAVAILABLE",
          "Full current canonical restoration and remote-confirmed issuance reopening are unavailable; the scope remains restoring",
        );
      const parsed = restorationProjectionSchema.safeParse(
        await adapter.prepare({ ...identity, scope, epoch: restoring.epoch }),
      );
      if (!parsed.success)
        throw new ProtocolError(
          409,
          "LEGACY_RESTORE_BLOCKED",
          "A complete current canonical projection is required",
          {
            blockers: parsed.error.issues.map((issue) => issue.path.join(".")),
          },
        );
      const projection = parsed.data;
      if (
        projection.owner !== identity.owner ||
        projection.serverGeneration !== identity.serverGeneration ||
        projection.scope !== scope ||
        projection.envelope.scope !== scope ||
        projection.canonicalIdentity.servingGeneration !==
          identity.serverGeneration
      )
        fail(
          "LEGACY_RESTORE_BLOCKED",
          "Canonical restoration identity mismatch",
        );
      const operation = createHash("sha256")
        .update(
          canonicalJson([
            identity.owner,
            identity.serverGeneration,
            scope,
            restoring.epoch,
            projection.canonicalRevision,
          ]),
        )
        .digest("hex");
      const bodyJson = canonicalJson(projection.envelope.data);
      if (
        Buffer.byteLength(bodyJson, "utf8") >
        (options.maxRestorationBytes ?? 512 * 1024 * 1024)
      )
        throw new ProtocolError(
          413,
          "LEGACY_RESTORE_TOO_LARGE",
          "Complete canonical projection exceeds the restoration limit; the scope remains restoring",
        );
      const bodySha256 = createHash("sha256").update(bodyJson).digest("hex");
      // Preserve the import journal's two durable phases. Do NOT wrap its
      // prepare and publication transactions in one outer transaction: a crash
      // after file publication would otherwise lose the prepared operation.
      const operations = createImportOperations(
        db,
        storage.indexManager,
        storage.hierarchyOptions,
      );
      const authority = `legacy-restore:${identity.serverGeneration}`;
      immediate(() => {
        const current = check(scope, restoring.epoch);
        if (
          current.state !== "restoring" ||
          adapter.assertCurrent(projection) !== true
        )
          fail(
            "LEGACY_RESTORE_BLOCKED",
            "Canonical projection changed before restoration commit",
          );
        if (
          db
            .prepare(
              `SELECT 1 FROM legacy_publication_restore_versions r
          JOIN data_files f ON f.id=r.version_id WHERE f.scope=? AND r.operation=? AND r.state='superseded'`,
            )
            .get(scope, operation)
        )
          fail(
            "LEGACY_RESTORE_BLOCKED",
            "A superseded restoration cannot become current again; a new canonical revision is required",
          );
        // Retirement is durable before another operation can publish. Keep the
        // accepted journal, retained row and file; only publication eligibility ends.
        db.prepare(
          `UPDATE legacy_publication_restore_versions SET state='superseded'
          WHERE version_id IN (SELECT id FROM data_files WHERE scope=?) AND state='current' AND operation!=?`,
        ).run(scope, operation);
        db.prepare(
          `INSERT INTO legacy_publication_restore_authorization(scope, owner, server_generation, epoch, operation, authority, body_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(scope) DO UPDATE SET owner=excluded.owner, server_generation=excluded.server_generation, epoch=excluded.epoch, operation=excluded.operation, authority=excluded.authority, body_sha256=excluded.body_sha256`,
        ).run(
          scope,
          identity.owner,
          identity.serverGeneration,
          current.epoch,
          operation,
          authority,
          bodySha256,
        );
      });
      const result = operations.commitVersionSync({
        kind: "append",
        envelope: {
          ...projection.envelope,
          collectedAt: new Date((options.now ?? Date.now)()).toISOString(),
        },
        metadata: {},
        import: { authority, owner: identity.owner, operation, bodySha256 },
      });
      const receipt = result.receipt!;
      const head = storage.indexManager.findLatestByScope(scope);
      if (!head?.generation || head.collectedAt !== receipt.collectedAt)
        fail(
          "LEGACY_RESTORE_BLOCKED",
          "Restored operation is not the persisted latest legacy head",
        );
      const commit: LegacyRestorationCommit = {
        projection,
        receipt,
        epoch: restoring.epoch,
        headGeneration: head.generation,
      };
      const remote = remoteConfirmationSchema.safeParse(
        await adapter.confirmRemote(commit),
      );
      if (!remote.success)
        fail(
          "LEGACY_RESTORE_BLOCKED",
          "Remote delivery or historical recovery is not confirmed",
        );
      const confirmation = remote.data;
      if (
        confirmation.owner !== identity.owner ||
        confirmation.serverGeneration !== identity.serverGeneration ||
        confirmation.scope !== scope ||
        confirmation.epoch !== commit.epoch ||
        confirmation.canonicalRevision !== projection.canonicalRevision ||
        confirmation.operation !== operation ||
        confirmation.bodySha256 !== bodySha256 ||
        confirmation.headGeneration !== commit.headGeneration
      )
        fail(
          "LEGACY_RESTORE_BLOCKED",
          "Remote confirmation does not identify this restored operation",
        );
      return immediate(() => {
        const current = check(scope, restoring.epoch);
        const head = storage.indexManager.findLatestByScope(scope);
        if (
          current.state !== "restoring" ||
          head?.generation !== commit.headGeneration ||
          head.collectedAt !== commit.receipt.collectedAt ||
          adapter.assertCurrent(projection) !== true
        )
          fail(
            "LEGACY_RESTORE_BLOCKED",
            "Current canonical projection or restored legacy head changed before reopening",
          );
        if (current.blockers.length)
          fail(
            "LEGACY_RESTORE_BLOCKED",
            "Held legacy changes require explicit recovery before reopening",
          );
        if (
          storage.indexManager
            .findUnsynced()
            .some((entry) => entry.scope === scope && entry.id !== head.id)
        )
          fail(
            "LEGACY_RESTORE_BLOCKED",
            "Unresolved queued versions must settle before reopening",
          );
        if (adapter.commitReopen({ ...commit, confirmation }) !== true)
          fail(
            "LEGACY_RESTORE_BLOCKED",
            "Global issuer reopening could not be recorded atomically",
          );
        db.prepare(
          "INSERT OR IGNORE INTO legacy_publication_retained_versions SELECT id FROM data_files WHERE scope = ?",
        ).run(scope);
        // Preserve shutdown evidence and the qualified restoration receipt.

        db.prepare(
          "INSERT INTO legacy_publication_restorations VALUES (?, ?, ?, ?, ?, ?)",
        ).run(
          identity.owner,
          identity.serverGeneration,
          scope,
          current.epoch,
          JSON.stringify(commit.receipt),
          JSON.stringify(confirmation),
        );
        persist(scope, "mirroring", current.epoch + 1, current.evidence);
        db.prepare(
          "UPDATE legacy_publication_restore_versions SET state='confirmed' WHERE version_id=? AND state='current'",
        ).run(head.id);
        db.prepare(
          "DELETE FROM legacy_publication_restore_authorization WHERE scope = ?",
        ).run(scope);
        return read(scope);
      });
    },
  };
}
