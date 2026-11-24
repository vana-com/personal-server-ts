import { createAccessActivity } from "../logging/activity-stream.js";
import { isReservedSystemConnector } from "../policy/reserved-scopes.js";
import type {
  DeltaApplyResult,
  RegistryChangeDelta,
  StreamSyncFiles,
} from "../stream-sync/ports.js";
import { applyRegistryDelta } from "./delta-apply.js";
import {
  readBeginReceipt,
  readEndReceipt,
  readPublicationStatus,
} from "./run-receipts.js";
import { createGrantHistory } from "./query.js";
import {
  createLinkedRecordQuery,
  type ConnectionLink,
} from "./connection-link.js";
import {
  RunIntakeError,
  type ResolveArtifact,
  type RunIntake,
} from "../stream-sync/intake.js";
import { applyConnection } from "./apply.js";
import { bootstrapConnections } from "./bootstrap.js";
import { createBlobStore, type BlobStore } from "./blobs.js";
import {
  runCycle,
  runPublish,
  syncConnection,
  type CycleReport,
  type CycleScope,
} from "./cycle.js";
import {
  createConnectionDeleter,
  type ConnectionDeleter,
  type PendingDelete,
} from "./delete.js";
import type { LocalSyncDeps } from "./deps.js";
import {
  eraseDeletedConnectionLogs,
  retainedPiecesIn,
  type LogErasurePorts,
} from "./log-erase.js";
import { readerOf } from "./driver.js";
import { createLocalHistory, type LocalHistory } from "./history.js";
import { createLocalListing, type LocalListing } from "./listing.js";
import { createRecordQuery, type RecordQuery } from "./query.js";
import {
  createLocalResolver,
  type LocalResolver,
  type AliasScopes,
  type AliasTargets,
} from "./resolve.js";
import { onConnectionPurged } from "./purge.js";
import { ELIGIBLE_CHANGE, PENDING_RUN } from "./publication-work.js";
import { createRunEndStore } from "./run-end.js";
import { createRunIntakeStore } from "./run-intake.js";

/**
 * The one facade a host holds for a switched owner's stream sync on the
 * database. Node bootstrap and Lite sync build it from deps
 * and wire its parts to the existing routes; nothing else reaches the modules.
 */
export interface LocalSync {
  readonly intake: RunIntake;
  readonly accessActivity: ReturnType<typeof createAccessActivity>;
  readonly deleter: ConnectionDeleter;
  readonly resolver: LocalResolver;
  readonly listing: LocalListing;
  readonly query: RecordQuery;
  recordsFor(link: ConnectionLink): RecordQuery;
  changesFor(link: ConnectionLink): ReturnType<typeof createGrantHistory>;
  readonly history: LocalHistory;
  /** What connections here declare: the one source both hosts read it from. */
  readonly declarations: {
    /**
     * The streams a connector has here: those of its active connections that
     * are not deleted, read from the synced stream state, so a device that
     * only synced answers as one that wrote.
     */
    streamsOf(connector: string): Promise<readonly string[]>;
    /** Connectors with an active connection in this database. */
    connectors(): Promise<readonly string[]>;
  };
  readonly blobs: BlobStore;
  hasPendingPublication(): Promise<boolean>;
  /** `/sync/trigger` and the timer: C.4 order, apply then publish. */
  cycle(scope?: CycleScope): Promise<CycleReport>;
  /**
   * A save's await: publish what is pending and return when the registry has
   * committed it (`runPublish`). Apply and the registry listing run in the
   * next `cycle()`, not here.
   */
  publish(awaited?: readonly string[]): Promise<CycleReport>;
  /** Apply remote logs without publishing (download hook). */
  apply(): Promise<void>;
  /**
   * Apply a change delta without the cycle's registry reads, or say that a
   * cycle must run (`applyRegistryDelta`). The host serializes answers and
   * advances its cursor only after this promise or that cycle completes.
   */
  applyDelta(delta: RegistryChangeDelta): Promise<DeltaApplyResult>;
  /** `/sync/file/:id`: apply and publish that connection, then read. */
  syncConnection(
    connectionId: string,
  ): Promise<CycleReport["connections"][number]>;
  close(): Promise<void>;
}

/** Default waits before a failed delete is resumed again; the wait doubles. */
const RESUME_RETRY_FIRST_MS = 5_000;
const RESUME_RETRY_MAX_MS = 5 * 60_000;

export function createLocalSync(
  deps: LocalSyncDeps,
  options: {
    readonly aliasScopes?: AliasScopes;
    readonly aliasTargets?: AliasTargets;
    /** A file space for the bodies of windowed aliases (`projectAlias`). */
    readonly aliasSpool?: StreamSyncFiles;
    readonly resolveArtifact: ResolveArtifact;
    readonly eraseLegacy?: (connector: string) => Promise<void>;
    /**
     * The host's ports for erasing a deleted connection's log objects from
     * storage (`log-erase.ts`). Read when an erasure runs, so a host that
     * builds them after this sync can pass them late; `undefined` (a host
     * that cannot delete from storage) erases nothing.
     */
    readonly erasure?: () => LogErasurePorts | undefined;
    readonly deleting?: (connector: string) => boolean | Promise<boolean>;
    readonly currentLease?: () => string | null;
    /** Waits between resumes of a delete that keeps failing (tests shorten). */
    readonly deleteRetryMs?: { readonly first: number; readonly max: number };
  },
): LocalSync {
  const retryFirst = options.deleteRetryMs?.first ?? RESUME_RETRY_FIRST_MS;
  const retryMax = options.deleteRetryMs?.max ?? RESUME_RETRY_MAX_MS;
  let intakeStore: ReturnType<typeof createRunIntakeStore> | undefined;
  const intake = () => (intakeStore ??= createRunIntakeStore(deps));
  const endStore = createRunEndStore(deps);
  const accessActivity = createAccessActivity(deps);
  const bindings = new Map<
    string,
    { readonly connector: string; readonly leaseId: string | null }
  >();
  const checkBinding = async (binding: {
    readonly connector: string;
    readonly leaseId: string | null;
  }) => {
    if (options.currentLease && options.currentLease() !== binding.leaseId) {
      throw new RunIntakeError("lease_lost");
    }
    if (await options.deleting?.(binding.connector)) {
      throw new RunIntakeError("connection_busy");
    }
  };
  // Runs live in `bindings`, which dies with the process: whatever the database
  // still holds as `collecting` when this sync starts has no one to end it. The
  // list is read once, before any run of this sync can begin, and only those
  // runs are ever ended here: a read at a later begin would also return live
  // runs. `begin` waits for the sweep. A run it could not end is retried at the
  // next `begin`; a failed read of the list fails `begin`, since without it no
  // run could be told from an orphan.
  let orphans: readonly string[] | undefined;
  let sweeping: Promise<void> = Promise.resolve();
  const sweepOnce = (): Promise<void> => {
    const sweep = sweeping.then(async () => {
      orphans ??= await endStore.orphans();
      if (orphans.length > 0) orphans = await endStore.endOrphans(orphans);
    });
    sweeping = sweep.catch(() => {});
    return sweep;
  };
  sweepOnce().catch((error) =>
    deps.logger.warn({ error: String(error) }, "orphaned-run sweep failed"),
  );
  const checkRun = async (runId: string) => {
    const binding = bindings.get(runId);
    if (!binding) throw new RunIntakeError("gone");
    await checkBinding(binding);
  };
  const runIntake: RunIntake = {
    async begin(runId, req) {
      if (
        !req ||
        !req.owner ||
        typeof req.owner.address !== "string" ||
        !/^0x[0-9a-fA-F]{40}$/.test(req.owner.address)
      ) {
        throw new RunIntakeError("invalid_request");
      }
      if (req.owner.address.toLowerCase() !== deps.ownerAddress.toLowerCase()) {
        throw new RunIntakeError("owner_mismatch");
      }
      if (isReservedSystemConnector(req.connector))
        throw new RunIntakeError(
          "invalid_request",
          "reserved system connector",
        );
      await sweepOnce();
      const receipt = await readBeginReceipt(deps.db, runId, req);
      if (receipt) return receipt;
      const binding = {
        connector: req.connector,
        leaseId: req.owner.leaseId,
      };
      await checkBinding(binding);
      const declarations = await options.resolveArtifact(req.artifactDigest);
      if (!declarations) throw new RunIntakeError("unknown_artifact");
      // Artifact resolution can yield while the owner changes the write lease.
      await checkBinding(binding);
      // An unfinished delete fences every run. Try to finish it first; if it
      // cannot finish, say so, so the host can show why the connection waits.
      const unfinished = await deps.db.query(
        "SELECT 1 FROM delete_intents WHERE connector=?",
        [req.connector],
      );
      if (req.connect === true || unfinished.length > 0) {
        const stuck = await deletes().resumeDelete(req.connector);
        if (stuck) armRetry();
        await checkBinding(binding);
        if (stuck)
          throw new RunIntakeError(
            "delete_pending",
            "delete_pending",
            undefined,
            stuck.why,
          );
      }
      const response = await intake().begin(runId, req, declarations);
      if (response.status === "collecting") bindings.set(runId, binding);
      return response;
    },
    async batch(runId, req) {
      await checkRun(runId);
      return intake().batch(runId, req);
    },
    async end(runId, req) {
      const receipt = await readEndReceipt(deps.db, runId);
      if (receipt) return { ...receipt, stuck: false };
      await checkRun(runId);
      // The store owns the atomic merge/checkpoint rule, including retry_pending.
      const result = await endStore.end(runId, req);
      bindings.delete(runId);
      return { ...result, stuck: false };
    },
    async abort(runId, reason) {
      await checkRun(runId);
      await endStore.abort(runId, reason);
      bindings.delete(runId);
    },
    checkpoint(connector) {
      return intake().checkpoint(connector);
    },
    async publicationStatus(runId, binding) {
      if (
        binding?.owner !== undefined &&
        binding.owner.toLowerCase() !== deps.ownerAddress.toLowerCase()
      ) {
        throw new RunIntakeError("owner_mismatch");
      }
      return readPublicationStatus(readerOf(deps.db), runId, {
        connector: binding?.connector,
      });
    },
  };
  const query = createRecordQuery(deps.db);
  const makeDeleter = () =>
    createConnectionDeleter(deps, {
      ...(options.eraseLegacy && { eraseLegacy: options.eraseLegacy }),
      ...(options.erasure && {
        eraseLogs: async (connector, signal, gate) => {
          const ports = options.erasure!();
          return ports
            ? eraseDeletedConnectionLogs(
                {
                  registry: deps.registry,
                  blobs: deps.blobs,
                  keys: deps.keys,
                  streamCrypto: deps.streamCrypto,
                  logger: deps.logger,
                  retained: retainedPiecesIn(deps.db),
                  ...ports,
                },
                {
                  connector,
                  signal,
                  ...(gate && { skipNamespaces: gate.skipNamespaces }),
                },
              )
            : { connections: [], pending: false };
        },
      }),
      // A request waits for the fence no longer than the loop waits to look
      // at a delete that has not landed.
      fenceWaitMs: retryFirst,
    });
  let deleteStore: ReturnType<typeof createConnectionDeleter> | undefined;
  const deletes = () => (deleteStore ??= makeDeleter());
  // A delete that cannot land is retried here, with backoff, until it lands:
  // finishing it must not wait for a begin or a sync cycle to ask.
  let retryTimer: ReturnType<typeof setTimeout> | undefined;
  let retryDelay = retryFirst;
  let closed = false;
  const armRetry = () => {
    if (closed || retryTimer) return;
    const delay = retryDelay;
    retryDelay = Math.min(retryDelay * 2, retryMax);
    retryTimer = setTimeout(() => {
      retryTimer = undefined;
      void resume().catch(armRetry);
    }, delay);
    retryTimer.unref?.();
  };
  // A connection purged here, by a delete made here or one adopted from
  // another device, may be erased from storage once its delete has settled;
  // the retry loop runs the erasure (and decides whether it is time).
  const stopHearingPurges = options.erasure
    ? onConnectionPurged(deps.db, (connector) => {
        if (connector === null) deletes().noteSweepOwed();
        else deletes().noteSettled(connector);
        armRetry();
      })
    : () => {};
  const resumes = new Set<Promise<readonly PendingDelete[]>>();
  const resume = () => {
    const work = resumeOnce();
    resumes.add(work);
    void work.then(
      () => resumes.delete(work),
      () => resumes.delete(work),
    );
    return work;
  };
  const resumeOnce = async () => {
    const pending = await deletes().resumeDeletes();
    // An erasure that is not finished is retried with the same backoff.
    const erasing = await deletes().resumeErasures();
    if (pending.length > 0 || erasing) armRetry();
    else {
      if (retryTimer) clearTimeout(retryTimer);
      retryTimer = undefined;
      retryDelay = retryFirst;
    }
    return pending;
  };
  // Start recovery without holding unrelated connections. The apply and
  // publish paths check their own connector's durable intent before work.
  const kickDeletes = async () => {
    const rows = await deps.db.query<{ connector: string }>(
      "SELECT connector FROM delete_intents ORDER BY connector",
    );
    if (rows.length || deletes().erasureOwed()) void resume().catch(armRetry);
    return rows;
  };
  const deleter: ConnectionDeleter = {
    readConnectionLifetime: (connector) =>
      deletes().readConnectionLifetime(connector),
    async requestConnectionDelete(connector, request) {
      const result = await deletes().requestConnectionDelete(
        connector,
        request,
      );
      // Its landing runs in the background; check back whether it landed.
      armRetry();
      return result;
    },
    resumeDeletes: resume,
  };
  const listingDeps = {
    ...deps,
    aliasScopes: options.aliasScopes,
    aliasTargets: options.aliasTargets,
    aliasSpool: options.aliasSpool,
  };
  // Completion belongs to this owner/network database runtime, not a UI read.
  // A local listing (including an empty one) says nothing about remote data.
  let accountHydrated = false;
  const listing = createLocalListing(listingDeps);
  let closing: Promise<void> | undefined;
  return {
    intake: runIntake,
    async hasPendingPublication() {
      const rows = await deps.db.query(`SELECT 1 FROM system_stream_outbox
        UNION ALL SELECT 1 FROM record_changes JOIN stream_state s
          ON s.connection_id=record_changes.connection_id AND s.stream=record_changes.stream
          WHERE record_changes.seq>s.publish_watermark AND ${ELIGIBLE_CHANGE}
        UNION ALL SELECT 1 FROM runs r JOIN run_streams rs ON rs.run_id=r.run_id
          WHERE ${PENDING_RUN} LIMIT 1`);
      return rows.length > 0;
    },
    accessActivity,
    deleter,
    resolver: createLocalResolver(deps, {
      query,
      aliasQuery: query,
      aliasScopes: options.aliasScopes,
      aliasTargets: options.aliasTargets,
      aliasSpool: options.aliasSpool,
    }),
    listing: {
      ...listing,
      async status(options) {
        return { ...(await listing.status(options)), accountHydrated };
      },
    },
    query,
    recordsFor: (link) => createLinkedRecordQuery(readerOf(deps.db), link),
    changesFor: (link) => createGrantHistory(readerOf(deps.db), link),
    history: createLocalHistory(deps, {
      aliasScopes: options.aliasScopes,
      aliasTargets: options.aliasTargets,
    }),
    declarations: {
      streamsOf: async (connector) =>
        isReservedSystemConnector(connector)
          ? []
          : // A stream whose delete floor reaches its head is `tombstoned` for
            // reads (read-selection.ts), unless a load of a newer head of this
            // generation has applied parts (`partialReadable`). One with no head
            // yet and no floor is mid first load.
            (
              await readerOf(deps.db).query<{ stream: string }>(
                `SELECT DISTINCT s.stream FROM stream_state s
               JOIN connections c ON c.connection_id = s.connection_id
              WHERE c.connector = ? AND c.control_state = 'active'
                AND c.deleted_at IS NULL
                AND (s.last_delete_version = 0
                     OR s.head_version > s.last_delete_version
                     OR EXISTS (SELECT 1 FROM stream_partial p
                                 WHERE p.connection_id = s.connection_id
                                   AND p.stream = s.stream
                                   AND p.generation = c.generation
                                   AND p.version > s.last_delete_version))
              ORDER BY s.stream`,
                [connector],
              )
            ).map((row) => row.stream),
      connectors: async () =>
        (
          await readerOf(deps.db).query<{ connector: string }>(
            "SELECT DISTINCT connector FROM connections WHERE control_state='active' ORDER BY connector",
          )
        )
          .map((row) => row.connector)
          .filter((connector) => !isReservedSystemConnector(connector)),
    },
    blobs: createBlobStore(deps),
    async cycle(scope) {
      await kickDeletes();
      let allApplied = true;
      const report = await runCycle(deps, scope, undefined, (outcome) => {
        if (outcome.kind !== "applied") allApplied = false;
      });
      if (
        !scope &&
        allApplied &&
        report.connections.every((connection) => connection.error === null)
      )
        accountHydrated = true;
      // Maintenance stages activity for a later publish. It must not delay
      // the early publish between a collection's admitted batch and its end.
      await accessActivity.drain();
      await accessActivity.prune();
      await accessActivity.project();
      return report;
    },
    async publish(awaited) {
      await kickDeletes();
      const report = await runPublish(deps, awaited);
      await accessActivity.project();
      return report;
    },
    async applyDelta(delta) {
      if ((await kickDeletes()).length > 0)
        return { outcome: "cycle", reason: "a delete is pending" };
      const result = await applyRegistryDelta(deps, delta);
      await accessActivity.project();
      return result;
    },
    async apply() {
      await kickDeletes();
      const listed = await deps.registry.listOwnerRows();
      let failed = false;
      let allApplied = true;
      let firstError: unknown;
      for (const connection of await bootstrapConnections(deps, listed)) {
        try {
          const outcome = await applyConnection(
            deps,
            connection.connectionId,
            listed,
            listed.find((row) => row.scope === connection.connectionId)?.read,
          );
          if (outcome.kind !== "applied") allApplied = false;
        } catch (error) {
          if (!failed) firstError = error;
          failed = true;
        }
      }
      if (failed)
        throw firstError instanceof Error
          ? firstError
          : new Error(String(firstError));
      await accessActivity.project();
      if (allApplied) accountHydrated = true;
    },
    async syncConnection(connectionId) {
      await kickDeletes();
      const report = await syncConnection(deps, connectionId);
      await accessActivity.project();
      return report;
    },
    close: () => {
      closed = true;
      stopHearingPurges();
      clearTimeout(retryTimer);
      retryTimer = undefined;
      return (closing ??= (async () => {
        await deleteStore?.close();
        await Promise.allSettled([...resumes]);
        await deps.db.close();
      })());
    },
  };
}
