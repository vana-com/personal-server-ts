import type {
  DeltaApplyResult,
  RegistryChangeDelta,
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
import { createConnectionDeleter, type ConnectionDeleter } from "./delete.js";
import type { LocalSyncDeps } from "./deps.js";
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
import { createRunEndStore } from "./run-end.js";
import { createRunIntakeStore } from "./run-intake.js";

/**
 * The one facade a host holds for a switched owner's stream sync on the
 * database. Node bootstrap and Lite sync build it from deps
 * and wire its parts to the existing routes; nothing else reaches the modules.
 */
export interface LocalSync {
  readonly intake: RunIntake;
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
  /** `/sync/trigger` and the timer: C.4 order, apply then publish. */
  cycle(scope?: CycleScope): Promise<CycleReport>;
  /**
   * A save's await: publish what is pending and return when the registry has
   * committed it (`runPublish`). Apply and the registry listing run in the
   * next `cycle()`, not here.
   */
  publish(): Promise<CycleReport>;
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
    readonly resolveArtifact: ResolveArtifact;
    readonly eraseLegacy?: (connector: string) => Promise<void>;
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
        const pending = await resume();
        await checkBinding(binding);
        const stuck = pending.find((p) => p.connector === req.connector);
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
      // A request waits for the fence no longer than the loop waits to look
      // at a delete that has not landed.
      fenceWaitMs: retryFirst,
    });
  let deleteStore: ConnectionDeleter | undefined;
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
  const resume = async () => {
    const pending = await deletes().resumeDeletes();
    if (pending.length > 0) armRetry();
    else {
      if (retryTimer) clearTimeout(retryTimer);
      retryTimer = undefined;
      retryDelay = retryFirst;
    }
    return pending;
  };
  const deleter: ConnectionDeleter = {
    async requestConnectionDelete(connector) {
      const result = await deletes().requestConnectionDelete(connector);
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
  };
  let closing: Promise<void> | undefined;
  return {
    intake: runIntake,
    deleter,
    resolver: createLocalResolver(deps, {
      query,
      aliasScopes: options.aliasScopes,
      aliasTargets: options.aliasTargets,
    }),
    listing: createLocalListing(listingDeps),
    query,
    recordsFor: (link) => createLinkedRecordQuery(readerOf(deps.db), link),
    changesFor: (link) => createGrantHistory(readerOf(deps.db), link),
    history: createLocalHistory(deps, {
      aliasScopes: options.aliasScopes,
      aliasTargets: options.aliasTargets,
    }),
    declarations: {
      streamsOf: async (connector) =>
        // A stream whose delete floor reaches its head is `tombstoned` for
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
        ).map((row) => row.connector),
    },
    blobs: createBlobStore(deps),
    async cycle(scope) {
      await resume();
      return runCycle(deps, scope);
    },
    async publish() {
      await resume();
      return runPublish(deps);
    },
    async applyDelta(delta) {
      if ((await resume()).length > 0)
        return { outcome: "cycle", reason: "a delete is pending" };
      return applyRegistryDelta(deps, delta);
    },
    async apply() {
      await resume();
      for (const connection of await bootstrapConnections(deps)) {
        await applyConnection(deps, connection.connectionId);
      }
    },
    async syncConnection(connectionId) {
      await resume();
      return syncConnection(deps, connectionId);
    },
    close: () => {
      closed = true;
      clearTimeout(retryTimer);
      retryTimer = undefined;
      return (closing ??= deps.db.close());
    },
  };
}
