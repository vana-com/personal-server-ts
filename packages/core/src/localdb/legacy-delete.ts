// The legacy stage of a connection delete: retire the connector's legacy copy
// at the gateway and in storage once the connection's control tombstone is
// final.
//
// It is driven by state, not by the device that started the delete: a deleted
// control row of connector C in the registry, a legacy scope bound to C
// (`ports.scopesOf`) whose gateway head is live. Any device of the
// account that sees both does the work, and the gateway's version check makes
// a repeat or a race safe (a second tombstone over a deleted head is a no-op).
//
// It does not use `delete_intents`: that row means "a delete is landing", is
// read by every reconnect and sync path as a block, and a legacy retire may
// take hours behind storage's rate limit. A restart resumes it from state: the
// start sweep re-lists the deleted control rows and the gateway heads.
//
// The tombstone leaves through the seal's `remove` (`deleteScope`), so it is
// admitted after the switch; the seal's `commit` stays closed to every legacy
// write that adds data. Blob deletes ride the pending-blob-deletion store.
//
// WHEN A SCOPE IS DONE
//
// A scope is `done` only on evidence that survives a crash and that any device
// of the account can re-check: a deleted head at the gateway, a finalized
// tombstone, and every slot of the scope's gateway history answered "deleted"
// or "missing" by storage's own idempotent delete. This device's queue being
// empty is not evidence: another device may hold the work, or a crash may have
// come between the tombstone and the queue write. So a device that finds a
// deleted head with nothing queued re-derives the work from the gateway's
// kept history (`GET /v1/data/:id/versions` lists every registered slot after
// a tombstone) and confirms each slot against storage. The only memory is
// in-process progress, so a rate-limited pass resumes where it stopped; a
// restart confirms again, and that costs nothing but delete requests.
//
// Why a connection added again cannot lose data to this stage: a legacy scope
// accepts no write after the switch (the seal refuses it on the device, the
// gateway's cutover policy refuses it everywhere), so a new connection's data
// lives only in its stream-sync log scope, which this stage never names. The
// stage also sends each tombstone fenced to the head it read, so a head that
// moved is not tombstoned on a guess. Before the switch a legacy scope is the
// live store; the stage does nothing then.
import {
  classifyControl,
  controlHashes,
  deriveKeyCheck,
  parseScope,
  controlScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf, type StreamCryptoPort } from "../stream-sync/crypto-port.js";
import type { LegacyWriteVerdict } from "../api/legacy-write-gate.js";
import type { DeleteScopeResult } from "../sync/workers/delete.js";
import type { LogObjectEraser, LogVersionLister } from "./log-erase.js";
import type {
  DataPointFeedPort,
  PendingBlobDeletionStore,
  TombstoneFence,
  TombstoneFinalityPort,
} from "../ports/index.js";
import type { LegacyWriteSeal } from "../storage/legacy-write-seal.js";
import {
  blocked,
  PART_DONE,
  PART_PENDING,
  type DeleteBlockReason,
  type DeletePart,
} from "./delete-status.js";
import {
  isGatewayAlreadyDeletedCode,
  isGatewayRefusalCode,
} from "../sync/gateway-refusal.js";
import type { LocalSyncDeps } from "./deps.js";

/** A legacy scope's gateway head, as the stage needs it. */
export type LegacyHead =
  | { readonly state: "absent" }
  | {
      readonly state: "deleted";
      /** The tombstone's registry version: it bounds every slot with a blob. */
      readonly version: string;
    }
  | { readonly state: "live"; readonly fence: TombstoneFence };

/** What the stage needs from the host: the legacy side of this device. */
export interface LegacyDeletePorts {
  /** The legacy scopes bound to `connector` (the host owns the binding table). */
  scopesOf(connector: string): readonly string[];
  /** What a legacy write would get now: `allow` is an account that has not switched. */
  mode(): "allow" | LegacyWriteVerdict;
  head(scope: string, signal?: AbortSignal): Promise<LegacyHead>;
  /** The durable scope delete, fenced to `fence`: tombstone, blobs, local erase. */
  retire(scope: string, fence: TombstoneFence): Promise<DeleteScopeResult>;
  /** Blob deletions of `scope` still queued on this device behind its tombstone. */
  pendingBlobs(scope: string): Promise<number>;
  finality: Pick<TombstoneFinalityPort, "tombstoneState">;
  /** The gateway's kept history of a scope, which outlives its tombstone. */
  versions: LogVersionLister;
  /** Storage's idempotent per-object delete: "missing" is a confirmed absence. */
  objects: LogObjectEraser;
}

/**
 * What a pass keeps between passes of one device. Nothing here is evidence of
 * a finished delete (a restart starts empty): it only spares the gateway and
 * storage requests a pass already made.
 */
export interface LegacyMemory {
  /** Scopes whose tombstone the gateway refused for good, or this device cannot send. */
  readonly refused: Map<string, DeleteBlockReason>;
  /** Slots storage answered for, by `<scope>@<tombstone version>`. */
  readonly erased: Map<string, Set<string>>;
  /**
   * The control tombstone this delete confirmed, by namespace (its registry
   * version). The delete is judged against these, not against whatever head
   * the control rows hold now: a reconnect replaces a tombstone with a live
   * head, and a rolled-back tombstone leaves the live head behind.
   */
  readonly tombstones?: ReadonlyMap<string, number>;
}

/** What one pass learned about a connector's legacy copy. */
export interface LegacyOutcome {
  readonly part: DeletePart;
  /** The control tombstone failed to settle: the connection is live again. */
  readonly rolledBack: boolean;
  /**
   * A later pass can make progress on some scope. Decided per scope, apart
   * from `part`: a refused scope shows `blocked` and asks for no retry, and it
   * does not hide a scope that is only waiting.
   */
  readonly pending: boolean;
}

/** One scope: what to show, and whether a later pass can change it. */
interface ScopeOutcome {
  readonly part: DeletePart;
  readonly retry: boolean;
}
const settled = (part: DeletePart): ScopeOutcome => ({ part, retry: false });
const waiting: ScopeOutcome = { part: PART_PENDING, retry: true };

const worst = (a: DeletePart, b: DeletePart): DeletePart => {
  const rank = (p: DeletePart) =>
    p.state === "blocked" ? 2 : p.state === "pending" ? 1 : 0;
  return rank(b) > rank(a) ? b : a;
};

/** The deletion-aware head of a legacy scope, from the gateway's feed. */
export function legacyHeadFrom(
  feed: Pick<DataPointFeedPort, "getDataPoint">,
  owner: string,
): LegacyDeletePorts["head"] {
  return async (scope, signal) => {
    const record = await feed.getDataPoint({
      ownerAddress: owner,
      scope,
      ...(signal && { signal }),
    });
    if (record === null) return { state: "absent" };
    if (record.deletedAt !== null)
      return { state: "deleted", version: record.expectedVersion };
    return {
      state: "live",
      fence: {
        expectedVersion: record.expectedVersion,
        dataHash: record.dataHash,
        metadataHash: record.metadataHash,
      },
    };
  };
}

/** The host's pending blob deletions of one scope. */
export function pendingBlobsFrom(
  store: Pick<PendingBlobDeletionStore, "list"> | undefined,
): LegacyDeletePorts["pendingBlobs"] {
  return async (scope) =>
    store ? (await store.list()).filter((k) => k.scope === scope).length : 0;
}

/** The account's storage mode as the stage's `mode`, for a host with no seal. */
export const modeOfAccount =
  (
    read: () => "switched" | "unswitched" | "unknown",
  ): LegacyDeletePorts["mode"] =>
  () => {
    const mode = read();
    return mode === "switched"
      ? "switched"
      : mode === "unswitched"
        ? "allow"
        : "unknown";
  };

/** The seal's verdict as the stage's `mode`. */
export const modeFrom =
  (
    seal: Pick<LegacyWriteSeal, "verdict"> | undefined,
  ): LegacyDeletePorts["mode"] =>
  () =>
    seal?.verdict() ?? "allow";

export interface LegacyStageDeps {
  readonly registry: LocalSyncDeps["registry"];
  readonly keys: Pick<LocalSyncDeps["keys"], "namespaceHmac">;
  readonly streamCrypto?: StreamCryptoPort;
  readonly logger: Pick<LocalSyncDeps["logger"], "warn" | "info">;
  /** In-process memory of this device's earlier passes (see `LegacyMemory`). */
  readonly memory?: LegacyMemory;
}

/**
 * One pass of the legacy stage for `connector`. Never throws: a failure is a
 * `pending` outcome for the caller to repeat. Only a refusal the gateway names
 * terminal (`GATEWAY_REFUSAL_CODES`) or a missing capability is `blocked`.
 */
export async function retireLegacyOf(
  deps: LegacyStageDeps,
  ports: LegacyDeletePorts,
  connector: string,
  signal?: AbortSignal,
): Promise<LegacyOutcome> {
  const pending = (): LegacyOutcome => ({
    part: PART_PENDING,
    rolledBack: false,
    pending: true,
  });
  try {
    const scopes = ports.scopesOf(connector);
    // Before the switch the legacy copy is the live store, and a connection
    // added again would write to it: nothing is retired. An unknown mode
    // waits for the module to answer.
    const mode = ports.mode();
    if (mode === "unknown") return pending();
    if (mode === "allow" || scopes.length === 0)
      return { part: PART_DONE, rolledBack: false, pending: false };

    const final = await finalControl(deps, ports, connector, signal);
    if (final === "rolled-back")
      return {
        part: blocked("tombstone_rolled_back"),
        rolledBack: true,
        pending: false,
      };
    if (final === "waiting") return pending();
    // No control row names this connector: nothing proves a deleted
    // connection of it, so there is nothing to retire against. A delete of a
    // connection that was never published is a local purge only.
    if (final === "none")
      return { part: PART_DONE, rolledBack: false, pending: false };

    let part: DeletePart = PART_DONE;
    let retry = false;
    for (const scope of scopes) {
      signal?.throwIfAborted();
      // One scope's failed read says nothing of the others: it waits and is
      // retried, and the scopes after it still retire.
      const outcome = await retireScope(deps, ports, scope, signal).catch(
        (error: unknown) => {
          if (signal?.aborted) throw error;
          deps.logger.warn(
            {
              connector,
              scope,
              error: error instanceof Error ? error.message : String(error),
            },
            "stream sync: a legacy scope could not be retired yet",
          );
          return waiting;
        },
      );
      part = worst(part, outcome.part);
      retry ||= outcome.retry;
    }
    return { part, rolledBack: false, pending: retry };
  } catch (error) {
    if (signal?.aborted) return pending();
    deps.logger.warn(
      {
        connector,
        error: error instanceof Error ? error.message : String(error),
      },
      "stream sync: legacy copy retire failed",
    );
    return pending();
  }
}

/**
 * Whether some control tombstone of `connector`'s delete is final. The
 * tombstones are the ones the deleter confirmed (`memory.tombstones`) and any
 * deleted head newer than them: a head that moved on (a reconnect) or came
 * back (a rollback) does not hide the tombstone's own finality. A tombstone
 * that failed does not count; if every one failed, the connection is live
 * again.
 */
async function finalControl(
  deps: LegacyStageDeps,
  ports: LegacyDeletePorts,
  connector: string,
  signal?: AbortSignal,
): Promise<"final" | "waiting" | "rolled-back" | "none"> {
  const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
  const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
  const tombstones = new Map(deps.memory?.tombstones);
  for (const { scope, read } of await deps.registry.listControlRows(signal)) {
    const parsed = parseScope(scope);
    if (parsed?.kind !== "control" || parsed.connector !== connector) continue;
    const state = classifyControl(read, hashes);
    if (
      state.kind === "deleted" &&
      state.version > (tombstones.get(parsed.ns) ?? 0)
    )
      tombstones.set(parsed.ns, state.version);
  }
  let rolledBack = 0;
  for (const [ns, version] of tombstones) {
    const finality = await ports.finality.tombstoneState(
      controlScope(connector, ns),
      String(version),
    );
    if (finality.rolledBack) {
      rolledBack += 1;
      continue;
    }
    if (
      finality.finalized !== null &&
      BigInt(finality.finalized) >= BigInt(version)
    )
      return "final";
  }
  if (tombstones.size === 0) return "none";
  return rolledBack === tombstones.size ? "rolled-back" : "waiting";
}

async function retireScope(
  deps: LegacyStageDeps,
  ports: LegacyDeletePorts,
  scope: string,
  signal?: AbortSignal,
): Promise<ScopeOutcome> {
  const refused = deps.memory?.refused.get(scope);
  if (refused) return settled(blocked(refused));
  let head = await ports.head(scope, signal);
  if (head.state === "live") {
    const result = await ports.retire(scope, head.fence);
    const { gateway } = result.steps;
    // data-gateway #212: a tombstone aimed at a head that is already deleted
    // gets a distinct answer (`gateway-refusal.ts`). The scope is retired
    // already: read the head again below instead of waiting or blocking.
    if (
      gateway.status === "failed" &&
      !isGatewayAlreadyDeletedCode(gateway.code)
    ) {
      if (!isGatewayRefusalCode(gateway.code)) return waiting;
      // The gateway's answer will not change: ask once, show it, and do not
      // let it hold back a scope that is only waiting.
      deps.memory?.refused.set(scope, gateway.code);
      return settled(blocked(gateway.code));
    }
    // No server key, or an enclave: this device cannot delete at the gateway.
    if (gateway.status === "skipped" && gateway.reason === "sync-disabled") {
      deps.memory?.refused.set(scope, "needs_another_device");
      return settled(blocked("needs_another_device"));
    }
    head = await ports.head(scope, signal);
  }
  // Never registered, or an account that has nothing here to retire.
  if (head.state === "absent") return settled(PART_DONE);
  // A head that moved, or a tombstone the registry has not kept: read again.
  if (head.state === "live") return waiting;
  // Work this device queued is still being drained by its sync manager.
  if ((await ports.pendingBlobs(scope)) > 0) return waiting;
  return confirmErased(deps, ports, scope, head.version, signal);
}

/** The legacy delete's batch: vana-storage rate-limits DELETE per owner. */
const SWEEP_BATCH = 15;

/**
 * Whether the blobs of a deleted legacy scope are gone, decided from the
 * gateway's history and storage's own answers, never from this device's queue.
 * Any device can run it, in any state: storage deletes are idempotent, so
 * repeating them is safe and an absent object (404) is the confirmation.
 */
async function confirmErased(
  deps: LegacyStageDeps,
  ports: LegacyDeletePorts,
  scope: string,
  tombstone: string,
  signal?: AbortSignal,
): Promise<ScopeOutcome> {
  const version = BigInt(tombstone);
  // Blobs are freed only by a final tombstone: a failed one rolls the head
  // back to live data whose blobs must still be there.
  const finality = await ports.finality.tombstoneState(scope, tombstone);
  if (
    finality.rolledBack !== null ||
    finality.finalized === null ||
    BigInt(finality.finalized) < version
  )
    return waiting;
  const history = await ports.versions.list(scope, signal && { signal });
  // A history read that is incomplete, or older than the head it must explain,
  // can miss a slot with a blob.
  if (
    history.complete !== true ||
    !history.versions.some(
      (row) => row.isTombstone && BigInt(row.expectedVersion) === version,
    )
  )
    return waiting;
  const key = `${scope}@${tombstone}`;
  const answered = deps.memory?.erased.get(key) ?? new Set<string>();
  deps.memory?.erased.set(key, answered);
  const slots = history.versions
    .filter((row) => !row.isTombstone && BigInt(row.expectedVersion) <= version)
    .map((row) => row.expectedVersion)
    .filter((slot) => !answered.has(slot));
  for (let at = 0; at < slots.length; at += SWEEP_BATCH) {
    signal?.throwIfAborted();
    const batch = slots.slice(at, at + SWEEP_BATCH);
    const outcome = await ports.objects
      .deleteBlobVersions(scope, batch)
      .catch(() => null);
    if (outcome === null) return waiting;
    // Record what storage answered before reporting pending: a retry then
    // starts at the slots still left, so a steady 429 on some slots cannot
    // spend every pass on the ones already gone.
    const acknowledged = new Set([...outcome.deleted, ...outcome.missing]);
    for (const slot of acknowledged) answered.add(slot);
    if (outcome.failed.length > 0) return waiting;
    if (batch.some((slot) => !acknowledged.has(slot))) return waiting;
  }
  return settled(PART_DONE);
}
