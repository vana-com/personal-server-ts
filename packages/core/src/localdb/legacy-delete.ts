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
import type {
  DataPointFeedPort,
  PendingBlobDeletionStore,
  TombstoneFence,
  TombstoneFinalityPort,
} from "../ports/index.js";
import type { LegacyWriteSeal } from "../storage/legacy-write-seal.js";
import {
  blocked,
  LEGACY_REFUSALS,
  PART_DONE,
  PART_PENDING,
  type DeletePart,
  type LegacyRefusal,
} from "./delete-status.js";
import type { LocalSyncDeps } from "./deps.js";

/** A legacy scope's gateway head, as the stage needs it. */
export type LegacyHead =
  | { readonly state: "absent" }
  | { readonly state: "deleted" }
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
  /** Blob deletions of `scope` still queued behind its tombstone. */
  pendingBlobs(scope: string): Promise<number>;
  finality: Pick<TombstoneFinalityPort, "tombstoneState">;
}

/** What one pass learned about a connector's legacy copy. */
export interface LegacyOutcome {
  readonly part: DeletePart;
  /** The control tombstone failed to settle: the connection is live again. */
  readonly rolledBack: boolean;
  /** A later pass can make progress. */
  readonly pending: boolean;
}

const worst = (a: DeletePart, b: DeletePart): DeletePart => {
  const rank = (p: DeletePart) =>
    p.state === "blocked" ? 2 : p.state === "pending" ? 1 : 0;
  return rank(b) > rank(a) ? b : a;
};

const isRefusal = (code: unknown): code is LegacyRefusal =>
  LEGACY_REFUSALS.includes(code as LegacyRefusal);

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
    if (record.deletedAt !== null) return { state: "deleted" };
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
}

/**
 * One pass of the legacy stage for `connector`. Never throws: a failure is a
 * `pending` outcome for the caller to repeat. Only a refusal the gateway names
 * terminal (`LEGACY_REFUSALS`) or a missing capability is `blocked`.
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
    for (const scope of scopes) {
      signal?.throwIfAborted();
      part = worst(part, await retireScope(deps, ports, scope, signal));
    }
    return { part, rolledBack: false, pending: part.state === "pending" };
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
 * Whether some deleted control row of `connector` has a final tombstone. A
 * row whose tombstone failed does not count; if every deleted row failed, the
 * connection is live again.
 */
async function finalControl(
  deps: LegacyStageDeps,
  ports: LegacyDeletePorts,
  connector: string,
  signal?: AbortSignal,
): Promise<"final" | "waiting" | "rolled-back" | "none"> {
  const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
  const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
  let seen = 0;
  let rolledBack = 0;
  for (const { scope, read } of await deps.registry.listControlRows(signal)) {
    const parsed = parseScope(scope);
    if (parsed?.kind !== "control" || parsed.connector !== connector) continue;
    const state = classifyControl(read, hashes);
    if (state.kind !== "deleted") continue;
    seen += 1;
    const finality = await ports.finality.tombstoneState(
      controlScope(connector, parsed.ns),
      String(state.version),
    );
    if (finality.rolledBack) {
      rolledBack += 1;
      continue;
    }
    if (
      finality.finalized !== null &&
      BigInt(finality.finalized) >= BigInt(state.version)
    )
      return "final";
  }
  if (seen === 0) return "none";
  return rolledBack === seen ? "rolled-back" : "waiting";
}

async function retireScope(
  deps: LegacyStageDeps,
  ports: LegacyDeletePorts,
  scope: string,
  signal?: AbortSignal,
): Promise<DeletePart> {
  const head = await ports.head(scope, signal);
  if (head.state !== "live")
    // The gateway lists the point as deleted (or never had it): what is left
    // is blobs a finished tombstone queued.
    return (await ports.pendingBlobs(scope)) > 0 ? PART_PENDING : PART_DONE;
  const result = await ports.retire(scope, head.fence);
  const { gateway } = result.steps;
  if (gateway.status === "failed")
    return isRefusal(gateway.code)
      ? blocked(gateway.code)
      : // A head that moved (fenced), the gateway down or a version conflict:
        // the next pass reads the head again.
        PART_PENDING;
  // No server key, or an enclave: this device cannot delete at the gateway.
  if (gateway.status === "skipped" && gateway.reason === "sync-disabled")
    return blocked("needs_another_device");
  if (result.pendingBlobDeletion || (await ports.pendingBlobs(scope)) > 0)
    return PART_PENDING;
  // The tombstone landed and its blobs are gone: it must read as deleted now.
  return (await ports.head(scope, signal)).state === "live"
    ? PART_PENDING
    : PART_DONE;
}
