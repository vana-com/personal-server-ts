// Physical erasure of a deleted connection's log objects from storage.
//
// A connection delete writes one fence: the control row's tombstone. It leaves
// the connection's encrypted objects in storage (segments `s-<hex>`, snapshot
// parts `q-<hex>`, out-of-line body pieces `v-<hex>`, all under the log scope
// `pdpp.<c>~<ns>.~log`), and the owner's own key can still read them. This
// module deletes them with the owner-signed per-object storage delete the
// legacy delete used.
//
// WHAT IS SAFE TO DELETE, AND WHEN
//
// A re-add of the same connection uses the SAME log scope: the log row is not
// tombstoned by the delete, its position keeps counting, and the new lifetime's
// first segment starts at `base` = the old position (`log-apply.ts`, "a log of
// an earlier lifetime holds none of this one"). So physical delete can race a
// re-add (`docs/design/write-once-publication.md`: no read-then-delete
// reclaim). The fence:
//
// 1. Nothing is deleted until the control tombstone is FINALIZED. A tombstone
//    the gateway has queued can still fail and roll the control row back to
//    live data; erasing before that is ruled out would destroy a connection
//    the registry can still show. The legacy blob delete waits the same way.
// 2. The control row is read again before every batch of deletes, and must
//    still be the tombstone this pass started from (same version). A log
//    commit requires the control row active at its generation, in the same
//    registry transaction (`log-publish.ts`), so while the control row is that
//    tombstone the log row cannot move: every version the inventory listed
//    belongs to a lifetime that ended. Once the control row moves (a re-add),
//    the pass stops and deletes nothing more.
// 3. Segment and part names cannot be shared with a later lifetime: they are
//    the Keccak-256 of clear bytes that hold the generation and the position,
//    and a position is used once per log row. Body pieces are named by their
//    clear bytes alone, so a re-add that collects the same large record names
//    the same piece. Pieces therefore go first, each batch under the control
//    check above, and are never deleted after a re-add is seen. What remains
//    is the window between that check and the DELETE reaching storage: a
//    re-add whose upload of the piece is answered by the old copy (storage
//    keeps the first bytes of a name) and whose commit lands inside that
//    window references a piece that is gone. Closing it needs a fence in the
//    storage or the gateway, as `write-once-publication.md` says; a read here
//    cannot.
//
// RETRY WITHOUT A JOURNAL
//
// Objects are deleted in an order that keeps the log readable until what it
// names is gone: pieces, then parts, then segments, the newest segment (the
// one the registry's log row names) last. Each phase finishes before the next
// starts, and a failed batch stops the pass. So a pass that stops anywhere,
// or a restart, leaves every segment that names a remaining part or piece in
// place, and the next pass enumerates the same objects again. The newest
// segment is removed only after a complete inventory and acknowledged deletes.
// Its absence is checked against the full version inventory before a repeat
// reports completion. A delete that answers 404 counts as done, so every step repeats.

import {
  bodyPieceBlobName,
  classifyControl,
  controlHashes,
  controlScope,
  decodeSegment,
  decodeSnapshotPart,
  deriveKeyCheck,
  logScope,
  parseScope,
  segmentBlobName,
  snapshotPartBlobName,
  type ControlHashes,
  type ControlRead,
  type WireEntry,
  type WireOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf, type StreamCryptoPort } from "../stream-sync/crypto-port.js";
import type {
  StreamSyncBlobs,
  StreamSyncKeyPorts,
  StreamSyncRegistry,
} from "../stream-sync/ports.js";
import { PARTS_IN_FLIGHT } from "../stream-sync/storage-retry.js";

/** The registry's version inventory of one scope (`GET /v1/data/:id/versions`). */
export interface LogVersionLister {
  list(
    scope: string,
    options?: { readonly signal?: AbortSignal },
  ): Promise<{
    /** True only when all pages of the version inventory were read. */
    readonly complete: boolean;
    readonly versions: readonly {
      readonly expectedVersion: string;
      readonly dataHash: string;
      readonly isTombstone: boolean;
    }[];
  }>;
}

/**
 * Whether a control tombstone can no longer be rolled back
 * (`TombstoneFinalityPort.tombstoneState`).
 */
export interface TombstoneFinality {
  tombstoneState(
    scope: string,
    atOrAbove: string,
  ): Promise<{
    /** The highest finalized tombstone at or above the asked version. */
    readonly finalized: string | null;
    /** Set when the tombstone failed and the row is live data again. */
    readonly rolledBack: unknown;
  }>;
}

/**
 * The owner-signed per-object storage delete (`DeleteDataPort.deleteBlobVersions`):
 * `names` are blob names under `scope`. An absent object is reported as
 * `missing`, which counts as deleted; a failure is reported per name, never
 * thrown for the batch.
 */
export interface LogObjectEraser {
  deleteBlobVersions(
    scope: string,
    names: string[],
  ): Promise<{
    readonly deleted: readonly string[];
    readonly missing: readonly string[];
    readonly failed: readonly { readonly version: string; error: string }[];
  }>;
}

export interface LogErasureDeps {
  readonly registry: Pick<StreamSyncRegistry, "read" | "listControlRows">;
  readonly versions: LogVersionLister;
  readonly finality: TombstoneFinality;
  readonly blobs: Pick<StreamSyncBlobs, "get">;
  readonly keys: Pick<StreamSyncKeyPorts, "namespaceHmac" | "decrypt">;
  readonly streamCrypto?: StreamCryptoPort;
  readonly objects: LogObjectEraser;
  readonly logger: {
    info(obj: Record<string, unknown>, msg?: string): void;
    warn(obj: Record<string, unknown>, msg?: string): void;
  };
}

export type ErasureOutcome =
  /**
   * Every object discovered from the complete version inventory was acknowledged
   * deleted or missing. A successful outcome always has zero unenumerated objects.
   */
  | {
      readonly kind: "erased";
      readonly deleted: number;
      readonly unenumerated: number;
    }
  /** Not finished; the same call again continues. */
  | {
      readonly kind: "pending";
      readonly why: "finality" | "storage" | "inventory" | "error";
      readonly detail?: string;
    }
  /** Not erased, and a repeat will not change that. */
  | {
      readonly kind: "stopped";
      /**
       * `re-added`: the control row moved since the pass began.
       * `rolled-back`: the tombstone failed; the connection is live again.
       * `head-unreadable`: the newest segment does not open with this key.
       */
      readonly why: "re-added" | "rolled-back" | "head-unreadable";
    };

export interface ConnectionErasure {
  readonly connector: string;
  readonly ns: string;
  readonly outcome: ErasureOutcome;
}

export interface ErasureReport {
  readonly connections: readonly ConnectionErasure[];
  /** True when a later call can still make progress (a `pending` outcome). */
  readonly pending: boolean;
}

/** The legacy delete's batch: vana-storage rate-limits DELETE per owner. */
const DELETE_BATCH = 15;

/**
 * Erase the log objects of every deleted connection of `connector` (every
 * deleted connection of the owner when none is named). The one call the
 * connection delete makes after its fence lands, and again to resume after a
 * restart. It never throws and never touches the delete itself: a failure
 * comes back as a `pending` outcome for the caller to repeat later.
 */
export async function eraseDeletedConnectionLogs(
  deps: LogErasureDeps,
  options: { readonly connector?: string; readonly signal?: AbortSignal } = {},
): Promise<ErasureReport> {
  const connections: ConnectionErasure[] = [];
  try {
    const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
    const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
    const rows = await deps.registry.listControlRows(options.signal);
    for (const { scope, read } of rows) {
      const parsed = parseScope(scope);
      if (parsed?.kind !== "control") continue;
      if (
        options.connector !== undefined &&
        parsed.connector !== options.connector
      )
        continue;
      const state = classifyControl(read, hashes);
      if (state.kind !== "deleted") continue;
      const { connector, ns } = parsed;
      const outcome = await eraseOne(
        deps,
        { connector, ns, keyCheck, hashes, tombstone: state.version },
        options.signal,
      );
      report(deps, connector, outcome);
      connections.push({ connector, ns, outcome });
    }
  } catch (error) {
    deps.logger.warn(
      { error: error instanceof Error ? error.message : String(error) },
      "stream sync: connection log erasure could not list the deleted connections",
    );
    return { connections, pending: true };
  }
  return {
    connections,
    pending: connections.some((c) => c.outcome.kind === "pending"),
  };
}

function report(deps: LogErasureDeps, connector: string, o: ErasureOutcome) {
  if (o.kind === "erased")
    deps.logger.info(
      { connector, deleted: o.deleted, unenumerated: o.unenumerated },
      "stream sync: erased a deleted connection's log objects",
    );
  else
    deps.logger.warn(
      { connector, ...o },
      "stream sync: a deleted connection's log objects are not erased yet",
    );
}

interface Target {
  readonly connector: string;
  readonly ns: string;
  readonly keyCheck: string;
  readonly hashes: ControlHashes;
  /** The control row's tombstone version this pass started from. */
  readonly tombstone: number;
}

class Moved extends Error {}

async function eraseOne(
  deps: LogErasureDeps,
  target: Target,
  signal?: AbortSignal,
): Promise<ErasureOutcome> {
  const { connector, ns, tombstone } = target;
  const control = controlScope(connector, ns);
  const scope = logScope(connector, ns);
  try {
    const finality = await deps.finality.tombstoneState(
      control,
      String(tombstone),
    );
    if (finality.rolledBack) return { kind: "stopped", why: "rolled-back" };
    if (finality.finalized === null)
      return { kind: "pending", why: "finality" };

    const head = await deps.registry.read(scope, signal);
    const headName = head.found ? segmentBlobName(head.dataHash) : null;
    const inventory = await deps.versions.list(scope, { signal });
    if (inventory.complete !== true)
      return {
        kind: "pending",
        why: "inventory",
        detail: "log version inventory is incomplete",
      };

    const segments = new Set<string>();
    for (const v of inventory.versions)
      if (!v.isTombstone) segments.add(segmentBlobName(v.dataHash));
    const opened =
      headName === null ? "absent" : await open(deps, scope, headName);
    if (headName === null || opened === "absent") {
      // A finished pass leaves no listed segment in storage (the head went
      // last). Do not treat a missing head with surviving segments as proof.
      for (const name of segments) {
        if (
          name !== headName &&
          (await deps.blobs.get(`${scope}/${name}`)) !== null
        )
          return {
            kind: "pending",
            why: "inventory",
            detail: "log head is missing with listed segments still present",
          };
      }
      return { kind: "erased", deleted: 0, unenumerated: 0 };
    }
    const decoded = opened === "unreadable" ? null : decodeSegment(opened);
    if (decoded?.kind !== "ok" || decoded.segment.keyCheck !== target.keyCheck)
      return { kind: "stopped", why: "head-unreadable" };

    segments.add(headName);
    for (const ref of decoded.segment.refs)
      segments.add(segmentBlobName(ref.dataHash));

    const parts = new Set<string>();
    const pieces = new Set<string>();
    let unenumerated = 0;
    const note = (references: Iterable<WireOperation | WireEntry>) => {
      for (const op of references)
        if (op.kind === "upsert-ref")
          for (const piece of op.body.pieces)
            pieces.add(bodyPieceBlobName(piece));
    };
    await each([...segments], async (name) => {
      const bytes = await open(deps, scope, name);
      if (bytes === "absent") return;
      const segment = bytes === "unreadable" ? null : decodeSegment(bytes);
      if (segment?.kind !== "ok") {
        unenumerated += 1;
        return;
      }
      for (const part of segment.segment.snapshot?.parts ?? [])
        parts.add(snapshotPartBlobName(part.dataHash));
      note(segment.segment.operations);
    });
    await each([...parts], async (name) => {
      const bytes = await open(deps, scope, name);
      if (bytes === "absent") return;
      const part = bytes === "unreadable" ? null : decodeSnapshotPart(bytes);
      if (part?.kind !== "ok") {
        unenumerated += 1;
        return;
      }
      note(part.part.entries);
    });

    if (unenumerated > 0)
      return {
        kind: "pending",
        why: "inventory",
        detail: `${unenumerated} log objects could not be enumerated`,
      };

    const rest = [...segments].filter((name) => name !== headName);
    let deleted = 0;
    for (const phase of [[...pieces], [...parts], rest, [headName]]) {
      for (let at = 0; at < phase.length; at += DELETE_BATCH) {
        signal?.throwIfAborted();
        await stillTombstoned(deps, target, signal);
        const batch = phase.slice(at, at + DELETE_BATCH);
        const outcome = await deps.objects
          .deleteBlobVersions(scope, batch)
          .catch((error: unknown) => ({
            deleted: [] as string[],
            missing: [] as string[],
            failed: batch.map((version) => ({
              version,
              error: error instanceof Error ? error.message : String(error),
            })),
          }));
        deleted += outcome.deleted.length;
        // A failure stops the pass: the next phase would delete what this
        // one still needs in order to be found again.
        if (outcome.failed.length > 0)
          return {
            kind: "pending",
            why: "storage",
            detail: `${outcome.failed.length} of ${batch.length} deletes failed: ${outcome.failed[0]!.error}`,
          };
        const acknowledged = [...outcome.deleted, ...outcome.missing];
        const names = new Set(acknowledged);
        if (
          acknowledged.length !== batch.length ||
          names.size !== batch.length ||
          batch.some((name) => !names.has(name))
        )
          return {
            kind: "pending",
            why: "storage",
            detail: "delete batch was not fully acknowledged",
          };
      }
    }
    return { kind: "erased", deleted, unenumerated };
  } catch (error) {
    if (error instanceof Moved) return { kind: "stopped", why: "re-added" };
    return {
      kind: "pending",
      why: "error",
      detail: error instanceof Error ? error.message : String(error),
    };
  }
}

/** Throws `Moved` unless the control row is still the tombstone the pass began from. */
async function stillTombstoned(
  deps: LogErasureDeps,
  target: Target,
  signal?: AbortSignal,
): Promise<void> {
  const read: ControlRead = await deps.registry.read(
    controlScope(target.connector, target.ns),
    signal,
  );
  const state = classifyControl(read, target.hashes);
  if (state.kind !== "deleted" || state.version !== target.tombstone)
    throw new Moved();
}

/** A decrypted object, `"absent"` when storage has none, `"unreadable"` when it does not open. */
async function open(
  deps: LogErasureDeps,
  scope: string,
  name: string,
): Promise<Uint8Array | "absent" | "unreadable"> {
  const cipher = await deps.blobs.get(`${scope}/${name}`);
  if (cipher === null) return "absent";
  try {
    return await deps.keys.decrypt(scope, cipher);
  } catch {
    return "unreadable";
  }
}

/** `work` over `items`, at most the store gate's width at once; the first failure stops it. */
async function each<T>(items: readonly T[], work: (item: T) => Promise<void>) {
  let next = 0;
  let failed = false;
  const lane = async () => {
    while (!failed && next < items.length) {
      const item = items[next++]!;
      try {
        await work(item);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(PARTS_IN_FLIGHT, items.length) }, lane),
  );
}
