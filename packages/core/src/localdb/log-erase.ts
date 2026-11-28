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
// A re-add of the same connection uses the SAME log scope. Its position keeps
// counting through the eraser's log tombstone. After erasure, a new lifetime's
// first segment starts after that version (`log-apply.ts`, "The log of an ended
// lifetime. A new one begins after its version."). Physical delete can race a
// re-add (`docs/design/write-once-publication.md`: no read-then-delete
// reclaim). The fence:
//
// 1. Nothing is deleted until the control tombstone is FINALIZED at its own
//    version or above (a lower finalized version says nothing about it). A tombstone
//    the gateway has queued can still fail and roll the control row back to
//    live data; erasing before that is ruled out would destroy a connection
//    the registry can still show. The legacy blob delete waits the same way.
// 2. The control row is read again before every batch of deletes, and must
//    still be the tombstone this pass started from (same version). A log
//    commit requires the control row active at its generation, in the same
//    registry transaction (`log-publish.ts`), so while the control row is that
//    tombstone no publish can move the log row: every inventoried version
//    belongs to a lifetime that ended. Once the control row moves (a re-add),
//    the pass stops and deletes nothing more.
// 3. Segment and part names cannot be shared with a later lifetime: they are
//    the Keccak-256 of clear bytes that hold the generation and the position,
//    and a position is used once per log row. Body pieces CAN: they are named
//    by the Keccak-256 of their clear bytes alone, so a re-add that collects
//    the same large record names the same piece, and storage keeps the first
//    bytes of a name, so its upload is answered by the old copy. A re-add that
//    commits between the control check of 2 and the DELETE reaching storage
//    would then name a piece the DELETE removes, and its log would not read
//    ("apply: missing a piece of an out-of-line body"). No read here can close
//    that window (`write-once-publication.md`: no read-then-delete reclaim),
//    and cutting pieces at other offsets does not either. Salting the name per
//    connection lifetime would, but it changes what a reader checks
//    (`keccak(piece) = name`): a LOG_FORMAT change every device must understand
//    first, and a follow-up. UNTIL THEN THE ERASER NEVER DELETES A BODY PIECE.
//    It still finds them, to write their names down (`RetainedPieces`) before
//    it deletes the parts and segments that name them: afterwards nothing
//    names them, so the record is the only way the salting change can sweep
//    them. A name in the record is a candidate, not proof it is unused: a live
//    log can name the same piece, and the sweep must check that first.
// 4. Before deleting the head, tombstone the log row with a fence on the
//    exact inventoried head. A re-add that committed first refuses the fence.
//    Wait for that log tombstone's finality too: a queued tombstone can roll
//    back, and a live row must never name a head this pass erased.
//
// RETRY WITHOUT A JOURNAL
//
// Objects are deleted in an order that keeps the log readable until what it
// names is gone: parts, then non-head segments, then the fenced log tombstone,
// then (after finality) the newest segment. Each phase finishes before the
// next starts, and a failed batch stops the pass. So a pass that stops anywhere, or a
// restart, leaves every segment that names a remaining part in place, and the
// next pass enumerates the same objects again. The piece names are recorded
// before the first delete, so no restart loses them. The newest segment is
// removed only after a complete inventory and acknowledged deletes. A restart
// recovers its hash from the version immediately before the log tombstone.
// Its absence and the final log tombstone are checked against the full version
// inventory before a repeat reports completion. A delete that answers 404
// counts as done, so every step repeats.

import {
  bodyPieceBlobName,
  classifyControl,
  classifyStreamRow,
  controlHashes,
  controlScope,
  deriveKeyCheck,
  logScope,
  parseScope,
  segmentBlobName,
  snapshotPartBlobName,
  verifySegment,
  verifySnapshotPart,
  type ControlHashes,
  type ControlRead,
  type WireEntry,
  type WireOperation,
  type WireSegment,
  type WireSnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import type { VersionInventoryClient } from "../additions/version-inventory.js";
import type { DeleteDataPort } from "../ports/index.js";
import type { SqlDriver } from "./driver.js";
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
 * Whether a control or log tombstone can no longer be rolled back
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
 * thrown for the batch. The legacy delete's own port, so the contract is one.
 */
export type LogObjectEraser = Pick<DeleteDataPort, "deleteBlobVersions">;

/**
 * Where the pass writes down the body pieces it leaves in storage (see 3
 * above), durably, before it deletes the objects that name them. Writing a
 * name twice is fine. A failure fails the pass before any delete.
 */
export interface RetainedPieces {
  /**
   * Write down `names`, the body pieces of the log whose registry head is
   * `head`. `complete` says the pass saw every object the head reaches
   * (nothing it listed was already gone): only then is the log marked as
   * enumerated by this device (`enumerated`).
   */
  keep(
    scope: string,
    head: string,
    names: readonly string[],
    options: { readonly complete: boolean },
  ): Promise<void>;
  /**
   * How many piece names the record holds for `scope`: every name any pass
   * wrote down, so a repeat pass that finds the log gone still answers for
   * what an earlier pass left in storage.
   */
  count(scope: string): Promise<number>;
  /**
   * Whether this device enumerated everything the log with registry head
   * `head` reaches before it removed any of it (`keep` ran with `complete`).
   * Without it, an empty record says nothing of what another device left.
   * The head names the lifetime: a log that went on after a re-add has a
   * newer head, and what this device enumerated before says nothing of it.
   */
  enumerated(scope: string, head: string): Promise<boolean>;
}

/** Rows per batch: a large body can name many pieces. */
const KEEP_BATCH = 500;

/**
 * `RetainedPieces` in the local database (`retained_log_pieces`). The table is
 * keyed by scope and name and survives a connection's purge: it is the
 * record of what a delete left in storage, which nothing else names.
 */
export function retainedPiecesIn(
  db: Pick<SqlDriver, "batch" | "query">,
): RetainedPieces {
  return {
    async count(scope) {
      const [row] = await db.query<{ n: number }>(
        "SELECT COUNT(*) AS n FROM retained_log_pieces WHERE scope = ?",
        [scope],
      );
      return Number(row?.n ?? 0);
    },
    async enumerated(scope, head) {
      const rows = await db.query(
        "SELECT 1 FROM enumerated_logs WHERE scope = ? AND head = ?",
        [scope, head],
      );
      return rows.length > 0;
    },
    async keep(scope, head, names, { complete }) {
      for (let at = 0; at < names.length; at += KEEP_BATCH)
        await db.batch(
          names.slice(at, at + KEEP_BATCH).map((name) => ({
            sql: "INSERT OR IGNORE INTO retained_log_pieces(scope, name, recorded_at) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) * 1000)",
            params: [scope, name],
          })),
        );
      // Last: a log marked here has every name above recorded.
      if (complete)
        await db.batch([
          {
            sql: "INSERT OR IGNORE INTO enumerated_logs(scope, head, recorded_at) VALUES (?, ?, CAST(strftime('%s','now') AS INTEGER) * 1000)",
            params: [scope, head],
          },
        ]);
    },
  };
}

export interface LogErasureDeps {
  readonly registry: Pick<StreamSyncRegistry, "read" | "listControlRows">;
  readonly versions: LogVersionLister;
  readonly finality: TombstoneFinality;
  readonly blobs: Pick<StreamSyncBlobs, "get">;
  readonly keys: Pick<StreamSyncKeyPorts, "namespaceHmac" | "decrypt">;
  readonly streamCrypto?: StreamCryptoPort;
  readonly objects: LogObjectEraser & Pick<DeleteDataPort, "tombstone">;
  readonly retained: RetainedPieces;
  readonly logger: {
    info(obj: Record<string, unknown>, msg?: string): void;
    warn(obj: Record<string, unknown>, msg?: string): void;
  };
}

/** What a host supplies to erase; the rest of `LogErasureDeps` is the sync's own. */
export type LogErasurePorts = Pick<
  LogErasureDeps,
  "versions" | "finality" | "objects"
>;

/**
 * The version inventory as a `LogVersionLister`. One traversal is "not a
 * completeness certificate" (`VersionInventoryClient.list`): a segment the
 * registry still lists can be missed. The inventory is read again and the two
 * reads compared, as every other certifying reader does
 * (`additions/durable.ts`); it is complete only when they match. A traversal
 * that cannot finish (a changed head, an exceeded page budget, a failed read)
 * throws, which a pass reports as pending.
 */
export function inventoryVersionLister(
  inventory: Pick<VersionInventoryClient, "list">,
): LogVersionLister {
  return {
    async list(scope, options) {
      const read = () => inventory.list(scope, { signal: options?.signal });
      const first = await read();
      const second = await read();
      return {
        complete: JSON.stringify(first) === JSON.stringify(second),
        versions: second.versions.map((v) => ({
          expectedVersion: v.expectedVersion,
          dataHash: v.dataHash,
          isTombstone: v.isTombstone,
        })),
      };
    },
  };
}

export type ErasureOutcome =
  /**
   * Every object discovered from the complete version inventory was acknowledged
   * deleted or missing, except the body pieces, which are not deleted and are
   * recorded (`retained`, see 3 above). A successful outcome always has zero
   * unenumerated objects.
   */
  | {
      readonly kind: "erased";
      readonly deleted: number;
      readonly retained: number;
      readonly unenumerated: number;
      /**
       * Whether this device's own evidence covers the log: it enumerated every
       * object the log's head reaches before it deleted any of them
       * (`RetainedPieces.enumerated`), or the registry shows the log never
       * held an object. `false`: something was gone before this device could
       * name it (another device stopped part way, or finished), and only that
       * device knows whether body pieces were left.
       */
      readonly witnessed: boolean;
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
       * `re-added`: the control row moved, or a reconnect ended the delete's
       * tombstone before the pass could start. The log scope is shared with
       * the new lifetime, so nothing is deleted and nothing is known gone.
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
  /**
   * Namespaces whose deleted control head the pass found and left alone:
   * `skipNamespaces` named them, because a local connection of theirs is not
   * deleted. Their log scope belongs to that connection too, so nothing of
   * the deleted lifetime is erased or shown gone. Listed, so the caller
   * judges them from this report instead of from what it does not mention.
   */
  readonly skipped: readonly string[];
  /** This device has no ports to delete from storage: nothing was tried. */
  readonly unavailable?: true;
}

/** The legacy delete's batch: vana-storage rate-limits DELETE per owner. */
const DELETE_BATCH = 15;

/**
 * Erase the log objects of every deleted connection of `connector` (every
 * deleted connection of the owner when none is named). The connection deleter
 * calls it once the delete has settled on this device (`delete.ts`,
 * `eraseLogs`), and again to resume. It never throws and never touches the delete itself: a failure
 * comes back as a `pending` outcome for the caller to repeat later.
 * `skipNamespaces` are namespaces of `connector` whose delete has not settled
 * here (a local connection of theirs is not deleted): they are left alone and
 * are listed in the report's `skipped`, and the rest are erased.
 */
export async function eraseDeletedConnectionLogs(
  deps: LogErasureDeps,
  options: {
    readonly connector?: string;
    readonly skipNamespaces?: ReadonlySet<string>;
    /**
     * The control tombstone of the delete being erased, by namespace (see
     * `LegacyMemory.tombstones`). A namespace named here whose head is no
     * longer deleted is judged by its tombstone's own finality: rolled back
     * and re-added (the tombstone is final, a reconnect replaced it) are both
     * reported, and neither erases anything.
     */
    readonly tombstones?: ReadonlyMap<string, number>;
    readonly signal?: AbortSignal;
  } = {},
): Promise<ErasureReport> {
  const connections: ConnectionErasure[] = [];
  const skipped: string[] = [];
  try {
    const keyCheck = await deriveKeyCheck((m) => deps.keys.namespaceHmac(m));
    const hashes = await controlHashes(keccakOf(deps.streamCrypto), keyCheck);
    const rows = await deps.registry.listControlRows(options.signal);
    const deletedAt = new Map<string, number>();
    for (const { scope, read } of rows) {
      const parsed = parseScope(scope);
      if (parsed?.kind !== "control") continue;
      if (
        options.connector !== undefined &&
        parsed.connector !== options.connector
      )
        continue;
      const state = classifyControl(read, hashes);
      if (state.kind === "deleted") deletedAt.set(parsed.ns, state.version);
      if (state.kind !== "deleted") continue;
      const { connector, ns } = parsed;
      if (options.skipNamespaces?.has(ns)) {
        skipped.push(ns);
        continue;
      }
      const outcome = await eraseOne(
        deps,
        { connector, ns, keyCheck, hashes, tombstone: state.version },
        options.signal,
      );
      report(deps, connector, outcome);
      connections.push({ connector, ns, outcome });
    }
    // A tombstone the delete confirmed whose head is not deleted any more:
    // rolled back (the live head came back) or ended by a reconnect.
    if (options.connector !== undefined)
      for (const [ns, version] of options.tombstones ?? []) {
        if ((deletedAt.get(ns) ?? 0) >= version) continue;
        const finality = await deps.finality.tombstoneState(
          controlScope(options.connector, ns),
          String(version),
        );
        // A final tombstone under a head that is not deleted: a reconnect
        // ended the lifetime before this pass could erase it. Its objects
        // stay: the log scope belongs to the new lifetime too, so nothing here
        // can tell them apart or delete them.
        const outcome: ErasureOutcome = finality.rolledBack
          ? { kind: "stopped", why: "rolled-back" }
          : finalizedAtOrAbove(finality.finalized, version)
            ? { kind: "stopped", why: "re-added" }
            : { kind: "pending", why: "finality" };
        report(deps, options.connector, outcome);
        connections.push({ connector: options.connector, ns, outcome });
      }
  } catch (error) {
    deps.logger.warn(
      { error: error instanceof Error ? error.message : String(error) },
      "stream sync: connection log erasure could not list the deleted connections",
    );
    return { connections, pending: true, skipped };
  }
  return {
    connections,
    pending: connections.some((c) => c.outcome.kind === "pending"),
    skipped,
  };
}

function report(deps: LogErasureDeps, connector: string, o: ErasureOutcome) {
  if (o.kind === "erased")
    deps.logger.info(
      {
        connector,
        deleted: o.deleted,
        retained: o.retained,
        unenumerated: o.unenumerated,
      },
      "stream sync: erased a deleted connection's log objects, not its body pieces",
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
    // The port answers the highest finalized tombstone at or above the asked
    // version, but an adapter can answer a lower one while a newer tombstone
    // is still settling and could yet roll back. Only a finalized version at
    // or above the one this pass erases for proves it final.
    if (!finalizedAtOrAbove(finality.finalized, tombstone))
      return { kind: "pending", why: "finality" };

    const head = await deps.registry.read(scope, signal);
    const inventory = await deps.versions.list(scope, { signal });
    if (inventory.complete !== true)
      return {
        kind: "pending",
        why: "inventory",
        detail: "log version inventory is incomplete",
      };
    const ended = classifyStreamRow(head, target.hashes) === "tombstoned";
    // On restart the tombstone occupies the slot after the erased head.
    // Recover that head from the complete inventory, never from the tombstone hash.
    const previous =
      head.found && ended
        ? inventory.versions.find(
            (v) =>
              !v.isTombstone && Number(v.expectedVersion) === head.version - 1,
          )
        : undefined;
    if (head.found && ended && !previous)
      return {
        kind: "pending",
        why: "inventory",
        detail: `log tombstone is not the version after the fenced head: tombstone ${head.version}, expected head ${head.version - 1}, non-tombstone versions [${inventory.versions
          .filter((v) => !v.isTombstone)
          .map((v) => v.expectedVersion)
          .join(", ")}]`,
      };
    const headRef = head.found
      ? ended
        ? { dataHash: previous!.dataHash, position: head.version - 1 }
        : { dataHash: head.dataHash, position: head.version }
      : null;
    const headName = headRef ? segmentBlobName(headRef.dataHash) : null;
    const endLog = async (): Promise<ErasureOutcome | null> => {
      await stillTombstoned(deps, target, signal);
      if (!head.found) return null;
      let version = String(head.version);
      if (!ended) {
        const outcome = await deps.objects.tombstone(scope, {
          head: {
            expectedVersion: version,
            dataHash: head.dataHash,
            metadataHash: head.metadataHash,
          },
        });
        if (outcome.status === "not-registered")
          return { kind: "pending", why: "finality" };
        if (outcome.version !== String(head.version + 1))
          return {
            kind: "pending",
            why: "inventory",
            detail: "log tombstone is not the version after the fenced head",
          };
        version = outcome.version;
      }
      const state = await deps.finality.tombstoneState(scope, version);
      if (
        state.rolledBack ||
        !finalizedAtOrAbove(state.finalized, Number(version))
      )
        return { kind: "pending", why: "finality" };
      // A later re-add owns this scope now, even if the tombstone is final.
      await stillTombstoned(deps, target, signal);
      return null;
    };

    // Every object is found by the name its bytes hash to: the registry's
    // data hashes name the segments, and a verified segment names its parts.
    // `position` is set where the registry or a ref promised one.
    const segments = new Map<
      string,
      { readonly dataHash: string; position?: number }
    >();
    for (const v of inventory.versions)
      if (!v.isTombstone)
        segments.set(segmentBlobName(v.dataHash), { dataHash: v.dataHash });
    const opened = headRef
      ? await openSegment(deps, scope, target, headRef)
      : "absent";
    if (headName === null || opened === "absent") {
      // A finished pass leaves no listed segment in storage (the head went
      // last). Do not treat a missing head with surviving segments as proof.
      for (const name of segments.keys()) {
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
      const ending = await endLog();
      if (ending !== null) return ending;
      // The pieces an earlier pass left are still in storage: say so. Only
      // this device's own enumeration of this log (this head) vouches for
      // them; a log that is gone with no such record was erased by another
      // device. A log the registry never held an object of has nothing to
      // vouch for.
      return {
        kind: "erased",
        deleted: 0,
        retained: await deps.retained.count(scope),
        unenumerated: 0,
        witnessed:
          headRef === null
            ? segments.size === 0
            : await deps.retained.enumerated(scope, headRef.dataHash),
      };
    }
    if (opened === "unreadable")
      return { kind: "stopped", why: "head-unreadable" };

    segments.set(headName, headRef!);
    for (const ref of opened.refs)
      segments.set(segmentBlobName(ref.dataHash), {
        dataHash: ref.dataHash,
        position: ref.position,
      });

    const parts = new Map<
      string,
      { readonly dataHash: string; readonly position: number }
    >();
    const pieces = new Set<string>();
    // Objects storage answered "none" for. A listed name can be gone already
    // (an earlier pass deleted it); sending it again only spends the owner's
    // DELETE quota, so a rate-limited retry never reaches the rest.
    const gone = new Set<string>();
    let unenumerated = 0;
    const note = (references: Iterable<WireOperation | WireEntry>) => {
      for (const op of references)
        if (op.kind === "upsert-ref")
          for (const piece of op.body.pieces)
            pieces.add(bodyPieceBlobName(piece));
    };
    await each([...segments.entries()], async ([name, expected]) => {
      const segment = await openSegment(deps, scope, target, expected);
      if (segment === "absent") {
        gone.add(name);
        return;
      }
      if (segment === "unreadable") {
        unenumerated += 1;
        return;
      }
      for (const part of segment.snapshot?.parts ?? [])
        parts.set(snapshotPartBlobName(part.dataHash), {
          dataHash: part.dataHash,
          position: segment.snapshot!.position,
        });
      note(segment.operations);
    });
    await each([...parts.entries()], async ([name, expected]) => {
      const part = await openPart(deps, scope, target, expected);
      if (part === "absent") {
        gone.add(name);
        return;
      }
      if (part === "unreadable") {
        unenumerated += 1;
        return;
      }
      note(part.entries);
    });

    if (unenumerated > 0)
      return {
        kind: "pending",
        why: "inventory",
        detail: `${unenumerated} log objects could not be enumerated`,
      };

    // Written down before anything that names them is deleted (see 3 above).
    // An object that was already gone when this pass looked (another device
    // stopped part way through, or an earlier pass here) cannot be read for
    // the pieces it named. This device vouches for the log only if it
    // enumerated it whole before: an earlier pass here marked this head.
    const witnessed =
      gone.size === 0 ||
      (await deps.retained.enumerated(scope, headRef!.dataHash));
    await deps.retained.keep(scope, headRef!.dataHash, [...pieces], {
      complete: witnessed,
    });

    const rest = [...segments.keys()].filter(
      (name) => name !== headName && !gone.has(name),
    );
    const present = [...parts.keys()].filter((name) => !gone.has(name));
    let deleted = 0;
    for (const [index, phase] of [present, rest, [headName]].entries()) {
      if (index === 2) {
        const ending = await endLog();
        if (ending !== null) return ending;
      }
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
    return {
      kind: "erased",
      deleted,
      retained: await deps.retained.count(scope),
      unenumerated,
      witnessed,
    };
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

/**
 * The reader's own checks (`verifySegment`, as `fetchSegment` in `log-apply.ts`
 * runs them) on the segment a name holds: its bytes hash to the name, it is
 * this connection's log, under this key, at the promised position. An object
 * that fails any of them, however well it decodes, is another object served
 * under this name, and is not read for what it names. `"absent"` when storage
 * has none.
 */
async function openSegment(
  deps: LogErasureDeps,
  scope: string,
  target: Target,
  expected: { readonly dataHash: string; readonly position?: number },
): Promise<WireSegment | "absent" | "unreadable"> {
  const bytes = await open(deps, scope, segmentBlobName(expected.dataHash));
  if (bytes === "absent" || bytes === "unreadable") return bytes;
  const verified = await verifySegment(keccakOf(deps.streamCrypto), bytes, {
    dataHash: expected.dataHash,
    connector: target.connector,
    ns: target.ns,
    keyCheck: target.keyCheck,
    ...(expected.position !== undefined && { position: expected.position }),
  });
  return verified.kind === "ok" ? verified.segment : "unreadable";
}

/** `openSegment` for a snapshot part. */
async function openPart(
  deps: LogErasureDeps,
  scope: string,
  target: Target,
  expected: { readonly dataHash: string; readonly position: number },
): Promise<WireSnapshotPart | "absent" | "unreadable"> {
  const bytes = await open(
    deps,
    scope,
    snapshotPartBlobName(expected.dataHash),
  );
  if (bytes === "absent" || bytes === "unreadable") return bytes;
  const verified = await verifySnapshotPart(
    keccakOf(deps.streamCrypto),
    bytes,
    {
      dataHash: expected.dataHash,
      connector: target.connector,
      ns: target.ns,
      keyCheck: target.keyCheck,
      position: expected.position,
    },
  );
  return verified.kind === "ok" ? verified.part : "unreadable";
}

/** Whether `finalized` is a version at or above `tombstone`. */
function finalizedAtOrAbove(
  finalized: string | null,
  tombstone: number,
): boolean {
  if (finalized === null) return false;
  try {
    return BigInt(finalized) >= BigInt(tombstone);
  } catch {
    return false;
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
