/**
 * §2.3 control-row states.
 *
 * The authoritative control read is `GET /v1/data/:id?includeDeleted=true`.
 * A device classifies the row against its own `ACTIVE_DATA`:
 *
 *   absent       no row
 *   deleted(v)   the row at version v is a tombstone
 *   active(g)    live row whose dataHash is this device's ACTIVE_DATA; g = version
 *   foreign      live row with any other dataHash (another key → key_mismatch)
 */

import { InvalidArgumentError } from "./errors.js";
import type { StreamRow } from "./head.js";
import type { ControlHashes } from "./namespace.js";

export type ControlState =
  | { readonly kind: "absent" }
  | { readonly kind: "active"; readonly generation: number }
  | { readonly kind: "deleted"; readonly version: number }
  | { readonly kind: "foreign"; readonly version: number };

/** What the registry returned for the control scope. */
export type ControlRead =
  | { readonly found: false }
  | {
      readonly found: true;
      readonly version: number;
      readonly dataHash: string;
      readonly metadataHash: string;
      /** The row's `deleted_at` is set. */
      readonly deleted: boolean;
    };

function checkVersion(version: number): void {
  if (!Number.isSafeInteger(version) || version < 1) {
    throw new InvalidArgumentError(
      "registry version must be a positive safe integer",
    );
  }
}

export function classifyControl(
  read: ControlRead,
  hashes: Pick<
    ControlHashes,
    "activeData" | "tombstoneData" | "tombstoneMetadata"
  >,
): ControlState {
  if (!read.found) return { kind: "absent" };
  checkVersion(read.version);
  const dataHash = read.dataHash.toLowerCase();
  const metadataHash = read.metadataHash.toLowerCase();
  const tombstone =
    dataHash === hashes.tombstoneData &&
    metadataHash === hashes.tombstoneMetadata;
  if (read.deleted || tombstone)
    return { kind: "deleted", version: read.version };
  if (dataHash === hashes.activeData) {
    return { kind: "active", generation: read.version };
  }
  return { kind: "foreign", version: read.version };
}

/**
 * The one rule for reading a stream row: a row is tombstoned when its
 * `deleted_at` is set or when it carries the tombstone dataHash and
 * metadataHash pair. Writers and readers both call this, so the two
 * encodings cannot drift apart.
 */
export function classifyStreamRow(
  read: ControlRead,
  hashes: Pick<ControlHashes, "tombstoneData" | "tombstoneMetadata">,
): StreamRow {
  if (!read.found) return "absent";
  const tombstone =
    read.dataHash.toLowerCase() === hashes.tombstoneData &&
    read.metadataHash.toLowerCase() === hashes.tombstoneMetadata;
  return read.deleted || tombstone ? "tombstoned" : "present";
}

export function sameControl(a: ControlState, b: ControlState): boolean {
  if (a.kind !== b.kind) return false;
  switch (a.kind) {
    case "absent":
      return true;
    case "active":
      return a.generation === (b as typeof a).generation;
    default:
      return a.version === (b as typeof a).version;
  }
}

/**
 * The hide rule of §2.4, shared by publish admission and every reader: data
 * collected under an active control row is hidden once that row reads
 * deleted. `start` is the state the run began under (`unknown` when no
 * snapshot was taken); `now` is the newest state known. Both are for the same
 * connector and namespace. A reconnect (active at a higher generation) is not
 * a deletion and does not match.
 */
export function deletedSinceStart(
  start: ControlState | { readonly kind: "unknown" },
  now: ControlState,
): boolean {
  return start.kind === "active" && now.kind === "deleted";
}

/**
 * The one delete predicate for a run, shared by publish admission and any
 * reader that hides pending runs. A run is deleted when its connection was
 * active at start and is deleted now (control arm), or when its stream row
 * was not a tombstone at start and is one now (stream arm). Each arm is
 * skipped when its start or now state is not known.
 *
 * `streamTombstoned` is the stream row at start (`undefined` = not stamped).
 * The stream arm cannot see a tombstone a later write overwrote before `now`
 * was read; the registry returns only the latest row.
 */
export function runDeletedSince(
  start: {
    readonly control: ControlState | { readonly kind: "unknown" };
    readonly streamTombstoned?: boolean;
  },
  now: {
    readonly control?: ControlState;
    readonly stream?: ControlRead;
    readonly hashes: Pick<ControlHashes, "tombstoneData" | "tombstoneMetadata">;
  },
): boolean {
  if (now.control && deletedSinceStart(start.control, now.control)) return true;
  return (
    start.streamTombstoned === false &&
    now.stream !== undefined &&
    classifyStreamRow(now.stream, now.hashes) === "tombstoned"
  );
}
