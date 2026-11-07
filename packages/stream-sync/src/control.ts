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
