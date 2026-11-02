import { createHash } from "node:crypto";
import {
  encodeLiveSnapshotDigestInput,
  type LiveSnapshotIdentity,
  type LiveSnapshotRow,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/completion";

export * from "@opendatalabs/personal-server-ts-core/storage/pdpp-records/completion";

/** Synchronous Node adapter over the same validated bytes as Web Crypto. */
export function liveSnapshotDigest(
  identity: LiveSnapshotIdentity,
  primaryKey: readonly string[],
  rows: readonly LiveSnapshotRow[],
): string {
  return createHash("sha256")
    .update(encodeLiveSnapshotDigestInput(identity, primaryKey, rows))
    .digest("hex");
}
