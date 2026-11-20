// Verified input I/O is separate from replay scheduling, so callers can read
// wire metadata without resolving every referenced record body.
import {
  segmentBlobName,
  snapshotPartBlobName,
  verifySegment,
  verifySnapshotPart,
  segmentRemoves,
  type Segment,
  type SnapshotPart,
  type WireSegment,
  type WireSnapshotPart,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { keccakOf } from "../stream-sync/crypto-port.js";
import { runtimeAdmission } from "./workspace.js";
import { resolveBodies } from "./log-bodies.js";
import { UpdateRequiredError } from "./update-required.js";
import type { LocalSyncDeps } from "./deps.js";
import type { LogApplyContext } from "./log-apply.js";
/** One segment, fetched, decrypted and verified against the hash and position. */
export async function fetchSegmentWire(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  dataHash: string,
  position: number,
): Promise<{ segment: WireSegment; bytes: number; cipherBytes: number }> {
  const cipher = await deps.blobs.get(`${scope}/${segmentBlobName(dataHash)}`);
  if (cipher === null)
    throw new Error(`apply: missing log segment ${position}`);
  const verified = await verifySegment(
    keccakOf(deps.streamCrypto),
    await deps.keys.decrypt(scope, cipher),
    {
      dataHash,
      connector: context.connector,
      ns: context.ns,
      keyCheck: context.keyCheck,
      position,
    },
  );
  if (verified.kind === "unsupported_format")
    throw new UpdateRequiredError(
      `apply: invalid log segment ${position} (unsupported_format)`,
      verified.format,
    );
  if (verified.kind !== "ok")
    throw new Error(
      `apply: invalid log segment ${position} (${verified.kind})`,
    );
  return {
    segment: verified.segment,
    bytes: verified.bytes,
    cipherBytes: cipher.length,
  };
}

/** One snapshot part, fetched, decrypted and verified. */
export async function fetchSnapshotPartWire(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  dataHash: string,
  position: number,
): Promise<WireSnapshotPart> {
  const cipher = await deps.blobs.get(
    `${scope}/${snapshotPartBlobName(dataHash)}`,
  );
  if (cipher === null) throw new Error("apply: missing log snapshot part");
  const verified = await verifySnapshotPart(
    keccakOf(deps.streamCrypto),
    await deps.keys.decrypt(scope, cipher),
    {
      dataHash,
      connector: context.connector,
      ns: context.ns,
      keyCheck: context.keyCheck,
      position,
    },
  );
  if (verified.kind === "unsupported_format")
    throw new UpdateRequiredError(
      "apply: invalid log snapshot part (unsupported_format)",
      verified.format,
    );
  if (verified.kind !== "ok")
    throw new Error(`apply: invalid log snapshot part (${verified.kind})`);
  return verified.part;
}

/** Ordinary callers receive resolved bodies; progressive replay resolves one record at a time. */
export async function fetchSegment(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  dataHash: string,
  position: number,
  metadataOnly = false,
): Promise<{
  segment: Segment;
  bytes: number;
  cipherBytes: number;
  removes: boolean;
}> {
  const lease = metadataOnly
    ? await runtimeAdmission.acquire(`head:${dataHash}`, 128 * 1024 * 1024)
    : null;
  try {
    const fetched = await fetchSegmentWire(
      deps,
      scope,
      context,
      dataHash,
      position,
    );
    const segment: Segment = {
      ...fetched.segment,
      operations: metadataOnly
        ? []
        : await resolveBodies(deps, scope, fetched.segment.operations),
    };
    return {
      ...fetched,
      segment,
      removes: segmentRemoves(fetched.segment.operations),
    };
  } finally {
    await lease?.release();
  }
}
export async function fetchSnapshotPart(
  deps: LocalSyncDeps,
  scope: string,
  context: Pick<LogApplyContext, "connector" | "ns" | "keyCheck">,
  dataHash: string,
  position: number,
): Promise<SnapshotPart> {
  const part = await fetchSnapshotPartWire(
    deps,
    scope,
    context,
    dataHash,
    position,
  );
  return { ...part, entries: await resolveBodies(deps, scope, part.entries) };
}
