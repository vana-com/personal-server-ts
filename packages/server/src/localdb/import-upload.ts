import type { ResolveArtifact } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type {
  ImportSource,
  LegacyImportResult,
  LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.2: D6/P7 upload identity is authenticated owner + network + immutable source revision. */
export interface LegacyImportUpload {
  /** Authenticated stable install id, bound by the caller; never a path. This
   * is provenance only: it MUST NOT select a device-specific sync namespace. */
  readonly source: string;
  /** Lowercase SHA-256 of complete uploaded NDJSON bytes. Stage privately,
   * verify at EOF, then atomically seal. No import before a matching seal.
   * Same revision with different bytes refuses; partial staging never reopens. */
  readonly revision: string;
  readonly artifactDigest: string;
  readonly stream: string;
  /** Exact bounded NDJSON batches; durable staging permits replay and read-back. */
  readonly body: AsyncIterable<Uint8Array>;
}

/** Durable replay key is JSON [owner,network,installId,artifactDigest,stream,
 * revision]; local path is a hash of this tuple, never raw input. Re-entering
 * staging with that tuple reopens only a verified sealed file and rehashes it.
 * Returned ledger source is JSON [installId, verified source id, revision].
 * F.2: replaces seed-staging's writer dependency; verifies retained artifact, <=4 MiB batch incl. envelope, backpressure; rejects oversize line. No delete. */
export function stageLegacyImportUpload(_options: {
  readonly owner: string;
  readonly network: string;
  readonly upload: LegacyImportUpload;
  readonly stagingRoot: string;
  readonly resolveArtifact: ResolveArtifact;
  /** Existing authenticated connection authority, independent of install id.
   * Refuse null/ambiguous mappings; never derive a connection from install id.
   * The artifact resolver verifies declarations; it does not prove identity. */
  readonly resolveTarget: (
    upload: LegacyImportUpload,
  ) => Promise<ImportSource["target"] | null>;
}): Promise<ImportSource> {
  throw new Error("PS-3: not built");
}

/** F.2/C.0: authenticated switched-owner adapter calls staging then SQL import; retries preserve identity. No writer/spool/frame dependency. */
export function acceptLegacyImportUpload(
  _deps: LocalSyncDeps,
  _source: ImportSource,
): Promise<LegacyImportResult> {
  throw new Error("PS-3: not built");
}
