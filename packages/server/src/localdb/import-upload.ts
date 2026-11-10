import type { ResolveArtifact } from "@opendatalabs/personal-server-ts-core/stream-sync";
import type {
  ImportSource,
  LegacyImportResult,
  LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.2: D6/P7 upload identity is authenticated owner + network + immutable source revision. */
export interface LegacyImportUpload {
  readonly source: string;
  readonly revision: string;
  readonly artifactDigest: string;
  readonly stream: string;
  /** Exact bounded NDJSON batches; durable staging permits replay and read-back. */
  readonly body: AsyncIterable<Uint8Array>;
}

/** F.2: replaces seed-staging's writer dependency; verifies retained artifact, <=4 MiB batch incl. envelope, backpressure; rejects oversize line. No delete. */
export function stageLegacyImportUpload(_options: {
  readonly owner: string;
  readonly network: string;
  readonly upload: LegacyImportUpload;
  readonly stagingRoot: string;
  readonly resolveArtifact: ResolveArtifact;
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
