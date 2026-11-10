import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import type { ImportSource } from "@opendatalabs/personal-server-ts-core/localdb";

/** F.2/F.4: bounded page port implemented privately by legacy-access; no store opened here. */
export interface CanonicalImportPageReader {
  /** Declarations retained and verified by the existing authority, not caller manifests. */
  readonly declarations: readonly DeclarationSnapshot[];
  connections(
    sourceId: string,
  ): Promise<readonly { instance: string; deleted: boolean }[]>;
  page(
    instance: string,
    stream: string,
    after: string | null,
    limit: number,
  ): Promise<{
    readonly rows: readonly Record<string, unknown>[];
    readonly next: string | null;
  }>;
}

/**
 * F.2/F.3: adapt canonical pdpp_records via verified declarations and LIMIT
 * pages (byte bound too). Immutable revision, explicit exclusions; ambiguous
 * instances or missing declarations are held, never silently selected. Derive
 * connector/stream/key from declarations, never connector-id literals. Do not
 * invert legacy projected JSON or add transition tables. Oversized record
 * refuses, never skips silently. Factory returns descriptors lazily.
 */
export function createCanonicalImportSource(_options: {
  readonly owner: string;
  readonly network: string;
  readonly revision: string;
  readonly reader: CanonicalImportPageReader;
}): AsyncIterable<ImportSource> {
  throw new Error("PS-3: not built");
}
