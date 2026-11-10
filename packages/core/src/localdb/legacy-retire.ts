import type { LocalSyncDeps } from "./deps.js";
import type {
  ImportReadback,
  LegacyCopy,
  LegacyRetireFileReport,
  LegacyRetireReport,
} from "./legacy-import-types.js";

/** F.2/F.4: host capability comes only from switched-owner legacy-access. */
export interface LegacyRetireAccess {
  copies(): AsyncIterable<LegacyCopy>;
  /** Fresh proof for every source named by copy, bound to this exact hash/revision. Caller holds queues: must not reacquire them. */
  readBack(copy: LegacyCopy): Promise<readonly ImportReadback[]>;
  /** Atomic compare-and-erase of local copies only; never gateway operations. */
  erase(copy: LegacyCopy): Promise<boolean>;
}

/** F.2: absent streamSync.retireLegacy means false on every host. */
export interface LegacyRetireOptions {
  readonly streamSync?: { readonly retireLegacy?: boolean };
  readonly dryRun?: boolean;
  readonly reportFile: (report: LegacyRetireFileReport) => void;
}

/**
 * F.2-F.5: under each connection queue, fresh read-back, unchanged source/file,
 * generation 1, no delete intent/control tombstone, nonempty complete source
 * coverage and stream.publish_watermark >= EACH receipt.highestSeq are ALL
 * required. Recheck before erase; serialize multi-stream copies in sorted
 * connection order. Stored verified status alone grants nothing. Unknowns,
 * exclusions and deleted connections hold files. Dry run never calls erase or
 * persists verified/retired state even with the flag on. Erase then mark retired;
 * a crash after erase may leave the receipt unretired. Generic ENOENT or
 * erase(false) is NOT evidence of exact-copy absence. Until a host supplies
 * durable exact-copy retirement intent/reconciliation, retain that unknown
 * state; never erase a replacement or synthesize retired evidence.
 */
export function retireLegacyCopies(
  _deps: LocalSyncDeps,
  _access: LegacyRetireAccess,
  _options: LegacyRetireOptions,
): Promise<LegacyRetireReport> {
  throw new Error("PS-3: not built");
}
