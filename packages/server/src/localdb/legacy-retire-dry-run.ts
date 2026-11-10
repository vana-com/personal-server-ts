import type {
  LegacyRetireFileReport,
  LegacyRetireReport,
} from "@opendatalabs/personal-server-ts-core/localdb";

/** F.2/F.4, #601: byte-copy input only; both configs require explicit selection. */
export interface LegacyRetireDryRunOptions {
  readonly copyRoot: string;
  readonly scratchRoot: string;
  readonly configFile?: "server.json" | "config.json";
  readonly reportFile: (report: LegacyRetireFileReport) => void;
}

/**
 * F.2/F.4: read-only on a byte copy under ~/.tmp, never ~/.vana, symlink or
 * live WAL/SHM input. Open a fresh scratch DB copy through legacy-access so
 * replication closure cannot mutate the input. No import, publish, registry
 * writes or erase capability. Fingerprint input before/after. Same row and
 * projection comparisons and watermark decisions as real retirement, report
 * per file with redacted ids. Flag on cannot enable deletion. Missing import
 * receipts hold files. No network needed: DB rows are the read-back source.
 */
export function runLegacyRetireDryRun(
  _options: LegacyRetireDryRunOptions,
): Promise<LegacyRetireReport> {
  throw new Error("PS-3: not built");
}
