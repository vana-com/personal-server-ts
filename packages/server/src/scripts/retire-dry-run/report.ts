/**
 * REPORT_REDACTED: the only thing the tool writes about a person's data.
 *
 * Per legacy file: scope name, counts, a short hash and the verdicts. Never a
 * record body, title, message text, key, token, owner address or database id.
 * Hashes are cut to 8 hex characters. Everything here is built from the
 * retire report and the ledger's counts; no record value reaches this module.
 *
 * This is a dry run: a snapshot on a copy. The real pass re-reads and
 * re-decides before every delete, so it is never looser than this report, and
 * this report can only over-predict deletions.
 */

import { createHash } from "node:crypto";
import type {
  ReadbackRecord,
  RetireDecision,
  RetireFileReport,
  RetireReport,
} from "@opendatalabs/personal-server-ts-core/sync";

export interface RedactedFile {
  /**
   * The connector name only: the scope's text before its first dot, if that
   * is a plain name. A scope can carry more than a stream name, so the rest
   * is never printed.
   */
  readonly connector: string;
  /** 8 hex of a hash over the whole scope; ties a row to a scope you know. */
  readonly scopeHash: string;
  /** 8 hex of a hash over the local version key; tells two versions apart. */
  readonly version: string;
  readonly importDone: boolean;
  readonly readback: RetireFileReport["readback"];
  readonly readbackReason: string | null;
  readonly counts: {
    readonly local: number;
    readonly matched: number;
    readonly missing: number;
    readonly changed: number;
    readonly fenced: number;
  };
  /** 8 hex of the hash over the matched entities. */
  readonly matchedHash: string;
  readonly decision: RetireFileReport["decision"];
  readonly wouldDelete: boolean;
}

export interface RedactedReport {
  readonly tool: "legacy-retire-dry-run";
  readonly status: "ok" | "aborted";
  /** Set only when aborted: a short code, never a message. */
  readonly abortReason?: string;
  readonly generatedAt: string;
  readonly mode: RetireReport["mode"] | null;
  readonly hosts: { readonly gateway: string; readonly storage: string };
  /**
   * How old the copy is: the newest modification time of any file in it. The
   * device's full-run proofs and import state are read from the copy, so the
   * report is true as of this time and no later. Null when the run aborted
   * before the copy was read.
   */
  readonly copy: {
    readonly newestFileModified: string;
    readonly files: number;
  } | null;
  readonly deviceImport: {
    readonly complete: boolean;
    readonly connectors: number;
    /** Of those, how many hold a per-stream receipt (older records hold none). */
    readonly receipts: number;
  };
  readonly publishedListing: {
    readonly pages: number;
    readonly rows: number;
    /** The copy held the device's registry mirror (its delete history). */
    readonly deviceMirror: boolean;
  };
  readonly files: readonly RedactedFile[];
  readonly totals: {
    readonly scopes: number;
    readonly localVersions: number;
    readonly reported: number;
    /** Local versions the pass did not report (no read target, or reserved). */
    readonly notReported: number;
    readonly wouldDelete: number;
    /** Every decision the retire pass has, zero when none: a new one fails the type. */
    readonly byDecision: Readonly<Record<RetireDecision, number>>;
    readonly counts: {
      readonly local: number;
      readonly matched: number;
      readonly missing: number;
      readonly changed: number;
      readonly fenced: number;
    };
  };
}

const hex8 = (text: string): string =>
  createHash("sha256").update(text).digest("hex").slice(0, 8);

/** The 8-hex hash that stands for a scope in the report. */
export const scopeHash = hex8;

export function connectorLabel(scope: string): string {
  const name = scope.split(".")[0] ?? "";
  return /^[a-z0-9_-]{1,40}$/.test(name) ? name : "unknown";
}

const emptyDecisions = (): Record<RetireDecision, number> => ({
  no_import: 0,
  no_readback: 0,
  readback_failed: 0,
  fence_not_imported: 0,
  fence_not_recollected: 0,
  file_changed: 0,
  ready: 0,
});

const ZERO = { local: 0, matched: 0, missing: 0, changed: 0, fenced: 0 };

export function redactFile(
  file: RetireFileReport,
  record: ReadbackRecord | null,
): RedactedFile {
  return {
    connector: connectorLabel(file.scope),
    scopeHash: scopeHash(file.scope),
    version: hex8(file.version),
    importDone: file.importDone,
    readback: file.readback,
    readbackReason: file.readbackReason,
    counts: record ? { ...record.counts, fenced: record.fenced } : ZERO,
    matchedHash: record ? record.aggregate.slice(0, 8) : "",
    decision: file.decision,
    wouldDelete: file.wouldDelete,
  };
}

export function buildReport(input: {
  readonly generatedAt: string;
  readonly retire: RetireReport;
  readonly records: ReadonlyMap<string, ReadbackRecord>;
  readonly hosts: RedactedReport["hosts"];
  readonly copy: RedactedReport["copy"];
  readonly deviceImport: RedactedReport["deviceImport"];
  readonly publishedListing: RedactedReport["publishedListing"];
  readonly store: { readonly scopes: number; readonly versions: number };
}): RedactedReport {
  const files = input.retire.files.map((f) =>
    redactFile(f, input.records.get(`${f.scope}|${f.version}`) ?? null),
  );
  const byDecision = emptyDecisions();
  const counts = { ...ZERO };
  for (const f of files) {
    byDecision[f.decision] += 1;
    counts.local += f.counts.local;
    counts.matched += f.counts.matched;
    counts.missing += f.counts.missing;
    counts.changed += f.counts.changed;
    counts.fenced += f.counts.fenced;
  }
  return {
    tool: "legacy-retire-dry-run",
    status: "ok",
    generatedAt: input.generatedAt,
    mode: input.retire.mode,
    hosts: input.hosts,
    copy: input.copy,
    deviceImport: input.deviceImport,
    publishedListing: input.publishedListing,
    files,
    totals: {
      scopes: input.store.scopes,
      localVersions: input.store.versions,
      reported: files.length,
      notReported: Math.max(0, input.store.versions - files.length),
      wouldDelete: files.filter((f) => f.wouldDelete).length,
      byDecision,
      counts,
    },
  };
}

export function abortedReport(input: {
  readonly generatedAt: string;
  readonly abortReason: string;
  readonly hosts: RedactedReport["hosts"];
}): RedactedReport {
  return {
    tool: "legacy-retire-dry-run",
    status: "aborted",
    abortReason: input.abortReason,
    generatedAt: input.generatedAt,
    mode: null,
    hosts: input.hosts,
    copy: null,
    deviceImport: { complete: false, connectors: 0, receipts: 0 },
    publishedListing: { pages: 0, rows: 0, deviceMirror: false },
    files: [],
    totals: {
      scopes: 0,
      localVersions: 0,
      reported: 0,
      notReported: 0,
      wouldDelete: 0,
      byDecision: emptyDecisions(),
      counts: { ...ZERO },
    },
  };
}
