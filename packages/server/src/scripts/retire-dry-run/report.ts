/**
 * REPORT_REDACTED: the only thing the tool writes about a person's data.
 *
 * Per legacy file: scope name, counts, a short hash and the verdicts. Never a
 * record body, title, message text, key, token, owner address or database id.
 * Hashes are cut to 8 hex characters. Everything here is built from the
 * retire report and the ledger's counts; no record value reaches this module.
 */

import { createHash } from "node:crypto";
import type {
  ReadbackRecord,
  RetireFileReport,
  RetireReport,
} from "@opendatalabs/personal-server-ts-core/sync";

export interface RedactedFile {
  readonly scope: string;
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
  readonly deviceImport: {
    readonly complete: boolean;
    readonly connectors: number;
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
    readonly byDecision: Readonly<Record<string, number>>;
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

const ZERO = { local: 0, matched: 0, missing: 0, changed: 0, fenced: 0 };

export function redactFile(
  file: RetireFileReport,
  record: ReadbackRecord | null,
): RedactedFile {
  return {
    scope: file.scope,
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
  readonly deviceImport: RedactedReport["deviceImport"];
  readonly publishedListing: RedactedReport["publishedListing"];
  readonly store: { readonly scopes: number; readonly versions: number };
}): RedactedReport {
  const files = input.retire.files.map((f) =>
    redactFile(f, input.records.get(`${f.scope}|${f.version}`) ?? null),
  );
  const byDecision: Record<string, number> = {};
  const counts = { ...ZERO };
  for (const f of files) {
    byDecision[f.decision] = (byDecision[f.decision] ?? 0) + 1;
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
    deviceImport: { complete: false, connectors: 0 },
    publishedListing: { pages: 0, rows: 0, deviceMirror: false },
    files: [],
    totals: {
      scopes: 0,
      localVersions: 0,
      reported: 0,
      notReported: 0,
      wouldDelete: 0,
      byDecision: {},
      counts: { ...ZERO },
    },
  };
}
