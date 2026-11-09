/**
 * The durable record of the legacy import and of each readback, kept in the
 * stream-sync home's files (the same durable store the writer uses, on the
 * full server and in PS-Lite). Counts, hashes and pass/fail only: no record
 * body, no value.
 */

import type { StreamSyncFiles } from "../../stream-sync/ports.js";

const PATH = "legacy-retire/ledger.json";

/** One readback of one local legacy version. */
export interface ReadbackRecord {
  readonly scope: string;
  /** `id|path|collectedAt` of the local version it was proved for. */
  readonly version: string;
  readonly pass: boolean;
  readonly reason:
    | "ok"
    | "no_published_view"
    | "unreadable"
    | "unkeyed"
    | "empty"
    | "mismatch";
  /** Entities of the local file / entities found hash-equal in the published view. */
  readonly counts: {
    readonly local: number;
    readonly matched: number;
    readonly missing: number;
    readonly changed: number;
  };
  /** Local entities absent or changed but explained by the delete fence. */
  readonly fenced: number;
  /** SHA-256 over the matched `path|key|hash` lines, sorted. */
  readonly aggregate: string;
  readonly at: string;
  /**
   * Made by a dry run. A report, never a basis: a real pass ignores it and
   * reads the version back again.
   */
  readonly dry?: true;
  /**
   * Made before this device's import finished. A report, never a basis: a
   * real pass ignores it and reads the version back again.
   */
  readonly preImport?: true;
}

export interface LedgerData {
  /** A pass over the importable source finished with every stream staged. */
  importComplete: boolean;
  /** Connectors whose streams were all staged. */
  imported: Record<string, { readonly streams: number; readonly at: string }>;
  readbacks: Record<string, ReadbackRecord>;
}

const empty = (): LedgerData => ({
  importComplete: false,
  imported: {},
  readbacks: {},
});

const decoder = new TextDecoder();
const encoder = new TextEncoder();

export class RetireLedger {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly files: StreamSyncFiles) {}

  async read(): Promise<LedgerData> {
    const bytes = await this.files.read(PATH);
    if (!bytes) return empty();
    try {
      const parsed = JSON.parse(decoder.decode(bytes)) as Partial<LedgerData>;
      return {
        importComplete: parsed.importComplete === true,
        imported: parsed.imported ?? {},
        readbacks: parsed.readbacks ?? {},
      };
    } catch {
      return empty(); // unreadable = nothing proved
    }
  }

  /** Read-modify-write, serialized in this process. */
  update(change: (data: LedgerData) => void): Promise<void> {
    const next = this.chain.then(async () => {
      const data = await this.read();
      change(data);
      await this.files.write(PATH, encoder.encode(JSON.stringify(data)));
    });
    this.chain = next.catch(() => undefined);
    return next;
  }

  async importDone(connector: string): Promise<boolean> {
    const data = await this.read();
    return data.importComplete || data.imported[connector] !== undefined;
  }

  /** The stored readback of this version, or null (a dry or pre-import record is none). */
  async readback(
    scope: string,
    version: string,
  ): Promise<ReadbackRecord | null> {
    const found = (await this.read()).readbacks[`${scope}|${version}`];
    return found && found.dry !== true && found.preImport !== true
      ? found
      : null;
  }
}

export const versionKey = (row: {
  id: number;
  path: string;
  collectedAt: string;
}): string => `${row.id}|${row.path}|${row.collectedAt}`;
