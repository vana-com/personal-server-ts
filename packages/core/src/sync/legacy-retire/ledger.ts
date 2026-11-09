/**
 * The durable record of the legacy import and of each readback, kept in the
 * stream-sync home's files (the same durable store the writer uses, on the
 * full server and in PS-Lite). Counts, hashes and pass/fail only: no record
 * body, no value.
 */

import type { StreamSyncFiles } from "../../stream-sync/ports.js";
import type { ImportExclusion } from "./import.js";

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
  /** SHA-256 of the canonical JSON of the whole local file this was proved for. */
  readonly fileHash?: string;
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
  /**
   * The Account owner (lowercase) every field below was recorded for.
   */
  owner: string;
  /**
   * Connectors whose streams were all staged. `staged` is the receipt: each
   * stream this device handed to the writer, with how many rows. A record
   * written before receipts existed has none, and proves no stream.
   */
  imported: Record<
    string,
    {
      readonly streams: number;
      readonly at: string;
      readonly staged?: Readonly<Record<string, number>>;
      /** The writer merged every staged stream into the stream store. */
      readonly published?: true;
      /**
       * The writer's answer is final: every stream has a receipt. Streams it
       * did NOT merge are counted in `excluded` as `seed_skipped`; they are
       * not published.
       */
      readonly seedDone?: true;
      /**
       * Set only when the connector had several live connections: which one
       * was imported (a truncated hash, never the id) and how many were
       * passed over. `tied`: the top two had the same latest write.
       */
      readonly connection?: {
        readonly chosen: string;
        readonly passedOver: number;
        readonly tied: boolean;
      };
    }
  >;
  /**
   * Connectors whose import failed, with how many passes tried. After the
   * bound the connector is given up: its writes proceed, and its legacy file
   * is never retired.
   */
  failures: Record<
    string,
    {
      readonly attempts: number;
      readonly at: string;
      readonly gaveUp: boolean;
      /**
       * Rows that stayed only in the legacy file because of the failure, when
       * the source could be read to count them; absent when it could not.
       */
      readonly stayed?: number;
    }
  >;
  /** Passes that could not list the source at all. */
  listAttempts: number;
  /**
   * The source was listed at least once. Until then no row was examined, so
   * the count of rows left in legacy files is unknown, not zero.
   */
  listed: boolean;
  /** The source could not be listed within the bound; no file is retired. */
  abandoned: boolean;
  /**
   * Rows of each connector the import left in the legacy file, by reason.
   * Counts only. A connector with an entry here keeps those rows' file.
   */
  excluded: Record<string, ImportExclusion[]>;
  readbacks: Record<string, ReadbackRecord>;
  /**
   * This device's first import finished: every staged stream has the writer's
   * final answer. The one place "import done" is kept; the writer's gate and
   * the retire pass both read it here.
   */
  importComplete: boolean;
}

const empty = (owner: string): LedgerData => ({
  owner,
  imported: {},
  failures: {},
  listAttempts: 0,
  listed: false,
  abandoned: false,
  excluded: {},
  readbacks: {},
  importComplete: false,
});

const decoder = new TextDecoder();
const encoder = new TextEncoder();

export class RetireLedger {
  private chain: Promise<unknown> = Promise.resolve();

  /** The Account owner this ledger is for, lowercase. */
  readonly owner: string;

  constructor(
    private readonly files: StreamSyncFiles,
    owner: string,
  ) {
    this.owner = owner.toLowerCase();
  }

  /**
   * What is recorded for this ledger's owner. A file recorded for nobody, or
   * for another owner, reads as empty: it proves nothing here, and the next
   * `update` replaces it.
   */
  async read(): Promise<LedgerData> {
    const bytes = await this.files.read(PATH);
    if (!bytes) return empty(this.owner);
    try {
      const parsed = JSON.parse(decoder.decode(bytes)) as Partial<LedgerData>;
      if (parsed.owner !== this.owner) return empty(this.owner);
      return {
        owner: this.owner,
        imported: parsed.imported ?? {},
        failures: parsed.failures ?? {},
        listAttempts: parsed.listAttempts ?? 0,
        listed: parsed.listed === true,
        abandoned: parsed.abandoned === true,
        excluded: parsed.excluded ?? {},
        readbacks: parsed.readbacks ?? {},
        importComplete: parsed.importComplete === true,
      };
    } catch {
      return empty(this.owner); // unreadable = nothing proved
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

  /** Whether this account's import is still to finish. */
  async importPending(): Promise<boolean> {
    return !(await this.read()).importComplete;
  }

  /** Record that this account's import is finished. */
  async markImportDone(): Promise<void> {
    await this.update((data) => {
      data.importComplete = true;
    });
  }

  /**
   * Nothing is left to wait for on this connector: the import is complete,
   * its rows are staged, or the import gave it up. The writer's gate.
   */
  async importDone(connector: string): Promise<boolean> {
    const data = await this.read();
    return (
      data.importComplete ||
      data.imported[connector] !== undefined ||
      data.failures[connector]?.gaveUp === true
    );
  }

  /**
   * Import is done AND left nothing behind: no row stayed in the legacy
   * store, the connector was not given up, and the source was listed. Only
   * then may a legacy file of the connector be retired.
   */
  async importProven(connector: string): Promise<boolean> {
    const data = await this.read();
    if (data.abandoned || data.failures[connector]?.gaveUp === true) {
      return false;
    }
    if ((data.excluded[connector] ?? []).some((e) => e.rows > 0)) return false;
    return data.imported[connector] !== undefined || data.importComplete;
  }

  /**
   * This device staged at least one row of this stream. Stricter than
   * `importDone`: a finished import over an EMPTY source is done for every
   * connector (nothing to wait for), and a source may list a connector with
   * no stream, or a stream with no row. None of those staged anything, so
   * none proves that a row of a file was ever delivered.
   */
  async staged(connector: string, stream: string): Promise<boolean> {
    const rows = (await this.read()).imported[connector]?.staged?.[stream];
    return rows !== undefined && rows > 0;
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
