/**
 * Import this device's own local data into stream data (one-time, per device).
 *
 * The source is stream-shaped rows already on the device (the canonical
 * record store); a legacy scope body is a lossy projection of them and is
 * never turned back into records. Rows go to the writer through its seed
 * intake, which is an ordinary publish with `collectedAt` 0: the delete
 * fence applies (a stream that has seen a delete drops the seed) and a row is
 * keyed by its primary key, so running the import again after a crash adds
 * nothing and loses nothing.
 *
 * The writer refuses to start a run of a connector until its import is done
 * (`StreamSyncWriterOptions.importDone`), so no run publishes first and
 * leaves the import to be skipped.
 */

import type { HeadProfile } from "@opendatalabs/personal-server-ts-stream-sync";
import type { RetireLedger } from "./ledger.js";

export interface ImportStream {
  readonly stream: string;
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  /** The device's current rows of the stream. */
  records(): AsyncIterable<Record<string, unknown>>;
}

/**
 * Why some of a connector's rows are not imported. They stay in the legacy
 * file, and the ledger keeps this count so that "not imported" is never mistaken
 * for "nothing there". `stream` is null for a whole-connector reason.
 */
export interface ImportExclusion {
  readonly stream: string | null;
  readonly reason:
    | "unmapped_stream"
    | "no_primary_key"
    | "unkeyed_row"
    /** Rows of a live connection other than the one imported. */
    | "other_connection";
  readonly rows: number;
}

/**
 * The source cannot be read yet (the host has not opened its stores). A pass
 * that meets it is pending: it records nothing, and the writer keeps waiting.
 * An empty source answers with an empty list, never with this.
 */
export class ImportSourceUnavailableError extends Error {
  constructor() {
    super("legacy import source is not available yet");
    this.name = "ImportSourceUnavailableError";
  }
}

export interface LegacyImportSource {
  /**
   * The Account owner whose device rows this source reads. A pass refuses a
   * source whose owner is not the importer's.
   */
  readonly owner: string;
  /**
   * Connectors this device holds importable rows for. Throws
   * `ImportSourceUnavailableError` while the source cannot be read.
   */
  connectors(): Promise<readonly string[]>;
  streams(connector: string): Promise<readonly ImportStream[]>;
  /** What `streams(connector)` left out; read right after it. */
  excluded?(connector: string): Promise<readonly ImportExclusion[]>;
}

export interface LegacyImportSink {
  /**
   * Hand one stream's rows to the writer's seed intake. The previous upload
   * of the stream is replaced, so calling it again is safe. Returns how many
   * rows the intake KEPT, counted at its commit point. Pulling a row is not
   * keeping it: an intake may drop a row it cannot key.
   */
  stage(
    connector: string,
    stream: ImportStream,
    rows: AsyncIterable<Record<string, unknown>>,
  ): Promise<number>;
}

export interface LegacyImporterOptions {
  readonly source: LegacyImportSource;
  readonly sink: LegacyImportSink;
  readonly ledger: RetireLedger;
  /** Whether the account is switched now; read on every call. */
  readonly switched: () => boolean;
  /**
   * Whether the connection of `connector` was deleted (by any device). A
   * deleted connection's legacy rows are never staged: its import is recorded
   * done with nothing staged, so a later reconnect does not bring them back.
   */
  readonly deleted?: (connector: string) => Promise<boolean>;
  /**
   * Ask the writer to publish the rows staged for a connector, so they are
   * readable with no connector run. Called on every pass until it answers
   * `done`. Absent: staged rows wait for the connector's first run (a host
   * with no writer of its own).
   */
  readonly publish?: (connector: string) => Promise<"done" | "waiting">;
  /** Failed passes before a connector (or the source listing) is given up. */
  readonly maxAttempts?: number;
  readonly now?: () => Date;
  readonly logger?: {
    warn(obj: Record<string, unknown>, msg?: string): void;
  };
}

export interface ImportPassResult {
  readonly ran: boolean;
  readonly connectorsStaged: number;
  readonly failed: number;
  /** The source was not readable yet; nothing was recorded. */
  readonly pending?: true;
  /** The pass did not start: the source belongs to another owner. */
  readonly refused?: "owner_mismatch";
}

/** Failed passes before a connector is given up, when the host sets none. */
export const DEFAULT_MAX_ATTEMPTS = 5;

/**
 * What the import did, for the owner to see. Counts and names only: no row,
 * no stream name, no error text.
 */
export interface ImportStatus {
  /** Every connector was imported or given up. */
  readonly complete: boolean;
  /** The source could not be listed within the bound; no file is retired. */
  readonly abandoned: boolean;
  readonly connectors: readonly {
    readonly connector: string;
    /** `pending` = tried and failed, will try again. */
    readonly state: "imported" | "pending" | "failed";
    readonly attempts: number;
    /** Rows handed to the writer. */
    readonly staged: number;
    /** Rows left in the legacy store, by reason. */
    readonly excluded: readonly { reason: string; rows: number }[];
  }[];
}

export class LegacyImporter {
  private pass: Promise<ImportPassResult> | null = null;

  constructor(private readonly options: LegacyImporterOptions) {}

  /**
   * The writer's gate: true once this connector's rows are staged (or the
   * whole pass finished). Not switched: nothing to wait for.
   */
  importDone = async (connector: string): Promise<boolean> => {
    if (!this.options.switched()) return true;
    return this.options.ledger.importDone(connector);
  };

  /**
   * One pass over the source. Safe to call on every boot and cycle: a
   * finished pass returns at once, a failed one starts again from the
   * connectors not yet staged.
   */
  run(): Promise<ImportPassResult> {
    this.pass ??= this.runPass().finally(() => {
      this.pass = null;
    });
    return this.pass;
  }

  private async runPass(): Promise<ImportPassResult> {
    const { source, ledger } = this.options;
    if (!this.options.switched()) {
      return { ran: false, connectorsStaged: 0, failed: 0 };
    }
    if (source.owner.toLowerCase() !== ledger.owner) {
      this.options.logger?.warn(
        {},
        "Legacy import source belongs to another owner",
      );
      return {
        ran: false,
        connectorsStaged: 0,
        failed: 0,
        refused: "owner_mismatch",
      };
    }
    const result = (await ledger.read()).importComplete
      ? { ran: false, connectorsStaged: 0, failed: 0 }
      : await this.stage();
    await this.queueRuns();
    return result;
  }

  private get maxAttempts(): number {
    return this.options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  }

  private now(): string {
    return (this.options.now?.() ?? new Date()).toISOString();
  }

  /** Stage every connector the source lists that is not imported or given up. */
  private async stage(): Promise<ImportPassResult> {
    const { source, sink, ledger } = this.options;
    let connectors: readonly string[];
    try {
      connectors = await source.connectors();
    } catch (error) {
      if (error instanceof ImportSourceUnavailableError) {
        return { ran: true, connectorsStaged: 0, failed: 0, pending: true };
      }
      this.options.logger?.warn(
        { error: error instanceof Error ? error.name : "NonError" },
        "Legacy import source could not be listed; retried next cycle",
      );
      // A source that never lists would stall every connector's writes. After
      // the bound the import gives up: writes proceed, no file is retired.
      await ledger.update((data) => {
        data.listAttempts += 1;
        if (data.listAttempts >= this.maxAttempts) {
          data.abandoned = true;
          data.importComplete = true;
        }
      });
      return { ran: true, connectorsStaged: 0, failed: 1 };
    }
    let staged = 0;
    let failed = 0;
    let waiting = 0;
    for (const connector of connectors) {
      const known = await ledger.read();
      if (known.imported[connector] || known.failures[connector]?.gaveUp) {
        continue;
      }
      if (await this.options.deleted?.(connector)) {
        const at = (this.options.now?.() ?? new Date()).toISOString();
        await ledger.update((data) => {
          data.imported[connector] = { streams: 0, at, staged: {} };
        });
        continue;
      }
      try {
        const streams = await source.streams(connector);
        // The receipt: per stream, the rows the sink says it kept.
        const receipt: Record<string, number> = {};
        for (const stream of streams) {
          receipt[stream.stream] = await sink.stage(
            connector,
            stream,
            stream.records(),
          );
        }
        const excluded = (await source.excluded?.(connector)) ?? [];
        const at = this.now();
        await ledger.update((data) => {
          data.imported[connector] = {
            streams: streams.length,
            at,
            staged: receipt,
          };
          delete data.failures[connector];
          if (excluded.length > 0) data.excluded[connector] = [...excluded];
          else delete data.excluded[connector];
        });
        staged += 1;
      } catch (error) {
        failed += 1;
        let gaveUp = false;
        await ledger.update((data) => {
          const attempts = (data.failures[connector]?.attempts ?? 0) + 1;
          gaveUp = attempts >= this.maxAttempts;
          data.failures[connector] = { attempts, at: this.now(), gaveUp };
        });
        if (!gaveUp) waiting += 1;
        this.options.logger?.warn(
          {
            error: error instanceof Error ? error.name : "NonError",
            gaveUp,
          },
          gaveUp
            ? "Legacy import of a connector failed; given up, its legacy file is kept"
            : "Legacy import of a connector failed; retried next cycle",
        );
      }
    }
    if (waiting === 0) {
      await ledger.update((data) => {
        data.importComplete = true;
      });
    }
    return { ran: true, connectorsStaged: staged, failed };
  }

  /**
   * Ask for the publish of each connector's staged rows until the writer
   * says it is done. A failure is retried on the next pass; the connector's
   * own runs are not held for it.
   */
  private async queueRuns(): Promise<void> {
    const { publish, ledger } = this.options;
    if (!publish) return;
    const { imported } = await ledger.read();
    for (const [connector, record] of Object.entries(imported)) {
      if (record.published) continue;
      const rows = Object.values(record.staged ?? {}).reduce(
        (sum, n) => sum + n,
        0,
      );
      if (rows === 0) continue;
      try {
        if ((await publish(connector)) === "done") {
          await ledger.update((data) => {
            const own = data.imported[connector];
            if (own) data.imported[connector] = { ...own, published: true };
          });
        }
      } catch (error) {
        this.options.logger?.warn(
          { error: error instanceof Error ? error.name : "NonError" },
          "Legacy import rows were staged but their publish run could not be queued; retried next cycle",
        );
      }
    }
  }

  /** What the import did, for the owner: counts per connector and reason. */
  async status(): Promise<ImportStatus> {
    const data = await this.options.ledger.read();
    const names = new Set([
      ...Object.keys(data.imported),
      ...Object.keys(data.failures),
      ...Object.keys(data.excluded),
    ]);
    return {
      complete: data.importComplete,
      abandoned: data.abandoned,
      connectors: [...names].sort().map((connector) => {
        const byReason = new Map<string, number>();
        for (const e of data.excluded[connector] ?? []) {
          byReason.set(e.reason, (byReason.get(e.reason) ?? 0) + e.rows);
        }
        const failure = data.failures[connector];
        return {
          connector,
          state: data.imported[connector]
            ? ("imported" as const)
            : failure?.gaveUp
              ? ("failed" as const)
              : ("pending" as const),
          attempts: failure?.attempts ?? 0,
          staged: Object.values(data.imported[connector]?.staged ?? {}).reduce(
            (sum, n) => sum + n,
            0,
          ),
          excluded: [...byReason]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([reason, rows]) => ({ reason, rows })),
        };
      }),
    };
  }
}
