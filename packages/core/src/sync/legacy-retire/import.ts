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
import type { SeedPublication } from "../../stream-sync/writer.js";
import type { RetireLedger } from "./ledger.js";

export interface ImportStream {
  readonly stream: string;
  readonly primaryKey: readonly string[];
  readonly profile: HeadProfile;
  /** How many rows `records()` will yield, when the source counted them. */
  readonly rows?: number;
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
    | "other_connection"
    /**
     * Staged, but the writer did not merge the stream's seed (another device
     * had already published generation 1, or a delete dropped it). Those rows
     * are not readable from the stream store.
     */
    | "seed_skipped";
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

/**
 * Which of several live connections a connector imported. Counts and a
 * truncated hash only: never the connection id.
 */
export interface ImportConnectionChoice {
  readonly chosen: string;
  readonly passedOver: number;
  /** The top two connections had the same latest write. */
  readonly tied: boolean;
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
  /**
   * Which connection `streams(connector)` imported, when the connector had
   * more than one live; null otherwise. Read right after it.
   */
  connection?(connector: string): Promise<ImportConnectionChoice | null>;
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
  /**
   * The Account this importer acts for: the owner the mode authority is asked
   * about. The source and the ledger must both belong to it.
   */
  readonly owner: string;
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
   * `done`; it names the streams whose seed was not merged. Absent: staged
   * rows wait for the connector's first run (a host with no writer of its
   * own).
   */
  readonly publish?: (connector: string) => Promise<SeedPublication>;
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
 * What the import did, for the owner to see. Counts, names and truncated
 * hashes only: no row, no stream name, no connection id, no error text.
 */
export interface ImportStatus {
  /** The authority no longer waits for this account's import. */
  readonly complete: boolean;
  /** The source could not be listed within the bound; no file is retired. */
  readonly abandoned: boolean;
  /**
   * Rows that stayed only in a legacy file, over all connectors; null when
   * some could not be counted (an unreadable source or connector).
   */
  readonly stayed: number | null;
  readonly connectors: readonly {
    readonly connector: string;
    /**
     * `published`: the writer merged every staged stream. `imported`: staged,
     * not (fully) published yet. `pending`: tried and failed, will try again.
     * `failed`: given up.
     */
    readonly state: "published" | "imported" | "pending" | "failed";
    readonly attempts: number;
    /** Rows handed to the writer. */
    readonly staged: number;
    /** Rows that stayed only in the legacy file; null when not countable. */
    readonly stayed: number | null;
    /** Rows left in the legacy store, by reason. */
    readonly excluded: readonly { reason: string; rows: number }[];
    /** Present when the connector had several live connections. */
    readonly connection?: ImportConnectionChoice;
  }[];
}

const sumRows = (list: readonly { rows: number }[]): number =>
  list.reduce((sum, e) => sum + e.rows, 0);

export class LegacyImporter {
  private pass: Promise<ImportPassResult> | null = null;

  constructor(private readonly options: LegacyImporterOptions) {}

  /**
   * The writer's gate: true once this connector's rows are staged, or the
   * authority says the import is done. Not switched: nothing to wait for.
   */
  importDone = async (connector: string): Promise<boolean> => {
    if (!this.options.switched()) return true;
    return this.options.ledger.importDone(connector);
  };

  /**
   * One pass over the source. Safe to call on every boot and cycle: once the
   * authority says the import is done it returns at once, and a pass that
   * failed starts again from the connectors not yet staged.
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
    // The request owner (whom the mode is asked about) against the owner the
    // source reads for and the owner the ledger was recorded for.
    const owner = this.options.owner.toLowerCase();
    if (source.owner.toLowerCase() !== owner || ledger.owner !== owner) {
      this.options.logger?.warn(
        {},
        "Legacy import source or ledger belongs to another owner",
      );
      return {
        ran: false,
        connectorsStaged: 0,
        failed: 0,
        refused: "owner_mismatch",
      };
    }
    // The authority owns "done": once it says so, the import never runs again.
    if (!(await ledger.importPending())) {
      return { ran: false, connectorsStaged: 0, failed: 0 };
    }
    const { result, settled } = await this.stage();
    await this.queueRuns();
    if (settled && (await this.allSeedsFinal())) {
      try {
        await ledger.markImportDone();
      } catch (error) {
        this.options.logger?.warn(
          { error: error instanceof Error ? error.name : "NonError" },
          "Legacy import finished but the authority was not told; retried next cycle",
        );
      }
    }
    return result;
  }

  private get maxAttempts(): number {
    return this.options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  }

  private now(): string {
    return (this.options.now?.() ?? new Date()).toISOString();
  }

  /**
   * Stage every connector the source lists that is not imported or given up.
   * `settled`: the listing worked (or was given up) and no connector is still
   * waiting for a retry.
   */
  private async stage(): Promise<{
    result: ImportPassResult;
    settled: boolean;
  }> {
    const { source, sink, ledger } = this.options;
    let connectors: readonly string[];
    try {
      connectors = await source.connectors();
    } catch (error) {
      if (error instanceof ImportSourceUnavailableError) {
        return {
          result: { ran: true, connectorsStaged: 0, failed: 0, pending: true },
          settled: false,
        };
      }
      this.options.logger?.warn(
        { error: error instanceof Error ? error.name : "NonError" },
        "Legacy import source could not be listed; retried next cycle",
      );
      // A source that never lists would stall every connector's writes. After
      // the bound the import gives up: writes proceed, no file is retired.
      let abandoned = false;
      await ledger.update((data) => {
        data.listAttempts += 1;
        if (data.listAttempts >= this.maxAttempts) {
          data.abandoned = true;
          abandoned = true;
        }
      });
      return {
        result: { ran: true, connectorsStaged: 0, failed: 1 },
        settled: abandoned,
      };
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
      let stayed: number | undefined;
      try {
        const streams = await source.streams(connector);
        const excluded = (await source.excluded?.(connector)) ?? [];
        const connection = (await source.connection?.(connector)) ?? null;
        // Should the staging fail, these rows stay in the legacy file.
        if (streams.every((s) => s.rows !== undefined)) {
          stayed = streams.reduce((sum, s) => sum + (s.rows ?? 0), 0);
          stayed += sumRows(excluded);
        }
        // The receipt: per stream, the rows the sink says it kept.
        const receipt: Record<string, number> = {};
        for (const stream of streams) {
          receipt[stream.stream] = await sink.stage(
            connector,
            stream,
            stream.records(),
          );
        }
        const at = this.now();
        await ledger.update((data) => {
          data.imported[connector] = {
            streams: streams.length,
            at,
            staged: receipt,
            ...(connection ? { connection } : {}),
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
          data.failures[connector] = {
            attempts,
            at: this.now(),
            gaveUp,
            ...(stayed === undefined ? {} : { stayed }),
          };
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
    return {
      result: { ran: true, connectorsStaged: staged, failed },
      settled: waiting === 0,
    };
  }

  /**
   * Ask for the publish of each connector's staged rows until the writer
   * says it is done. A failure is retried on the next pass; the connector's
   * own runs are not held for it. Streams the writer did not merge are
   * counted as left behind, never as published.
   */
  private async queueRuns(): Promise<void> {
    const { publish, ledger } = this.options;
    if (!publish) return;
    const { imported } = await ledger.read();
    for (const [connector, record] of Object.entries(imported)) {
      if (record.published || record.seedDone) continue;
      if (this.stagedRows(record) === 0) continue;
      try {
        const outcome = await publish(connector);
        if (outcome.state !== "done") continue;
        const skipped = outcome.skipped;
        await ledger.update((data) => {
          const own = data.imported[connector];
          if (!own) return;
          const lost = skipped
            .map((stream) => ({
              stream,
              reason: "seed_skipped" as const,
              rows: own.staged?.[stream] ?? 0,
            }))
            .filter((e) => e.rows > 0);
          data.imported[connector] = {
            ...own,
            seedDone: true,
            ...(lost.length === 0 ? { published: true as const } : {}),
          };
          if (lost.length > 0) {
            data.excluded[connector] = [
              ...(data.excluded[connector] ?? []),
              ...lost,
            ];
          }
        });
      } catch (error) {
        this.options.logger?.warn(
          { error: error instanceof Error ? error.name : "NonError" },
          "Legacy import rows were staged but their publish run could not be queued; retried next cycle",
        );
      }
    }
  }

  private stagedRows(record: { staged?: Readonly<Record<string, number>> }) {
    return Object.values(record.staged ?? {}).reduce((sum, n) => sum + n, 0);
  }

  /** Every staged connector has a final answer from the writer. */
  private async allSeedsFinal(): Promise<boolean> {
    if (!this.options.publish) return true;
    const { imported } = await this.options.ledger.read();
    return Object.values(imported).every(
      (record) =>
        record.published === true ||
        record.seedDone === true ||
        this.stagedRows(record) === 0,
    );
  }

  /** What the import did, for the owner: counts per connector and reason. */
  async status(): Promise<ImportStatus> {
    const data = await this.options.ledger.read();
    const names = new Set([
      ...Object.keys(data.imported),
      ...Object.keys(data.failures),
      ...Object.keys(data.excluded),
    ]);
    const connectors = [...names].sort().map((connector) => {
      const byReason = new Map<string, number>();
      for (const e of data.excluded[connector] ?? []) {
        byReason.set(e.reason, (byReason.get(e.reason) ?? 0) + e.rows);
      }
      const failure = data.failures[connector];
      const imported = data.imported[connector];
      const excludedRows = sumRows(data.excluded[connector] ?? []);
      return {
        connector,
        state: imported
          ? imported.published === true
            ? ("published" as const)
            : ("imported" as const)
          : failure?.gaveUp
            ? ("failed" as const)
            : ("pending" as const),
        attempts: failure?.attempts ?? 0,
        staged: this.stagedRows(imported ?? {}),
        stayed: imported ? excludedRows : (failure?.stayed ?? null),
        excluded: [...byReason]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([reason, rows]) => ({ reason, rows })),
        ...(imported?.connection ? { connection: imported.connection } : {}),
      };
    });
    const unknown = data.abandoned || connectors.some((c) => c.stayed === null);
    return {
      complete: !(await this.options.ledger.importPending()),
      abandoned: data.abandoned,
      stayed: unknown
        ? null
        : connectors.reduce((n, c) => n + (c.stayed ?? 0), 0),
      connectors,
    };
  }
}
