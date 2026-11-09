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
import type { AccountStorageModeValue } from "./account-storage-mode.js";
import type { SeedPublication } from "../../stream-sync/writer.js";
import type { RetireLedger } from "./ledger.js";
import type { AccountStorageMode } from "./account-storage-mode.js";

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
   * The Account this importer acts for: the owner the mode is asked about.
   * The source and the ledger must both belong to it.
   */
  readonly owner: string;
  /**
   * The shared account-mode port, read on every call. Only `switched`
   * imports. `unswitched` has nothing to wait for; `unknown` is no decision:
   * the writer's gate stays closed and the status reports no count.
   */
  readonly mode: AccountStorageMode;
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
  readonly publish?: (
    connector: string,
    streams: readonly string[],
  ) => Promise<SeedPublication>;
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
  /** This account's import is finished. */
  readonly complete: boolean;
  /**
   * The source could not be listed within the bound; no file is retired. It is
   * listed again on the next boot.
   */
  readonly abandoned: boolean;
  /**
   * Connectors given up after the bound. Each is tried again on the next boot,
   * and its legacy file is kept until a retry proves it.
   */
  readonly givenUp: number;
  /**
   * Rows that stayed only in a legacy file, over all connectors; null while
   * pending or when some could not be counted (an unreadable source or
   * connector, a staged connector the writer has not answered for).
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
    /**
     * Rows that stayed only in the legacy file; null when not countable, and
     * while the writer has not answered for the staged rows (pending).
     */
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

  /** The account's mode now, asked for the one owner (lowercase). */
  private mode(): AccountStorageModeValue {
    return this.options.mode.read(this.options.owner.toLowerCase());
  }

  /** Whether the Account has switched; hosts ask here, never read a flag. */
  switched(): boolean {
    return this.mode() === "switched";
  }

  /**
   * The writer's gate, and the one owner of "import owed": true once this
   * connector's rows are staged or the import is complete. Unswitched:
   * nothing to wait for. Unknown: never done, so no run binds a generation on
   * a guess.
   */
  importDone = async (connector: string): Promise<boolean> => {
    const mode = this.mode();
    if (mode === "unknown") return false;
    if (mode === "unswitched") return true;
    return this.options.ledger.importDone(connector);
  };

  /**
   * One pass over the source. Safe to call on every boot, wake and cycle:
   * once the import is complete it only retries what was given up, and a
   * pass that failed starts again from the connectors not yet staged. A
   * `signal` that aborts ends the pass before its next step; what is staged
   * stays recorded, so a later pass resumes without a duplicate.
   */
  run(signal?: AbortSignal): Promise<ImportPassResult> {
    this.pass ??= this.runPass(signal).finally(() => {
      this.pass = null;
    });
    return this.pass;
  }

  private async runPass(signal?: AbortSignal): Promise<ImportPassResult> {
    const { source, ledger } = this.options;
    const idle: ImportPassResult = {
      ran: false,
      connectorsStaged: 0,
      failed: 0,
    };
    if (this.mode() !== "switched" || signal?.aborted) return idle;
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
    // The ledger owns "done": once set, the first import never runs again,
    // but what was given up is tried again on a later boot.
    if ((await ledger.read()).importComplete) return this.retryGivenUp(signal);
    // This boot carried the first import: what it gave up waits for the next.
    this.retriedGivenUp = true;
    const { result, settled } = await this.stage(null, signal);
    await this.queueRuns(signal);
    if (settled && !signal?.aborted && (await this.allSeedsFinal())) {
      await ledger.markImportDone();
    }
    return result;
  }

  /** Set once the given-up work was tried on this boot (or the boot carried the import). */
  private retriedGivenUp = false;

  /**
   * ABANDONED_NEVER_RETRIED: a connector (or the whole listing) given up is
   * not forgotten. The ledger keeps it; on a later boot, once, the import is
   * tried again in the background. The import is already complete, so the
   * gate is not touched and no run waits for it. The connector's file is kept
   * until a retry proves it (`importProven`).
   */
  private async retryGivenUp(signal?: AbortSignal): Promise<ImportPassResult> {
    let result: ImportPassResult = {
      ran: false,
      connectorsStaged: 0,
      failed: 0,
    };
    if (!this.retriedGivenUp) {
      const data = await this.options.ledger.read();
      const gaveUp = Object.entries(data.failures)
        .filter(([connector, f]) => f.gaveUp && !data.imported[connector])
        .map(([connector]) => connector);
      if (data.abandoned || gaveUp.length > 0) {
        this.retriedGivenUp = true;
        // An abandoned listing examined nothing, so every connector is still
        // to do; otherwise only the connectors given up.
        ({ result } = await this.stage(
          data.abandoned ? null : new Set(gaveUp),
          signal,
        ));
        // A source that is not open yet is no attempt: ask again next call.
        if (result.pending) this.retriedGivenUp = false;
      }
    }
    // Rows a retry staged are published and finalized.
    await this.queueRuns(signal);
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
   * `retry`: a later boot's retry; it tries only the connectors named (given
   * up before), or all of them when null and the listing had been given up.
   * `settled`: the listing worked (or was given up) and no connector is still
   * waiting for a retry.
   */
  private async stage(
    retry: ReadonlySet<string> | null,
    signal?: AbortSignal,
  ): Promise<{
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
      // A retry of given-up connectors: the listing worked before. Its failure
      // changes nothing; the next boot tries again.
      if (retry !== null) {
        return {
          result: { ran: true, connectorsStaged: 0, failed: 1 },
          settled: false,
        };
      }
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
    // From here the rows of the source are examined, so they can be counted.
    if (!(await ledger.read()).listed || (await ledger.read()).abandoned) {
      await ledger.update((data) => {
        data.listed = true;
        // A listing given up earlier works now: the bound is lifted.
        data.abandoned = false;
        data.listAttempts = 0;
      });
    }
    let staged = 0;
    let failed = 0;
    let waiting = 0;
    for (const connector of connectors) {
      // An abort ends the pass between connectors: nothing half-staged is
      // recorded, and the connector is staged again by the next pass.
      if (signal?.aborted)
        return {
          result: { ran: true, connectorsStaged: staged, failed },
          settled: false,
        };
      const known = await ledger.read();
      if (known.imported[connector]) continue;
      if (
        retry === null
          ? known.failures[connector]?.gaveUp
          : !retry.has(connector)
      ) {
        // First import: a given-up connector waits for a later boot. A retry
        // tries only what was given up.
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
  private async queueRuns(signal?: AbortSignal): Promise<void> {
    const { publish, ledger } = this.options;
    if (!publish) return;
    const { imported } = await ledger.read();
    for (const [connector, record] of Object.entries(imported)) {
      if (signal?.aborted) return;
      if (record.published || record.seedDone) continue;
      if (this.stagedRows(record) === 0) continue;
      try {
        const stagedStreams = Object.entries(record.staged ?? {})
          .filter(([, rows]) => rows > 0)
          .map(([stream]) => stream);
        const outcome = await publish(connector, stagedStreams);
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

  /**
   * Every staged connector has a final answer from the writer. With no
   * `publish` bound nothing can ever give one, so a connector with staged
   * rows is never final: the import is not done while it holds rows nobody
   * will publish.
   */
  private async allSeedsFinal(): Promise<boolean> {
    const { imported } = await this.options.ledger.read();
    const bound = this.options.publish !== undefined;
    return Object.values(imported).every(
      (record) =>
        (bound && (record.published === true || record.seedDone === true)) ||
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
      // What stayed is known only once the writer answered for the staged
      // rows (a skipped seed adds to it). Until then it is pending: null.
      const final =
        imported !== undefined &&
        (imported.published === true ||
          imported.seedDone === true ||
          this.stagedRows(imported) === 0);
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
        stayed: imported
          ? final
            ? excludedRows
            : null
          : (failure?.stayed ?? null),
        excluded: [...byReason]
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([reason, rows]) => ({ reason, rows })),
        ...(imported?.connection ? { connection: imported.connection } : {}),
      };
    });
    // Not counted: the mode is no decision, the source was never listed, it
    // was given up, or a connector's rows could not be counted.
    const unknown =
      this.mode() === "unknown" ||
      !data.listed ||
      data.abandoned ||
      connectors.some((c) => c.stayed === null);
    return {
      complete: !(await this.options.ledger.importPending()),
      abandoned: data.abandoned,
      givenUp: connectors.filter((c) => c.state === "failed").length,
      stayed: unknown
        ? null
        : connectors.reduce((n, c) => n + (c.stayed ?? 0), 0),
      connectors,
    };
  }
}
