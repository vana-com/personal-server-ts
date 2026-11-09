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

export interface LegacyImportSource {
  /** Connectors this device holds importable rows for. */
  connectors(): Promise<readonly string[]>;
  streams(connector: string): Promise<readonly ImportStream[]>;
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
  readonly now?: () => Date;
  readonly logger?: {
    warn(obj: Record<string, unknown>, msg?: string): void;
  };
}

export interface ImportPassResult {
  readonly ran: boolean;
  readonly connectorsStaged: number;
  readonly failed: number;
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
    const { source, sink, ledger } = this.options;
    if (!this.options.switched()) {
      return { ran: false, connectorsStaged: 0, failed: 0 };
    }
    if ((await ledger.read()).importComplete) {
      return { ran: false, connectorsStaged: 0, failed: 0 };
    }
    let staged = 0;
    let failed = 0;
    for (const connector of await source.connectors()) {
      if ((await ledger.read()).imported[connector]) continue;
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
        const at = (this.options.now?.() ?? new Date()).toISOString();
        await ledger.update((data) => {
          data.imported[connector] = {
            streams: streams.length,
            at,
            staged: receipt,
          };
        });
        staged += 1;
      } catch (error) {
        failed += 1;
        this.options.logger?.warn(
          { error: error instanceof Error ? error.name : "NonError" },
          "Legacy import of a connector failed; retried next cycle",
        );
      }
    }
    if (failed === 0) {
      await ledger.update((data) => {
        data.importComplete = true;
      });
    }
    return { ran: true, connectorsStaged: staged, failed };
  }
}
