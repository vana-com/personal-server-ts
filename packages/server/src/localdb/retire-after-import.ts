import { retireLegacyCopies } from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  LegacyCopy,
  LegacyRetireAccess,
  LocalSyncDeps,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type { ImportRunner } from "@opendatalabs/personal-server-ts-core/sync/account-mode";

/** The host's switched-owner view of the old files, opened per retirement.
 * `open` must refuse (throw) unless the owner is switched and every legacy
 * writer is quiet; it must not create or reconnect a database. */
export interface LegacyRetirePort {
  open(deps: LocalSyncDeps): Promise<{
    readonly access: LegacyRetireAccess;
    close(): Promise<void>;
  }>;
}

export interface RetireAfterImportOptions {
  /** The host's importer. Retirement follows its successful `run`. */
  readonly importer: ImportRunner;
  readonly port: LegacyRetirePort;
  /** The server's one open database for the owner. */
  readonly getDeps: () => Promise<LocalSyncDeps>;
  /** True only while the owner is switched (the legacy-write seal's verdict). */
  readonly isSwitched: () => boolean;
  /** Read at each run, so it follows `streamSync.retireLegacy`. */
  readonly streamSync: () => { readonly retireLegacy?: boolean };
  readonly logger: LocalSyncDeps["logger"];
}

/**
 * Old files are a one-time seed: once the import has run for a switched owner,
 * `retireLegacyCopies` removes them, but only when `streamSync.retireLegacy`
 * is on; with it off the same call writes a read-back-only report.
 *
 * It runs inside the importer's own `run`, which the import waker already
 * keeps to one run at a time, so it never overlaps an import. A failed import
 * retires nothing. A failed retirement is logged and does not fail the
 * import or the server start: the waker's next run, at the next Account
 * answer or the next start, retires what is left. Shutdown aborts the run at
 * the next copy.
 */
export function retireAfterImport(
  options: RetireAfterImportOptions,
): ImportRunner {
  const { importer, port, logger } = options;
  async function retire(signal: AbortSignal): Promise<void> {
    const deps = await options.getDeps();
    const opened = await port.open(deps);
    try {
      const report = await retireLegacyCopies(
        deps,
        stopsWhenAborted(opened.access, signal),
        {
          streamSync: options.streamSync(),
          reportFile: (file) =>
            logger.info({ ...file }, "legacy file retirement"),
        },
      );
      logger.info(
        { ...report, stopped: signal.aborted },
        "legacy retirement finished",
      );
    } finally {
      await opened.close();
    }
  }
  return {
    async run(signal) {
      await importer.run(signal);
      if (signal.aborted || !options.isSwitched()) return;
      try {
        await retire(signal);
      } catch (error) {
        logger.warn(
          { error: String(error) },
          "legacy retirement failed; it runs again at the next import run",
        );
      }
    },
  };
}

/** Ends the copy listing, so no further file is read or erased, once aborted. */
function stopsWhenAborted(
  access: LegacyRetireAccess,
  signal: AbortSignal,
): LegacyRetireAccess {
  async function* copies(): AsyncIterable<LegacyCopy> {
    for await (const copy of access.copies()) {
      if (signal.aborted) return;
      yield copy;
    }
  }
  const { erasedWithIntent, finishErase } = access;
  return {
    copies,
    readBack: (copy) => access.readBack(copy),
    erase: (copy) => access.erase(copy),
    ...(erasedWithIntent && {
      erasedWithIntent: (copy: LegacyCopy) =>
        erasedWithIntent.call(access, copy),
    }),
    ...(finishErase && {
      finishErase: (copy: LegacyCopy) => finishErase.call(access, copy),
    }),
  };
}
