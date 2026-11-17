/** A server that stops accepting connections and reports when all have ended. */
export interface ClosableServer {
  close(onClosed: () => void): unknown;
}

export interface ShutdownOptions {
  servers: readonly ClosableServer[];
  /** Releases what the servers used: stores, background work, the outbound pool. */
  cleanup: () => Promise<void>;
  logger: {
    info(message: string): void;
    warn(message: string): void;
    error(fields: { err: unknown }, message: string): void;
  };
  exit: (code: number) => void;
  /** How long the servers may take to finish their requests. */
  drainTimeoutMs: number;
  /** How long `cleanup` may take once the servers have drained. */
  cleanupTimeoutMs: number;
}

/**
 * The shutdown order, in three steps that each wait for the one before:
 * stop accepting and let requests in flight finish, run `cleanup`, then exit.
 * `cleanup` closes the stores and the outbound pool, so it must not start
 * while a request that uses them is still running. A step that overruns its
 * time exits with code 1.
 */
export async function runShutdown(options: ShutdownOptions): Promise<void> {
  const { servers, cleanup, logger, exit } = options;

  const within = async (
    ms: number,
    overrun: string,
    step: () => Promise<void>,
  ): Promise<boolean> => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const overran = new Promise<"overran">((resolve) => {
      timer = setTimeout(() => resolve("overran"), ms);
    });
    try {
      const outcome = await Promise.race([step(), overran]);
      if (outcome === "overran") logger.warn(overrun);
      return outcome !== "overran";
    } finally {
      clearTimeout(timer);
    }
  };

  const drained = await within(
    options.drainTimeoutMs,
    "Drain timeout exceeded, forcing exit",
    () =>
      Promise.all(
        servers.map(
          (server) => new Promise<void>((resolve) => server.close(resolve)),
        ),
      ).then(() => undefined),
  );
  if (!drained) return exit(1);

  let failed = false;
  const cleaned = await within(
    options.cleanupTimeoutMs,
    "Cleanup timeout exceeded, forcing exit",
    async () => {
      try {
        await cleanup();
      } catch (err) {
        failed = true;
        logger.error({ err }, "Cleanup failed");
      }
    },
  );
  if (!cleaned || failed) return exit(1);

  logger.info("Server stopped");
  exit(0);
}
