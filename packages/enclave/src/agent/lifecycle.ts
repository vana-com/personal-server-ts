export interface LifecycleLogger {
  warn(context: Record<string, unknown>, message: string): void;
}

export async function drainWithTimeout(
  drain: () => Promise<void>,
  timeoutMs: number,
  logger: LifecycleLogger,
): Promise<boolean> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<false>((resolve) => {
    timeout = setTimeout(() => resolve(false), timeoutMs);
  });
  const drained = drain().then(() => true as const);
  const completed = await Promise.race([drained, timedOut]);
  if (timeout) {
    clearTimeout(timeout);
  }
  if (!completed) {
    logger.warn({ timeoutMs }, "Timed out while draining agent jobs");
  }

  return completed;
}
