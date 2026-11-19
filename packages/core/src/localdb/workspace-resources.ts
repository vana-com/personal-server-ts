/** Charged workspace data, separate from the host allocator and SQLite's
 * unexposed statement/native overhead. cache_size is a target, not a malloc cap. */
export interface WorkspaceResourceConfig {
  readonly cacheKiB: number;
  readonly frameBytes: number;
  readonly connections: number;
}
export function workspaceResourceBudget(config: WorkspaceResourceConfig) {
  if (
    !Number.isInteger(config.cacheKiB) ||
    config.cacheKiB < 64 ||
    !Number.isInteger(config.connections) ||
    config.connections < 1 ||
    config.connections > 2 ||
    !Number.isInteger(config.frameBytes) ||
    config.frameBytes < 4096 ||
    config.frameBytes > 4 * 1024 * 1024
  )
    throw new Error("workspace_resource_config");
  const chunkBytes = Math.min(
    65536,
    Math.floor((config.frameBytes - 2048) / 6),
  );
  const sqlitePageTargets = config.connections * config.cacheKiB * 1024;
  const valueBuffers = 6 * chunkBytes + 2048;
  const metadataBuffers = 64 * 1024 * 24;
  // Fixed-size transaction descriptors, not one statement per historical row.
  const statementFrames =
    2 * Math.max(config.frameBytes, 2 * 64 * 1024 + 16 * 1024 + chunkBytes);
  // The Node worker collects received messages every 25 calls. Charge their
  // possible unreclaimed data as well as live frames; release is not a GC.
  const workerGarbageBuffers = 25 * statementFrames;
  const statementTextBuffers = (64 + 256) * 8192;
  return {
    config,
    chunkBytes,
    sqlitePageTargets,
    valueBuffers,
    metadataBuffers,
    statementFrames,
    workerGarbageBuffers,
    statementTextBuffers,
    chargedBytes:
      sqlitePageTargets +
      Math.max(valueBuffers, metadataBuffers) +
      statementFrames +
      workerGarbageBuffers +
      statementTextBuffers,
    sqliteNativeOverhead: "unmeasured" as const,
  };
}
