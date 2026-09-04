import { randomBytes, timingSafeEqual } from "node:crypto";
import type { ActiveSandboxJob, SandboxJobLookup } from "../agent/types.js";
import type { SandboxHandle, SandboxRuntime, SandboxSpec } from "./runtime.js";

export const SANDBOX_MAX = 20;
export const SANDBOX_IDLE_TTL_SECONDS = 600;

const ACCESS_TOKEN_BYTES = 32;
const MILLISECONDS_PER_SECOND = 1_000;
const TEARDOWN_GRACE_MS = 0;
const CAPACITY_MESSAGE = "Sandbox capacity exhausted";
const DRAINING_MESSAGE = "Sandbox registry is draining";
const UNAVAILABLE_MESSAGE = "Sandbox entry is unavailable";

type SandboxState = "starting" | "ready" | "expiring" | "destroyed";

export interface RegistryTimer {
  unref(): unknown;
}

export type SetTimer = (
  callback: () => void,
  milliseconds: number,
) => RegistryTimer;

export interface RegistryOptions {
  runtime: SandboxRuntime;
  logger?: SandboxRegistryLogger;
  max?: number;
  idleTtlMs?: number;
  now?: () => number;
  setTimer?: SetTimer;
}

export interface SandboxRegistryLogger {
  warn(context: Record<string, unknown>, message: string): void;
}

export interface SandboxLease {
  handle: SandboxHandle;
  accessToken: string;
}

export interface SandboxRegistry {
  acquire(
    key: string,
    buildSpec: (accessToken: string) => SandboxSpec,
  ): Promise<SandboxLease>;
  release(key: string): void;
  bindJob(key: string, job: ActiveSandboxJob): () => void;
  lookupJob(accessToken: string, jobId: string): SandboxJobLookup;
  drain(): Promise<void>;
  activeCount(): number;
}

interface RegistryEntry {
  handle?: SandboxHandle;
  state: SandboxState;
  lastUsedAt: number;
  accessToken: string;
  useCount: number;
  expiryVersion: number;
  activeJobs: Map<string, ActiveSandboxJob>;
  startPromise?: Promise<SandboxHandle>;
}

export class SandboxCapacityError extends Error {
  constructor() {
    super(CAPACITY_MESSAGE);
    this.name = "SandboxCapacityError";
  }
}

export function createSandboxRegistry(
  options: RegistryOptions,
): SandboxRegistry {
  const entries = new Map<string, RegistryEntry>();
  const now = options.now ?? Date.now;
  const setTimer = options.setTimer ?? defaultSetTimer;
  const max = options.max ?? SANDBOX_MAX;
  const idleTtlMs =
    options.idleTtlMs ?? SANDBOX_IDLE_TTL_SECONDS * MILLISECONDS_PER_SECOND;
  const logger = options.logger ?? consoleRegistryLogger;
  let draining = false;

  return {
    async acquire(key, buildSpec): Promise<SandboxLease> {
      if (draining) {
        throw new Error(DRAINING_MESSAGE);
      }

      const existing = entries.get(key);
      if (existing) {
        return acquireExisting(existing, now);
      }

      const victim = capacityVictim(entries, max);
      const entry: RegistryEntry = {
        state: "starting",
        lastUsedAt: now(),
        accessToken: randomBytes(ACCESS_TOKEN_BYTES).toString("hex"),
        useCount: 1,
        expiryVersion: 0,
        activeJobs: new Map(),
      };
      entries.set(key, entry);

      if (victim) {
        destroyEntry(entries, victim.key, victim.entry);
      }

      entry.startPromise = startEntry({
        key,
        entry,
        victim: victim?.entry,
        entries,
        runtime: options.runtime,
        logger,
        buildSpec,
        isDraining: () => draining,
      });
      const handle = await entry.startPromise;

      return { handle, accessToken: entry.accessToken };
    },
    release(key): void {
      const entry = entries.get(key);
      if (!entry || entry.state === "destroyed") {
        return;
      }

      entry.useCount = Math.max(0, entry.useCount - 1);
      entry.lastUsedAt = now();
      if (entry.useCount !== 0 || entry.state !== "ready") {
        return;
      }

      scheduleExpiry({
        key,
        entry,
        entries,
        runtime: options.runtime,
        logger,
        idleTtlMs,
        setTimer,
      });
    },
    bindJob(key, job): () => void {
      const entry = entries.get(key);
      if (!entry || entry.state === "destroyed") {
        throw new Error(UNAVAILABLE_MESSAGE);
      }
      entry.activeJobs.set(job.jobId, job);

      return () => {
        if (entry.activeJobs.get(job.jobId) === job) {
          entry.activeJobs.delete(job.jobId);
        }
      };
    },
    lookupJob(accessToken, jobId): SandboxJobLookup {
      const entry = findByAccessToken(entries, accessToken);
      if (!entry) {
        return { kind: "unauthorized" };
      }
      const job = entry.activeJobs.get(jobId);

      return job ? { kind: "active", job } : { kind: "inactive" };
    },
    async drain(): Promise<void> {
      draining = true;
      for (const entry of entries.values()) {
        entry.expiryVersion += 1;
      }

      const starts = [...entries.values()].flatMap((entry) =>
        entry.startPromise ? [entry.startPromise.catch(() => undefined)] : [],
      );
      await Promise.all(starts);

      const stops = [...entries.entries()].flatMap(([key, entry]) => {
        if (!entry.handle || entry.state === "destroyed") {
          return [];
        }

        destroyEntry(entries, key, entry);

        return [forceRemove(options.runtime, entry.handle.id, logger)];
      });

      try {
        await Promise.all(stops);
      } finally {
        entries.clear();
      }
    },
    activeCount(): number {
      return entries.size;
    },
  };
}

function findByAccessToken(
  entries: Map<string, RegistryEntry>,
  accessToken: string,
): RegistryEntry | undefined {
  const supplied = Buffer.from(accessToken, "utf8");
  for (const entry of entries.values()) {
    const expected = Buffer.from(entry.accessToken, "utf8");
    if (
      supplied.length === expected.length &&
      timingSafeEqual(supplied, expected)
    ) {
      return entry;
    }
  }

  return undefined;
}

function acquireExisting(
  entry: RegistryEntry,
  now: () => number,
): Promise<SandboxLease> {
  entry.useCount += 1;
  entry.lastUsedAt = now();
  entry.expiryVersion += 1;

  if (entry.state === "expiring") {
    entry.state = "ready";
  }

  if (entry.state === "starting" && entry.startPromise) {
    return entry.startPromise.then((handle) => ({
      handle,
      accessToken: entry.accessToken,
    }));
  }

  if (entry.state === "ready" && entry.handle) {
    return Promise.resolve({
      handle: entry.handle,
      accessToken: entry.accessToken,
    });
  }

  return Promise.reject(new Error(UNAVAILABLE_MESSAGE));
}

interface StartEntryOptions {
  key: string;
  entry: RegistryEntry;
  victim?: RegistryEntry;
  entries: Map<string, RegistryEntry>;
  runtime: SandboxRuntime;
  logger: SandboxRegistryLogger;
  buildSpec: (accessToken: string) => SandboxSpec;
  isDraining: () => boolean;
}

async function startEntry(options: StartEntryOptions): Promise<SandboxHandle> {
  try {
    if (options.victim?.handle) {
      await forceRemove(
        options.runtime,
        options.victim.handle.id,
        options.logger,
      );
    }
    if (options.isDraining()) {
      throw new Error(DRAINING_MESSAGE);
    }

    const spec = options.buildSpec(options.entry.accessToken);
    const handle = await options.runtime.start(spec);
    if (options.isDraining()) {
      await forceRemove(options.runtime, handle.id, options.logger);
      throw new Error(DRAINING_MESSAGE);
    }

    options.entry.handle = handle;
    options.entry.state = "ready";

    return handle;
  } catch (error) {
    destroyEntry(options.entries, options.key, options.entry);
    throw error;
  }
}

function capacityVictim(
  entries: Map<string, RegistryEntry>,
  max: number,
): { key: string; entry: RegistryEntry } | undefined {
  if (entries.size < max) {
    return undefined;
  }

  let victim: { key: string; entry: RegistryEntry } | undefined;
  for (const [key, entry] of entries) {
    if (entry.state !== "ready" || entry.useCount !== 0) {
      continue;
    }

    if (!victim || entry.lastUsedAt < victim.entry.lastUsedAt) {
      victim = { key, entry };
    }
  }
  if (!victim) {
    throw new SandboxCapacityError();
  }

  return victim;
}

interface ExpiryOptions {
  key: string;
  entry: RegistryEntry;
  entries: Map<string, RegistryEntry>;
  runtime: SandboxRuntime;
  logger: SandboxRegistryLogger;
  idleTtlMs: number;
  setTimer: SetTimer;
}

function scheduleExpiry(options: ExpiryOptions): void {
  const version = ++options.entry.expiryVersion;
  const timer = options.setTimer(() => {
    if (
      options.entry.expiryVersion !== version ||
      options.entry.state !== "ready" ||
      options.entry.useCount !== 0
    ) {
      return;
    }

    options.entry.state = "expiring";
    // Give an arriving claim one event-loop turn to cancel destructive stop.
    const teardown = options.setTimer(() => {
      void expireEntry(options);
    }, TEARDOWN_GRACE_MS);
    teardown.unref();
  }, options.idleTtlMs);
  timer.unref();
}

async function expireEntry(options: ExpiryOptions): Promise<void> {
  if (
    options.entry.state !== "expiring" ||
    options.entry.useCount !== 0 ||
    !options.entry.handle
  ) {
    return;
  }

  const handleId = options.entry.handle.id;
  destroyEntry(options.entries, options.key, options.entry);
  await forceRemove(options.runtime, handleId, options.logger);
}

async function forceRemove(
  runtime: SandboxRuntime,
  sandboxId: string,
  logger: SandboxRegistryLogger,
): Promise<void> {
  try {
    await runtime.stop(sandboxId);
  } catch (error) {
    logger.warn(
      { sandboxId, error: String(error) },
      "Failed to force-remove sandbox",
    );
  }
}

function destroyEntry(
  entries: Map<string, RegistryEntry>,
  key: string,
  entry: RegistryEntry,
): void {
  entry.state = "destroyed";
  entry.expiryVersion += 1;
  if (entries.get(key) === entry) {
    entries.delete(key);
  }
}

function defaultSetTimer(
  callback: () => void,
  milliseconds: number,
): RegistryTimer {
  return setTimeout(callback, milliseconds);
}

const consoleRegistryLogger: SandboxRegistryLogger = {
  warn(context, message): void {
    console.error({ level: "warn", ...context, message });
  },
};
