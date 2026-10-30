import type {
  PendingBlobDeletion,
  PendingBlobDeletionStore,
  TombstoneFence,
} from "../ports/index.js";

/**
 * Minimal persistence seam for the pending-blob-deletion markers. Hosts
 * supply the storage (a JSON file on Node, IndexedDB state in the browser);
 * the store keeps the set semantics, de-duplication and mutation ordering in
 * one place. `write` must replace the whole value atomically (tmp + rename on
 * disk, a single IndexedDB put in the browser) so a crash mid-write cannot
 * leave a torn marker file.
 */
export interface PendingBlobDeletionKv {
  /**
   * The stored markers, either bare (a host that predates the planned
   * watermark) or with the per-scope watermark map next to them.
   */
  read(): Promise<PendingBlobDeletion[] | PendingBlobDeletionState | null>;
  /** Replace both the markers and the watermark map in one atomic write. */
  write(
    keys: PendingBlobDeletion[],
    planned: PendingBlobDeletionPlanned,
  ): Promise<void>;
}

/**
 * Per scope, the highest tombstone version whose covered registry range has
 * been taken on (see `PendingBlobDeletionStore.plannedThrough`).
 */
export type PendingBlobDeletionPlanned = Record<string, string>;

export interface PendingBlobDeletionState {
  keys: PendingBlobDeletion[];
  planned: PendingBlobDeletionPlanned;
}

/** Accept a stored watermark map, dropping anything that is not a version. */
export function normalizePendingBlobDeletionPlanned(
  stored: unknown,
): PendingBlobDeletionPlanned {
  const planned: PendingBlobDeletionPlanned = {};
  if (typeof stored !== "object" || stored === null || Array.isArray(stored)) {
    return planned;
  }
  for (const [scope, version] of Object.entries(stored)) {
    if (typeof version === "string" && /^\d+$/.test(version)) {
      planned[scope] = BigInt(version).toString();
    }
  }
  return planned;
}

function markerId(key: PendingBlobDeletion): string {
  const range = key.range ? `${key.range.from}-${key.range.to}` : "";
  return `${key.scope}\u0000${key.version ?? ""}\u0000${range}`;
}

function normalizeHead(value: unknown): TombstoneFence | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const { expectedVersion, dataHash, metadataHash } = value as Record<
    string,
    unknown
  >;
  if (
    typeof expectedVersion !== "string" ||
    !/^\d+$/.test(expectedVersion) ||
    typeof dataHash !== "string" ||
    !/^0x[0-9a-fA-F]{64}$/.test(dataHash) ||
    typeof metadataHash !== "string" ||
    !/^0x[0-9a-fA-F]{64}$/.test(metadataHash)
  ) {
    return undefined;
  }
  return {
    expectedVersion: BigInt(expectedVersion).toString(),
    dataHash: dataHash.toLowerCase(),
    metadataHash: metadataHash.toLowerCase(),
  };
}

function normalizeRange(
  value: unknown,
): { from: string; to: string } | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const { from, to } = value as { from?: unknown; to?: unknown };
  if (
    typeof from !== "string" ||
    typeof to !== "string" ||
    !/^\d+$/.test(from) ||
    !/^\d+$/.test(to) ||
    BigInt(from) > BigInt(to)
  ) {
    return undefined;
  }
  return { from, to };
}

/**
 * Accept the stored value from either marker generation: exact keys
 * (`{ scope, version }`) or the pre-key format that recorded whole scopes,
 * which maps to a version-less marker the retry expands into exact keys.
 */
export function normalizePendingBlobDeletions(
  stored: unknown,
): PendingBlobDeletion[] {
  if (!Array.isArray(stored)) return [];
  const keys: PendingBlobDeletion[] = [];
  for (const item of stored) {
    if (typeof item === "string") {
      keys.push({ scope: item, version: null });
    } else if (
      typeof item === "object" &&
      item !== null &&
      typeof (item as { scope?: unknown }).scope === "string"
    ) {
      const version = (item as { version?: unknown }).version;
      const range =
        typeof version === "string"
          ? undefined
          : normalizeRange((item as { range?: unknown }).range);
      const gate = (item as { tombstoneVersion?: unknown }).tombstoneVersion;
      const replacedHead = normalizeHead(
        (item as { replacedHead?: unknown }).replacedHead,
      );
      keys.push({
        scope: (item as { scope: string }).scope,
        version: typeof version === "string" ? version : null,
        ...(range ? { range } : {}),
        ...(typeof gate === "string" && /^\d+$/.test(gate)
          ? { tombstoneVersion: BigInt(gate).toString() }
          : {}),
        ...(replacedHead ? { replacedHead } : {}),
      });
    }
  }
  return keys;
}

/**
 * Every operation is a read-modify-write of the whole marker set, so the
 * store serialises them: a delete recording keys while a sync cycle's retry
 * clears others must not lose either update. Ordering is FIFO, and a failed
 * operation never blocks the ones queued behind it.
 */
export function createPendingBlobDeletionStore(
  kv: PendingBlobDeletionKv,
): PendingBlobDeletionStore {
  let queue: Promise<unknown> = Promise.resolve();

  function serialized<T>(operation: () => Promise<T>): Promise<T> {
    const run = queue.then(operation, operation);
    queue = run.catch(() => undefined);
    return run;
  }

  async function current(): Promise<PendingBlobDeletionState> {
    const stored = await kv.read();
    if (Array.isArray(stored) || stored === null) {
      return { keys: normalizePendingBlobDeletions(stored), planned: {} };
    }
    return {
      keys: normalizePendingBlobDeletions(stored.keys),
      planned: normalizePendingBlobDeletionPlanned(stored.planned),
    };
  }

  function merge(
    existing: PendingBlobDeletion[],
    keys: PendingBlobDeletion[],
  ): PendingBlobDeletion[] {
    const known = new Set(existing.map(markerId));
    const next = [...existing];
    for (const key of keys) {
      const id = markerId(key);
      if (known.has(id)) continue;
      known.add(id);
      next.push({
        scope: key.scope,
        version: key.version,
        ...(key.range ? { range: { ...key.range } } : {}),
        ...(key.tombstoneVersion !== undefined
          ? { tombstoneVersion: key.tombstoneVersion }
          : {}),
        ...(key.replacedHead ? { replacedHead: { ...key.replacedHead } } : {}),
      });
    }
    return next;
  }

  return {
    list() {
      return serialized(async () => (await current()).keys);
    },
    add(keys) {
      return serialized(async () => {
        if (keys.length === 0) return;
        const { keys: existing, planned } = await current();
        const next = merge(existing, keys);
        if (next.length === existing.length) return;
        await kv.write(next, planned);
      });
    },
    remove(keys) {
      return serialized(async () => {
        if (keys.length === 0) return;
        const { keys: existing, planned } = await current();
        const gone = new Set(keys.map(markerId));
        const next = existing.filter((key) => !gone.has(markerId(key)));
        if (next.length === existing.length) return;
        await kv.write(next, planned);
      });
    },
    plannedThrough(scope) {
      return serialized(async () => {
        const { planned } = await current();
        return Object.hasOwn(planned, scope) ? planned[scope] : null;
      });
    },
    enqueue(scope, keys, through) {
      return serialized(async () => {
        const { keys: existing, planned } = await current();
        const next = merge(existing, keys);
        const before = Object.hasOwn(planned, scope) ? planned[scope] : null;
        const raise =
          through !== null &&
          /^\d+$/.test(through) &&
          (before === null || BigInt(through) > BigInt(before));
        if (next.length === existing.length && !raise) return;
        await kv.write(
          next,
          raise ? { ...planned, [scope]: BigInt(through).toString() } : planned,
        );
      });
    },
  };
}

/** Non-durable store: markers survive only for the process lifetime. */
export function createMemoryPendingBlobDeletionStore(): PendingBlobDeletionStore {
  let state: PendingBlobDeletionState = { keys: [], planned: {} };
  return createPendingBlobDeletionStore({
    async read() {
      return state;
    },
    async write(keys, planned) {
      state = {
        keys: keys.map((key) => ({ ...key })),
        planned: { ...planned },
      };
    },
  });
}
