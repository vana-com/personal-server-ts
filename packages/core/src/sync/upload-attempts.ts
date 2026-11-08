/**
 * Durable upload-attempt markers.
 *
 * An upload can kill its own process (out of memory in a WebView, a crash in a
 * host). Nothing in memory survives that, so the failure counters in
 * `upload-state.ts` never see the attempt, and after every restart the worker
 * picks the same entry first and dies again, starving every later scope.
 *
 * Fix, kept to the smallest form: before an attempt builds its body, one
 * marker for that entry version is written durably. The marker is removed when
 * the attempt settles (success, or a failure that was caught). A marker found
 * at startup therefore means the last attempt never settled: it counts as one
 * interrupted attempt. After `MAX_INTERRUPTED_UPLOAD_ATTEMPTS` of them the
 * entry is quarantined, and the worker skips it until new data replaces it
 * (a different entry version has a different key) or the owner retries.
 *
 * What this does not bound: the first attempts (up to the cap) still run, and
 * it does not make an upload use less memory. Caught-failure backoff stays in
 * memory (`upload-state.ts`).
 *
 * Hosts supply only a whole-value read/write (`UploadAttemptStore`); the
 * ledger keeps the semantics and orders the writes.
 */
import type { IndexEntry } from "../storage/index/types.js";

/** Interrupted attempts an entry version gets before it is quarantined. */
export const MAX_INTERRUPTED_UPLOAD_ATTEMPTS = 2;

/** Status text for a quarantined entry. */
export const CRASHED_UPLOAD_REASON = "stopped: crashed during upload";

export interface UploadAttemptRecord {
  /** `uploadAttemptKey` of the entry version. */
  key: string;
  scope: string;
  path: string;
  /** Index row id of the entry version; scopes pruning to a scanned window. */
  rowId: number;
  /** Attempts that never settled, counted at startup. */
  interrupted: number;
  /** An attempt started and has not settled. Only meaningful at startup. */
  inFlight: boolean;
  quarantined: boolean;
}

/**
 * Host persistence: replace the whole value atomically (tmp + rename on disk,
 * one put in a key-value state store). `write` resolves only once the value is
 * durable; the ledger awaits it before any body is built.
 */
export interface UploadAttemptStore {
  read(): Promise<UploadAttemptRecord[] | null>;
  write(records: UploadAttemptRecord[]): Promise<void>;
}

/** In-memory store: no durability. Default for callers that supply none. */
export function createMemoryUploadAttemptStore(): UploadAttemptStore {
  let value: UploadAttemptRecord[] | null = null;
  return {
    async read() {
      return value && value.map((record) => ({ ...record }));
    },
    async write(records) {
      value = records.map((record) => ({ ...record }));
    },
  };
}

/**
 * Identity of one entry version for one owner. A new ingest at the same scope
 * has a different row id, collected time, version or size, so it starts fresh.
 */
export function uploadAttemptKey(
  ownerAddress: string,
  entry: Pick<
    IndexEntry,
    "scope" | "path" | "id" | "version" | "sizeBytes" | "collectedAt"
  >,
): string {
  return [
    ownerAddress.toLowerCase(),
    entry.scope,
    entry.path,
    entry.id,
    entry.collectedAt,
    entry.version,
    entry.sizeBytes,
  ].join("\u0000");
}

export interface UploadAttemptLedger {
  /** Read the store once and count leftover markers. Idempotent. */
  recover(): Promise<void>;
  isQuarantined(key: string): boolean;
  /** Persist the marker for an attempt; resolves once durable. */
  begin(entry: IndexEntry): Promise<void>;
  /** The attempt settled (success or caught failure): drop its marker. */
  settle(entry: IndexEntry): Promise<void>;
  /**
   * Drop records of entry versions that are no longer among `entries`. After
   * a partial (paged) scan pass the scanned row-id range: only records whose
   * row id lies inside it are judged, so rows the scan did not reach keep
   * their markers.
   */
  reconcile(
    entries: readonly IndexEntry[],
    scanned?: { afterId: number; throughId: number },
  ): Promise<void>;
  /**
   * Owner retry: lift quarantine (and the interrupted count) for `scope`, or
   * for every scope. Returns the paths released.
   */
  release(scope?: string): Promise<string[]>;
  /** Quarantined records, for status. */
  quarantined(): UploadAttemptRecord[];
}

export function createUploadAttemptLedger(
  store: UploadAttemptStore,
  ownerAddress: string,
  options: { maxInterrupted?: number } = {},
): UploadAttemptLedger {
  const maxInterrupted =
    options.maxInterrupted ?? MAX_INTERRUPTED_UPLOAD_ATTEMPTS;
  const records = new Map<string, UploadAttemptRecord>();
  let recovered: Promise<void> | null = null;
  let writes: Promise<unknown> = Promise.resolve();
  const keyOf = (entry: IndexEntry) => uploadAttemptKey(ownerAddress, entry);

  /** Serialised, whole-value persist of the current records. */
  function persist(): Promise<void> {
    const run = writes.then(() => store.write([...records.values()]));
    writes = run.catch(() => undefined);
    return run;
  }

  return {
    recover() {
      recovered ??= (async () => {
        const stored = (await store.read()) ?? [];
        let changed = false;
        for (const record of stored) {
          const next = { ...record };
          if (next.inFlight) {
            next.inFlight = false;
            next.interrupted += 1;
            changed = true;
          }
          if (!next.quarantined && next.interrupted >= maxInterrupted) {
            next.quarantined = true;
            changed = true;
          }
          records.set(next.key, next);
        }
        if (changed) await persist();
      })();
      // A failed read must not stick: the next cycle tries again.
      recovered.catch(() => {
        recovered = null;
      });
      return recovered;
    },
    isQuarantined(key) {
      return records.get(key)?.quarantined === true;
    },
    async begin(entry) {
      const key = keyOf(entry);
      const known = records.get(key);
      records.set(key, {
        key,
        scope: entry.scope,
        path: entry.path,
        rowId: entry.id,
        interrupted: known?.interrupted ?? 0,
        inFlight: true,
        quarantined: false,
      });
      await persist();
    },
    async settle(entry) {
      if (records.delete(keyOf(entry))) await persist();
    },
    async reconcile(entries, scanned) {
      const keep = new Set(entries.map(keyOf));
      let changed = false;
      for (const [key, record] of [...records]) {
        const covered =
          !scanned ||
          (record.rowId > scanned.afterId && record.rowId <= scanned.throughId);
        if (covered && !keep.has(key)) {
          records.delete(key);
          changed = true;
        }
      }
      if (changed) await persist();
    },
    async release(scope) {
      const released: string[] = [];
      for (const [key, record] of [...records]) {
        if (!record.quarantined) continue;
        if (scope !== undefined && record.scope !== scope) continue;
        records.delete(key);
        released.push(record.path);
      }
      if (released.length > 0) await persist();
      return released;
    },
    quarantined() {
      return [...records.values()].filter((record) => record.quarantined);
    },
  };
}
