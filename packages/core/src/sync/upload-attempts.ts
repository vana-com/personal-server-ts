/**
 * Durable upload-attempt markers.
 *
 * An upload can kill its own process (out of memory in a WebView, a crash in a
 * host). Nothing in memory survives that, so the failure counters in
 * `upload-state.ts` never see the attempt, and after every restart the worker
 * picks the same entry first and dies again, starving every later scope.
 *
 * Fix, kept to the smallest form: before an attempt builds its body, one
 * marker for that entry version is written durably. The marker is cleared when
 * the attempt settles. A marker found at startup therefore means the last
 * attempt never settled: it counts as one interrupted attempt. After `MAX_INTERRUPTED_UPLOAD_ATTEMPTS` of them the
 * entry is quarantined, and the worker skips it until new data replaces it
 * (a different entry version has a different key) or the owner retries.
 *
 * The interrupted count is cumulative. A caught failure clears only the
 * in-flight marker and keeps the count, so crash, caught failure, crash still
 * reaches the cap; the count resets only on a successful upload, a new entry
 * version (a different key) or an owner retry.
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
  /** Lowercased owner address; a ledger only reads and writes its own. */
  owner: string;
  scope: string;
  path: string;
  /** Index row id of the entry version; scopes pruning to a scanned window. */
  rowId: number;
  /** Attempts that never settled, counted at startup. Cumulative. */
  interrupted: number;
  /** An attempt started and has not settled. Only meaningful at startup. */
  inFlight: boolean;
  quarantined: boolean;
}

export const UPLOAD_ATTEMPTS_ENVELOPE_VERSION = 1;

/** The persisted value: records inside a versioned envelope. */
export interface UploadAttemptsEnvelope {
  version: typeof UPLOAD_ATTEMPTS_ENVELOPE_VERSION;
  records: UploadAttemptRecord[];
}

/** The persisted value is present but is not a ledger. It is left as found. */
export class UploadAttemptStoreInvalidError extends Error {
  constructor(reason: string) {
    super(`Upload attempt store is invalid: ${reason}`);
    this.name = "UploadAttemptStoreInvalidError";
  }
}

/** Held by one ledger at a time; released when its manager stops. */
export interface UploadAttemptLease {
  release(): void;
}

/**
 * Host persistence: replace the whole value atomically. `write` resolves only
 * once the value is durable; the ledger awaits it before any body is built.
 */
export interface UploadAttemptStore {
  /** The persisted value exactly as stored; `null` only when none exists. */
  read(): Promise<unknown | null>;
  write(envelope: UploadAttemptsEnvelope): Promise<void>;
  /**
   * Take the store's single-owner lock, or `null` when another manager holds
   * it. One owner per store is what keeps a second manager from counting a
   * live attempt as a crash or overwriting its markers from a stale snapshot.
   * Absent: the store is private to its ledger.
   */
  acquire?(): Promise<UploadAttemptLease | null>;
}

const heldLocks = new Set<string>();

/**
 * Exclusive lock inside one JS realm, for stores whose host has no stronger
 * lock (a server process; a test). Hosts with one (browser locks) use theirs.
 */
export function acquireProcessLock(name: string): UploadAttemptLease | null {
  if (heldLocks.has(name)) return null;
  heldLocks.add(name);
  let released = false;
  return {
    release() {
      if (released) return;
      released = true;
      heldLocks.delete(name);
    },
  };
}

/** In-memory store: no durability. Default for callers that supply none. */
export function createMemoryUploadAttemptStore(): UploadAttemptStore {
  let value: unknown | null = null;
  let held = false;
  return {
    async read() {
      return value && structuredClone(value);
    },
    async write(envelope) {
      value = structuredClone(envelope);
    },
    async acquire() {
      if (held) return null;
      held = true;
      return {
        release() {
          held = false;
        },
      };
    },
  };
}

const isCount = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const isText = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

/** Accept only a well-formed ledger; anything else throws, never resets. */
export function parseUploadAttemptsEnvelope(
  raw: unknown,
): UploadAttemptRecord[] {
  if (raw === null) return [];
  if (typeof raw !== "object" || Array.isArray(raw))
    throw new UploadAttemptStoreInvalidError("not an envelope");
  const { version, records } = raw as Record<string, unknown>;
  if (version !== UPLOAD_ATTEMPTS_ENVELOPE_VERSION)
    throw new UploadAttemptStoreInvalidError("unknown version");
  if (!Array.isArray(records))
    throw new UploadAttemptStoreInvalidError("records is not a list");
  return records.map((value, index) => {
    const r = (value ?? {}) as Record<string, unknown>;
    if (
      !isText(r.key) ||
      !isText(r.owner) ||
      !isText(r.scope) ||
      !isText(r.path) ||
      !isCount(r.rowId) ||
      !isCount(r.interrupted) ||
      typeof r.inFlight !== "boolean" ||
      typeof r.quarantined !== "boolean"
    )
      throw new UploadAttemptStoreInvalidError(`record ${index} is malformed`);
    return {
      key: r.key,
      owner: r.owner,
      scope: r.scope,
      path: r.path,
      rowId: r.rowId,
      interrupted: r.interrupted,
      inFlight: r.inFlight,
      quarantined: r.quarantined,
    };
  });
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
  /**
   * Take the store's owner lock, read it, validate it and count leftover
   * markers. Resolves `false` when another manager owns the store: this one
   * must not upload. Throws `UploadAttemptStoreInvalidError` for a stored
   * value that is not a ledger; that value is left untouched. Idempotent once
   * it has resolved `true`; a failed or refused call is tried again.
   */
  recover(): Promise<boolean>;
  isQuarantined(key: string): boolean;
  /** An attempt for this entry version started and has not truly settled. */
  isLive(key: string): boolean;
  /** Persist the marker for an attempt; resolves once durable. */
  begin(entry: IndexEntry): Promise<void>;
  /**
   * The attempt has stopped running. `success` forgets the entry. `failure`
   * (caught and recorded elsewhere) clears the in-flight marker but keeps the
   * interrupted count.
   */
  settle(entry: IndexEntry, outcome: "success" | "failure"): Promise<void>;
  /**
   * Drop this owner's records for entry versions that are no longer among
   * `entries`. After a partial (paged) scan pass the scanned row-id range:
   * only records whose row id lies inside it are judged, so rows the scan did
   * not reach keep their markers.
   */
  reconcile(
    entries: readonly IndexEntry[],
    scanned?: { afterId: number; throughId: number },
  ): Promise<void>;
  /**
   * Owner retry: reset the interrupted count and lift quarantine for this
   * owner's `scope`, or every scope. Returns the quarantined paths released.
   */
  release(scope?: string): Promise<string[]>;
  /** This owner's quarantined records, for status. */
  quarantined(): UploadAttemptRecord[];
  /** Give up the store's owner lock (the manager stopped). */
  close(): Promise<void>;
}

export function createUploadAttemptLedger(
  store: UploadAttemptStore,
  ownerAddress: string,
  options: { maxInterrupted?: number } = {},
): UploadAttemptLedger {
  const maxInterrupted =
    options.maxInterrupted ?? MAX_INTERRUPTED_UPLOAD_ATTEMPTS;
  const owner = ownerAddress.toLowerCase();
  /** Every owner's records: the whole value is replaced on each write. */
  const records = new Map<string, UploadAttemptRecord>();
  const live = new Set<string>();
  let lease: UploadAttemptLease | null = null;
  let recovering: Promise<boolean> | null = null;
  let writes: Promise<unknown> = Promise.resolve();
  const keyOf = (entry: IndexEntry) => uploadAttemptKey(owner, entry);
  const mine = (record: UploadAttemptRecord) => record.owner === owner;

  /** A ledger that does not own a valid, loaded store must not write it. */
  function assertOwned() {
    if (!lease || recovering === null)
      throw new Error("Upload attempt ledger is not recovered");
  }

  /** Serialised, whole-value persist of the current records. */
  function persist(): Promise<void> {
    assertOwned();
    const run = writes.then(() =>
      store.write({
        version: UPLOAD_ATTEMPTS_ENVELOPE_VERSION,
        records: [...records.values()],
      }),
    );
    writes = run.catch(() => undefined);
    return run;
  }

  async function load(): Promise<boolean> {
    const taken = store.acquire ? await store.acquire() : NO_LOCK;
    if (!taken) return false;
    try {
      const stored = parseUploadAttemptsEnvelope(await store.read());
      lease = taken;
      let changed = false;
      for (const record of stored) {
        const next = { ...record };
        if (mine(next)) {
          if (next.inFlight) {
            next.inFlight = false;
            next.interrupted += 1;
            changed = true;
          }
          if (!next.quarantined && next.interrupted >= maxInterrupted) {
            next.quarantined = true;
            changed = true;
          }
        }
        records.set(next.key, next);
      }
      if (changed) await persist();
      return true;
    } catch (error) {
      lease = null;
      records.clear();
      taken.release();
      throw error;
    }
  }

  return {
    recover() {
      if (lease && recovering) return recovering;
      recovering ??= load();
      const attempt = recovering;
      // A refused or failed load must not stick: the next cycle tries again.
      attempt.then(
        (owned) => {
          if (!owned && recovering === attempt) recovering = null;
        },
        () => {
          if (recovering === attempt) recovering = null;
        },
      );
      return attempt;
    },
    isQuarantined(key) {
      return records.get(key)?.quarantined === true;
    },
    isLive(key) {
      return live.has(key);
    },
    async begin(entry) {
      assertOwned();
      const key = keyOf(entry);
      const known = records.get(key);
      records.set(key, {
        key,
        owner,
        scope: entry.scope,
        path: entry.path,
        rowId: entry.id,
        interrupted: known?.interrupted ?? 0,
        inFlight: true,
        quarantined: false,
      });
      live.add(key);
      try {
        await persist();
      } catch (error) {
        live.delete(key);
        throw error;
      }
    },
    async settle(entry, outcome) {
      const key = keyOf(entry);
      live.delete(key);
      const record = records.get(key);
      if (!record) return;
      if (outcome === "success" || record.interrupted === 0) {
        records.delete(key);
      } else {
        record.inFlight = false;
      }
      await persist();
    },
    async reconcile(entries, scanned) {
      const keep = new Set(entries.map(keyOf));
      let changed = false;
      for (const [key, record] of [...records]) {
        if (!mine(record) || live.has(key)) continue;
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
      let changed = false;
      for (const [key, record] of [...records]) {
        if (!mine(record) || live.has(key)) continue;
        if (scope !== undefined && record.scope !== scope) continue;
        records.delete(key);
        if (record.quarantined) released.push(record.path);
        changed = true;
      }
      if (changed) await persist();
      return released;
    },
    quarantined() {
      return [...records.values()].filter(
        (record) => mine(record) && record.quarantined,
      );
    },
    async close() {
      await writes;
      lease?.release();
      lease = null;
      recovering = null;
      records.clear();
      live.clear();
    },
  };
}

const NO_LOCK: UploadAttemptLease = { release() {} };
