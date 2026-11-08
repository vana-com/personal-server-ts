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
 * Hosts supply only a whole-value read/write and the name of their backing
 * store (`UploadAttemptStore`); the ledger keeps the semantics, orders the
 * writes and takes the store's single-owner lock, named by that store.
 *
 * Three things hold by construction:
 * - Order: one queue runs every state change (begin, settle, reconcile,
 *   release, close, recover) alone, start to finish. An operation reads the
 *   committed state, builds the next one, writes it, and only then adopts it,
 *   so no write ever carries another operation's tentative change. If
 *   storage may differ from the committed state (an uncertain or failed
 *   write), every operation repairs that first and the lease is never given
 *   up until it is repaired. A store write that never returns blocks the
 *   queue; no timeout may release the lease in its place.
 * - Identity: the lock is keyed by the store's `namespace` (Lite: IndexedDB
 *   database + object store + key; server: the resolved file path). Never by
 *   a wrapper object, never one name for all stores. Browser locks cover every
 *   tab of the origin; without them the lock covers one JS realm only.
 * - Attempts: `begin` returns a token and `settle` acts only for the token
 *   that still owns the entry. A manager that stops with an attempt still
 *   running keeps that entry excluded (and the store owned) until it settles.
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

/**
 * A store `write` may throw this when it cannot tell whether the value reached
 * storage. Any other rejection means nothing was stored.
 */
export class UploadAttemptWriteUncertainError extends Error {
  constructor(reason: string) {
    super(`Upload attempt write outcome is unknown: ${reason}`);
    this.name = "UploadAttemptWriteUncertainError";
  }
}

/**
 * A begin whose marker write was uncertain could not be undone in storage. The
 * body did not start, but a marker for it may be durable: no further upload
 * may start until a write of the corrected ledger succeeds.
 */
export class UploadAttemptStorageFailedError extends Error {
  constructor(cause: unknown) {
    super(
      `Upload attempt store could not be repaired: ${
        cause instanceof Error ? cause.message : String(cause)
      }`,
      { cause },
    );
    this.name = "UploadAttemptStorageFailedError";
  }
}

/** Status text recorded when a malformed ledger was preserved and reset. */
export const UPLOAD_ATTEMPTS_RESET_NOTICE =
  "Upload crash protection was reset; earlier interruption counts were lost";

/** Waiting for a running attempt to settle when a manager stops. */
export const DEFAULT_ABANDON_GRACE_MS = 5_000;

/** Held by one ledger at a time; released when its manager stops. */
export interface UploadAttemptLease {
  release(): void;
}

/**
 * Host persistence: replace the whole value atomically. `write` resolves only
 * once the value is durable; the ledger awaits it before any body is built.
 */
export interface UploadAttemptStore {
  /**
   * Stable name of the backing store, passed in by the host: the same store
   * always has the same name, different stores never share one. It names the
   * single-owner lock.
   */
  readonly namespace: string;
  /** The host's lock is shared across realms (browser Web Locks). */
  readonly crossRealmLock?: boolean;
  /** The persisted value exactly as stored; `null` only when none exists. */
  read(): Promise<unknown | null>;
  write(envelope: UploadAttemptsEnvelope): Promise<void>;
  /**
   * Keep a copy of a value that is not a ledger, durably, so the ledger can
   * replace it. At most a few copies are kept. `stamp` is a file-safe time.
   */
  preserveCorrupt(value: unknown, stamp: string): Promise<void>;
}

const heldLocks = new Set<string>();

/**
 * Exclusive lock inside one JS realm. It cannot exclude another realm
 * (another tab, worker or process); hosts with a cross-realm lock use theirs.
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

interface WebLocks {
  request(
    name: string,
    options: { ifAvailable: true },
    callback: (lock: object | null) => Promise<void> | undefined,
  ): Promise<unknown>;
}

/** The store's lock: browser locks when the host shares them, else this realm. */
function acquireStoreLock(
  store: UploadAttemptStore,
): Promise<UploadAttemptLease | null> | UploadAttemptLease | null {
  const name = `upload-attempts:${store.namespace}`;
  const locks = store.crossRealmLock
    ? (globalThis as { navigator?: { locks?: WebLocks } }).navigator?.locks
    : undefined;
  if (!locks) return acquireProcessLock(name);
  return new Promise((resolve, reject) => {
    // The lock is held by a callback that stays pending until released.
    locks
      .request(name, { ifAvailable: true }, (lock) => {
        if (!lock) {
          resolve(null);
          return undefined;
        }
        return new Promise<void>((release) =>
          resolve({ release: () => release() }),
        );
      })
      .catch(reject);
  });
}

let memoryStores = 0;

/** In-memory store: no durability. Default for callers that supply none. */
export function createMemoryUploadAttemptStore(): UploadAttemptStore {
  let value: unknown | null = null;
  return {
    namespace: `memory:${++memoryStores}`,
    async read() {
      return value && structuredClone(value);
    },
    async write(envelope) {
      value = structuredClone(envelope);
    },
    async preserveCorrupt() {},
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

/** Proof that one `begin` still owns its entry; only it may `settle` it. */
export interface UploadAttemptToken {
  readonly key: string;
  /** Which ownership of the store began the attempt. */
  readonly generation: number;
  readonly seq: number;
}

export interface UploadAttemptLedger {
  /**
   * Take the store's owner lock, read it, validate it and count leftover
   * markers. Resolves `false` when another manager owns the store: this one
   * must not upload. A readable value that is not a ledger is copied aside
   * (`preserveCorrupt`) and replaced by an empty ledger, once per ledger
   * object, with `onDegraded` told; a second one throws
   * `UploadAttemptStoreInvalidError` and is left as found, like an unreadable
   * or unwritable store. Idempotent once it has resolved `true`; a failed or
   * refused call is tried again.
   */
  recover(): Promise<boolean>;
  isQuarantined(key: string): boolean;
  /** An attempt for this entry version started and has not truly settled. */
  isLive(key: string): boolean;
  /**
   * Persist the marker for an attempt; resolves once durable. Throws when an
   * attempt for the entry is still live.
   */
  begin(entry: IndexEntry): Promise<UploadAttemptToken>;
  /**
   * The attempt has stopped running. `success` forgets the entry. `failure`
   * (caught and recorded elsewhere) clears the in-flight marker but keeps the
   * interrupted count. A token that no longer owns the entry changes nothing.
   */
  settle(
    token: UploadAttemptToken,
    outcome: "success" | "failure",
  ): Promise<void>;
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
  /**
   * The manager stopped. Waits up to `graceMs` for running attempts to
   * settle, then gives up the store's owner lock. An attempt that has not
   * settled keeps its entry excluded and the store owned (a reactivated
   * manager shares this ledger and cannot start a second body for it); the
   * lock is given up when it settles. A manager that takes the store back
   * (`recover`) during the wait cancels the release. `Infinity` waits for
   * the attempts however long they take.
   */
  close(graceMs?: number): Promise<void>;
}

export function createUploadAttemptLedger(
  store: UploadAttemptStore,
  ownerAddress: string,
  options: {
    maxInterrupted?: number;
    /** Crash protection lost something; the owner should be told. */
    onDegraded?: (message: string) => void;
    /** First wait before a stop that could not repair storage is retried. */
    repairRetryMs?: number;
  } = {},
): UploadAttemptLedger {
  const maxInterrupted =
    options.maxInterrupted ?? MAX_INTERRUPTED_UPLOAD_ATTEMPTS;
  const owner = ownerAddress.toLowerCase();
  /**
   * The committed state: what storage is known to hold (see `dirty`). Every
   * owner's records, because the whole value is replaced on each write. It is
   * replaced, never edited, and only inside an operation, after a write.
   */
  let records = new Map<string, UploadAttemptRecord>();
  const live = new Map<string, UploadAttemptToken>();
  let generation = 0;
  let attempts = 0;
  let lease: UploadAttemptLease | null = null;
  let recovering: Promise<boolean> | null = null;
  /**
   * Storage may differ from `records` (an uncertain or failed write). Every
   * operation repairs this first; a lease is never given up while it is set.
   */
  let dirty = false;
  /** Set once a malformed value was replaced: it is not replaced twice. */
  let resetOnce = false;
  let closeWhenIdle = false;
  /**
   * Bumped whenever a manager takes the store back (`recover` on a held
   * lease). A release that began earlier sees the change and stands down.
   */
  let reactivations = 0;
  const baseRetryMs = options.repairRetryMs ?? 1_000;
  let retryDelay = baseRetryMs;
  const idleWaiters: Array<() => void> = [];
  const keyOf = (entry: IndexEntry) => uploadAttemptKey(owner, entry);
  const mine = (record: UploadAttemptRecord) => record.owner === owner;

  /**
   * The one queue. Each operation runs alone, start to finish: it reads the
   * committed state, builds the next one, writes it, and only then adopts it.
   * No other operation can see, or snapshot, a tentative state.
   */
  let tail: Promise<void> = Promise.resolve();
  function enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const run = tail.then(operation);
    tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }

  const draft = () =>
    new Map([...records].map(([key, record]) => [key, { ...record }]));
  const write = (next: Map<string, UploadAttemptRecord>) =>
    store.write({
      version: UPLOAD_ATTEMPTS_ENVELOPE_VERSION,
      records: [...next.values()],
    });

  /** A ledger that does not own a valid, loaded store must not write it. */
  function assertOwned() {
    if (!lease || recovering === null)
      throw new Error("Upload attempt ledger is not recovered");
  }

  /** Write the committed state again; fail closed if storage still refuses. */
  async function repair() {
    if (!dirty) return;
    try {
      await write(records);
      dirty = false;
    } catch (error) {
      throw new UploadAttemptStorageFailedError(error);
    }
  }

  /**
   * Write `next`; adopt it only once the write succeeded. An uncertain write
   * is undone in the same operation by writing the committed state back.
   */
  async function persist(next: Map<string, UploadAttemptRecord>) {
    try {
      await write(next);
    } catch (error) {
      if (error instanceof UploadAttemptWriteUncertainError) {
        dirty = true;
        await repair();
      }
      throw error;
    }
    records = next;
    dirty = false;
  }

  /**
   * Give up the store, if still due: `since` is the `reactivations` count when
   * the release was decided; a manager may have taken the store back, and
   * begun an attempt, since. Storage must hold the committed state first.
   */
  async function giveUp(since: number) {
    if (reactivations !== since || live.size > 0 || !lease) return;
    try {
      await repair();
    } catch (error) {
      // The stop could not hand the store over. This ledger keeps the lease
      // and the repair duty: it retries on its own until storage heals, so a
      // discarded manager does not leave the store owned for good.
      closeWhenIdle = true; // the stop is still owed, whatever else happens
      const delay = retryDelay;
      retryDelay = Math.min(retryDelay * 2, 30 * baseRetryMs);
      const timer = setTimeout(
        () => void enqueue(() => giveUp(since)).catch(() => undefined),
        delay,
      );
      (timer as { unref?: () => void }).unref?.();
      throw error;
    }
    if (reactivations !== since || live.size > 0 || !lease) return;
    lease.release();
    lease = null;
    recovering = null;
    closeWhenIdle = false;
    retryDelay = baseRetryMs;
    records = new Map();
  }

  async function load(): Promise<boolean> {
    const taken = await acquireStoreLock(store);
    if (!taken) return false;
    try {
      const raw = await store.read();
      let stored: UploadAttemptRecord[];
      let replaced = false;
      try {
        stored = parseUploadAttemptsEnvelope(raw);
      } catch (error) {
        if (!(error instanceof UploadAttemptStoreInvalidError) || resetOnce)
          throw error;
        // Keep the bad value before it is replaced; if that fails, so does
        // this pass, and nothing is replaced.
        await store.preserveCorrupt(raw, new Date().toISOString());
        stored = [];
        replaced = true;
      }
      let changed = replaced;
      const next = new Map<string, UploadAttemptRecord>();
      for (const record of stored) {
        const entry = { ...record };
        if (mine(entry)) {
          if (entry.inFlight) {
            entry.inFlight = false;
            entry.interrupted += 1;
            changed = true;
          }
          if (!entry.quarantined && entry.interrupted >= maxInterrupted) {
            entry.quarantined = true;
            changed = true;
          }
        }
        next.set(entry.key, entry);
      }
      if (changed) await write(next);
      records = next;
      dirty = false;
      lease = taken;
      generation += 1;
      if (replaced) {
        resetOnce = true;
        options.onDegraded?.(UPLOAD_ATTEMPTS_RESET_NOTICE);
      }
      return true;
    } catch (error) {
      lease = null;
      records = new Map();
      taken.release();
      throw error;
    }
  }

  /** Drop this owner's idle records chosen by `drop`; returns the dropped. */
  async function dropRecords(drop: (record: UploadAttemptRecord) => boolean) {
    assertOwned();
    await repair();
    const next = draft();
    const dropped: UploadAttemptRecord[] = [];
    for (const [key, record] of next) {
      if (!mine(record) || live.has(key) || !drop(record)) continue;
      next.delete(key);
      dropped.push(record);
    }
    if (dropped.length) await persist(next);
    return dropped;
  }

  /** A running attempt's token `token`: stop it and write the outcome. */
  async function settleOperation(
    token: UploadAttemptToken,
    outcome: "success" | "failure",
  ) {
    const current = live.get(token.key);
    if (
      !current ||
      current.generation !== token.generation ||
      current.seq !== token.seq
    )
      return;
    const since = reactivations;
    live.delete(token.key);
    let failure: unknown;
    const record = records.get(token.key);
    if (record) {
      const next = draft();
      if (outcome === "success" || record.interrupted === 0) {
        next.delete(token.key);
      } else {
        next.get(token.key)!.inFlight = false;
      }
      // The body has stopped whatever storage says, so `next` is adopted
      // either way; a failed write leaves `dirty` for the next operation.
      try {
        await write(next);
        dirty = false;
      } catch (error) {
        dirty = true;
        failure = error;
      }
      records = next;
    }
    if (live.size === 0) {
      for (const wake of idleWaiters.splice(0)) wake();
      if (closeWhenIdle) {
        try {
          await giveUp(since);
        } catch (error) {
          failure ??= error;
        }
      }
    }
    if (failure !== undefined) throw failure;
  }

  return {
    recover() {
      if (lease && recovering) {
        closeWhenIdle = false;
        reactivations += 1;
        return recovering;
      }
      recovering ??= enqueue(load);
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
    begin(entry) {
      return enqueue(async () => {
        assertOwned();
        if (closeWhenIdle) throw new Error("Upload attempt ledger is stopping");
        await repair(); // refused until storage holds the committed state
        const key = keyOf(entry);
        if (live.has(key))
          throw new Error("An upload attempt for this entry is still running");
        const next = draft();
        next.set(key, {
          key,
          owner,
          scope: entry.scope,
          path: entry.path,
          rowId: entry.id,
          interrupted: records.get(key)?.interrupted ?? 0,
          inFlight: true,
          quarantined: false,
        });
        // The body starts only after this resolves. If the write fails the
        // marker is never adopted (and an uncertain one is written away).
        await persist(next);
        const token: UploadAttemptToken = { key, generation, seq: ++attempts };
        live.set(key, token);
        return token;
      });
    },
    settle: (token, outcome) => enqueue(() => settleOperation(token, outcome)),
    async reconcile(entries, scanned) {
      const keep = new Set(entries.map(keyOf));
      await enqueue(() =>
        dropRecords(
          (record) =>
            (!scanned ||
              (record.rowId > scanned.afterId &&
                record.rowId <= scanned.throughId)) &&
            !keep.has(record.key),
        ),
      );
    },
    async release(scope) {
      const dropped = await enqueue(() =>
        dropRecords((record) => scope === undefined || record.scope === scope),
      );
      return dropped.filter((r) => r.quarantined).map((r) => r.path);
    },
    quarantined() {
      return [...records.values()]
        .filter((record) => mine(record) && record.quarantined)
        .map((record) => ({ ...record }));
    },
    async close(graceMs = DEFAULT_ABANDON_GRACE_MS) {
      const since = reactivations;
      if (live.size > 0) {
        let timer: ReturnType<typeof setTimeout> | undefined;
        await Promise.race([
          new Promise<void>((wake) => idleWaiters.push(wake)),
          // An infinite grace waits for the attempts, however long.
          new Promise<void>((wake) => {
            if (Number.isFinite(graceMs)) timer = setTimeout(wake, graceMs);
          }),
        ]);
        clearTimeout(timer);
      }
      await enqueue(async () => {
        if (reactivations !== since) return;
        if (live.size > 0) {
          closeWhenIdle = true;
          return;
        }
        await giveUp(since);
      });
    },
  };
}
