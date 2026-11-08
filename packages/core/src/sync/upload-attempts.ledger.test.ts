import { describe, expect, it, vi } from "vitest";

import {
  createMemoryUploadAttemptStore,
  createUploadAttemptLedger,
  UPLOAD_ATTEMPTS_RESET_NOTICE,
  UploadAttemptStorageFailedError,
  UploadAttemptStoreInvalidError,
  UploadAttemptWriteUncertainError,
  uploadAttemptKey,
  type UploadAttemptStore,
} from "./upload-attempts.js";
import type { IndexEntry } from "../storage/index/types.js";

const OWNER_A = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const OWNER_B = "0x1111111111111111111111111111111111111111";

function entry(n: number): IndexEntry {
  const collectedAt = `2026-11-07T10:0${n}:00Z`;
  return {
    id: n,
    fileId: null,
    schemaId: null,
    path: `scope.${n}/${collectedAt}.json`,
    scope: `scope.${n}`,
    collectedAt,
    createdAt: collectedAt,
    sizeBytes: 1024,
    version: 1,
    dataPointId: null,
  };
}

/** A store whose persisted value is whatever the test says it is. */
let stores = 0;
function storeHolding(value: unknown): UploadAttemptStore & {
  written: unknown[];
  preserved: unknown[];
  failPreserve?: boolean;
} {
  const written: unknown[] = [];
  const preserved: unknown[] = [];
  const store = {
    namespace: `holding:${++stores}`,
    written,
    preserved,
    failPreserve: false,
    async read() {
      return written.length ? written[written.length - 1] : value;
    },
    async write(envelope: unknown) {
      written.push(envelope);
    },
    async preserveCorrupt(bad: unknown) {
      if (store.failPreserve) throw new Error("side write failed");
      preserved.push(bad);
    },
  };
  return store as never;
}

/** The store as a later process sees it: its own lock, the same bytes. */
let processes = 0;
const processOver = (store: UploadAttemptStore): UploadAttemptStore => ({
  namespace: `${store.namespace}#process-${++processes}`,
  read: () => store.read(),
  write: (envelope) => store.write(envelope),
  preserveCorrupt: (value, stamp) => store.preserveCorrupt(value, stamp),
});

const record = (over: Record<string, unknown> = {}) => ({
  key: "k",
  owner: OWNER_A.toLowerCase(),
  scope: "scope.1",
  path: "scope.1/p.json",
  rowId: 1,
  interrupted: 1,
  inFlight: false,
  quarantined: false,
  ...over,
});

describe("owner isolation", () => {
  it("keeps another owner's quarantine through recover, reconcile and release", async () => {
    const store = createMemoryUploadAttemptStore();
    const a = createUploadAttemptLedger(processOver(store), OWNER_A, {
      maxInterrupted: 1,
    });
    await a.recover();
    await a.begin(entry(1)); // owner A dies mid-upload

    const again = createUploadAttemptLedger(processOver(store), OWNER_A, {
      maxInterrupted: 1,
    });
    await again.recover();
    expect(again.quarantined()).toHaveLength(1);
    await again.close();

    const b = createUploadAttemptLedger(processOver(store), OWNER_B, {
      maxInterrupted: 1,
    });
    await b.recover();
    await b.reconcile([], { afterId: 0, throughId: 5 });
    expect(await b.release()).toEqual([]);
    expect(b.quarantined()).toEqual([]);
    await b.close();

    const back = createUploadAttemptLedger(processOver(store), OWNER_A, {
      maxInterrupted: 1,
    });
    await back.recover();
    expect(back.isQuarantined(uploadAttemptKey(OWNER_A, entry(1)))).toBe(true);
  });
});

describe("an invalid persisted ledger", () => {
  it.each([
    ["a wrong envelope", { version: 1, records: {} }],
    ["an unknown version", { version: 2, records: [] }],
    ["a missing version", { records: [] }],
    [
      "a bad counter",
      { version: 1, records: [record({ interrupted: "bad" })] },
    ],
    [
      "a negative counter",
      { version: 1, records: [record({ interrupted: -1 })] },
    ],
    ["a bad flag", { version: 1, records: [record({ inFlight: "yes" })] }],
    ["a bad row id", { version: 1, records: [record({ rowId: 1.5 })] }],
  ])(
    "preserves %s, starts an empty ledger and says so",
    async (_name, value) => {
      const store = storeHolding(value);
      const degraded: string[] = [];
      const ledger = createUploadAttemptLedger(store, OWNER_A, {
        onDegraded: (message) => degraded.push(message),
      });
      await expect(ledger.recover()).resolves.toBe(true);
      expect(store.preserved).toEqual([value]);
      expect(store.written).toEqual([{ version: 1, records: [] }]);
      expect(degraded).toEqual([UPLOAD_ATTEMPTS_RESET_NOTICE]);
      await expect(ledger.begin(entry(1))).resolves.toBeDefined();
    },
  );

  it("does not reset the same corruption twice in one ledger lifetime", async () => {
    const bad = { version: 2, records: [] };
    const store = storeHolding(bad);
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await ledger.recover();
    await ledger.close();
    // The same corruption appears again.
    store.written.push(bad);
    await expect(ledger.recover()).rejects.toBeInstanceOf(
      UploadAttemptStoreInvalidError,
    );
    expect(store.preserved).toEqual([bad]);
    expect(store.written).toHaveLength(2);
  });

  it("continues only after the copy is kept: a failed copy fails the pass and replaces nothing", async () => {
    const store = storeHolding({ version: 2, records: [] });
    store.failPreserve = true;
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await expect(ledger.recover()).rejects.toThrow("side write failed");
    expect(store.written).toEqual([]);
    // Once storage works again the next pass resets.
    store.failPreserve = false;
    await expect(ledger.recover()).resolves.toBe(true);
  });

  it("fails visibly, resetting nothing, when the store cannot be read", async () => {
    const store = storeHolding(null);
    store.read = async () => {
      throw new Error("storage unreadable");
    };
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await expect(ledger.recover()).rejects.toThrow("storage unreadable");
    expect(store.preserved).toEqual([]);
    expect(store.written).toEqual([]);
  });

  it("treats an absent value as a first use", async () => {
    const ledger = createUploadAttemptLedger(storeHolding(null), OWNER_A);
    await expect(ledger.recover()).resolves.toBe(true);
  });
});

describe("one active ledger per store", () => {
  it("does not let a second ledger count a live attempt as a crash or erase its marker", async () => {
    const store = createMemoryUploadAttemptStore();
    const first = createUploadAttemptLedger(store, OWNER_A);
    expect(await first.recover()).toBe(true);
    const token = await first.begin(entry(1)); // live: the upload is still running

    const second = createUploadAttemptLedger(store, OWNER_A);
    expect(await second.recover()).toBe(false);
    await expect(second.begin(entry(2))).rejects.toThrow();

    await first.settle(token, "success");
    // The live attempt was never counted as an interruption.
    expect(await store.read()).toEqual({ version: 1, records: [] });
  });

  it("lets a new ledger take over once the owner is closed", async () => {
    const store = createMemoryUploadAttemptStore();
    const first = createUploadAttemptLedger(store, OWNER_A);
    await first.recover();
    await first.settle(await first.begin(entry(1)), "failure");
    await first.close();
    const second = createUploadAttemptLedger(store, OWNER_A);
    expect(await second.recover()).toBe(true);
  });
});

describe("attempt tokens", () => {
  it("lets only the token that owns an entry settle it", async () => {
    const store = createMemoryUploadAttemptStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await ledger.recover();
    const token = await ledger.begin(entry(1));
    // The same entry cannot be begun again while it is live.
    await expect(ledger.begin(entry(1))).rejects.toThrow(/still running/);

    await ledger.settle({ ...token, seq: token.seq + 1 }, "success");
    await ledger.settle(
      { ...token, generation: token.generation + 1 },
      "success",
    );
    expect(ledger.isLive(token.key)).toBe(true);
    expect(await store.read()).toEqual({
      version: 1,
      records: [expect.objectContaining({ inFlight: true })],
    });

    await ledger.settle(token, "success");
    await ledger.settle(token, "success"); // a second settle changes nothing
    expect(ledger.isLive(token.key)).toBe(false);
  });

  it("keeps a running attempt excluded and the store owned across close, until it settles", async () => {
    vi.useFakeTimers();
    try {
      const store = createMemoryUploadAttemptStore();
      const ledger = createUploadAttemptLedger(store, OWNER_A);
      await ledger.recover();
      const token = await ledger.begin(entry(1));

      const closing = ledger.close(50);
      await vi.advanceTimersByTimeAsync(50);
      await closing;
      expect(ledger.isLive(token.key)).toBe(true);
      // Another ledger still cannot take the store.
      expect(await createUploadAttemptLedger(store, OWNER_A).recover()).toBe(
        false,
      );
      // The same ledger, reactivated, keeps the entry excluded.
      expect(await ledger.recover()).toBe(true);
      expect(ledger.isLive(token.key)).toBe(true);

      await ledger.settle(token, "failure");
      await ledger.close(50);
      expect(await createUploadAttemptLedger(store, OWNER_A).recover()).toBe(
        true,
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("gives up the store when the last running attempt settles after a close", async () => {
    vi.useFakeTimers();
    try {
      const store = createMemoryUploadAttemptStore();
      const ledger = createUploadAttemptLedger(store, OWNER_A);
      await ledger.recover();
      const token = await ledger.begin(entry(1));
      const closing = ledger.close(10);
      await vi.advanceTimersByTimeAsync(10);
      await closing;

      await ledger.settle(token, "success");
      expect(await createUploadAttemptLedger(store, OWNER_A).recover()).toBe(
        true,
      );
    } finally {
      vi.useRealTimers();
    }
  });
});

/** A store whose writes can be held, or made to fail, by the test. */
function controlledStore() {
  const inner = createMemoryUploadAttemptStore();
  const control = {
    hold: null as Promise<void> | null,
    started: 0,
    rejectNext: null as Error | null,
    /** Reject (without storing) the write that is call number N. */
    rejectOnCall: null as { call: number; error: Error } | null,
    /** Store the envelope, then fail with this error, on the next write. */
    commitThenReject: null as Error | null,
    /** Fail the write after the next one (the repair of a begin). */
    failAfterCommitThen: false,
    /** Reject (storing nothing) the Nth write that carries this scope's marker. */
    rejectCarrying: null as { scope: string; nth: number } | null,
    carried: 0,
  };
  const store: UploadAttemptStore = {
    namespace: inner.namespace,
    read: () => inner.read(),
    async write(envelope) {
      control.started += 1;
      if (control.rejectOnCall?.call === control.started) {
        throw control.rejectOnCall.error;
      }
      if (control.rejectCarrying) {
        const { scope, nth } = control.rejectCarrying;
        const carries = envelope.records.some(
          (r) => r.scope === scope && r.inFlight,
        );
        if (carries && ++control.carried === nth) throw new Error("disk full");
      }
      if (control.failAfterCommitThen && !control.commitThenReject) {
        control.failAfterCommitThen = false;
        throw new Error("repair failed");
      }
      if (control.commitThenReject) {
        const error = control.commitThenReject;
        control.commitThenReject = null;
        await inner.write(envelope);
        throw error;
      }
      if (control.rejectNext) {
        const error = control.rejectNext;
        control.rejectNext = null;
        throw error;
      }
      if (control.hold) await control.hold;
      await inner.write(envelope);
    },
    preserveCorrupt: () => inner.preserveCorrupt(),
  };
  return { store, control, inner };
}

describe("serialized operations", () => {
  it("never stores a marker for a begin whose own write failed, when a settle is queued the microtask after it", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await ledger.recover();
    const x = await ledger.begin(entry(1));
    // The second write that carries A's marker fails and stores nothing.
    control.rejectCarrying = { scope: entry(2).scope, nth: 2 };
    const begunA = ledger.begin(entry(2));
    await Promise.resolve();
    const settledX = ledger.settle(x, "success");
    const outcome = await Promise.allSettled([begunA, settledX]);
    // Whether A ran or was refused, only a body that ran may leave a marker.
    if (outcome[0].status === "fulfilled")
      await ledger.settle(outcome[0].value, "success").catch(() => undefined);
    await ledger.close().catch(() => undefined);

    for (let boot = 0; boot < 2; boot++) {
      const next = createUploadAttemptLedger(processOver(inner), OWNER_A, {
        maxInterrupted: 1,
      });
      await next.recover();
      expect(next.quarantined()).toEqual([]);
      await next.close();
    }
  });

  it("retries a failed repair during a stop, so the stop hands the store over once storage heals", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
      repairRetryMs: 5,
    });
    await ledger.recover();
    control.commitThenReject = new UploadAttemptWriteUncertainError("sync");
    control.failAfterCommitThen = true; // the repair fails too
    await expect(ledger.begin(entry(1))).rejects.toBeInstanceOf(
      UploadAttemptStorageFailedError,
    );

    // The stop's first repair fails; its retry is referenced and succeeds.
    control.rejectNext = new Error("still down");
    await ledger.close();
    expect(((await inner.read()) as { records: unknown[] }).records).toEqual(
      [],
    );
    const rebuilt = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    expect(await rebuilt.recover()).toBe(true);
    expect(rebuilt.quarantined()).toEqual([]);
  });

  it("keeps a settlement whose write failed, so a stop cannot hand over a marker for a body that stopped", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await ledger.recover();
    const a = await ledger.begin(entry(1));
    control.rejectNext = new Error("disk full");
    await expect(ledger.settle(a, "success")).rejects.toThrow("disk full");
    // The body is over: it is no longer live, and the stop repairs storage.
    expect(ledger.isLive(a.key)).toBe(false);
    await ledger.close();

    const next = createUploadAttemptLedger(processOver(inner), OWNER_A, {
      maxInterrupted: 1,
    });
    await next.recover();
    expect(next.quarantined()).toEqual([]);
    expect(((await inner.read()) as { records: unknown[] }).records).toEqual(
      [],
    );
  });

  it("counts a leftover marker once when the recovery write is uncertain and tried again", async () => {
    const { store, control, inner } = controlledStore();
    const dead = createUploadAttemptLedger(store, OWNER_A);
    await dead.recover();
    await dead.begin(entry(1)); // the process dies mid-upload

    const reboot = createUploadAttemptLedger(processOver(store), OWNER_A, {
      maxInterrupted: 5,
    });
    control.commitThenReject = new UploadAttemptWriteUncertainError("sync");
    await expect(reboot.recover()).rejects.toThrow(/unknown/);
    expect(await reboot.recover()).toBe(true);
    const [record] = (
      (await inner.read()) as {
        records: Array<{ interrupted: number; inFlight: boolean }>;
      }
    ).records;
    expect(record).toEqual(
      expect.objectContaining({ interrupted: 1, inFlight: false }),
    );
  });

  it("lets a stop that waits for a running attempt and that attempt's settlement both finish", async () => {
    const { store, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await ledger.recover();
    const a = await ledger.begin(entry(1));
    const closing = ledger.close(Infinity);
    await Promise.resolve();
    await ledger.settle(a, "success");
    await closing;
    expect(await createUploadAttemptLedger(inner, OWNER_A).recover()).toBe(
      true,
    );
  });
});

describe("release against reactivation", () => {
  it("keeps ownership when a manager takes the store back and begins an attempt while a pending close is writing", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await ledger.recover();
    const a = await ledger.begin(entry(1));
    await ledger.close(0); // grace passes: A stays live, the close is pending
    expect(ledger.isLive(a.key)).toBe(true);

    let resume!: () => void;
    control.hold = new Promise<void>((r) => (resume = r));
    const before = control.started;
    const settling = ledger.settle(a, "success"); // marker write is held
    await vi.waitFor(() => expect(control.started).toBeGreaterThan(before));

    // The same manager is reactivated and begins B for the same entry.
    expect(await ledger.recover()).toBe(true);
    const begunB = ledger.begin(entry(1));
    resume();
    await settling;
    const b = await begunB;

    expect(ledger.isLive(b.key)).toBe(true);
    expect(await createUploadAttemptLedger(inner, OWNER_A).recover()).toBe(
      false,
    );

    await ledger.settle(b, "failure"); // a clean settle
    const later = createUploadAttemptLedger(inner, OWNER_A);
    await ledger.close(0);
    expect(await later.recover()).toBe(true);
    expect(later.quarantined()).toEqual([]);
    expect(
      ((await inner.read()) as { records: Array<{ interrupted: number }> })
        .records,
    ).toEqual([]);
  });
});

describe("a begin whose write was rejected", () => {
  it("is not persisted later as an attempt that ran", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await ledger.recover();
    control.rejectNext = new Error("disk full");
    await expect(ledger.begin(entry(1))).rejects.toThrow("disk full");
    expect(ledger.isLive(uploadAttemptKey(OWNER_A, entry(1)))).toBe(false);

    const b = await ledger.begin(entry(2));
    await ledger.settle(b, "success");
    await ledger.close();

    for (let boot = 0; boot < 2; boot++) {
      const next = createUploadAttemptLedger(processOver(inner), OWNER_A, {
        maxInterrupted: 1,
      });
      await next.recover();
      expect(next.quarantined()).toEqual([]);
      expect(next.isQuarantined(uploadAttemptKey(OWNER_A, entry(1)))).toBe(
        false,
      );
      await next.close();
    }
    expect(((await inner.read()) as { records: unknown[] }).records).toEqual(
      [],
    );
  });

  it("does not let an older queued write commit a later begin that fails", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await ledger.recover();
    const x = await ledger.begin(entry(1));
    const y = await ledger.begin(entry(2));

    let release!: () => void;
    control.hold = new Promise<void>((r) => (release = r));
    const before = control.started;
    const settleX = ledger.settle(x, "success"); // write held after its snapshot
    await vi.waitFor(() => expect(control.started).toBe(before + 1));
    const settleY = ledger.settle(y, "success"); // queued behind X
    // X, Y and then A's own write: the third call fails, storing nothing.
    control.rejectOnCall = {
      call: before + 3,
      error: new Error("disk full"),
    };
    const begunA = ledger.begin(entry(3));
    const failed = expect(begunA).rejects.toThrow("disk full");
    release();
    await Promise.all([settleX, settleY, failed]);
    await ledger.close();

    for (let boot = 0; boot < 2; boot++) {
      const next = createUploadAttemptLedger(processOver(inner), OWNER_A, {
        maxInterrupted: 1,
      });
      await next.recover();
      expect(next.quarantined()).toEqual([]);
      await next.close();
    }
    expect(((await inner.read()) as { records: unknown[] }).records).toEqual(
      [],
    );
  });

  it("does not count a start whose marker write was uncertain, because its body never ran", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await ledger.recover();
    control.commitThenReject = new UploadAttemptWriteUncertainError("sync");
    await expect(ledger.begin(entry(1))).rejects.toThrow(/unknown/);
    const b = await ledger.begin(entry(2));
    await ledger.settle(b, "success");
    await ledger.close();

    for (let boot = 0; boot < 2; boot++) {
      const next = createUploadAttemptLedger(processOver(inner), OWNER_A, {
        maxInterrupted: 1,
      });
      await next.recover();
      expect(next.quarantined()).toEqual([]);
      await next.close();
    }
    expect(((await inner.read()) as { records: unknown[] }).records).toEqual(
      [],
    );
  });

  it("fails closed when an uncertain begin cannot be repaired", async () => {
    const { store, control, inner } = controlledStore();
    const ledger = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await ledger.recover();
    control.commitThenReject = new UploadAttemptWriteUncertainError("sync");
    control.failAfterCommitThen = true;
    await expect(ledger.begin(entry(1))).rejects.toBeInstanceOf(
      UploadAttemptStorageFailedError,
    );
    // The next begin first repairs; it succeeds and clears the marker.
    const b = await ledger.begin(entry(2));
    await ledger.settle(b, "success");
    await ledger.close();
    const next = createUploadAttemptLedger(processOver(inner), OWNER_A, {
      maxInterrupted: 1,
    });
    await next.recover();
    expect(next.quarantined()).toEqual([]);
  });
});
