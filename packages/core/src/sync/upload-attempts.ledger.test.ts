import { describe, expect, it } from "vitest";

import {
  createMemoryUploadAttemptStore,
  createUploadAttemptLedger,
  UploadAttemptStoreInvalidError,
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
function storeHolding(
  value: unknown,
): UploadAttemptStore & { written: unknown[] } {
  const written: unknown[] = [];
  return {
    written,
    async read() {
      return value;
    },
    async write(envelope) {
      written.push(envelope);
    },
  };
}

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
    const a = createUploadAttemptLedger(store, OWNER_A, { maxInterrupted: 1 });
    await a.recover();
    await a.begin(entry(1)); // owner A dies mid-upload
    await a.close();

    const again = createUploadAttemptLedger(store, OWNER_A, {
      maxInterrupted: 1,
    });
    await again.recover();
    expect(again.quarantined()).toHaveLength(1);
    await again.close();

    const b = createUploadAttemptLedger(store, OWNER_B, { maxInterrupted: 1 });
    await b.recover();
    await b.reconcile([], { afterId: 0, throughId: 5 });
    expect(await b.release()).toEqual([]);
    expect(b.quarantined()).toEqual([]);
    await b.close();

    const back = createUploadAttemptLedger(store, OWNER_A, {
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
  ])("fails closed on %s and writes nothing", async (_name, value) => {
    const store = storeHolding(value);
    const ledger = createUploadAttemptLedger(store, OWNER_A);
    await expect(ledger.recover()).rejects.toBeInstanceOf(
      UploadAttemptStoreInvalidError,
    );
    // Nothing may begin or rewrite the bad value as an empty ledger.
    await expect(ledger.begin(entry(1))).rejects.toThrow();
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
    await first.begin(entry(1)); // live: the upload is still running

    const second = createUploadAttemptLedger(store, OWNER_A);
    expect(await second.recover()).toBe(false);
    await expect(second.begin(entry(2))).rejects.toThrow();

    await first.settle(entry(1), "success");
    // The live attempt was never counted as an interruption.
    expect(await store.read()).toEqual({ version: 1, records: [] });
  });

  it("lets a new ledger take over once the owner is closed", async () => {
    const store = createMemoryUploadAttemptStore();
    const first = createUploadAttemptLedger(store, OWNER_A);
    await first.recover();
    await first.begin(entry(1));
    await first.close();
    const second = createUploadAttemptLedger(store, OWNER_A);
    expect(await second.recover()).toBe(true);
  });
});
