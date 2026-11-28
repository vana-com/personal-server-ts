import { describe, expect, it } from "vitest";

import {
  createUploadAttemptLedger,
  parseUploadAttemptsEnvelope,
  type UploadAttemptStore,
} from "./upload-attempts.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12";
const MAX = Number.MAX_SAFE_INTEGER;

const record = (over: Record<string, unknown> = {}) => ({
  key: "k",
  owner: OWNER.toLowerCase(),
  scope: "scope.1",
  path: "scope.1/p.json",
  rowId: 1,
  interrupted: 2,
  inFlight: false,
  quarantined: false,
  ...over,
});

/** A store whose persisted value is whatever the test says it is. */
let stores = 0;
function storeHolding(value: unknown): UploadAttemptStore & {
  written: unknown[];
} {
  const written: unknown[] = [];
  return {
    namespace: `kfx-l24:${++stores}`,
    written,
    async read() {
      return written.length ? written[written.length - 1] : value;
    },
    async write(envelope: unknown) {
      written.push(envelope);
    },
    async preserveCorrupt() {},
  } as never;
}

/** The store as a later process sees it: its own lock, the same bytes. */
const processOver = (store: UploadAttemptStore): UploadAttemptStore => ({
  namespace: `${store.namespace}#process`,
  read: () => store.read(),
  write: (envelope) => store.write(envelope),
  preserveCorrupt: (value, stamp) => store.preserveCorrupt(value, stamp),
});

describe("quarantine counters at the persistence boundary (L24)", () => {
  it("keeps a quarantine count at the maximum safe integer parseable after the next quarantine", async () => {
    const store = storeHolding({
      version: 1,
      records: [
        record({
          interrupted: 2,
          inFlight: true,
          quarantined: false,
          quarantines: MAX,
        }),
      ],
    });
    const ledger = createUploadAttemptLedger(store, OWNER, { now: () => 1000 });
    await ledger.recover();
    const written = store.written[store.written.length - 1];
    expect(() => parseUploadAttemptsEnvelope(written)).not.toThrow();
    expect(parseUploadAttemptsEnvelope(written)[0].quarantines).toBe(MAX);
    const again = createUploadAttemptLedger(processOver(store), OWNER, {
      now: () => 1000,
    });
    await again.recover();
    expect(again.quarantined().map((entry) => entry.key)).toEqual(["k"]);
  });

  it("keeps an interrupted count at the maximum safe integer parseable after the next crash", async () => {
    const store = storeHolding({
      version: 1,
      records: [
        record({ interrupted: MAX, inFlight: true, quarantined: false }),
      ],
    });
    const ledger = createUploadAttemptLedger(store, OWNER, { now: () => 1000 });
    await ledger.recover();
    const written = store.written[store.written.length - 1];
    expect(() => parseUploadAttemptsEnvelope(written)).not.toThrow();
    const parsed = parseUploadAttemptsEnvelope(written)[0];
    expect(parsed.interrupted).toBe(MAX);
    expect(parsed.quarantines).toBe(1);
    const again = createUploadAttemptLedger(processOver(store), OWNER, {
      now: () => 1000,
    });
    await again.recover();
    expect(again.quarantined().map((entry) => entry.key)).toEqual(["k"]);
  });
});
