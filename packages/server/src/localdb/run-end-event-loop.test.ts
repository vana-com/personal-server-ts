import { afterEach, describe, expect, it, vi } from "vitest";
import {
  connectionQueue,
  openLocalDb,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import type {
  BeginRequest,
  IntakeDeclarations,
} from "../../../core/src/stream-sync/intake.js";
import { createRunIntakeStore } from "../../../core/src/localdb/run-intake.js";
import { createRunEndStore } from "../../../core/src/localdb/run-end.js";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

const owner = `0x${"12".repeat(20)}` as const;
const declaration: IntakeDeclarations = {
  connector: "fixture-source",
  version: "1",
  streams: [{ name: "items", semantics: "mutable_state", primaryKey: ["id"] }],
};
const request: BeginRequest = {
  connector: declaration.connector,
  artifactDigest: "fixture-artifact",
  owner: { address: owner, leaseId: null },
  observedAt: 40,
};
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});

async function fixture() {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "intake",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  let op = 0;
  const deps: LocalSyncDeps = {
    db,
    keys,
    registry: remote.registry,
    blobs: remote.storage,
    queue: connectionQueue(),
    ownerAddress: owner,
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 100,
    newOp: () => `intake-${++op}`,
  };
  return {
    db,
    store: createRunIntakeStore(deps),
    end: createRunEndStore(deps),
  };
}

/** Longest gap between ticks of a 20 ms timer while `work` runs. */
async function longestLoopBlock(work: () => Promise<unknown>) {
  let last = performance.now();
  let longest = 0;
  const timer = setInterval(() => {
    const now = performance.now();
    longest = Math.max(longest, now - last);
    last = now;
  }, 20);
  last = performance.now();
  try {
    await work();
  } finally {
    clearInterval(timer);
  }
  return Math.max(longest, performance.now() - last);
}

describe("run end does not hold the event loop", () => {
  it("keeps timers firing while a large staged run merges", async () => {
    const f = await fixture();
    await f.store.begin("run", request, declaration);
    const rows = 150_000;
    const text = "x".repeat(300);
    let batch = 0;
    for (let start = 0; start < rows; start += 7_000) {
      const records = Array.from(
        { length: Math.min(7_000, rows - start) },
        (_, i) => ({
          stream: "items",
          data: { id: `r${start + i}`, text },
        }),
      );
      await f.store.batch("run", { batch: batch++, records });
    }
    const request_ = {
      outcome: "succeeded" as const,
      coveredStreams: ["items"],
      provenFullStreams: ["items"],
      lastBatch: batch - 1,
      checkpointCandidate: { items: "C" },
    };
    const mergeMs = { value: 0 };
    const blocked = await longestLoopBlock(async () => {
      const t0 = performance.now();
      await f.end.end("run", request_);
      mergeMs.value = performance.now() - t0;
    });
    const [{ n }] = await f.db.query<{ n: number }>(
      "SELECT COUNT(*) AS n FROM records",
    );
    expect(n).toBe(rows);
    // The merge itself must be long enough to matter, or the bound proves nothing.
    expect(mergeMs.value).toBeGreaterThan(1_000);
    expect(blocked).toBeLessThan(1_000);
  }, 300_000);
});
