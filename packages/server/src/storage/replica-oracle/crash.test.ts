/**
 * Crash and lost-acknowledgement matrix (oracle design §3).
 *
 * Every mutating entry point runs once cleanly (the reference) and once per
 * crash point. A crash inside a transaction must leave the complete durable
 * state as it was. A crash after a commit may leave a committed prefix of a
 * multi-transaction entry point. Either way, closing and reopening the store
 * and retrying the same request must reach the reference state with the
 * reference receipt, and a retry after a lost acknowledgement must change
 * nothing. Snapshots hold every row, id, receipt and byte, not counts.
 *
 * Lite crashes through its persistence hooks. Node crashes through a
 * temporary SQLite trigger that aborts the first write to one table the
 * entry point changes; the trigger dies with the connection on reopen.
 * Generated ids come from counters, so the clean and crashed runs are
 * byte-comparable; a crash rewinds the counter past ids its rollback
 * discarded.
 */
import type * as Crypto from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { CanonicalCrashPoint } from "../../../../lite/src/test-support/canonical-persistence.js";
import { BINDINGS } from "./generator.test-utils.js";
import {
  blobPayload,
  liteDriver,
  liteMemoryPersistence,
  liteSqlitePersistence,
  METHOD,
  nodeDriver,
  OWNER,
  SOURCE,
  sqliteDump,
  type LiteDriver,
  type NodeDriver,
  type ReplicaPortDriver,
} from "./ports.test-utils.js";

const uuids = vi.hoisted(() => ({ count: 0 }));
vi.mock("node:crypto", async (original) => ({
  ...(await original<typeof Crypto>()),
  randomUUID: () =>
    `00000000-0000-4000-8000-${(uuids.count++).toString(16).padStart(12, "0")}`,
}));

const base = (connection = "c1") => ({
  owner: OWNER,
  sourceId: SOURCE,
  connectionId: connection,
  methodId: METHOD,
  generation: 1,
});
const rev = (counter: number, operationId: string) => ({
  counter,
  writerId: "w-remote",
  operationId,
});
const put = (key: string, text: string, counter: number, connection = "c1") =>
  ({
    ...base(connection),
    kind: "upsert",
    declaration: BINDINGS.m,
    recordKey: key,
    emittedAt: "2026-10-20T00:00:00Z",
    data: { id: key, text },
    blobs: [],
    revision: rev(counter, `put-${connection}-${key}-${counter}`),
  }) as const satisfies ReplicaOperation;
const blob = blobPayload(
  new TextEncoder().encode("crash matrix blob"),
  "text/plain",
);
const imported: ReplicaOperation[] = [
  {
    ...base(),
    kind: "blob-claim",
    blob: blob.descriptor,
    revision: rev(5, "claim"),
  },
  {
    ...put("k2", "with blob", 6),
    data: { id: "k2", blob_ref: { blob_id: blob.descriptor.blobId } },
    blobs: [blob.descriptor],
  },
  put("k0", "replaced", 7),
  {
    ...base(),
    kind: "delete",
    declaration: BINDINGS.m,
    recordKey: "k1",
    emittedAt: "2026-10-20T00:00:00Z",
    deletedAt: "2026-10-20T00:00:01Z",
    revision: rev(8, "delete-k1"),
  },
];
const local = (text: string) => ({
  requestId: "local-request",
  connection: "c2",
  generation: 1,
  binding: BINDINGS.m,
  key: "k3",
  data: { id: "k3", text },
  emittedAt: "2026-10-22T00:00:00Z",
});

/** Every state starts here: registered connections with live rows on both. */
async function setup(driver: ReplicaPortDriver) {
  await driver.importBatch(
    "baseline",
    [
      {
        ...base(),
        generation: 1,
        kind: "connection-register",
        revision: rev(1, "register-c1"),
      },
      {
        ...base("c2"),
        generation: 1,
        kind: "connection-register",
        revision: rev(1, "register-c2"),
      },
      put("k0", "original", 2),
      put("k1", "doomed", 3),
      put("k0", "other", 2, "c2"),
    ],
    [],
  );
  await driver.stage("pending", [put("k1", "pending", 9, "c2")], []);
}

interface Scenario {
  name: string;
  act(driver: ReplicaPortDriver): Promise<unknown>;
  /** Request that reuses the id with different content, when the port has request ids. */
  conflicting?(driver: ReplicaPortDriver): Promise<unknown>;
}
const scenarios: Scenario[] = [
  {
    name: "import",
    act: (d) => d.importBatch("crash-batch", imported, [blob]),
  },
  {
    name: "local write",
    act: (d) => d.local(local("written")),
    conflicting: (d) => d.local(local("changed")),
  },
  { name: "promotion", act: (d) => d.promote("pending") },
  { name: "terminal quarantine", act: (d) => d.quarantineConnection("c1") },
];

async function outcome(fn: () => Promise<unknown>) {
  try {
    return { receipt: await fn() };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

interface Port<D extends ReplicaPortDriver> {
  open(): Promise<D>;
  dump(driver: D): unknown;
  /**
   * The dump a repeated request must leave unchanged. Lite still bumps its
   * view revisions on a repeated import or promotion (oracle finding D4, see
   * cursors.test.ts), so Lite compares repeats without those counters.
   */
  repeatDump(driver: D): unknown;
  /** Entry points whose repeat returns the original receipt. */
  stableReceipts: readonly string[];
  /** Whether local writes carry a request id that rejects changed content. */
  requestIds: boolean;
  /** Crash points of this port, given the clean run's before/after dumps. */
  points(before: unknown, after: unknown): string[];
  arm(driver: D, point: string): void;
  /** Whether the point fires after a commit. */
  afterCommit(point: string): boolean;
  /** Read or rewind the port's generated-id counter. */
  ids(driver: D, value?: number): number;
}

const VIEW_REVISION = /^(canonical-view|preview)-revision\//;
function withoutViewRevisions(dump: Record<string, unknown>) {
  const { rows, kv, ...rest } = dump as {
    rows?: Record<string, string>;
    kv?: string[];
  };
  return {
    ...rest,
    ...(rows && {
      rows: Object.fromEntries(
        Object.entries(rows).filter(([key]) => !VIEW_REVISION.test(key)),
      ),
    }),
    ...(kv && {
      kv: kv.filter(
        (row) => !VIEW_REVISION.test((JSON.parse(row) as { key: string }).key),
      ),
    }),
  };
}
const LITE_POINTS: CanonicalCrashPoint[] = [
  "record",
  "blob",
  "journal",
  "outbox",
  "import",
  "before-commit",
  "after-commit",
];
const litePort = (sqlite: boolean): Port<LiteDriver> => ({
  open: () =>
    liteDriver({
      name: sqlite ? "lite-sqlite" : "lite-memory",
      persistence: sqlite ? liteSqlitePersistence() : liteMemoryPersistence(),
      declarations: [BINDINGS.m, BINDINGS.a],
      provisioned: ["c1", "c2"],
    }),
  dump: (driver) => driver.persistence.dump(),
  repeatDump: (driver) => withoutViewRevisions(driver.persistence.dump()),
  stableReceipts: ["import", "local write", "promotion", "terminal quarantine"],
  requestIds: true,
  points: () => LITE_POINTS,
  arm: (driver, point) =>
    driver.persistence.crashAt(point as CanonicalCrashPoint),
  afterCommit: (point) => point === "after-commit",
  ids: (driver, value) => {
    if (value !== undefined) driver.idCount = value;
    return driver.idCount;
  },
});
const nodePort: Port<NodeDriver> = {
  open: async () =>
    nodeDriver({
      durable: true,
      declarations: [BINDINGS.m, BINDINGS.a],
      provisioned: ["c1", "c2"],
    }),
  dump: (driver) => sqliteDump(driver.db),
  // A repeated unchanged ingest refreshes key arrival order. That predates
  // replication (it is on main) and changes no record, change or journal row.
  repeatDump: (driver) => {
    const {
      pdpp_record_arrival: _arrival,
      pdpp_record_arrival_clock: _clock,
      ...rest
    } = sqliteDump(driver.db);
    return rest;
  },
  // Node local writes carry no request id and a repeated promotion returns
  // no receipt; both must still change nothing.
  stableReceipts: ["import", "terminal quarantine"],
  requestIds: false,
  // One point per table the clean run changed. Each Node entry point
  // commits once, so the lost-acknowledgement retry covers after-commit.
  points: (before, after) => {
    const a = before as Record<string, string[]>;
    const b = after as Record<string, string[]>;
    return Object.keys(b)
      .filter((table) => !table.startsWith("sqlite_"))
      .filter((table) => JSON.stringify(a[table]) !== JSON.stringify(b[table]))
      .sort();
  },
  arm: (driver, point) => {
    for (const event of ["INSERT", "UPDATE", "DELETE"])
      driver.db.exec(
        `CREATE TEMP TRIGGER crash_${event.toLowerCase()} BEFORE ${event} ON main."${point}" BEGIN SELECT RAISE(ABORT, 'interrupted:${point}'); END`,
      );
  },
  afterCommit: () => false,
  ids: (_driver, value) => {
    if (value !== undefined) uuids.count = value;
    return uuids.count;
  },
};

function matrix<D extends ReplicaPortDriver>(name: string, port: Port<D>) {
  async function prepared() {
    uuids.count = 0;
    const driver = await port.open();
    await setup(driver);
    return driver;
  }
  describe(`${name} crash matrix`, () => {
    for (const scenario of scenarios)
      it(scenario.name, async () => {
        const clean = await prepared();
        let reference: { dump: unknown; receipt: unknown; before: unknown };
        let referenceRepeat: unknown;
        try {
          const before = port.dump(clean);
          const result = await outcome(() => scenario.act(clean));
          expect(result.error).toBeUndefined();
          // Imported operations never echo into the importer's own journal.
          if (scenario.name === "import")
            expect(
              (await clean.localOperations()).some(
                (op) => op.revision.writerId === "w-remote",
              ),
            ).toBe(false);
          await clean.reopen();
          reference = {
            dump: port.dump(clean),
            receipt: result.receipt,
            before,
          };
          referenceRepeat = port.repeatDump(clean);
          expect(reference.dump).not.toEqual(before);
          // Lost acknowledgement: the same request again returns the same
          // receipt and changes nothing.
          const repeated = port.repeatDump(clean);
          const again = await outcome(() => scenario.act(clean));
          expect(again.error).toBeUndefined();
          if (port.stableReceipts.includes(scenario.name))
            expect(again.receipt).toEqual(reference.receipt);
          expect(port.repeatDump(clean)).toEqual(repeated);
          if (scenario.conflicting && port.requestIds) {
            expect(
              (await outcome(() => scenario.conflicting!(clean))).error,
            ).toBeDefined();
            expect(port.repeatDump(clean)).toEqual(repeated);
          }
        } finally {
          clean.close();
        }
        const fired: string[] = [];
        for (const point of port.points(reference.before, reference.dump)) {
          const driver = await prepared();
          try {
            const before = port.dump(driver);
            expect(before).toEqual(reference.before);
            const ids = port.ids(driver);
            port.arm(driver, point);
            const crashed = await outcome(() => scenario.act(driver));
            const committed = port.afterCommit(point);
            await driver.reopen();
            if (crashed.error === undefined) {
              // The entry point never reached this point; the run was clean.
              expect(port.dump(driver), point).toEqual(reference.dump);
              continue;
            }
            expect(crashed.error, point).toBe(`interrupted:${point}`);
            fired.push(point);
            if (!committed) {
              expect(port.dump(driver), point).toEqual(before);
              port.ids(driver, ids);
            }
            // Retrying the same request after reopen reaches the reference.
            const retried = await outcome(() => scenario.act(driver));
            expect(retried.error, point).toBeUndefined();
            if (!committed || port.stableReceipts.includes(scenario.name))
              expect(retried.receipt, point).toEqual(reference.receipt);
            if (committed)
              expect(port.repeatDump(driver), point).toEqual(referenceRepeat);
            else expect(port.dump(driver), point).toEqual(reference.dump);
          } finally {
            driver.close();
          }
        }
        // Every changed table (Node) or both sides of a commit (Lite) fire.
        const points = port.points(reference.before, reference.dump);
        if (points.includes("after-commit"))
          expect(fired).toContain("after-commit");
        expect(fired.length).toBeGreaterThan(1);
      });
  });
}

matrix("Lite fake disk", litePort(false));
matrix("Lite SQLite", litePort(true));
matrix("Node", nodePort);
