import Database from "better-sqlite3";
import { afterEach, expect, it, vi } from "vitest";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import { planReplicaMerge } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import type * as MergePlan from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { createStreamDeclarationRegistry } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { pdppRecordsRoutes } from "../routes/pdpp-records.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";

// Count reducer runs: the receiver's canonical reconcile plus any view materialization.
vi.mock(
  "@opendatalabs/personal-server-ts-core/replication/merge-plan",
  async (original) => {
    const actual = await original<typeof MergePlan>();
    return { ...actual, planReplicaMerge: vi.fn(actual.planReplicaMerge) };
  },
);
const merges = vi.mocked(planReplicaMerge);

const stores: ReturnType<typeof createReplicaRecordStore>[] = [];
afterEach(() => {
  merges.mockClear();
  for (const store of stores.splice(0)) store.close();
});

const declarations = [
  { sourceId: identity.sourceId, binding, validateData: () => true },
];
const envelope = (batchId: string, operations: unknown[]) => ({
  format: "vana-pdpp-replica",
  version: 1,
  owner: identity.owner,
  batchId,
  operations,
});
const rows = (prefix: string, n: number, instance = identity.connectionId) =>
  Array.from({ length: n }, (_, i) => {
    const key = `${prefix}${String(i).padStart(4, "0")}`;
    return {
      instance,
      stream: binding.stream,
      key,
      data: { id: key, text: "x".repeat(200) },
      emitted_at: `2026-10-21T00:00:${String(i % 60).padStart(2, "0")}.000Z`,
    };
  });

function device(size: number) {
  const db = new Database(":memory:");
  const store = createReplicaRecordStore(db);
  stores.push(store);
  store.registerConnection({
    instance: identity.connectionId,
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "A",
  });
  store.replication.beginBaseline({ owner: identity.owner, declarations });
  const ingest = (batch: ReturnType<typeof rows>) =>
    store.ingestBatch(
      batch,
      () => "mutable_state",
      () => ["id"],
      {
        method: identity.methodId,
        generation: 1,
      },
    );
  ingest(rows("base", size));
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: identity.owner,
      authenticate: () => identity.owner,
      declarations: () => declarations,
      enabled: true,
    });
  return { db, store, ingest, receiver };
}

/** Bytes held by derived view tables and their indexes. */
function viewBytes(db: Database.Database) {
  return (
    db
      .prepare(
        "SELECT COALESCE(SUM(pgsize),0) AS bytes FROM dbstat WHERE name IN (SELECT name FROM sqlite_master WHERE tbl_name GLOB 'pdpp_replica_view*' OR tbl_name='pdpp_replica_local_view')",
      )
      .get() as { bytes: number }
  ).bytes;
}
/** Derived view tables and indexes; each is one b-tree of at least a page. */
const viewObjects = (db: Database.Database) =>
  (
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM sqlite_master WHERE type IN ('table','index') AND (tbl_name GLOB 'pdpp_replica_view*' OR tbl_name='pdpp_replica_local_view')",
      )
      .get() as { n: number }
  ).n;
const pageSize = (db: Database.Database) =>
  db.pragma("page_size", { simple: true }) as number;
const overlayRows = (db: Database.Database) =>
  (
    db.prepare("SELECT COUNT(*) AS n FROM pdpp_replica_view").get() as {
      n: number;
    }
  ).n;

it.each([100, 1000])(
  "keeps derived view storage independent of %i canonical rows",
  (size) => {
    const { db, receiver } = device(size);
    receiver();
    expect(overlayRows(db)).toBe(0);
    // Each derived table and index holds only its root page, never a copy of
    // rows or operation JSON: 28 pages at 100, 1,000 and 5,000 rows, four of
    // them the empty local projection that the conflict-fact table enables.
    expect(viewBytes(db)).toBeLessThanOrEqual(viewObjects(db) * pageSize(db));
  },
);

it("persists only keys whose owner-visible state differs from canonical", () => {
  const { db, receiver } = device(120);
  const replica = receiver();
  replica.stage({
    credential: "x",
    id: "pending",
    envelope: envelope("pending", [
      {
        ...upsert("pending", 1_000_000, "pending", "device-b"),
        recordKey: "base0007",
        data: { id: "base0007", text: "pending" },
      },
    ]),
  });
  expect(overlayRows(db)).toBe(1);
  const owner = replica.readStore({ reader: "owner" });
  expect(
    owner.getRecord(identity.connectionId, binding.stream, "base0007"),
  ).toMatchObject({
    data: { text: "pending" },
    visibility: "pending",
  });
  const page = owner.listRecords(binding.stream, {
    instanceIds: [identity.connectionId],
    limit: 200,
    order: "asc",
  });
  expect(page.data).toHaveLength(120);
  expect(page.data.filter((row) => row.visibility === "pending")).toHaveLength(
    1,
  );
  replica.quarantine({ credential: "x", id: "pending", reason: "test" });
  expect(overlayRows(db)).toBe(0);
});

it("runs no view reducer for constructor rebuild or local ingest outside pending keys", () => {
  const { ingest, receiver } = device(300);
  merges.mockClear();
  const replica = receiver();
  expect(merges).not.toHaveBeenCalled();
  replica.stage({
    credential: "x",
    id: "pending",
    envelope: envelope("pending", [
      {
        ...registration,
        revision: {
          counter: 1,
          writerId: "device-b",
          operationId: "register-b",
        },
      },
      {
        ...upsert("pending", 1_000_000, "pending", "device-b"),
        recordKey: "base0007",
        data: { id: "base0007", text: "pending" },
      },
    ]),
  });
  merges.mockClear();
  ingest(rows("new", 200));
  expect(merges).not.toHaveBeenCalled();
});

it("keeps the local journal projection only for conflicted connections", () => {
  const { db, store, ingest } = device(50);
  store.registerConnection({
    instance: "connection-b",
    sourceId: identity.sourceId,
    method: identity.methodId,
    label: "B",
  });
  ingest(rows("b", 50, "connection-b"));
  db.exec(
    "CREATE TABLE IF NOT EXISTS pdpp_replica_binding_conflicts (instance TEXT PRIMARY KEY, reason TEXT NOT NULL, evidence_json TEXT NOT NULL)",
  );
  db.prepare(
    "INSERT INTO pdpp_replica_binding_conflicts VALUES (?, 'source_binding_conflict', '{}')",
  ).run("connection-b");
  const replica = createReplicaReceiver({
    db,
    store,
    owner: identity.owner,
    authenticate: () => identity.owner,
    declarations: () => declarations,
    enabled: true,
  });
  expect(
    db.prepare("SELECT DISTINCT instance FROM pdpp_replica_local_view").all(),
  ).toEqual([{ instance: "connection-b" }]);
  ingest(rows("late", 5));
  expect(
    db.prepare("SELECT DISTINCT instance FROM pdpp_replica_local_view").all(),
  ).toEqual([{ instance: "connection-b" }]);
  const owner = replica.readStore({ reader: "owner" });
  expect(
    owner.listRecords(binding.stream, {
      instanceIds: ["connection-b"],
      limit: 100,
      order: "asc",
    }).data,
  ).toHaveLength(50);
  db.prepare(
    "INSERT INTO pdpp_replica_binding_conflicts VALUES (?, 'source_binding_conflict', '{}')",
  ).run(identity.connectionId);
  expect(
    owner.listRecords(binding.stream, {
      instanceIds: [identity.connectionId],
      limit: 100,
      order: "asc",
    }).data,
  ).toHaveLength(55);
});

/**
 * Rows the canonical and overlay keysets visit per owner page. A counting SQL
 * function wraps the quarantine predicate that every page source evaluates on
 * each row it visits, so the count is SQLite work, not rows returned.
 */
function maskedPageWork(masked: number, mask: "overwrite" | "delete") {
  const { db, store } = device(masked);
  let visits = 0;
  db.function("pdpp_test_visit", { deterministic: false }, () => {
    visits += 1;
    return 1;
  });
  const replica = createReplicaReceiver({
    db,
    store: {
      ...store,
      unquarantinedRecordSql: (alias: string) =>
        `pdpp_test_visit() AND ${store.unquarantinedRecordSql(alias)}`,
    },
    owner: identity.owner,
    authenticate: () => identity.owner,
    declarations: () => declarations,
    enabled: true,
  });
  // Either mask gives every canonical key an overlay row: pending overwrites
  // sort before canonical rows; pending removals share their positions.
  replica.stage({
    credential: "x",
    id: "mask-all",
    envelope: envelope(
      "mask-all",
      mask === "overwrite"
        ? rows("base", masked).map((row, i) => ({
            ...upsert(`overwrite-${i}`, 1_000_000 + i, "pending", "device-b"),
            recordKey: row.key,
            data: { id: row.key, text: "pending" },
          }))
        : [
            {
              ...identity,
              kind: "connection-delete",
              revision: {
                counter: 2_000_000,
                writerId: "device-b",
                operationId: "delete-b",
              },
            },
          ],
    ),
  });
  expect(overlayRows(db)).toBe(masked);
  const owner = replica.readStore({ reader: "owner" });
  const page = (order: "asc" | "desc", limit: number, cursor?: string) => {
    visits = 0;
    const result = owner.listRecords(binding.stream, {
      instanceIds: [identity.connectionId],
      limit,
      order,
      cursor,
    });
    return { ...result, visits };
  };
  const work: Record<string, number> = {};
  const times: Record<string, number> = {};
  for (const order of ["asc", "desc"] as const) {
    const first = page(order, 1);
    work[`${order} first`] = first.visits;
    work[`${order} continuation`] = page(order, 1, first.nextCursor).visits;
    const samples: number[] = [];
    for (let i = 0; i < 21; i += 1) {
      const start = process.hrtime.bigint();
      page(order, 1);
      samples.push(Number(process.hrtime.bigint() - start) / 1e6);
    }
    times[`${order} first ms (median of 21)`] = samples.sort(
      (a, b) => a - b,
    )[10];
    // Walking every page returns each key once, all marked, in merged order.
    const seen: [string, string][] = [];
    let cursor: string | undefined;
    let maxPageWork = 0;
    do {
      const next = page(order, 100, cursor);
      maxPageWork = Math.max(maxPageWork, next.visits);
      for (const row of next.data) {
        expect(row.visibility).toBe("pending");
        expect(row.deleted).toBe(mask === "delete");
        seen.push([row.emittedAt, row.recordKey]);
      }
      cursor = next.nextCursor;
    } while (cursor);
    work[`${order} max per 100-row page`] = maxPageWork;
    const sorted = [...seen].sort(([a, x], [b, y]) =>
      a === b ? (x < y ? -1 : x > y ? 1 : 0) : a < b ? -1 : 1,
    );
    expect(seen).toEqual(order === "asc" ? sorted : sorted.reverse());
    expect(new Set(seen.map(([, key]) => key)).size).toBe(masked);
  }
  return { work, times };
}

it.each(["overwrite", "delete"] as const)(
  "bounds owner page work by page size, not by keys a pending %s masks",
  (mask) => {
    const small = maskedPageWork(100, mask);
    const large = maskedPageWork(3000, mask);
    console.log(
      JSON.stringify({ mask, masked100: small, masked3000: large }, null, 2),
    );
    for (const [read, visits] of Object.entries(large.work)) {
      // Each of the two sources visits at most limit+1 rows, plus a few rows
      // at the keyset seek boundary. Nothing grows with the masked count.
      const limit = read.includes("100-row") ? 100 : 1;
      expect(visits, read).toBeGreaterThan(0);
      expect(visits, read).toBeLessThanOrEqual(2 * (limit + 1) + 4);
      expect(visits, read).toBeLessThanOrEqual(small.work[read] + 4);
    }
  },
  120_000,
);

/**
 * Rows visited by one owner HTTP page and one owner stream summary when a
 * pending overwrite masks every canonical key. The overwrites sort before the
 * canonical rows, so a descending page starts in a fully masked range.
 */
async function maskedReaderWork(masked: number) {
  const { db, store } = device(masked);
  let visits = 0;
  db.function("pdpp_test_visit", { deterministic: false }, () => {
    visits += 1;
    return 1;
  });
  const replica = createReplicaReceiver({
    db,
    store: {
      ...store,
      unquarantinedRecordSql: (alias: string) =>
        `pdpp_test_visit() AND ${store.unquarantinedRecordSql(alias)}`,
    },
    owner: identity.owner,
    authenticate: () => identity.owner,
    declarations: () => declarations,
    enabled: true,
  });
  replica.stage({
    credential: "x",
    id: "mask-all",
    envelope: envelope(
      "mask-all",
      rows("base", masked).map((row, i) => ({
        ...upsert(`overwrite-${i}`, 1_000_000 + i, "pending", "device-b"),
        recordKey: row.key,
        data: { id: row.key, text: "pending" },
      })),
    ),
  });
  const app = pdppRecordsRoutes({
    store,
    reads: (reader) => replica.readStore({ reader }),
    auth: createFixtureAuthorizationService({
      owner: {
        active: true,
        tokenKind: "owner",
        subjectId: identity.owner,
        instanceIds: [identity.connectionId],
      },
    }),
    declarations: createStreamDeclarationRegistry([
      {
        name: binding.stream,
        semantics: binding.semantics,
        primaryKey: ["id"],
        cursorField: "emitted_at",
        requiredFields: ["id"],
      },
    ]),
    instancesForSubject: () => [identity.connectionId],
  });
  visits = 0;
  const response = await app.request(
    `/streams/${binding.stream}/records?order=desc&limit=1`,
    { headers: { Authorization: "Bearer owner" } },
  );
  const body = await response.json();
  const page = visits;
  visits = 0;
  const [summary] = replica
    .readStore({ reader: "owner" })
    .listStreams([identity.connectionId]);
  // A later unmasked canonical write moves the summary at write time.
  store.ingestBatch(
    [{ ...rows("late", 1)[0]!, emitted_at: "2026-10-22T00:00:00.000Z" }],
    () => "mutable_state",
    () => ["id"],
    { method: identity.methodId, generation: 1 },
  );
  const [afterWrite] = replica
    .readStore({ reader: "owner" })
    .listStreams([identity.connectionId]);
  return {
    afterWrite,
    work: {
      "owner HTTP desc limit=1 page": page,
      "owner stream summary": visits,
    },
    page: body,
    summary,
  };
}

it("bounds owner HTTP page and stream summary work by page size, not by masked keys", async () => {
  const small = await maskedReaderWork(100);
  const large = await maskedReaderWork(3000);
  console.log(
    JSON.stringify({ masked100: small.work, masked3000: large.work }, null, 2),
  );
  for (const [read, visits] of Object.entries(large.work))
    expect(visits, read).toBeLessThanOrEqual(small.work[read] + 4);
  // A short page continues; the summary still reports the overlay's latest row.
  expect(large.page.has_more).toBe(true);
  expect(large.summary).toMatchObject({
    recordCount: 3000,
    lastUpdated: "2026-10-20T00:00:00Z",
  });
  expect(large.afterWrite).toMatchObject({
    recordCount: 3001,
    lastUpdated: "2026-10-22T00:00:00.000Z",
  });
}, 120_000);
