import { afterEach, expect, it, vi } from "vitest";
import { replicaChainCommitment } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  clock,
  cleanupHarness,
  network,
  transportDevice,
  type Network,
  type TransportDevice,
} from "./pdpp-replica-contract.test-utils.js";

/**
 * Batch-copy promotion through the Node transport (contract v3.1 §3
 * "Coordinator step", F2, F4, A, H). The receiver-level transitions are in
 * pdpp-replica-copies.test.ts.
 */

afterEach(() => {
  vi.restoreAllMocks();
  cleanupHarness();
});

const hex = (n: number) => `0x${n.toString(16).padStart(64, "0")}` as const;
const num = (d: TransportDevice, sql: string, ...params: unknown[]) =>
  (d.db.prepare(sql).get(...params) as { n: number }).n;
async function steps(d: TransportDevice, n: number, ms = 0) {
  for (let i = 0; i < n; i++) {
    clock.advance(ms);
    await d.step({ units: 50 });
  }
}
/** A writer whose single batch is published and finalized. */
async function published(net: Network, text = "remote") {
  const a = transportDevice(net, { preexisting: text });
  await steps(a, 6, 0);
  expect(net.head.size).toBeGreaterThan(0);
  return { a, scopes: new Set(net.head.keys()) };
}
/** Finalized evidence that commits every published slot to another copy. */
function disproveAll(net: Network, scopes: Set<string>) {
  let n = 0;
  for (const scope of scopes) {
    n += 1;
    net.chain.set(scope, {
      ...net.chain.get(scope)!,
      commitment: replicaChainCommitment(hex(1000 + n), hex(2000 + n)),
      blockNumber: 130n,
    });
  }
}
/** Import work of the remote writer's batches (a device also imports its own). */
const importWork = (d: TransportDevice) =>
  (
    d.db
      .prepare(
        "SELECT outcome,dependency,refetch_attempts FROM pdpp_transport_import_work",
      )
      .all() as {
      outcome: string;
      dependency: string | null;
      refetch_attempts: number;
    }[]
  ).filter((row) => row.outcome !== "progress");
const inScopes = (scopes: Set<string>) =>
  `(${[...scopes].map((s) => `'${s.replace(/'/g, "''")}'`).join(",")})`;

it("confirm appends verified finalized facts, and polling an unchanged slot adds none", async () => {
  const net = network();
  const { scopes } = await published(net);
  const b = transportDevice(net);
  await steps(b, 6, 0);
  expect(b.get("a")).toEqual({ id: "a", text: "remote" });
  const facts = num(
    b,
    "SELECT count(*) AS n FROM pdpp_replica_finalized_facts",
  );
  expect(facts).toBeGreaterThan(0);
  expect(
    num(
      b,
      `SELECT count(*) AS n FROM pdpp_replica_finalized_facts WHERE eligible=1 AND current_version='1' AND scope IN ${inScopes(scopes)}`,
    ),
  ).toBe(scopes.size);
  await steps(b, 6, 60_000);
  expect(num(b, "SELECT count(*) AS n FROM pdpp_replica_finalized_facts")).toBe(
    facts,
  );
});

it("every copy disproved: refetches spend the budget once each, then Wait(owner) persists across restart; nothing is imported", async () => {
  const net = network();
  const { scopes } = await published(net);
  disproveAll(net, scopes);
  const b = transportDevice(net, { worker: { refetchBudget: 2 } });
  const gets = () => net.calls.gets.filter((s) => scopes.has(s)).length;
  await steps(b, 6, 0);
  const firstGets = gets();
  for (let i = 0; i < 12; i++) await steps(b, 1, 70_000);
  expect(importWork(b)).toEqual([
    {
      outcome: "wait",
      dependency: expect.stringMatching(/^owner:/),
      refetch_attempts: 2,
    },
  ]);
  // Two refetches each re-downloaded every slot once.
  expect(gets() - firstGets).toBe(2 * scopes.size);
  expect(b.get("a")).toBeUndefined();
  expect(
    b.db
      .prepare(
        "SELECT state,reason FROM pdpp_replica_copies WHERE state<>'confirmed'",
      )
      .all(),
  ).toEqual([{ state: "quarantined", reason: "copy_conflict" }]);
  b.reopen();
  for (let i = 0; i < 6; i++) await steps(b, 1, 70_000);
  expect(importWork(b)[0]).toMatchObject({
    outcome: "wait",
    dependency: expect.stringMatching(/^owner:/),
    refetch_attempts: 2,
  });
  expect(gets() - firstGets).toBe(2 * scopes.size);
  expect(b.get("a")).toBeUndefined();
});

it("a contradiction after import is terminal: the batch's connection is withdrawn from both readers and its slots leave revalidation", async () => {
  const net = network();
  const { scopes } = await published(net);
  const b = transportDevice(net, { worker: { revalidateIntervalMs: 0 } });
  await steps(b, 6, 0);
  expect(b.get("a")).toEqual({ id: "a", text: "remote" });
  const epoch = b.store.replicaIntegrityEpoch(b.instance);
  // A later version-1 fact with another commitment at a new block.
  disproveAll(net, scopes);
  await steps(b, 4, 1_000);
  expect(
    b.db
      .prepare(
        "SELECT state,terminal_reason FROM pdpp_replica_batch_disposition WHERE state<>'promoted'",
      )
      .all(),
  ).toEqual([{ state: "terminal", terminal_reason: "finalized_conflict" }]);
  expect(b.store.replicaIntegrityEpoch(b.instance)).toBeGreaterThan(epoch);
  for (const reader of ["owner", "grant"] as const)
    expect(
      b.receiver.readStore({ reader }).getRecord(b.instance, "messages", "a"),
    ).toBeUndefined();
  expect(
    num(
      b,
      `SELECT count(*) AS n FROM pdpp_transport_inbox WHERE state<>'quarantined' AND scope IN ${inScopes(scopes)}`,
    ),
  ).toBe(0);
});
