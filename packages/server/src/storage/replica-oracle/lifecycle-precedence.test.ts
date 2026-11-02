/**
 * Connection lifecycle precedence, judged in every order of a few events.
 *
 * The contract: a deletion whose source and method match the host mapping
 * deletes the connection, ahead of terminal quarantine, equivocation and a
 * binding conflict. A deletion that names another binding never deletes; it
 * is binding-conflict evidence. Otherwise terminal quarantine, then
 * equivocation, then a binding conflict withdraw the connection.
 *
 * Each sequence is checked against that contract, and the step engine
 * (`evaluate` one change at a time), the full-history engine (`evaluate`
 * of all evidence from nothing) and the oracle reference must agree.
 */
import { describe, expect, it } from "vitest";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import {
  binding,
  identity,
  registration,
  upsert,
} from "@opendatalabs/personal-server-ts-core/replication/fixtures";
import {
  createMemoryVisibilityCommitter,
  EMPTY_PROJECTION,
  evaluate,
  INITIAL_VISIBILITY_EPOCH,
  type EvidenceChange,
  type VisibilityWorld,
} from "@opendatalabs/personal-server-ts-core/replication/visibility-engine";
import { refConnectionStatus } from "./reference.test-utils.js";

const C = identity.connectionId;
const write = { ...upsert("w0", 2, "zero"), recordKey: "k0" };
const deletion = (methodId: string, counter: number): ReplicaOperation => ({
  ...identity,
  methodId,
  kind: "connection-delete",
  revision: {
    counter,
    writerId: "device-a",
    operationId: `delete-${methodId}`,
  },
});
type Event =
  | "matching delete"
  | "mismatched delete"
  | "quarantine"
  | "equivocation"
  | "ordinary write";
const CHANGES: Record<Event, EvidenceChange> = {
  "matching delete": {
    kind: "evidence",
    operations: [deletion(identity.methodId, 10)],
  },
  "mismatched delete": {
    kind: "evidence",
    operations: [deletion("other", 11)],
  },
  quarantine: { kind: "host", terminal: [C] },
  // w0's revision with other content.
  equivocation: {
    kind: "evidence",
    operations: [{ ...write, data: { id: "k0", text: "twin" } }],
  },
  "ordinary write": {
    kind: "evidence",
    operations: [
      { ...upsert("w1", 3, "one"), recordKey: "k1", data: { id: "k1" } },
    ],
  },
};
const EVENTS = Object.keys(CHANGES) as Event[];

/** Every ordering of every non-empty subset of the events. */
function* sequences(
  rest: readonly Event[],
  prefix: Event[] = [],
): Generator<Event[]> {
  if (prefix.length) yield prefix;
  for (const event of rest)
    yield* sequences(
      rest.filter((other) => other !== event),
      [...prefix, event],
    );
}

const world: VisibilityWorld = {
  owner: identity.owner,
  declarations: [
    { sourceId: identity.sourceId, binding, validateData: () => true },
  ],
  mappings: new Map([
    [C, { sourceId: identity.sourceId, methodId: identity.methodId }],
  ]),
  verifiedBlobs: new Set(),
  terminal: new Set(),
};

/** The status the contract text gives. */
function contract(events: readonly Event[]) {
  if (events.includes("matching delete")) return "deleted";
  if (events.includes("quarantine")) return "withdrawn:terminal_quarantine";
  if (events.includes("equivocation"))
    return "withdrawn:operation_id_equivocation";
  if (events.includes("mismatched delete"))
    return "withdrawn:local_mapping_conflict";
  return "active";
}

async function judge(events: readonly Event[]) {
  const committer = createMemoryVisibilityCommitter();
  let facts = { world, evidence: [] as ReplicaOperation[] };
  for (const change of [
    { kind: "evidence", operations: [registration, write] } as const,
    ...events.map((event) => CHANGES[event]),
  ]) {
    const { epoch, projection } = committer.read();
    await committer.commit(
      epoch,
      evaluate({ epoch, projection, ...facts }, change),
      {},
    );
    if (change.kind === "evidence")
      facts = {
        ...facts,
        evidence: [...facts.evidence, ...change.operations],
      };
    else
      facts = {
        ...facts,
        world: {
          ...facts.world,
          terminal: new Set([
            ...facts.world.terminal,
            ...(change.terminal ?? []),
          ]),
        },
      };
  }
  const full = evaluate(
    {
      epoch: INITIAL_VISIBILITY_EPOCH,
      projection: EMPTY_PROJECTION,
      world: facts.world,
      evidence: [],
    },
    { kind: "evidence", operations: facts.evidence },
  );
  const label = (connection: { status: string; reason?: string }) =>
    connection.reason
      ? `${connection.status}:${connection.reason}`
      : connection.status;
  return {
    step: label(committer.read().projection.connections[C]),
    full: label(full.connections[C]),
    oracle: refConnectionStatus(
      { ...facts.world, bytes: new Set() },
      facts.evidence,
      C,
    ).status,
  };
}

describe("connection lifecycle precedence", () => {
  const all = [...sequences(EVENTS)];
  it("covers both orders of a matching and a mismatched delete", () => {
    const orders = all.map((events) => events.join(","));
    expect(orders).toContain("mismatched delete,matching delete");
    expect(orders).toContain("matching delete,mismatched delete");
    expect(all).toHaveLength(325);
  });
  it("step engine, full-history engine and oracle follow the contract in every order", async () => {
    const wrong = [];
    for (const events of all) {
      const expected = contract(events);
      const got = await judge(events);
      if (
        got.step !== expected ||
        got.full !== expected ||
        got.oracle !== expected.split(":")[0]
      )
        wrong.push({ events: events.join(","), expected, ...got });
    }
    expect(wrong).toEqual([]);
  });
});
