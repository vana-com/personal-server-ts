import Database from "better-sqlite3";
import { join } from "node:path";
import { expect, it } from "vitest";
import {
  ReplicaRosterUnavailableError,
  type ReplicaRosterPort,
} from "@opendatalabs/personal-server-ts-core/replication/roster";
import {
  createTestReplicaRoster,
  createTestReplicaSigner,
} from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import { owner, scratchDirectory } from "./pdpp-replica-contract.test-utils.js";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import {
  currentReplicaWriterIdentity,
  enableReplicaWriterIdentity,
} from "./pdpp-replica-writer-identity.js";

function setup() {
  const db = new Database(
    join(scratchDirectory("replica-roster-deadline"), "db.sqlite"),
  );
  createReplicaRecordStore(db);
  return { db, signer: createTestReplicaSigner() };
}

/** A roster whose answer never comes, whatever the signal does. */
function hangingRoster() {
  const signals: AbortSignal[] = [];
  const port: ReplicaRosterPort = {
    server: (_address, call) => {
      if (call?.signal) signals.push(call.signal);
      return new Promise(() => {});
    },
  };
  return { port, signals };
}

it("a roster lookup that hangs waits as unavailable instead of holding the step", async () => {
  const { db, signer } = setup();
  const roster = hangingRoster();
  const state = await enableReplicaWriterIdentity({
    db,
    owner,
    server: signer.address,
    roster: roster.port,
    deadlineMs: 20,
  });
  expect(state).toEqual({ tag: "waiting", reason: "roster_unavailable" });
  // The late answer path is cut off: the lookup's own signal is aborted.
  expect(roster.signals[0]!.aborted).toBe(true);
  expect(currentReplicaWriterIdentity(db)).toBeUndefined();
});

it("keeps an existing identity usable when the roster hangs, then recovers", async () => {
  const { db, signer } = setup();
  const good = createTestReplicaRoster();
  good.register(signer.address, owner);
  const first = await enableReplicaWriterIdentity({
    db,
    owner,
    server: signer.address,
    roster: good.port,
  });
  expect(first.tag).toBe("ready");
  const stalled = await enableReplicaWriterIdentity({
    db,
    owner,
    server: signer.address,
    roster: hangingRoster().port,
    deadlineMs: 20,
  });
  expect(stalled).toEqual(first);
  // A later lookup that answers is read normally.
  expect(
    (
      await enableReplicaWriterIdentity({
        db,
        owner,
        server: signer.address,
        roster: good.port,
        deadlineMs: 20,
      })
    ).tag,
  ).toBe("ready");
});

it("ignores an answer that arrives after the deadline", async () => {
  const { db, signer } = setup();
  const good = createTestReplicaRoster();
  const id = good.register(signer.address, owner);
  const late: ReplicaRosterPort = {
    server: () =>
      new Promise((resolve) =>
        setTimeout(() => resolve({ owner, id, revokedAt: null }), 60),
      ),
  };
  const state = await enableReplicaWriterIdentity({
    db,
    owner,
    server: signer.address,
    roster: late,
    deadlineMs: 10,
  });
  expect(state).toEqual({ tag: "waiting", reason: "roster_unavailable" });
  await new Promise((resolve) => setTimeout(resolve, 100));
  expect(currentReplicaWriterIdentity(db)).toBeUndefined();
});

it("passes the host's abort to the lookup and clears its deadline timer", async () => {
  const { db, signer } = setup();
  const controller = new AbortController();
  const roster: ReplicaRosterPort = {
    server: (_address, call) =>
      new Promise((_resolve, reject) =>
        call!.signal!.addEventListener("abort", () =>
          reject(new ReplicaRosterUnavailableError()),
        ),
      ),
  };
  const pending = new Set<unknown>();
  let next = 0;
  const state = enableReplicaWriterIdentity({
    db,
    owner,
    server: signer.address,
    roster,
    signal: controller.signal,
    deadlineMs: 1_000,
    timers: {
      now: () => 0,
      setTimeout: () => {
        const id = ++next;
        pending.add(id);
        return id;
      },
      clearTimeout: (id) => pending.delete(id),
    },
  });
  expect(pending.size).toBe(1);
  controller.abort();
  expect(await state).toEqual({ tag: "waiting", reason: "roster_unavailable" });
  expect(pending.size).toBe(0);
});
