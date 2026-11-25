// The change feed's opaque cursor, end to end against a fake gateway.
//
// The gateway mints cursors that carry its database epoch
// (`change-feed-gateway.test-helper.ts` implements the contract). The real
// registry client and the real change push run over `fetch` against it, so
// what is under test is what a client does with a cursor: keep it as received,
// send it back, compare it for equality, and treat the gateway's answer as the
// only judge of a replaced database. The helper is the only code in this file
// that opens a cursor.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Logger } from "../../logger/index.js";
import type { DownloadWorkerDeps } from "../workers/download.js";
import type { UploadWorkerDeps } from "../workers/upload.js";
import {
  EPOCH_A,
  EPOCH_B,
  createFakeChangeGateway,
  mintCursor,
  readCursor,
  type WireRow,
} from "../../stream-sync/change-feed-gateway.test-helper.js";
import {
  changeCursorToWire,
  type ChangeCursor,
  type RegistryChangeDelta,
} from "../../stream-sync/ports.js";
import { createGatewayStreamSyncRegistry } from "../../stream-sync/registry.js";
import {
  CHANGE_PUSH_WAIT_MS,
  createRegistryChangePush,
} from "./change-push.js";
import { deltaToCycle } from "./local-sync.test-helper.js";
import { createSyncManager } from "./sync-manager.js";

const logger = {
  info: vi.fn(),
  error: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  trace: vi.fn(),
  fatal: vi.fn(),
} as unknown as Logger;

const wire = changeCursorToWire;
const flush = () => vi.advanceTimersByTimeAsync(0);

const ROW: WireRow = {
  scope: "pdpp.fixture~.~log",
  expectedVersion: "4",
  dataHash: "0x" + "aa".repeat(32),
  metadataHash: "0x" + "bb".repeat(32),
  deletedAt: null,
};

type Event =
  | { kind: "position"; position: string }
  | { kind: "change"; delta: RegistryChangeDelta | undefined }
  | { kind: "health"; healthy: boolean };

/**
 * The real registry client and push over the fake gateway, handlers recorded.
 * `since` is what the manager would offer: the position of the last answer,
 * unless the test says otherwise.
 */
function subscribed(
  gateway: ReturnType<typeof createFakeChangeGateway>,
  since?: () => ChangeCursor | undefined,
) {
  const registry = createGatewayStreamSyncRegistry({
    gatewayUrl: "https://gateway.test/",
    ownerAddress: "0x" + "11".repeat(20),
    fetch: gateway.fetch,
  });
  const push = createRegistryChangePush(registry)!;
  const events: Event[] = [];
  let latest: ChangeCursor | undefined;
  const stop = push.subscribe({
    onChange: (delta) => events.push({ kind: "change", delta }),
    onHealth: (healthy) => events.push({ kind: "health", healthy }),
    onPosition: (position) => {
      latest = position;
      events.push({ kind: "position", position: wire(position) });
    },
    since: since ?? (() => latest),
  });
  const changes = () =>
    events.flatMap((e) => (e.kind === "change" ? [e.delta] : []));
  const positions = () =>
    events.flatMap((e) => (e.kind === "position" ? [e.position] : []));
  return { events, changes, positions, stop };
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(Math, "random").mockReturnValue(0.5);
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("the first request", () => {
  it("sends no cursor, takes the gateway's answer at once as a poke, and reports its cursor untouched", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    expect(gateway.requests[0]).toMatchObject({
      after: undefined,
      since: undefined,
      wait: undefined,
    });
    expect(t.events).toEqual([
      { kind: "health", healthy: true },
      { kind: "position", position: mintCursor(EPOCH_A, 5) },
      { kind: "change", delta: undefined },
    ]);
    t.stop();
  });
});

describe("a held request", () => {
  it("is held while nothing changes, answers on a write, and the next request carries that answer's cursor", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    const first = mintCursor(EPOCH_A, 5);
    expect(gateway.requests[1]).toMatchObject({ after: first, wait: "25" });
    expect(gateway.held()).toBe(1);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(t.changes()).toEqual([undefined]); // only the first answer's poke
    const second = gateway.commit();
    await flush();
    expect(t.positions()).toEqual([first, second]);
    // Poked once for the first answer, once for the write (a delta: the
    // push holds the cursor it was given, and the manager's since is that one).
    expect(t.changes()).toMatchObject([
      undefined,
      { since: first, cursor: second, reset: false },
    ]);
    expect(gateway.requests[2]!.after).toBe(second);
    t.stop();
  });

  it("an answer that ends its wait with nothing new is no poke, and the next request holds the same cursor", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS);
    const first = mintCursor(EPOCH_A, 5);
    expect(t.positions()).toEqual([first, first]);
    expect(t.changes()).toEqual([undefined]);
    expect(gateway.requests[2]!.after).toBe(first);
    t.stop();
  });
});

describe("a changed answer with a delta", () => {
  it("hands the rows on, between the since it sent and the cursor it received", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const held = mintCursor(EPOCH_A, 5);
    const t = subscribed(gateway);
    await flush();
    const next = gateway.commit(ROW);
    await flush();
    expect(gateway.requests[1]!.since).toBe(held);
    expect(t.changes()[1]).toMatchObject({
      since: held,
      cursor: next,
      reset: false,
      rows: [
        {
          scope: ROW.scope,
          read: { found: true, version: 4, deleted: false },
        },
      ],
      gone: [],
      serversChanged: false,
    });
    t.stop();
  });
});

describe("a database replaced mid-session", () => {
  it("the gateway's reset is handed on once, the next request holds the new cursor, and nothing doubles it", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const old = mintCursor(EPOCH_A, 5);
    const t = subscribed(gateway);
    await flush();
    // A counter that restarts, under an epoch that sorts before the old one:
    // nothing about the new cursor is "above" the old.
    const fresh = gateway.replaceDatabase({ epoch: EPOCH_B, seq: 2 });
    await flush();
    expect(t.positions()).toEqual([old, fresh]);
    const resets = t.changes().filter((delta) => delta?.reset);
    expect(resets).toEqual([{ since: old, cursor: fresh, reset: true }]);
    expect(gateway.requests[2]!.after).toBe(fresh);
    expect(gateway.held()).toBe(1);
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS * 2);
    expect(t.changes().filter((delta) => delta?.reset)).toHaveLength(1);
    t.stop();
  });

  it("the same counter under a new epoch is still a reset: the cursor differs, which the number alone would hide", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const old = mintCursor(EPOCH_A, 5);
    const t = subscribed(gateway);
    await flush();
    const fresh = gateway.replaceDatabase({ epoch: EPOCH_B, seq: 5 });
    await flush();
    expect(fresh).not.toBe(old);
    expect(t.changes().at(-1)).toEqual({
      since: old,
      cursor: fresh,
      reset: true,
    });
    expect(gateway.requests[2]!.after).toBe(fresh);
    t.stop();
  });

  it("a reset for a stale since echoes it byte for byte, and the client resets once", async () => {
    // The gateway answers `delta.since` with the string it was sent, never a
    // cursor it re-minted under its new epoch (which would never have
    // existed). The client takes the reset as the answer to its own request.
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    const stale = mintCursor(EPOCH_A, 5);
    expect(gateway.requests[1]!.since).toBe(stale);
    const fresh = gateway.replaceDatabase({ epoch: EPOCH_B, seq: 9 });
    await flush();
    const resets = t.changes().filter((delta) => delta?.reset);
    expect(resets).toHaveLength(1);
    expect(wire(resets[0]!.since)).toBe(stale);
    expect(wire(resets[0]!.since)).toBe(gateway.requests[1]!.since);
    expect(wire(resets[0]!.cursor)).toBe(fresh);
    t.stop();
  });

  it("a reset that names another since than the one sent fails the request: it is not this request's answer", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    // A gateway that re-minted the stale cursor under its new epoch.
    gateway.answerRequestWith(1, () =>
      Response.json({
        cursor: mintCursor(EPOCH_B, 9),
        changed: true,
        delta: { since: mintCursor(EPOCH_B, 5), reset: true },
      }),
    );
    const t = subscribed(gateway);
    await flush();
    expect(t.events.at(-1)).toEqual({ kind: "health", healthy: false });
    expect(t.changes()).toEqual([undefined]);
    t.stop();
  });

  it("with no since to name, the answer is a poke without a delta, once", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway, () => undefined);
    await flush();
    const fresh = gateway.replaceDatabase({ epoch: EPOCH_B, seq: 2 });
    await flush();
    expect(t.positions().at(-1)).toBe(fresh);
    expect(t.changes()).toEqual([undefined, undefined]);
    expect(gateway.requests[2]!.after).toBe(fresh);
    t.stop();
  });
});

describe("a malformed answer", () => {
  it.each([
    ["the older seq shape", () => Response.json({ seq: "7", changed: true })],
    ["no cursor", () => Response.json({ changed: true })],
    ["an empty cursor", () => Response.json({ cursor: "", changed: true })],
    [
      "a number for a cursor",
      () => Response.json({ cursor: 7, changed: true }),
    ],
    ["no changed flag", () => Response.json({ cursor: "c7" })],
  ])(
    "%s is a failure: the push goes unhealthy, holds its old cursor, backs off, and pokes once when answers return",
    async (_name, bad) => {
      const gateway = createFakeChangeGateway({ seq: 5 });
      // The second request is the held one; the script answers it.
      gateway.answerRequestWith(1, bad);
      const t = subscribed(gateway);
      await flush();
      const first = mintCursor(EPOCH_A, 5);
      expect(t.positions()).toEqual([first]); // nothing from the bad answer
      expect(t.events.at(-1)).toEqual({ kind: "health", healthy: false });
      const sent = gateway.requests.length;
      await vi.advanceTimersByTimeAsync(999);
      expect(gateway.requests).toHaveLength(sent);
      await vi.advanceTimersByTimeAsync(1);
      expect(gateway.requests).toHaveLength(sent + 1);
      expect(gateway.requests.at(-1)!.after).toBe(first);
      expect(t.changes()).toHaveLength(1); // no poke from a failed attempt
      // The next answer, even one that says nothing changed, is the repair poke.
      await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS);
      expect(t.changes()).toHaveLength(2);
      expect(t.events.at(-1)).toEqual({ kind: "change", delta: undefined });
      t.stop();
    },
  );
});

describe("a 400 on a cursor of the older numeric kind", () => {
  it("is dropped, not resent: the next request asks from no position, and the gateway's fresh cursor is held from then on, and it is not read as a missing route", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    // A bare decimal: what a gateway of the older kind answered. The gateway
    // that implements the contract refuses it.
    gateway.answerRequestWith(0, () =>
      Response.json({ cursor: "12", changed: true }),
    );
    const t = subscribed(gateway);
    await flush();
    const fresh = mintCursor(EPOCH_A, 5);
    expect(t.positions()).toEqual(["12", fresh]);
    expect(gateway.requests[1]).toMatchObject({ after: "12" });
    expect(gateway.requests[2]).toMatchObject({ after: undefined });
    expect(gateway.requests[3]).toMatchObject({ after: fresh });
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS * 2);
    expect(gateway.requests.slice(3).every((r) => r.after !== "12")).toBe(true);
    expect(t.changes()).toEqual([undefined, undefined]);
    expect(
      t.events.flatMap((e) => (e.kind === "health" ? [e.healthy] : [])),
    ).toEqual([true, false, true]);
    t.stop();
  });
});

describe("an abort mid-hold", () => {
  it("ends the held request at once, asks for nothing more, and a write after it pokes nobody", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    expect(gateway.held()).toBe(1);
    const events = t.events.length;
    t.stop();
    expect(gateway.requests[1]!.signal!.aborted).toBe(true);
    expect(gateway.held()).toBe(0);
    gateway.commit();
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS * 3);
    expect(gateway.requests).toHaveLength(2);
    expect(t.events).toHaveLength(events);
    expect(vi.getTimerCount()).toBe(0);
  });
});

// A cycle can be running when the gateway's database is replaced. The cursor
// of the new database must reach the next request, and no position of the old
// one may be offered as the manager's `since` after it.
describe("a cycle in flight when an answer with a new epoch's cursor arrives", () => {
  function managed() {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const registry = createGatewayStreamSyncRegistry({
      gatewayUrl: "https://gateway.test/",
      ownerAddress: "0x" + "11".repeat(20),
      fetch: gateway.fetch,
    });
    const push = createRegistryChangePush(registry)!;
    const cycle = vi.fn<() => Promise<unknown>>(async () => {});
    const manager = createSyncManager(
      {
        logger,
        serverOwner: "0x1111111111111111111111111111111111111111",
        storage: { findUnsynced: () => [] },
      } as unknown as UploadWorkerDeps,
      { logger } as unknown as DownloadWorkerDeps,
      {
        accountStorageMode: { read: () => "switched" },
        pollInterval: 60_000,
        localSync: { cycle, applyDelta: deltaToCycle },
        changeProbe: { read: async () => "m1", intervalMs: 5_000, push },
      },
    );
    return { gateway, cycle, manager };
  }

  const epochOf = (wireCursor: string) => readCursor(wireCursor)?.epoch;

  /** What the requests sent after the replaced database's answer carried. */
  function sentAfter(
    gateway: ReturnType<typeof createFakeChangeGateway>,
    from: number,
  ) {
    return gateway.requests.slice(from).map((r) => ({
      after: r.after && epochOf(r.after),
      since: r.since && epochOf(r.since),
    }));
  }

  it("the next request holds the new cursor, and `since` is never a position of the old epoch", async () => {
    const { gateway, cycle, manager } = managed();
    manager.start();
    await flush(); // the first answer's poke runs a cycle, which finishes
    const settled = mintCursor(EPOCH_A, 5);
    expect(gateway.requests[1]).toMatchObject({ after: settled });
    expect(gateway.requests[1]!.since).toBe(settled);

    // A write starts a pass that does not finish until the test says so.
    let release!: () => void;
    cycle.mockImplementationOnce(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    const cyclesBefore = cycle.mock.calls.length;
    const written = gateway.commit();
    await flush();
    expect(cycle).toHaveBeenCalledTimes(cyclesBefore + 1);
    expect(gateway.requests[2]).toMatchObject({
      after: written,
      since: written,
    });

    // The database is replaced while that pass runs.
    const fresh = gateway.replaceDatabase({ epoch: EPOCH_B, seq: 2 });
    await flush();
    const next = gateway.requests[3]!;
    expect(next.after).toBe(fresh);
    expect(next.since).toBe(fresh);

    release();
    await flush();
    // The pass on the old epoch ended; one more lists from the new cursor.
    expect(cycle).toHaveBeenCalledTimes(cyclesBefore + 2);
    gateway.commit(ROW);
    await flush();
    expect(sentAfter(gateway, 3)).toEqual([
      { after: EPOCH_B, since: EPOCH_B },
      { after: EPOCH_B, since: EPOCH_B },
    ]);
    await manager.stop();
  });

  it("when that pass fails, the request after it asks from no position rather than the old one", async () => {
    const { gateway, cycle, manager } = managed();
    manager.start();
    await flush();
    let fail!: (error: Error) => void;
    cycle.mockImplementationOnce(
      () => new Promise<void>((_resolve, reject) => (fail = reject)),
    );
    gateway.commit();
    await flush();
    gateway.replaceDatabase({ epoch: EPOCH_B, seq: 2 });
    await flush();
    fail(new Error("listing failed"));
    await flush();
    gateway.commit();
    await flush();
    const sent = sentAfter(gateway, 3);
    expect(sent.length).toBeGreaterThan(0);
    for (const request of sent) {
      expect(request.after).toBe(EPOCH_B);
      expect([undefined, EPOCH_B]).toContain(request.since);
    }
    await manager.stop();
  });
});

describe("a cursor the gateway rejects", () => {
  it("is dropped: the next request carries no cursor, its fresh answer pokes a full pull once, and later requests carry the fresh cursor", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    const a = mintCursor(EPOCH_A, 5);
    expect(gateway.requests[1]).toMatchObject({ after: a });
    gateway.rejectCursorOnce(a);
    const b = gateway.commit();
    await flush(); // no timer advance: the retry is at once
    expect(gateway.requests[2]).toMatchObject({
      after: undefined,
      since: undefined,
    });
    expect(t.positions()).toEqual([a, b]);
    expect(t.changes()).toEqual([undefined, undefined]);
    expect(gateway.requests[3]).toMatchObject({ after: b, wait: "25" });
    expect(t.events.filter((e) => e.kind === "health")).toEqual([
      { kind: "health", healthy: true },
      { kind: "health", healthy: false },
      { kind: "health", healthy: true },
    ]);
    t.stop();
  });

  it("backs off, and does not spin, when the request without a cursor is rejected too", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    const a = mintCursor(EPOCH_A, 5);
    gateway.rejectCursorOnce(a);
    gateway.answerRequestWith(
      2,
      () =>
        new Response(
          JSON.stringify({
            error: "Invalid after: expected a change-feed cursor",
          }),
          { status: 400 },
        ),
    );
    gateway.commit();
    await flush();
    expect(gateway.requests).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(999);
    expect(gateway.requests).toHaveLength(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(gateway.requests[3]).toMatchObject({ after: undefined });
    // It answered at once, so the next request is held with its cursor.
    expect(gateway.requests).toHaveLength(5);
    expect(gateway.requests[4]).toMatchObject({ after: gateway.cursor() });
    await vi.advanceTimersByTimeAsync(CHANGE_PUSH_WAIT_MS * 2);
    expect(gateway.requests.length).toBeLessThan(8);
    t.stop();
  });
  it("backs off with growing delays when the gateway rejects every fresh cursor it hands out", async () => {
    vi.spyOn(Math, "random").mockReturnValue(0.5); // back-off steps exactly 1 s, 2 s, 4 s
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    await flush();
    gateway.rejectEveryCursor();
    gateway.commit();
    await flush();
    const cursorless = () =>
      gateway.requests.slice(2).filter((r) => r.after === undefined).length;
    // The rejected held cursor is retried at once without one; that answer's
    // fresh cursor is rejected too, and the back-off starts at 1 s.
    expect(cursorless()).toBe(1);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(cursorless()).toBe(2);
    // A cursorless answer does not end the failure run: the next step is 2 s.
    await vi.advanceTimersByTimeAsync(1_999);
    expect(cursorless()).toBe(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(cursorless()).toBe(3);
    await vi.advanceTimersByTimeAsync(3_999);
    expect(cursorless()).toBe(3);
    await vi.advanceTimersByTimeAsync(1);
    expect(cursorless()).toBe(4);
    t.stop();
  });

  it("restarts cursor-rejection back-off after a successful request with a cursor", async () => {
    const gateway = createFakeChangeGateway({ seq: 5 });
    const t = subscribed(gateway);
    try {
      await flush();
      const first = gateway.cursor();
      expect(gateway.requests.at(-1)!.after).toBe(first);
      gateway.rejectCursorOnce(first);
      const duringFailures = gateway.commit();
      gateway.rejectCursorOnce(duringFailures);
      await flush();
      expect(gateway.requests.slice(-2).map((r) => r.after)).toEqual([
        undefined,
        duringFailures,
      ]);

      // Keep the first failure run going for two back-off steps.
      gateway.rejectCursorOnce(duringFailures);
      const firstBackoff = gateway.requests.length;
      await vi.advanceTimersByTimeAsync(999);
      expect(gateway.requests).toHaveLength(firstBackoff);
      await vi.advanceTimersByTimeAsync(1);
      expect(gateway.requests.slice(firstBackoff).map((r) => r.after)).toEqual([
        undefined,
        duringFailures,
      ]);
      const secondBackoff = gateway.requests.length;
      await vi.advanceTimersByTimeAsync(1_999);
      expect(gateway.requests).toHaveLength(secondBackoff);
      await vi.advanceTimersByTimeAsync(1);
      expect(gateway.requests.slice(secondBackoff).map((r) => r.after)).toEqual(
        [undefined, duringFailures],
      );

      // The fresh cursor is now held. A write makes it answer successfully.
      expect(gateway.held()).toBe(1);
      const recovered = gateway.commit();
      await flush();
      expect(t.positions().at(-1)).toBe(recovered);
      expect(gateway.requests.at(-1)!.after).toBe(recovered);

      const secondRun = gateway.requests.length;
      gateway.rejectCursorOnce(recovered);
      const fresh = gateway.commit();
      gateway.rejectCursorOnce(fresh);
      await flush(); // No positive fake-clock advance: the cursorless retry is immediate.
      expect(gateway.requests.slice(secondRun).map((r) => r.after)).toEqual([
        undefined,
        fresh,
      ]);
      const resetBackoff = gateway.requests.length;
      await vi.advanceTimersByTimeAsync(999);
      expect(gateway.requests).toHaveLength(resetBackoff);
      await vi.advanceTimersByTimeAsync(1);
      expect(gateway.requests.slice(resetBackoff).map((r) => r.after)).toEqual([
        undefined,
        fresh,
      ]);
    } finally {
      t.stop();
    }
  });
});
