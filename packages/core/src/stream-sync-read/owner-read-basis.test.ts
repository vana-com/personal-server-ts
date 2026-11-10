import { fixedOwnedAccountStorageMode } from "../test-utils/account-mode.js";
/**
 * One owner response is computed from one writer-and-import state. It names
 * the streams it read, and only a change to those streams can make it start
 * over. A publication the writer started and has not reconciled holds back
 * every run it would reorder or supersede.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { handlePersonalServerDataRequest } from "../api/index.js";
import type { PersonalServerDataApiDeps } from "../api/index.js";
import type { SignedRegistryPost } from "../stream-sync/index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import type { ReadDecision } from "./service.js";
import { Rig, type RunSpec } from "./writer-rig.js";

const run = (spec: Partial<RunSpec> & { runId: string }): RunSpec => ({
  key: "id",
  version: "1.0.0",
  rows: [],
  full: false,
  ...spec,
});

const SCOPE = "pdpp.acme.items";

async function ownerRead(rig: Rig) {
  const decision = await rig.service.resolve({
    scope: SCOPE,
    connection: null,
    cursor: null,
    legacyFile: false,
    isOwnerView: true,
  });
  if (decision.kind !== "view" && decision.kind !== "local_pending") {
    return { decision, ids: [] as string[], withheld: [] as string[] };
  }
  const envelope = JSON.parse(await new Response(decision.body).text()) as {
    data: { records: { id: string }[] };
  };
  return {
    decision,
    ids: envelope.data.records.map((r) => r.id).sort(),
    withheld: (decision.withheld ?? []).map((w) => `${w.runId}:${w.reason}`),
  };
}

async function baseRig(): Promise<Rig> {
  const rig = new Rig();
  await rig.open();
  await rig.collect(
    run({ runId: "base", full: true, rows: [{ id: "a" }, { id: "b" }] }),
  );
  await rig.publish();
  await rig.sync();
  return rig;
}

/** Holds the next registry POST of `rig` where `at` says; resolves `arrived` when it gets there. */
function holdPost(rig: Rig, at: "beforePost" | "afterPost") {
  let release!: () => void;
  let reached!: () => void;
  const held = new Promise<void>((resolve) => (release = resolve));
  const arrived = new Promise<void>((resolve) => (reached = resolve));
  rig.gateway[at] = async (_request: SignedRegistryPost) => {
    rig.gateway[at] = undefined;
    reached();
    await held;
  };
  return { release, arrived };
}

describe("a publication in flight holds back the runs it would reorder", () => {
  it("barrier a: C's request is persisted and its POST is paused, then B finishes intake", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    const post = holdPost(rig, "beforePost");
    const publishing = rig.publish();
    await post.arrived;
    await rig.collect(run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }));

    const owner = await ownerRead(rig);
    expect(owner.ids).toEqual(["a", "b"]);
    expect(owner.withheld).toContain("rB:publication_in_flight");

    post.release();
    await publishing;
    await rig.sync();
    const settled = await ownerRead(rig);
    expect(settled.ids).toEqual(["a", "b", "c"]);
    expect(settled.withheld).toEqual(["rB:out_of_order"]);
  });

  it("barrier b: C committed and was imported before the writer heard of it, then a new read", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    const post = holdPost(rig, "afterPost");
    const publishing = rig.publish();
    await post.arrived;
    await rig.sync();
    await rig.collect(run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }));

    const owner = await ownerRead(rig);
    expect(owner.ids).toEqual(["a", "b", "c"]);
    expect(owner.withheld).toContain("rB:publication_in_flight");

    post.release();
    await publishing;
    await rig.sync();
    const settled = await ownerRead(rig);
    expect(settled.ids).toEqual(["a", "b", "c"]);
    expect(settled.withheld).toEqual(["rB:out_of_order"]);
  });
});

describe("a selected publication holds back the runs it would reorder", () => {
  it("barrier c: C is selected and its signer is held before the request exists, then B finishes intake", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    let release!: () => void;
    let reached!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const arrived = new Promise<void>((resolve) => (reached = resolve));
    rig.beforeSign = async () => {
      rig.beforeSign = undefined;
      reached();
      await held;
    };
    const publishing = rig.publish();
    await arrived;
    await rig.collect(run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }));

    const owner = await ownerRead(rig);
    expect(owner.ids).toEqual(["a", "b"]);
    expect(owner.withheld).toContain("rB:publication_in_flight");
    expect(owner.withheld).toEqual([
      "rB:publication_in_flight",
      "rC:earlier_run_pending",
    ]);

    release();
    await publishing;
    await rig.sync();
    const settled = await ownerRead(rig);
    expect(settled.ids).toEqual(["a", "b", "c"]);
    expect(settled.withheld).toEqual(["rB:out_of_order"]);
  });

  it("barrier d: C is a no-op of the base, held at its registry read, then B finishes intake", async () => {
    const rig = await baseRig();
    await rig.collect(
      run({
        runId: "rC",
        at: 20_000,
        full: true,
        rows: [{ id: "a" }, { id: "b" }],
      }),
    );
    let release!: () => void;
    let reached!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const arrived = new Promise<void>((resolve) => (reached = resolve));
    rig.gateway.beforeRead = async (scope) => {
      if (scope !== "pdpp.acme~.items") return;
      rig.gateway.beforeRead = undefined;
      reached();
      await held;
    };
    const publishing = rig.publish();
    await arrived;
    await rig.collect(run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }));

    const owner = await ownerRead(rig);
    expect(owner.withheld).toContain("rB:publication_in_flight");

    release();
    await publishing;
    await rig.sync();
    const settled = await ownerRead(rig);
    expect(settled.ids).toEqual(["a", "b"]);
    expect(settled.withheld).toEqual(["rB:out_of_order"]);
  });

  /** Holds one file operation of the publisher until released. */
  function holdFiles(
    rig: Rig,
    op: "read" | "list",
    target: string,
  ): { release: () => void; arrived: Promise<void> } {
    let release!: () => void;
    let reached!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    const arrived = new Promise<void>((resolve) => (reached = resolve));
    const files = rig.files as unknown as Record<
      string,
      (arg: string) => Promise<unknown>
    >;
    const original = files[op]!.bind(files);
    files[op] = async (arg: string) => {
      if (arg !== target) return original(arg);
      files[op] = original;
      const result = await original(arg);
      reached();
      await held;
      return result;
    };
    return { release, arrived };
  }

  async function expectNoUnreservedSelection(
    rig: Rig,
    publishing: Promise<unknown>,
    hold: { release: () => void },
  ) {
    // B's intake write and the owner read may wait for the selection to end,
    // so neither is awaited before the held read is released.
    const finishing = rig.collect(
      run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }),
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    const reading = finishing.then(() => ownerRead(rig));
    await new Promise((resolve) => setTimeout(resolve, 20));
    hold.release();
    const owner = await reading;
    await publishing;
    // Never a prediction that holds C's row and B's row with no run withheld.
    expect(owner.ids).not.toEqual(["a", "b", "b2", "c"]);
    expect(owner.withheld.length).toBeGreaterThan(0);
  }

  it("barrier e: an entry read of the enumeration is held, B finishes intake, an owner read completes", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    await rig.collect(
      run({ runId: "rD", at: 30_000, stream: "other", rows: [{ id: "d" }] }),
    );
    const hold = holdFiles(rig, "read", "runs/rD/entry.json");
    const publishing = rig.publish();
    await hold.arrived;
    await expectNoUnreservedSelection(rig, publishing, hold);
  });

  it("barrier f: the run list is held after it was captured without B", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    const hold = holdFiles(rig, "list", "runs");
    const publishing = rig.publish();
    await hold.arrived;
    await expectNoUnreservedSelection(rig, publishing, hold);
  });

  it("the reservation is gone once the pass fails", async () => {
    const rig = await baseRig();
    await rig.collect(run({ runId: "rC", at: 20_000, rows: [{ id: "c" }] }));
    rig.beforeSign = async () => {
      rig.beforeSign = undefined;
      throw new Error("signer down");
    };
    await rig.publish().catch(() => undefined);
    await rig.collect(run({ runId: "rB", at: 10_000, rows: [{ id: "b2" }] }));
    const owner = await ownerRead(rig);
    expect(
      owner.withheld.filter((w) => w.endsWith("publication_in_flight")),
    ).toEqual([]);
  });
});

describe("a read is invalidated only by the streams it read", () => {
  let rig: Rig;
  afterEach(() => {
    rig.onSnapshot = undefined;
  });

  it("an unrelated stream imports during every attempt: the read succeeds", async () => {
    rig = await baseRig();
    let n = 0;
    rig.onSnapshot = async () => {
      n += 1;
      await rig.collect(
        run({
          runId: `u${n}`,
          stream: "other",
          full: true,
          rows: [{ id: `o${n}` }],
        }),
      );
      await rig.publish();
      await rig.sync();
    };
    const owner = await ownerRead(rig);
    expect(owner.ids).toEqual(["a", "b"]);
    expect(n).toBeGreaterThan(0);
  });

  function churn(target: Rig): () => number {
    let n = 0;
    target.onSnapshot = async () => {
      n += 1;
      await target.collect(run({ runId: `c${n}`, rows: [{ id: `c${n}` }] }));
      await target.publish();
      await target.sync();
    };
    return () => n;
  }

  it("relevant churn past the limit: an explicit retryable busy result", async () => {
    rig = await baseRig();
    churn(rig);
    const owner = await ownerRead(rig);
    expect(owner.decision.kind).toBe("busy");
    expect(
      (owner.decision as Extract<ReadDecision, { kind: "busy" }>)
        .retryAfterSeconds,
    ).toBeGreaterThan(0);
  });

  it("relevant churn past the limit: the API answers 503 with Retry-After, not 500", async () => {
    rig = await baseRig();
    churn(rig);
    const deps: PersonalServerDataApiDeps = {
      accountStorageMode: fixedOwnedAccountStorageMode("switched"),
      storage: createMemoryDataStorage(),
      streamSyncRead: rig.service,
      auth: {
        authorizeOwner: vi.fn(async () => undefined),
        authorizeBuilderList: vi.fn(async () => undefined),
        authorizeBuilderRead: vi.fn(async () => ({
          builder: "0x000000000000000000000000000000000000bEEF",
          grantId: "owner",
        })),
      } as never,
      accessLogWriter: { write: vi.fn(async () => undefined) },
      now: () => new Date("2026-11-01T00:00:00.000Z"),
      createLogId: () => "log-1",
    };
    const response = await handlePersonalServerDataRequest(
      new Request(`https://ps.example.com/${SCOPE}`),
      deps,
    );
    expect(response.status).toBe(503);
    expect(Number(response.headers.get("retry-after"))).toBeGreaterThan(0);
    const body = (await response.json()) as { error: { errorCode: string } };
    expect(body.error.errorCode).toBe("STREAM_SYNC_READ_BUSY");
  });
});
