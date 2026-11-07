/**
 * A device reads the rows it collected itself, whatever the publish state:
 * over an older imported view, or with no imported head at all (overlay-only).
 * Deletion, foreign keys and generations stay authoritative.
 */

import { describe, expect, it } from "vitest";
import type { Line } from "@opendatalabs/personal-server-ts-stream-sync";
import type { FakeRun } from "./service-fixture.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const T = Date.parse("2026-11-01T00:00:00Z");
const row = (id: string, v: number, o = T, r = "r1"): Line => ({
  o,
  r,
  v: { id, v },
});
const run = (
  ns: string | null,
  rows: Line[],
  extra: Partial<FakeRun> & { complete?: boolean; runId?: string } = {},
): FakeRun => ({
  runId: extra.runId ?? "r1",
  ns,
  generation: extra.generation ?? 1,
  ...(extra.state ? { state: extra.state } : {}),
  ...(extra.observedAt !== undefined ? { observedAt: extra.observedAt } : {}),
  streams: [{ name: "items", rows, complete: extra.complete ?? true }],
});

async function setup(seed: number, activate = true) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  if (activate) await f.activate("acme", ns);
  return { f, ns };
}

async function rows(f: Fixture, extra = {}) {
  const service = await f.service();
  await f.sync(service);
  const decision = await service.resolve(ask("pdpp.acme.items", extra));
  if (decision.kind !== "view") return decision.kind;
  const envelope = await body(decision);
  return Object.fromEntries(
    envelope.data.records.map((r: any) => [r.id, r.v]),
  );
}

describe("overlay over an older imported view", () => {
  it("shows a new key and a newer value of an existing key", async () => {
    const { f, ns } = await setup(51);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a", v: 1 }, { id: "r", v: 1 }],
      observedAt: T - 1000,
    });
    f.overlay.runs = [run(ns, [row("r", 2), row("new", 1)], { complete: false })];
    expect(await rows(f)).toEqual({ a: 1, r: 2, new: 1 });
  });

  it("does not let an older local line beat a newer imported line", async () => {
    const { f, ns } = await setup(52);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "r", v: 9 }],
      observedAt: T + 5000,
    });
    f.overlay.runs = [run(ns, [row("r", 2, T)], { complete: false })];
    expect(await rows(f)).toEqual({ r: 9 });
  });

  it("picks winners by stamp whatever order runs and lines come in", async () => {
    const { f, ns } = await setup(53);
    f.overlay.runs = [
      run(ns, [row("k", 3, T + 2, "b")], { runId: "b" }),
      run(ns, [row("k", 1, T + 1, "a"), row("e", 1, T, "a"), row("e", 2, T, "a")], {
        runId: "a",
      }),
      run(ns, [row("e", 3, T, "0")], { runId: "0" }),
    ];
    // k: newest stamp wins. e: equal stamps in run "a" (later line wins), and
    // run "a" > run "0" by r.
    expect(await rows(f)).toEqual({ k: 3, e: 2 });
  });
});

describe("overlay-only views", () => {
  it("serves a complete local run when the stream has no imported head", async () => {
    const { f, ns } = await setup(54);
    f.overlay.runs = [run(ns, [row("b", 1), row("a", 1)])];
    expect(await rows(f)).toEqual({ a: 1, b: 1 });
  });

  it("serves an identity-less (empty) namespace and does not leak another", async () => {
    const { f } = await setup(55, false);
    await f.activate("acme", "");
    const other = await f.key.ns("acme", "someone-else");
    await f.activate("acme", other);
    f.overlay.runs = [
      run("", [row("mine", 1)], { runId: "r1" }),
      run(other, [row("theirs", 1)], { runId: "r2" }),
    ];
    const service = await f.service();
    await f.sync(service);
    const ids = async (connection: string) => {
      const decision = await service.resolve(
        ask("pdpp.acme.items", { connection }),
      );
      return (await body(decision)).data.records.map((r: any) => r.id);
    };
    expect(await ids("")).toEqual(["mine"]);
    expect(await ids(other)).toEqual(["theirs"]);
  });

  it("does not attribute a run with no namespace", async () => {
    const { f } = await setup(56);
    f.overlay.runs = [run(null, [row("x", 1)])];
    expect(await rows(f)).toBe("pass");
  });

  it("is not a view without a verified active control state (activation unknown)", async () => {
    const { f, ns } = await setup(57, false);
    f.overlay.runs = [run(ns, [row("x", 1)])];
    expect(await rows(f)).toBe("pass");
    expect(await rows(f, { legacyFile: true })).toBe("pass");
  });

  it("is not a view when the run belongs to another generation", async () => {
    const { f, ns } = await setup(58);
    await f.activate("acme", ns); // control version 2: generation 2
    f.overlay.runs = [run(ns, [row("x", 1)], { generation: 1 })];
    expect(await rows(f)).toBe("pass");
  });

  it("is not a view for an unbound run", async () => {
    const { f, ns } = await setup(59);
    f.overlay.runs = [{ ...run(ns, [row("x", 1)]), generation: null }];
    expect(await rows(f)).toBe("pass");
  });

  it("keeps a deleted connection deleted", async () => {
    const { f, ns } = await setup(60);
    await f.deleteConnection("acme", ns);
    f.overlay.runs = [run(ns, [row("x", 1)])];
    expect(await rows(f)).toBe("unavailable");
  });

  it("does not serve a connection written with another key", async () => {
    const { f } = await setup(61, false);
    const foreign = await testOwnerKey(masterKey(99));
    const ns = await foreign.ns("acme", "account-1");
    await f.activate("acme", ns, foreign);
    f.overlay.runs = [run(ns, [row("x", 1)])];
    expect(await rows(f)).toBe("key_mismatch");
  });

  it("does not resurrect rows of a tombstoned stream", async () => {
    const { f, ns } = await setup(62);
    const first = await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a", v: 1 }],
    });
    const { tombstone } = await f.key.control();
    const prev = f.rows.get(first.scope)!;
    f.rows.set(first.scope, {
      ...prev,
      dataHash: tombstone.dataHash,
      metadataHash: tombstone.metadataHash,
      expectedVersion: "2",
      deletedAt: null,
    });
    f.overlay.runs = [run(ns, [row("x", 1)])];
    expect(await rows(f)).not.toEqual({ x: 1 });
  });

  it("does not displace an existing complete legacy body with incomplete local rows", async () => {
    const { f, ns } = await setup(63);
    f.overlay.runs = [run(ns, [row("x", 1)], { complete: false })];
    expect(await rows(f, { legacyFile: true })).toBe("legacy");
  });

  it("does not claim a multi-stream legacy name when an input stream is missing", async () => {
    const { f } = await setup(64, false);
    f.overlay.connector = "meta";
    const ns = await f.key.ns("meta", "account-1");
    await f.activate("meta", ns);
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        streams: [{ name: "posts", rows: [row("p", 1)], complete: true }],
      },
    ];
    const service = await f.service();
    await f.sync(service);
    expect((await service.resolve(ask("instagram.posts"))).kind).not.toBe("view");
  });

  it("serves the retained rows of a published stream until the imported view covers it", async () => {
    const { f, ns } = await setup(65);
    const receipt = { registryVersion: 2, dataHash: "ab".repeat(32), generation: 1 };
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        state: "published",
        streams: [
          { name: "items", rows: [row("r", 2), row("new", 1)], complete: true, receipt },
        ],
      },
    ];
    expect(await rows(f)).toEqual({ r: 2, new: 1 });
  });

  it("answers pass to a non-owner and releases the snapshot", async () => {
    const { f, ns } = await setup(66);
    f.overlay.runs = [run(ns, [row("x", 1)])];
    expect(await rows(f, { isOwnerView: false })).toBe("pass");
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.released).toBe(1);
  });

  it("still serves a non-owner a registered base merged with local rows", async () => {
    const { f, ns } = await setup(67);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a", v: 1 }],
      observedAt: T - 1000,
    });
    f.overlay.runs = [run(ns, [row("new", 1)], { complete: false })];
    expect(await rows(f, { isOwnerView: false })).toEqual({ a: 1, new: 1 });
  });
});
