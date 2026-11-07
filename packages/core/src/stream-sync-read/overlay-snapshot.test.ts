/**
 * The read service takes one pinned overlay snapshot per read, before it
 * leases any imported view, shares it between the input streams of a
 * projection, and releases it on every way out.
 */

import { describe, expect, it, vi } from "vitest";
import { ViewStore } from "./view-store.js";
import { testOwnerKey } from "./testing.js";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";

async function importedItems(seed: number) {
  const f = new Fixture(await testOwnerKey(masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    records: [{ id: "a", v: 1 }],
    complete: true,
  });
  const service = await f.service();
  await f.sync(service);
  return { f, ns, service };
}

describe("overlay snapshot lifecycle", () => {
  it("takes the snapshot before it leases an imported view", async () => {
    const { f, ns, service } = await importedItems(41);
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        streams: [{ name: "items", rows: [{ o: 9e12, r: "r1", v: { id: "n" } }] }],
      },
    ];
    const order: string[] = [];
    f.overlay.beforeSnapshot = () => void order.push("snapshot");
    const lease = vi.spyOn(ViewStore.prototype, "lease");
    lease.mockImplementationOnce(function (this: ViewStore, ...args) {
      order.push(`lease(open snapshots: ${f.overlay.open})`);
      return ViewStore.prototype.lease.apply(this, args);
    });
    try {
      const decision = await service.resolve(ask("pdpp.acme.items"));
      expect(order).toEqual(["snapshot", "lease(open snapshots: 1)"]);
      await body(decision);
    } finally {
      lease.mockRestore();
    }
  });

  it("serves a snapshot's rows and releases the snapshot when the body completes", async () => {
    const { f, ns, service } = await importedItems(42);
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        streams: [{ name: "items", rows: [{ o: 9e12, r: "r1", v: { id: "n" } }] }],
      },
    ];
    const decision = await service.resolve(ask("pdpp.acme.items"));
    expect(f.overlay.open).toBe(1);
    const ids = (await body(decision)).data.records.map((r: any) => r.id);
    expect(ids.sort()).toEqual(["a", "n"]);
    expect(f.overlay.snapshots).toBe(1);
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.released).toBe(1);
  });

  it("releases the snapshot when the body is cancelled before the first pull", async () => {
    const { f, service } = await importedItems(43);
    const decision = await service.resolve(ask("pdpp.acme.items"));
    expect(f.overlay.open).toBe(1);
    if (decision.kind !== "view") throw new Error("expected a view");
    await decision.body.cancel();
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.released).toBe(1);
  });

  it("releases the snapshot when a stale cursor refuses the read", async () => {
    const { f, service } = await importedItems(44);
    const first = await service.resolve(ask("pdpp.acme.items"));
    if (first.kind !== "view") throw new Error("expected a view");
    await body(first);
    const fresh = f.overlay.released;
    const decision = await service.resolve(
      ask("pdpp.acme.items", {
        cursor: btoa(
          JSON.stringify({ c: "other", ns: "", v: { items: 1 } }),
        ),
      }),
    );
    expect(decision.kind).toBe("cursor_stale");
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.released).toBeGreaterThan(fresh);
  });

  async function metaPosts(seed: number) {
    const f = new Fixture(await testOwnerKey(masterKey(seed)));
    f.overlay.connector = "meta";
    const ns = await f.key.ns("meta", "account-1");
    await f.activate("meta", ns);
    for (const [stream, key] of [
      ["posts", "id"],
      ["post_likes", "post_id"],
    ] as const) {
      await f.publish({
        connector: "meta",
        ns,
        stream,
        generation: 1,
        records: [{ [key]: "p1" }],
        primaryKey: [key],
        complete: true,
      });
    }
    return { f, ns };
  }

  it("takes one snapshot for both input streams of a projection and releases it when the projection fails mid-body", async () => {
    const { f } = await metaPosts(48);
    const service = await f.service();
    await f.sync(service);
    const decision = await service.resolve(ask("instagram.posts"));
    expect(decision.kind).toBe("view");
    expect(f.overlay.snapshots).toBe(1); // posts and post_likes share it
    expect(f.overlay.open).toBe(1);
    // The records are too thin for the legacy projection: the body errors.
    await expect(body(decision)).rejects.toThrow();
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.released).toBe(1);
  });

  it("fails the read and releases the snapshot when an overlay log is missing", async () => {
    const { f, ns, service } = await importedItems(46);
    f.overlay.runs = [
      {
        runId: "r1",
        ns,
        generation: 1,
        streams: [{ name: "items", rows: [{ o: 9e12, r: "r1", v: { id: "n" } }] }],
      },
    ];
    // The log of a described stream vanishes before it is read.
    f.overlay.beforeLines = () => {
      f.overlay.runs = [];
    };
    await expect(service.resolve(ask("pdpp.acme.items"))).rejects.toThrow(
      "overlay log is missing",
    );
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.released).toBe(1);
  });

  it("releases the snapshot when resolve throws", async () => {
    const { f, service } = await importedItems(47);
    const lease = vi.spyOn(ViewStore.prototype, "lease").mockImplementation(() => {
      throw new Error("lease failed");
    });
    try {
      await expect(service.resolve(ask("pdpp.acme.items"))).rejects.toThrow(
        "lease failed",
      );
    } finally {
      lease.mockRestore();
    }
    expect(f.overlay.open).toBe(0);
    expect(f.overlay.snapshots).toBe(1);
  });
});
