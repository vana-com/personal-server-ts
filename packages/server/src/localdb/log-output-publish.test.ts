// A compaction through the real publication cycle: its objects are sealed on
// disk, uploaded one at a time, `sent` before the registry request leaves, and
// settled from the registry's head afterwards, whatever the reply was.
import { afterEach, describe, expect, it } from "vitest";
import { shouldCompact } from "@opendatalabs/personal-server-ts-stream-sync";
import { AmbiguousRegistryReplyError } from "../../../core/dist/stream-sync/ports.js";
import {
  world,
  closeWorldDrivers,
  CONNECTION_ID,
  sName,
} from "./log-world.test-utils.js";
afterEach(closeWorldDrivers);

type Device = Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>;

async function grow(d: Device, count: number, from = 0) {
  for (let i = from; i < from + count; i++) {
    await d.run(`run-g${i}`, [{ stream: sName(0), id: "x", v: i }], {
      full: false,
      covered: [sName(0)],
      observedAt: 2000 + i,
    });
    await d.cycle();
  }
}

/** Whether this device's next publish would compact: the library's own rule. */
async function compactionDue(d: Device): Promise<boolean> {
  const [row] = await d.db.query<{ refs: string; snapshot: string | null }>(
    "SELECT refs, snapshot FROM log_state WHERE connection_id = ?",
    [CONNECTION_ID],
  );
  const refs = JSON.parse(row!.refs) as { bytes: number }[];
  const snapshot = row!.snapshot
    ? (JSON.parse(row!.snapshot) as { parts: { bytes: number }[] })
    : null;
  return shouldCompact({
    tailSegments: refs.length,
    tailBytes: refs.reduce((n, r) => n + r.bytes, 0),
    snapshotBytes: snapshot?.parts.reduce((n, p) => n + p.bytes, 0) ?? 0,
  });
}

async function growUntilDue(d: Device) {
  for (let i = 0; !(await compactionDue(d)); i++) {
    expect(i).toBeLessThan(60);
    await grow(d, 1, i);
  }
}

const workspaces = (d: Device) =>
  d.db.query<{ operation: string; phase: string }>(
    "SELECT operation,phase FROM workspaces ORDER BY operation",
  );

/** What the database says at the moment a registry request leaves. */
async function atRequest(d: Device) {
  const [row] = await d.db.query<{
    phase: string;
    sent: number;
    outputs: number;
    uploads: number;
    sentHead: string | null;
  }>(
    `SELECT w.phase AS phase,
      (SELECT COUNT(*) FROM workspace_sent s WHERE s.operation=w.operation) AS sent,
      (SELECT COUNT(*) FROM workspace_cells c WHERE c.operation=w.operation AND c.relation='outputs') AS outputs,
      (SELECT COUNT(*) FROM workspace_cells c WHERE c.operation=w.operation AND c.relation='uploads') AS uploads,
      (SELECT candidate_head FROM workspace_sent s WHERE s.operation=w.operation) AS sentHead
     FROM workspaces w WHERE w.phase NOT IN ('clean','aborted','finished') ORDER BY w.operation DESC LIMIT 1`,
  );
  return row ?? null;
}

describe("a compaction through the publication cycle", () => {
  it("is durably sent, with every output uploaded and receipted, before the registry request leaves; the watermark waits for the answer", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    await growUntilDue(a);
    const before = (await w.segments()).size;
    const marks = async () =>
      a.db.query<{ publish_watermark: number }>(
        "SELECT publish_watermark FROM stream_state ORDER BY stream",
      );
    const watermarkBefore = await marks();
    const seen: Awaited<ReturnType<typeof atRequest>>[] = [];
    const marksAtRequest: unknown[] = [];
    const registry = a.deps.registry;
    const post = registry.postBatch!.bind(registry);
    registry.postBatch = async (request) => {
      seen.push(await atRequest(a));
      marksAtRequest.push(await marks());
      return post(request);
    };
    await a.run("run-a", [{ stream: sName(0), id: "x", v: 99 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 9500,
    });
    await a.cycle();
    // The compaction's workspace was `sent` when the request left, with every
    // output uploaded; the local watermark had not moved.
    const compaction = seen.find((s) => s && s.outputs > 0);
    expect(compaction, "a compaction reached the registry").toBeTruthy();
    expect(compaction!.phase).toBe("sent");
    expect(compaction!.sent).toBe(1);
    expect(compaction!.uploads).toBe(compaction!.outputs);
    expect(compaction!.sentHead).toMatch(/^0x/);
    expect(marksAtRequest[0]).toEqual(
      // The collected run is unpublished: its change is not acknowledged yet.
      watermarkBefore,
    );
    // The log took it, and the workspace was settled and paged away.
    expect((await w.segments()).size).toBe(before + 1);
    const head = [...(await w.segments()).values()].at(-1)!;
    expect(head.snapshot).not.toBeNull();
    expect(
      (await workspaces(a)).filter((r) => r.phase !== "clean"),
      "every workspace is closed",
    ).toEqual([]);
    expect(await a.db.query("SELECT 1 FROM workspace_sent")).toEqual([]);
    expect(await a.db.query("SELECT 1 FROM body_values")).toEqual([]);
    expect(
      (
        await a.db.query<{ publish_watermark: number }>(
          "SELECT publish_watermark FROM stream_state",
        )
      )[0]!.publish_watermark,
    ).toBeGreaterThan(watermarkBefore[0]!.publish_watermark);
    const c = await w.device("c");
    await c.cycle();
    expect(await c.records()).toEqual(await a.records());
  }, 300_000);

  it("a request that landed but was never answered settles to finished from the registry's head, once, and does not publish again", async () => {
    const w = await world({ streams: 1 });
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    await growUntilDue(a);
    const registry = a.deps.registry;
    const post = registry.postBatch!.bind(registry);
    let lost = 0;
    registry.postBatch = async (request) => {
      const answer = await post(request);
      // The registry applied it. Both replies are lost: the first send and the
      // resend of the same request.
      if (lost++ < 2) throw new AmbiguousRegistryReplyError("reply lost");
      return answer;
    };
    const before = (await w.segments()).size;
    await a.run("run-a", [{ stream: sName(0), id: "x", v: 99 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 9500,
    });
    // The outcome is unknown to the caller: the cycle may report it, never hide it.
    const lostCycle = await a.sync.cycle();
    expect(lostCycle.connections[0]!.error).toBe("reply lost");
    // The candidate may have landed: its workspace stays sent, rows and all.
    expect((await workspaces(a)).map((r) => r.phase)).toContain("sent");
    registry.postBatch = post;
    await a.cycle();
    expect((await w.segments()).size).toBe(before + 1);
    expect(await a.db.query("SELECT 1 FROM workspace_sent")).toEqual([]);
    expect((await workspaces(a)).filter((r) => r.phase !== "clean")).toEqual(
      [],
    );
    expect(await a.records()).toContain(`${sName(0)}/x={"id":"x","v":99}`);
    const c = await w.device("c");
    await c.cycle();
    expect(await c.records()).toEqual(await a.records());
  }, 300_000);

  it("a compaction that loses the compare-and-set to another writer is aborted, cleaned, and replanned: it never advances the watermark or leaves a workspace behind", async () => {
    const w = await world({ streams: 2 });
    const b = await w.device("b");
    let atCas: Awaited<ReturnType<typeof atRequest>> = null;
    const a = await w.device("a");
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();
    await b.cycle();
    await growUntilDue(a);
    const registry = a.deps.registry;
    const post = registry.postBatch!.bind(registry);
    let armed = true;
    registry.postBatch = async (request) => {
      atCas ??= await atRequest(a);
      if (armed) {
        armed = false;
        // Another writer commits at the position `a` is about to take.
        await b.run("run-b", [{ stream: sName(1), id: "from-b" }], {
          full: false,
          covered: [sName(1)],
          observedAt: 9000,
        });
        await b.cycle();
      }
      return post(request);
    };
    await a.run("run-a", [{ stream: sName(0), id: "x", v: 99 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 9500,
    });
    await a.cycle();
    expect(atCas?.phase).toBe("sent"); // it was sent, and the request lost
    expect(
      (await workspaces(a)).filter((r) => r.phase !== "clean"),
      "no workspace is left sent, aborted or half done",
    ).toEqual([]);
    expect(await a.db.query("SELECT 1 FROM workspace_sent")).toEqual([]);
    expect(await a.db.query("SELECT 1 FROM body_values")).toEqual([]);
    await b.cycle();
    const c = await w.device("c");
    await c.cycle();
    const records = await a.records();
    expect(await b.records()).toEqual(records);
    expect(await c.records()).toEqual(records);
    expect(records).toContain(`${sName(0)}/x={"id":"x","v":99}`);
    expect(records.some((r) => r.includes("from-b"))).toBe(true);
  }, 300_000);
});
