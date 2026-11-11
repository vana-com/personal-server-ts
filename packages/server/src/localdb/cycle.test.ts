import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import { bootstrapConnections } from "../../../core/src/localdb/bootstrap.js";
import { runCycle, syncConnection } from "../../../core/src/localdb/cycle.js";
import type {
  ConnectionRow,
  LocalSyncDeps,
} from "../../../core/src/localdb/deps.js";
import { publishConnection } from "../../../core/src/localdb/publish.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";

vi.mock("../../../core/src/localdb/bootstrap.js", () => ({
  bootstrapConnections: vi.fn(),
}));
vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: vi.fn(),
}));
vi.mock("../../../core/src/localdb/publish.js", () => ({
  publishConnection: vi.fn(),
}));

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

const connection = (connectionId: string): ConnectionRow => ({
  connectionId,
  connector: connectionId,
  ns: "",
  generation: 1,
  controlState: "active",
  controlVersion: 1,
});
const applied = (id: string) => [
  { stream: id, outcome: "applied" as const, partsDownloaded: 1, partsKept: 0 },
];
const published = (id: string) => [
  { stream: id, outcome: "published" as const, watermark: 1 },
];
// The mocked siblings only need the real queue, not database or network ports.
const dependencies = () =>
  ({
    queue: connectionQueue(),
    logger: { info: vi.fn(), warn: vi.fn() },
  }) as unknown as LocalSyncDeps;

beforeEach(() => vi.resetAllMocks());

describe("local database cycle", () => {
  it("lists first and applies before publishing each queued connection", async () => {
    const deps = dependencies();
    const events: string[] = [];
    const listingStarted = deferred();
    const listingReady = deferred();
    const priorStarted = deferred();
    const priorReady = deferred();
    const applyStarted = deferred();
    const applyReady = deferred();
    const otherPublished = deferred();
    const prior = deps.queue.run("first", "end", async () => {
      priorStarted.resolve();
      await priorReady.promise;
    });
    await priorStarted.promise;
    vi.mocked(bootstrapConnections).mockImplementation(async () => {
      events.push("listing:start");
      listingStarted.resolve();
      await listingReady.promise;
      events.push("listing:end");
      return [connection("first"), connection("second")];
    });
    vi.mocked(applyConnection).mockImplementation((queued, id) =>
      queued.queue.run(id, "apply", async () => {
        events.push(`apply:${id}:start`);
        if (id === "first") {
          applyStarted.resolve();
          await applyReady.promise;
        }
        events.push(`apply:${id}:end`);
        return applied(id);
      }),
    );
    vi.mocked(publishConnection).mockImplementation((queued, id) =>
      queued.queue.run(id, "publish", async () => {
        events.push(`publish:${id}`);
        if (id === "second") otherPublished.resolve();
        return published(id);
      }),
    );

    const cycle = runCycle(deps);
    await listingStarted.promise;
    expect(events).toEqual(["listing:start"]);
    expect(applyConnection).not.toHaveBeenCalled();
    expect(publishConnection).not.toHaveBeenCalled();
    listingReady.resolve();
    await otherPublished.promise;
    // One connection's existing operation does not hold up the other.
    expect(events).toEqual([
      "listing:start",
      "listing:end",
      "apply:second:start",
      "apply:second:end",
      "publish:second",
    ]);
    priorReady.resolve();
    await applyStarted.promise;
    const next = deps.queue.run("first", "end", async () => {
      events.push("next:first");
    });
    expect(events).not.toContain("publish:first");
    applyReady.resolve();
    const report = await cycle;
    await Promise.all([prior, next]);
    expect(events.slice(-4)).toEqual([
      "apply:first:start",
      "apply:first:end",
      "publish:first",
      "next:first",
    ]);
    expect(report.connections).toEqual(
      ["first", "second"].map((id) => ({
        connectionId: id,
        applied: applied(id),
        published: published(id),
        error: null,
      })),
    );

    events.length = 0;
    await syncConnection(deps, "direct");
    expect(events).toEqual([
      "apply:direct:start",
      "apply:direct:end",
      "publish:direct",
    ]);
    expect(bootstrapConnections).toHaveBeenCalledTimes(1);
    expect(bootstrapConnections).toHaveBeenCalledWith(deps);
  });

  it("reports a connection's failure without stopping the other connections", async () => {
    const deps = dependencies();
    vi.mocked(bootstrapConnections).mockResolvedValue(
      ["apply-fails", "publish-fails", "succeeds"].map(connection),
    );
    vi.mocked(applyConnection).mockImplementation(async (_deps, id) => {
      if (id === "apply-fails") throw new Error("apply failed");
      return applied(id);
    });
    vi.mocked(publishConnection).mockImplementation(async (_deps, id) => {
      if (id === "publish-fails") throw "publish failed";
      return published(id);
    });

    expect(await runCycle(deps)).toEqual({
      connections: [
        {
          connectionId: "apply-fails",
          applied: [],
          published: [],
          error: "apply failed",
        },
        {
          connectionId: "publish-fails",
          applied: applied("publish-fails"),
          published: [],
          error: "publish failed",
        },
        {
          connectionId: "succeeds",
          applied: applied("succeeds"),
          published: published("succeeds"),
          error: null,
        },
      ],
    });
    expect(vi.mocked(publishConnection).mock.calls.map(([, id]) => id)).toEqual(
      ["publish-fails", "succeeds"],
    );
    // The failure is logged, not only returned: the timer drops the report.
    expect(vi.mocked(deps.logger.warn).mock.calls).toEqual([
      [
        { connectionId: "apply-fails", error: "apply failed" },
        "Stream sync cycle failed for a connection",
      ],
      [
        { connectionId: "publish-fails", error: "publish failed" },
        "Stream sync cycle failed for a connection",
      ],
    ]);
  });
});
