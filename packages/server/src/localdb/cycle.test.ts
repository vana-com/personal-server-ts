import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyConnection } from "../../../core/src/localdb/apply.js";
import {
  bootstrapConnections,
  connectionsWithStreams,
  knownActiveConnections,
  newConnectionsWithStreams,
} from "../../../core/src/localdb/bootstrap.js";
import {
  runCycle,
  runPublish,
  syncConnection,
} from "../../../core/src/localdb/cycle.js";
import type {
  ConnectionRow,
  LocalSyncDeps,
} from "../../../core/src/localdb/deps.js";
import { publishLog } from "../../../core/src/localdb/log-publish.js";
import { UpdateRequiredError } from "../../../core/src/localdb/update-required.js";
import { connectionQueue } from "../../../core/src/localdb/queue.js";

vi.mock("../../../core/src/localdb/bootstrap.js", () => ({
  bootstrapConnections: vi.fn(),
  connectionsWithStreams: vi.fn(),
  knownActiveConnections: vi.fn(),
  newConnectionsWithStreams: vi.fn(),
}));
vi.mock("../../../core/src/localdb/apply.js", () => ({
  applyConnection: vi.fn(),
}));
vi.mock("../../../core/src/localdb/log-publish.js", () => ({
  publishLog: vi.fn(),
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
const published = (id: string) => [
  { stream: id, outcome: "published" as const, watermark: 1 },
];
// The mocked siblings only need the real queue, not database or network ports.
// The cycle's one listing of the owner; the mocked siblings only pass it on.
const LISTED: readonly never[] = [];
// The registry's rows for the scoped table: a control row per connection, so a
// test can see whether the cycle bootstrapped a connection it must leave alone.
const OWNER_ROWS = ["own", "sibling", "A", "B", "C"].map((scope) => ({
  scope,
  read: { found: false },
})) as never;
const dependencies = () =>
  ({
    queue: connectionQueue(),
    registry: { listOwnerRows: async () => LISTED },
    logger: { info: vi.fn(), warn: vi.fn() },
  }) as unknown as LocalSyncDeps;

beforeEach(() => {
  vi.resetAllMocks();
  // No connection here is known to the device before the listing.
  vi.mocked(knownActiveConnections).mockResolvedValue([]);
  vi.mocked(newConnectionsWithStreams).mockResolvedValue([]);
  vi.mocked(connectionsWithStreams).mockResolvedValue([]);
});

describe("a scoped caller's result is decided only by its own connections", () => {
  const fails = (what: string) => new Error(`${what} failed`);
  const deferred = (id: string) => [
    { stream: id, outcome: "deferred" as const, watermark: 1 },
  ];
  it("keeps a settled receipt when owner discovery for an unplaced connection fails", async () => {
    const deps = dependencies();
    vi.mocked(knownActiveConnections).mockResolvedValue([connection("own")]);
    vi.mocked(newConnectionsWithStreams).mockResolvedValue([]);
    vi.mocked(connectionsWithStreams).mockResolvedValue([
      connection("own"),
      connection("unplaced"),
    ]);
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => published(id));
    vi.spyOn(deps.registry, "listOwnerRows").mockRejectedValue(fails("listing"));

    const report = await runPublish(deps, ["own"]);

    expect(report.cycleError).toBe("listing failed");
    expect(report.connections).toEqual([
      { connectionId: "own", published: published("own"), error: null },
      { connectionId: "unplaced", published: [], error: "listing failed" },
    ]);
    expect(publishLog).toHaveBeenCalledTimes(1);
  });

  /**
   * `sibling` always defers in the early publish, so the fallback runs. `own`
   * settles there, or (`ownNeedsFallback`: a reconnect, say) defers too and is
   * published by the fallback's own pass.
   */
  function scoped(
    ownNeedsFallback: boolean,
    step: (deps: LocalSyncDeps) => void,
  ) {
    const deps = dependencies();
    deps.registry.listOwnerRows = async () => OWNER_ROWS;
    if (ownNeedsFallback)
      vi.mocked(newConnectionsWithStreams).mockResolvedValue([
        connection("own"),
        connection("sibling"),
      ]);
    else {
      vi.mocked(knownActiveConnections).mockResolvedValue([connection("own")]);
      vi.mocked(newConnectionsWithStreams).mockResolvedValue([
        connection("sibling"),
      ]);
    }
    const calls = new Map<string, number>();
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => {
      const n = (calls.get(id) ?? 0) + 1;
      calls.set(id, n);
      if (id === "own" && !ownNeedsFallback) return published(id);
      return n === 1 ? deferred(id) : published(id);
    });
    vi.mocked(bootstrapConnections).mockResolvedValue([
      connection("own"),
      connection("sibling"),
    ]);
    vi.mocked(applyConnection).mockResolvedValue({
      kind: "applied",
    } as never);
    step(deps);
    return deps;
  }
  const rows: readonly [
    string,
    (deps: LocalSyncDeps) => void,
    { sibling: string; cycleError?: string; perConnection?: true },
  ][] = [
    [
      "registry listing",
      (deps) =>
        vi
          .spyOn(deps.registry, "listOwnerRows")
          .mockRejectedValue(fails("listing")),
      { sibling: "listing failed", cycleError: "listing failed" },
    ],
    [
      "discovery of the connections only the listing could place",
      () =>
        vi.mocked(connectionsWithStreams).mockRejectedValue(fails("discovery")),
      { sibling: "discovery failed", cycleError: "discovery failed" },
    ],
    [
      "control save or purge, not tied to one connection",
      () => vi.mocked(bootstrapConnections).mockRejectedValue(fails("purge")),
      { sibling: "purge failed", cycleError: "purge failed" },
    ],
    [
      "control purge, tied to the sibling",
      () =>
        vi
          .mocked(bootstrapConnections)
          .mockImplementation(async (_d, _listed, failures) => {
            failures?.set("sibling", fails("purge"));
            return [connection("own"), connection("sibling")];
          }),
      { sibling: "purge failed", perConnection: true },
    ],
    [
      "apply",
      () =>
        vi.mocked(applyConnection).mockImplementation(async (_d, id) => {
          if (id === "sibling") throw fails("apply");
          return { kind: "applied" } as never;
        }),
      { sibling: "apply failed", perConnection: true },
    ],
    [
      "apply that needs an update",
      () =>
        vi.mocked(applyConnection).mockImplementation(async (_d, id) => {
          if (id === "sibling")
            throw new UpdateRequiredError("unknown stream", 99);
          return { kind: "applied" } as never;
        }),
      { sibling: "unknown stream", perConnection: true },
    ],
    [
      "publish",
      () => {
        const calls = new Map<string, number>();
        vi.mocked(publishLog).mockImplementation(async (_d, id) => {
          const n = (calls.get(id) ?? 0) + 1;
          calls.set(id, n);
          if (id === "sibling") {
            if (n === 1) return deferred(id);
            throw fails("publish");
          }
          return n === 1 && ownEarlyDefers() ? deferred(id) : published(id);
        });
      },
      { sibling: "publish failed", perConnection: true },
    ],
  ];
  let ownEarlyDefers = () => false;
  it.each(
    // A failure of the whole pass (listing, an untied bootstrap failure) also
    // stops a caller that needs the pass, so only per-connection failures
    // are tried with the caller needing the fallback.
    rows.flatMap((row) =>
      row[2].perConnection
        ? [[false, ...row] as const, [true, ...row] as const]
        : [[false, ...row] as const],
    ),
  )(
    "with the caller needing the fallback: %s, is unchanged when the sibling's %s fails",
    async (needsFallback, _step, fail, expected) => {
      ownEarlyDefers = () => needsFallback;
      const deps = scoped(needsFallback, fail);
      const report = await runPublish(deps, ["own"]);
      expect(report.connections.find((c) => c.connectionId === "own")).toEqual({
        connectionId: "own",
        published: published("own"),
        error: null,
      });
      expect(
        vi.mocked(publishLog).mock.calls.filter(([, id]) => id === "own"),
      ).toHaveLength(needsFallback ? 2 : 1);
      expect(
        vi.mocked(applyConnection).mock.calls.filter(([, id]) => id === "own"),
      ).toHaveLength(needsFallback ? 1 : 0);
      // A caller connection that settled early is not bootstrapped (no control
      // save or purge, no queue slot) by the fallback either.
      if (!needsFallback)
        for (const [, listed] of vi.mocked(bootstrapConnections).mock.calls)
          expect(listed?.map((row) => row.scope)).not.toContain("own");
      expect(
        report.connections.find((c) => c.connectionId === "sibling"),
      ).toMatchObject({ error: expected.sibling });
      expect(report.cycleError).toBe(expected.cycleError);
    },
  );

  it("keeps a settled connection final when another requested connection has no early result", async () => {
    // A commits early. B is requested but the early publish does not take it.
    // C defers, which forces the fallback. A's apply would fail: the call must
    // not touch A again, so that failure cannot reach the caller.
    const deps = dependencies();
    deps.registry.listOwnerRows = async () => OWNER_ROWS;
    vi.mocked(knownActiveConnections).mockResolvedValue([connection("A")]);
    vi.mocked(newConnectionsWithStreams).mockResolvedValue([connection("C")]);
    const calls = new Map<string, number>();
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => {
      const n = (calls.get(id) ?? 0) + 1;
      calls.set(id, n);
      return id === "C" && n === 1 ? deferred(id) : published(id);
    });
    vi.mocked(bootstrapConnections).mockResolvedValue(
      ["A", "B", "C"].map(connection),
    );
    vi.mocked(applyConnection).mockImplementation(async (_d, id) => {
      if (id === "A") throw fails("apply");
      return { kind: "applied" } as never;
    });

    const report = await runPublish(deps, ["A", "B"]);

    expect(report.connections.find((c) => c.connectionId === "A")).toEqual({
      connectionId: "A",
      published: published("A"),
      error: null,
    });
    expect(report.connections.find((c) => c.connectionId === "B")).toEqual({
      connectionId: "B",
      published: published("B"),
      error: null,
    });
    expect(report.cycleError).toBeUndefined();
    const touched = (mock: typeof publishLog | typeof applyConnection) =>
      vi.mocked(mock).mock.calls.filter(([, id]) => id === "A");
    expect(touched(publishLog)).toHaveLength(1);
    expect(touched(applyConnection)).toHaveLength(0);
    for (const [, listed] of vi.mocked(bootstrapConnections).mock.calls)
      expect(listed?.map((row) => row.scope)).not.toContain("A");
  });

  it("does not settle a connection that has one published and one deferred stream", async () => {
    const deps = dependencies();
    vi.spyOn(deps.registry, "listOwnerRows").mockRejectedValue(
      new Error("listing unreachable"),
    );
    vi.mocked(newConnectionsWithStreams).mockResolvedValue([connection("own")]);
    vi.mocked(publishLog).mockResolvedValue([
      { stream: "a", outcome: "published" as const, watermark: 1 },
      { stream: "b", outcome: "deferred" as const, watermark: 1 },
    ]);
    await expect(runPublish(deps, ["own"])).rejects.toThrow(
      /listing unreachable/,
    );
  });
});

describe("local database cycle", () => {
  it("lists a connection only the listing could place as failed when the fallback listing fails", async () => {
    const deps = dependencies();
    vi.spyOn(deps.registry, "listOwnerRows").mockRejectedValue(
      new Error("listing unreachable"),
    );
    vi.mocked(knownActiveConnections).mockResolvedValue([connection("own")]);
    vi.mocked(connectionsWithStreams).mockResolvedValue([
      connection("own"),
      connection("orphan"),
    ]);
    vi.mocked(publishLog).mockImplementation(async (_deps, id) =>
      published(id),
    );
    const report = await runPublish(deps, ["own"]);
    const byId = new Map(report.connections.map((c) => [c.connectionId, c]));
    expect(byId.get("own")).toMatchObject({ error: null });
    expect(byId.get("orphan")).toEqual({
      connectionId: "orphan",
      published: [],
      error: "listing unreachable",
    });
  });

  it("reports a sibling's own early error, not the listing error, when the fallback listing fails", async () => {
    const deps = dependencies();
    vi.spyOn(deps.registry, "listOwnerRows").mockRejectedValue(
      new Error("listing unreachable"),
    );
    vi.mocked(knownActiveConnections).mockResolvedValue([
      connection("own"),
      connection("sibling"),
    ]);
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => {
      if (id === "sibling") throw new Error("commit failed");
      return published(id);
    });
    const report = await runPublish(deps, ["own"]);
    const byId = new Map(report.connections.map((c) => [c.connectionId, c]));
    expect(byId.get("own")).toMatchObject({ error: null });
    expect(byId.get("sibling")).toMatchObject({ error: "commit failed" });
  });

  it("reports a fresh sibling's dropped deferral as failed when the fallback listing fails", async () => {
    const deps = dependencies();
    vi.spyOn(deps.registry, "listOwnerRows").mockRejectedValue(
      new Error("listing unreachable"),
    );
    vi.mocked(knownActiveConnections).mockResolvedValue([connection("own")]);
    vi.mocked(newConnectionsWithStreams).mockResolvedValue([
      connection("sibling"),
    ]);
    vi.mocked(publishLog).mockImplementation(async (_deps, id) =>
      id === "own"
        ? published(id)
        : [{ stream: id, outcome: "deferred" as const, watermark: 1 }],
    );
    const report = await runPublish(deps, ["own"]);
    const byId = new Map(report.connections.map((c) => [c.connectionId, c]));
    expect(byId.get("own")).toMatchObject({
      error: null,
      published: published("own"),
    });
    expect(byId.get("sibling")).toMatchObject({
      error: "listing unreachable",
    });
  });

  it("lets a bootstrap failure propagate to an unscoped caller when a sibling forced the fallback", async () => {
    const deps = dependencies();
    vi.mocked(knownActiveConnections).mockResolvedValue([
      connection("own"),
      connection("sibling"),
    ]);
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => {
      if (id === "sibling") throw new Error("commit failed");
      return published(id);
    });
    vi.mocked(bootstrapConnections).mockRejectedValue(
      new Error("controls write failed"),
    );
    await expect(runPublish(deps)).rejects.toThrow(/controls write failed/);
  });

  it.each([[], ["missing"]])(
    "avoids registry calls when no scoped connection is held: %j",
    async (connections) => {
      const deps = dependencies();
      deps.db = {
        query: vi.fn().mockResolvedValue([]),
      } as unknown as LocalSyncDeps["db"];
      const list = vi.spyOn(deps.registry, "listOwnerRows");
      expect(await runCycle(deps, { connections })).toEqual({
        connections: [],
      });
      expect(list).not.toHaveBeenCalled();
      expect(publishLog).not.toHaveBeenCalled();
      expect(applyConnection).not.toHaveBeenCalled();
    },
  );

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
      }),
    );
    vi.mocked(publishLog).mockImplementation((queued, id) =>
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
    expect(publishLog).not.toHaveBeenCalled();
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
    // Apply keeps its slot. Publish takes its own slots afterwards, so an
    // operation queued during apply (a run's begin) runs before it rather
    // than behind the whole publish.
    expect(events.slice(-4)).toEqual([
      "apply:first:start",
      "apply:first:end",
      "next:first",
      "publish:first",
    ]);
    expect(report.connections).toEqual(
      ["first", "second"].map((id) => ({
        connectionId: id,
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
    expect(bootstrapConnections).toHaveBeenCalledWith(
      deps,
      LISTED,
      expect.any(Map),
    );
  });

  it("reports a connection's failure without stopping the other connections", async () => {
    const deps = dependencies();
    vi.mocked(bootstrapConnections).mockResolvedValue(
      ["apply-fails", "publish-fails", "succeeds"].map(connection),
    );
    vi.mocked(applyConnection).mockImplementation(async (_deps, id) => {
      if (id === "apply-fails") throw new Error("apply failed");
    });
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => {
      if (id === "publish-fails") throw "publish failed";
      return published(id);
    });

    expect(await runCycle(deps)).toEqual({
      connections: [
        {
          connectionId: "apply-fails",
          published: [],
          error: "apply failed",
        },
        {
          connectionId: "publish-fails",
          published: [],
          error: "publish failed",
        },
        {
          connectionId: "succeeds",
          published: published("succeeds"),
          error: null,
        },
      ],
    });
    expect(vi.mocked(publishLog).mock.calls.map(([, id]) => id)).toEqual([
      "publish-fails",
      "succeeds",
    ]);
    // The failure is logged, not only returned: the timer drops the report.
    // The connections run concurrently, so their log order is not fixed.
    const warned = vi.mocked(deps.logger.warn).mock.calls;
    expect(warned).toHaveLength(2);
    expect(warned).toEqual(
      expect.arrayContaining([
        [
          { connectionId: "apply-fails", error: "apply failed" },
          "Stream sync cycle failed for a connection",
        ],
        [
          { connectionId: "publish-fails", error: "publish failed" },
          "Stream sync cycle failed for a connection",
        ],
      ]),
    );
  });

  it("publishes the other connections while one is still failing", async () => {
    const deps = dependencies();
    vi.mocked(bootstrapConnections).mockResolvedValue(
      ["slow-failure", "healthy"].map(connection),
    );
    vi.mocked(applyConnection).mockResolvedValue(undefined);
    const healthyPublished = deferred();
    vi.mocked(publishLog).mockImplementation(async (_deps, id) => {
      if (id === "healthy") {
        healthyPublished.resolve();
        return published(id);
      }
      // Storage keeps refusing this connection's reads; it fails late.
      await healthyPublished.promise;
      throw new Error(
        "vana-storage download failed: 500 Internal Server Error",
      );
    });

    const report = await runCycle(deps);

    expect(report.connections).toEqual([
      expect.objectContaining({
        connectionId: "slow-failure",
        published: [],
        error: "vana-storage download failed: 500 Internal Server Error",
      }),
      expect.objectContaining({
        connectionId: "healthy",
        published: published("healthy"),
        error: null,
      }),
    ]);
    // The healthy connection published before the failing one gave up.
    expect(vi.mocked(publishLog).mock.calls.map(([, id]) => id)).toEqual([
      "slow-failure",
      "healthy",
    ]);
  });
});
