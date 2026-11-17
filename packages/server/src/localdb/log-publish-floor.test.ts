// The requests of one log-mode save, counted rather than timed. Every gateway
// and storage request is held for a fixed latency (request-trace.test-utils.ts),
// so what a save costs is its serial depth (the longest chain of requests in
// which each began after the one before it ended) and its request count, both
// independent of the host's speed.
//
// The floor of a save is one segment PUT and one registry commit, the commit
// after the PUT because it names the object: depth 2. A first save of a new
// connection creates its control row in that same commit (the commit's
// condition is judged on the state it commits), so it is depth 2 as well.
import { sha256 } from "@noble/hashes/sha2";
import { afterEach, describe, expect, it } from "vitest";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  applyConnection,
  syncConnection,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";
import { requestTrace } from "./request-trace.test-utils.js";
import { createGatewayStreamSyncRegistry } from "../../../core/src/stream-sync/registry.js";

afterEach(closeWorldDrivers);

const six = (prefix: string) =>
  Array.from({ length: 6 }, (_, i) => ({
    stream: sName(i),
    id: `${prefix}${i}`,
  }));

async function openWorld(
  others: number,
  latencyMs: Parameters<typeof requestTrace>[0] = 2,
) {
  const trace = requestTrace(latencyMs);
  const w = await world({ streams: 6, trace });
  const a = await w.device("a");
  for (let c = 0; c < others; c++) {
    await a.run(`other-${c}`, six("o"), { connector: `other${c}` });
    await a.cycle();
  }
  return { trace, w, a };
}

describe("log publish: the requests of one save", () => {
  it("a first save of a new connection puts the segment, then commits the control row and the log row in one request: depth 2, no control post (mutant: FIRST_SAVE_READS_CONTROL)", async () => {
    const { trace, a } = await openWorld(0);
    await a.run("first", six("a"), { connector: "fresh" });
    trace.clear();
    await a.cycle();
    expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
    expect(trace.count("post"), trace.describe()).toBe(0);
    expect(trace.count("put"), trace.describe()).toBe(1);
    expect(trace.count("batch"), trace.describe()).toBe(1);
  });

  it("a first save under a Batch-Policy with no room for its two rows fails clearly after the gateway refuses it, with no extra round trip, and writes nothing (mutant: NO_POLICY_ROOM_CHECK)", async () => {
    const trace = requestTrace(2);
    const w = await world({
      streams: 6,
      trace,
      policy: { rows: 1, requires: 16, bytes: 65_536 },
    });
    const a = await w.device("a");
    await a.run("first", six("a"), { connector: "fresh" });
    await expect(a.cycle()).rejects.toThrow(
      /Batch-Policy rows=1;requires=16 has no room for one request of 2 rows and 1 conditions/,
    );
    expect(w.gateway.rowsOf(streamScope("fresh", "", "~log"))).toBe(0);
    // The gateway's refusal carries the policy, so the clear failure costs no
    // request of its own: one commit sent, no policy read after it.
    expect(trace.count("batch"), trace.describe()).toBe(1);
    expect(trace.count("policy"), trace.describe()).toBe(0);
  });

  it("a later save is a PUT and a commit: depth 2", async () => {
    const { trace, a } = await openWorld(0);
    await a.run("first", six("a"), { connector: "fresh" });
    await a.cycle();
    await a.run("second", six("b"), {
      connector: "fresh",
      full: false,
      covered: [sName(0)],
    });
    trace.clear();
    await a.cycle();
    expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
  });

  // A regression that reintroduces point reads must fail whether their
  // replies arrive together or are staggered by the fake wire.
  for (const [name, latency] of [
    ["at one latency", 2],
    [
      "when the control reads answer at different times",
      (kind: string, nth: number) => (kind === "read" ? 2 + 6 * nth : 2),
    ],
  ] as const)
    it(`listings of the owner's rows: one per cycle, however many other connections the owner has (${name})`, async () => {
      for (const others of [1, 9]) {
        const { trace, a } = await openWorld(others, latency);
        await a.run("save", six("b"), {
          connector: "other0",
          full: false,
          covered: [sName(0)],
        });
        trace.clear();
        await a.cycle();
        // The publish itself is a PUT and a commit, ahead of everything else.
        expect(trace.depthToLast("batch"), trace.describe()).toBe(2);
        // The listing already carries every control and log row at one
        // registry snapshot. Apply needs no duplicate point reads.
        expect(trace.count("read"), trace.describe()).toBe(0);
        // The cycle's one listing, which every apply of the cycle reads its
        // log row from.
        expect(trace.count("list"), trace.describe()).toBe(1);
      }
    });

  it("an attachment goes up beside the segment, not before it: depth 3 (probe, PUT), not 4", async () => {
    const trace = requestTrace(2);
    const w = await world({ streams: 1, trace });
    const a = await w.device("a");
    const bytes = new Uint8Array(5000).fill(7);
    const hash = Buffer.from(sha256(bytes)).toString("hex");
    await a.run("first", [{ stream: sName(0), id: "plain" }]);
    await a.cycle();
    await a.run(
      "second",
      [{ stream: sName(0), id: "m", blobId: `sha256:${hash}` }],
      { blob: { hash, bytes }, full: false },
    );
    trace.clear();
    await a.cycle();
    const key = `${streamScope(CONNECTOR, "", sName(0))}/g1-b-${hash}`;
    expect(a.puts).toContain(key);
    expect(trace.count("put"), trace.describe()).toBe(2);
    expect(trace.depthToLast("batch"), trace.describe()).toBe(3);
  });
});

describe("log apply: the cycle's listing is a hint", () => {
  it("a listing taken before this device's own later commit is read again, not taken for a rolled-back registry", async () => {
    const w = await world({ streams: 2 });
    const a = await w.device("a");
    await a.run("first", [{ stream: sName(0), id: "x" }]);
    await a.cycle();
    // A listing a cycle took, then a commit of this device after it (a run's
    // end publishes while the cycle is still bootstrapping).
    const listed = await a.deps.registry.listOwnerRows();
    await a.run("second", [{ stream: sName(0), id: "y" }], {
      full: false,
      covered: [sName(0)],
    });
    await a.cycle();
    const position = await a.position();
    expect(position).toBe(2);
    await expect(
      applyConnection(a.deps, CONNECTION_ID, listed),
    ).resolves.toBeUndefined();
    expect(await a.position()).toBe(position);
  });
});

describe("registry listings: explicit arrival cohorts", () => {
  function deferred<T>() {
    let resolve!: (value: T | PromiseLike<T>) => void;
    const promise = new Promise<T>((done) => {
      resolve = done;
    });
    return { promise, resolve };
  }

  for (const lateCaller of [false, true])
    it(`held L1 queues one L2 for its cohort${lateCaller ? " and a fresh L3 for a late caller" : ""}`, async () => {
      const started = Array.from({ length: 3 }, () => deferred<void>());
      const replies = Array.from({ length: 3 }, () => deferred<Response>());
      const urls: string[] = [];
      const registry = createGatewayStreamSyncRegistry({
        gatewayUrl: "https://gateway.test",
        ownerAddress: `0x${"11".repeat(20)}`,
        fetch: ((input: string) => {
          const index = urls.push(input) - 1;
          if (!replies[index])
            return Promise.reject(new Error("unexpected extra listing"));
          started[index]!.resolve();
          return replies[index]!.promise;
        }) as typeof fetch,
      });
      const response = (version: number) =>
        new Response(
          JSON.stringify({
            data: {
              dataPoints: [
                {
                  scope: CONNECTION_ID,
                  expectedVersion: String(version),
                  dataHash: `0x${"ab".repeat(32)}`,
                  metadataHash: `0x${"cd".repeat(32)}`,
                },
              ],
            },
            pagination: { hasMore: false },
          }),
          { status: 200 },
        );
      const pending: ReturnType<typeof registry.listOwnerRows>[] = [];
      const list = () => {
        const promise = registry.listOwnerRows();
        // Observe rejection immediately, including when an assertion aborts.
        void promise.catch(() => {});
        pending.push(promise);
        return promise;
      };
      const versions = async (promise: ReturnType<typeof list>) =>
        (await promise).map(({ read }) => (read.found ? read.version : null));
      try {
        const first = list();
        await started[0]!.promise;
        const second = list();
        const third = list();
        expect(urls).toHaveLength(1); // L1 remains held; its later callers wait.
        replies[0]!.resolve(response(1));
        await started[1]!.promise;
        expect(await versions(first)).toEqual([1]);
        expect(urls).toHaveLength(2);

        // L2 has definitely begun. This caller must not receive its snapshot.
        const late = lateCaller ? list() : undefined;
        expect(urls).toHaveLength(2); // L3 cannot start until L2 completes.
        replies[1]!.resolve(response(2));
        expect(await versions(second)).toEqual([2]);
        expect(await versions(third)).toEqual([2]);
        if (late) {
          await started[2]!.promise;
          expect(urls).toHaveLength(3);
          replies[2]!.resolve(response(3));
          expect(await versions(late)).toEqual([3]);
        }
        expect(urls).toHaveLength(lateCaller ? 3 : 2);
        for (const input of urls) {
          const url = new URL(input);
          expect(url.pathname).toBe("/v1/data");
          expect(url.searchParams.get("includeDeleted")).toBe("true");
          expect(url.searchParams.has("cursor")).toBe(false);
        }
      } finally {
        // No held fetch or detached rejection survives a failed assertion.
        replies.forEach((reply, index) => reply.resolve(response(index + 1)));
        await Promise.allSettled(pending);
      }
    });
});

it("a cycle listing older than a local reconnect cannot roll its control lifetime back", async () => {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  await a.run("first", [{ stream: sName(0), id: "old" }]);
  await a.cycle();
  const listed = await a.deps.registry.listOwnerRows();
  await a.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(await a.sync.deleter.resumeDeletes()).toEqual([]);
  await a.run("new", [{ stream: sName(0), id: "new" }], { connect: true });
  await a.sync.publish();
  const report = await syncConnection(a.deps, CONNECTION_ID, undefined, listed);
  expect(report.error).toBeNull();
  expect((await a.sync.intake.publicationStatus("new")).state).toBe(
    "published",
  );
  expect(await a.records()).toEqual(['s0/new={"id":"new"}']);
});
