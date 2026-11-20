// Erasure of a deleted connection's log objects against a log the real
// publisher wrote: real segments, a real compaction into snapshot parts, and a
// record whose body is stored out of line in pieces. The registry is the
// fake gateway the publisher commits to; storage is its in-memory store.
import { afterEach, describe, expect, it } from "vitest";
import { logScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  eraseDeletedConnectionLogs,
  type LogErasureDeps,
} from "../../../core/src/localdb/log-erase.js";
import {
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const LOG = logScope(CONNECTOR, "");
const OTHER = "other";
const OTHER_LOG = logScope(OTHER, "");
// Compaction fires once a catch-up through a snapshot repays building it. A
// small part target makes the snapshot many parts, each a costly PUT, so the
// rule would never fire; this is large enough for it to, and a record three
// targets long is stored out of line, in pieces.
const PART_TARGET = 65536;

/**
 * A log that has compacted once and holds an out-of-line body, a second
 * connector's log beside it, and the delete of the first connector (fence
 * landed).
 */
async function deletedCompactedLog() {
  const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
  const a = await w.device("a");
  await a.run(
    "run-1",
    [
      // Over the part target: its body goes out of line, in pieces.
      { stream: sName(0), id: "big", pad: PART_TARGET * 2 + 1000 },
      { stream: sName(0), id: "x", v: 0 },
    ],
    { observedAt: 1100 },
  );
  await a.cycle();
  await a.run(
    "other-1",
    [{ stream: sName(0), id: "o", pad: PART_TARGET * 2 + 1000 }],
    {
      connector: OTHER,
      observedAt: 1100,
    },
  );
  await a.cycle();
  for (let i = 0; i < 400; i++) {
    const segments = await w.segments();
    const head = segments.get(Math.max(...segments.keys()))!;
    if (head.snapshot !== null) break;
    await a.run(`grow-${i}`, [{ stream: sName(0), id: "x", v: i + 1 }], {
      full: false,
      covered: [sName(0)],
      observedAt: 2000 + i,
    });
    await a.cycle();
  }
  const keys = (prefix: string) =>
    w.innerBlobs.keys().filter((key) => key.startsWith(`${prefix}/`));
  const before = keys(LOG);
  expect(before.some((k) => k.includes("/s-"))).toBe(true);
  expect(before.some((k) => k.includes("/q-"))).toBe(true);
  expect(before.some((k) => k.includes("/v-"))).toBe(true);

  const answer = await a.sync.deleter.requestConnectionDelete(CONNECTOR);
  expect(answer.fenced).toBe(true);

  const calls: string[][] = [];
  const deps = (overrides: Partial<LogErasureDeps> = {}): LogErasureDeps => ({
    registry: a.deps.registry,
    versions: {
      list: async (scope) => ({
        complete: true,
        versions: (w.gateway.versions.get(scope) ?? []).map((v, i) => ({
          expectedVersion: String(i + 1),
          dataHash: v.dataHash,
          isTombstone: false,
        })),
      }),
    },
    finality: {
      tombstoneState: async () => ({ finalized: "99", rolledBack: null }),
    },
    blobs: a.deps.blobs,
    keys: a.deps.keys,
    objects: {
      deleteBlobVersions: async (scope, names) => {
        calls.push([...names]);
        const out = {
          deleted: [] as string[],
          missing: [] as string[],
          failed: [] as { version: string; error: string }[],
        };
        for (const name of names)
          (w.innerBlobs.delete(`${scope}/${name}`)
            ? out.deleted
            : out.missing
          ).push(name);
        return out;
      },
    },
    logger: { info() {}, warn() {} },
    ...overrides,
  });
  return { w, a, keys, before, deps, calls };
}

describe("erasing a log the real publisher wrote", () => {
  it("removes every segment, snapshot part and body piece of the deleted connection and none of another", async () => {
    const { keys, before, deps, calls } = await deletedCompactedLog();
    const otherBefore = keys(OTHER_LOG);
    expect(otherBefore.length).toBeGreaterThan(0);

    const report = await eraseDeletedConnectionLogs(deps(), {
      connector: CONNECTOR,
    });

    expect(report.pending).toBe(false);
    expect(report.connections).toHaveLength(1);
    expect(report.connections[0]!.outcome).toEqual({
      kind: "erased",
      deleted: before.length,
      unenumerated: 0,
    });
    expect(keys(LOG)).toEqual([]);
    expect(keys(OTHER_LOG)).toEqual(otherBefore);
    // Pieces, then parts, then segments; the newest segment is the last call.
    const order = calls.flat().map((name) => name[0]);
    expect(order).toEqual(
      [...order].sort((x, y) => "vqs".indexOf(x!) - "vqs".indexOf(y!)),
    );
  });

  it("finishes after a storage failure part-way, with nothing remembered between the passes", async () => {
    const { w, keys, before, deps } = await deletedCompactedLog();
    let failures = 0;
    const flaky = deps();
    const delegate = flaky.objects;
    const failing: LogErasureDeps = {
      ...flaky,
      objects: {
        deleteBlobVersions: async (scope, names) => {
          // The second request of the pass fails for every name in it.
          if (++failures === 2)
            return {
              deleted: [],
              missing: [],
              failed: names.map((version) => ({ version, error: "503" })),
            };
          return delegate.deleteBlobVersions(scope, names);
        },
      },
    };

    const first = await eraseDeletedConnectionLogs(failing);
    expect(first.pending).toBe(true);
    const left = keys(LOG);
    expect(left.length).toBeGreaterThan(0);
    expect(left.length).toBeLessThan(before.length);
    // Every segment is still there: they name what is left.
    expect(left.filter((k) => k.includes("/s-")).length).toBe(
      before.filter((k) => k.includes("/s-")).length,
    );

    // A restart: a fresh pass over the same registry and storage.
    const second = await eraseDeletedConnectionLogs(deps());
    expect(second.pending).toBe(false);
    expect(keys(LOG)).toEqual([]);
    void w;
  });

  it("leaves the log alone before the control tombstone is final", async () => {
    const { keys, before, deps, calls } = await deletedCompactedLog();
    const report = await eraseDeletedConnectionLogs(
      deps({
        finality: {
          tombstoneState: async () => ({ finalized: null, rolledBack: null }),
        },
      }),
    );
    expect(report.pending).toBe(true);
    expect(calls).toEqual([]);
    expect(keys(LOG)).toEqual(before);
  });
});
