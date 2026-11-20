// Slice D: where the ciphertext of a compaction lives between its encryption
// and its PUT, and how a `sent` candidate ends. Each mutant the brief names is
// a test here: an early cursor, an omitted upload, an early ready, a settle on
// the old head and an early cleanup of sent outputs.
import { afterEach, expect, it } from "vitest";
import { createHash } from "node:crypto";
import {
  encodeSegment,
  digestSegment,
  segmentBlobName,
  logScope,
  type Segment,
  type LogOperation,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { planCompaction } from "../../../core/dist/localdb/log-compact.js";
import {
  outputProducer,
  releaseOutputs,
  sealOutputs,
  sendOutputs,
  settleOutputs,
  uploadOutputs,
  type OutputSet,
} from "../../../core/dist/localdb/log-output.js";
import {
  cleanupWorkspaceOne,
  runtimeAdmission,
  setWorkspaceAuthority,
} from "../../../core/dist/localdb/workspace.js";
import { openLogWorkspace } from "../../../core/dist/localdb/workspace-consumer.js";
import {
  world,
  closeWorldDrivers,
  CONNECTION_ID,
  idHash,
} from "./log-world.test-utils.js";
import { keccakOf } from "../../../core/src/stream-sync/crypto-port.js";
import type { LocalSyncDeps } from "../../../core/dist/localdb/deps.js";
afterEach(closeWorldDrivers);

type Device = Awaited<ReturnType<Awaited<ReturnType<typeof world>>["device"]>>;

/** Bytes of every typed array reachable from `root` by properties. A closure
 * holds data the walk cannot see, which is the point: a descriptor has none. */
function reachableBytes(root: unknown): number {
  const seen = new Set<object>();
  let total = 0;
  const walk = (v: unknown) => {
    if (v === null || typeof v !== "object" || seen.has(v)) return;
    seen.add(v);
    if (ArrayBuffer.isView(v)) {
      total += v.byteLength;
      return;
    }
    for (const key of Object.keys(v)) walk((v as Record<string, unknown>)[key]);
  };
  walk(root);
  return total;
}

async function uploaded(deps: LocalSyncDeps, outputs: OutputSet) {
  const objects = new Map<string, Uint8Array>();
  await uploadOutputs(deps, outputs, async (name, bytes) => {
    objects.set(name, bytes);
  });
  return objects;
}

const PART = 4096;

/** A log of `keys` upserts of about 700 bytes in 40 segments: enough tail for the
 * library's rule to compact it. */
async function history(keys: number) {
  const w = await world({ streams: 1 });
  const d = await w.device("d");
  await d.run("seed", [{ stream: "s0", id: 999999 }]);
  await d.cycle();
  const template = [...(await w.segments()).values()][0]!;
  const scope = logScope(template.connector, template.ns);
  const segments: Segment[] = [];
  const refs: { position: number; dataHash: `0x${string}`; bytes: number }[] =
    [];
  const per = Math.ceil(keys / 40);
  for (let at = 0, position = 1; at < keys; at += per, position++) {
    const operations: LogOperation[] = [];
    for (let id = at; id < Math.min(keys, at + per); id++)
      operations.push({
        kind: "upsert",
        stream: "s0",
        pkHash: await idHash(id),
        stamp: { o: 10 + position, r: "r" },
        firstSeen: null,
        value: { id, pad: "x".repeat(700) },
      });
    const segment: Segment = {
      ...template,
      position,
      refs: [...refs],
      operations,
      snapshot: null,
      base: 0,
    };
    segments.push(segment);
    const bytes = encodeSegment(segment);
    const { dataHash } = await digestSegment(
      keccakOf(d.deps.streamCrypto),
      bytes,
    );
    await d.deps.blobs.put(
      `${scope}/${segmentBlobName(dataHash)}`,
      await d.deps.keys.encryptPart(scope, bytes),
    );
    refs.push({ position, dataHash, bytes: bytes.length });
  }
  const plan = await planCompaction(
    { ...d.deps, partTargetBytes: PART },
    {
      connector: template.connector,
      ns: template.ns,
      keyCheck: template.keyCheck,
      generation: template.generation,
      scope,
      // Eligibility only: the bytes the rule weighs are not what is tested.
      log: {
        position: segments.length,
        base: 0,
        snapshot: null,
        refs: refs.map((r) => ({ ...r, bytes: 1 })),
      },
    },
  );
  return { d, deps: { ...d.deps, partTargetBytes: PART }, plan: plan! };
}

it("a plan and its candidate hold a workspace handle, never ciphertext, however large the snapshot", async () => {
  const small = await history(200);
  const large = await history(2000);
  const smallObjects = await uploaded(small.deps, small.plan.outputs);
  const largeObjects = await uploaded(large.deps, large.plan.outputs);
  const total = (m: Map<string, Uint8Array>) =>
    [...m.values()].reduce((n, o) => n + o.length, 0);
  // The snapshot really is many parts, and ten times as many in the large run.
  expect(smallObjects.size).toBeGreaterThan(10);
  expect(largeObjects.size).toBeGreaterThan(smallObjects.size * 5);
  expect(total(largeObjects)).toBeGreaterThan(total(smallObjects) * 5);
  // What the returned plan keeps reachable is flat: it is source-sized on the
  // slice before this one (`plan.objects` held every part).
  expect(reachableBytes(small.plan)).toBeLessThanOrEqual(PART);
  expect(reachableBytes(large.plan)).toBeLessThanOrEqual(PART);
  expect(reachableBytes(large.plan.outputs)).toBeLessThanOrEqual(PART);
  expect(large.plan.outputs.count).toBe(largeObjects.size);
}, 120_000);

it("the upload loop holds one object, puts each once and ends ready only when every object has its receipt", async () => {
  const { d, deps, plan } = await history(300);
  const phase = async () =>
    (await d.db.query<{ phase: string }>("SELECT phase FROM workspaces")).map(
      (r) => r.phase,
    );
  expect(await phase()).toEqual(["sealed"]);
  let active = 0,
    peak = 0;
  const puts: string[] = [];
  await uploadOutputs(deps, plan.outputs, async (name) => {
    active++;
    peak = Math.max(peak, active);
    await new Promise((resolve) => setTimeout(resolve, 1));
    puts.push(name);
    active--;
  });
  expect(peak).toBe(1);
  expect(new Set(puts).size).toBe(puts.length);
  expect(puts.length).toBe(plan.outputs.count);
  expect(await phase()).toEqual(["ready"]);
  // A second pass has nothing to do.
  await uploadOutputs(deps, plan.outputs, async () => {
    throw new Error("nothing is left to put");
  });
}, 120_000);

it("a put that fails leaves the workspace sealed; the retry puts the failed object again from the same sealed bytes and no other", async () => {
  const { d, deps, plan } = await history(300);
  const sums = new Map<string, string[]>();
  let calls = 0;
  const hash = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
  // The object whose receipt is lost: put (it reached the store), then lost.
  await expect(
    uploadOutputs(deps, plan.outputs, async (name, bytes) => {
      sums.set(name, [...(sums.get(name) ?? []), hash(bytes)]);
      if (++calls === 3) throw new Error("process lost before the receipt");
    }),
  ).rejects.toThrow("process lost");
  expect(
    (await d.db.query<{ phase: string }>("SELECT phase FROM workspaces")).map(
      (r) => r.phase,
    ),
  ).toEqual(["sealed"]);
  // Early ready: two receipts of the many are not every receipt.
  await expect(plan.outputs.ws.transition("sealed", "ready")).rejects.toThrow();
  await uploadOutputs(deps, plan.outputs, async (name, bytes) => {
    sums.set(name, [...(sums.get(name) ?? []), hash(bytes)]);
  });
  const twice = [...sums].filter(([, s]) => s.length > 1);
  expect(twice).toHaveLength(1);
  expect(new Set(twice[0]![1]).size).toBe(1); // identical bytes: never re-encrypted
  expect(sums.size).toBe(plan.outputs.count);
  expect(
    (await d.db.query<{ phase: string }>("SELECT phase FROM workspaces")).map(
      (r) => r.phase,
    ),
  ).toEqual(["ready"]);
}, 120_000);

/** Output units staged by hand, as a producer would, in a workspace of this device. */
async function staged(d: Device, names: readonly string[]) {
  const [meta] = await d.db.query<{
    owner: string;
    device_id: string;
    created_at: number;
  }>("SELECT owner,device_id,created_at FROM db_meta WHERE id=1");
  const binding = {
    owner: meta!.owner,
    databaseIncarnation: JSON.stringify([meta!.device_id, meta!.created_at]),
    connection: CONNECTION_ID,
    generation: 1,
    keyCheck: "k",
    expectedHead: "null",
    operation: `hand-${Math.random().toString(36).slice(2)}`,
    codecVersion: 1,
  };
  await setWorkspaceAuthority(d.db, binding);
  const ws = await openLogWorkspace(d.db, binding);
  const lease = await ws.acquire(128 * 1024 * 1024);
  const producer = outputProducer(d.deps, ws, lease);
  for (const name of names)
    await producer.put(name, new TextEncoder().encode(`bytes of ${name}`));
  await lease.release();
  await runtimeAdmission.finish(d.db, binding.operation);
  return { ws, outputs: { ws, count: producer.count } satisfies OutputSet };
}

it("an early cursor: nothing is put before every output is staged and sealed", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d");
  await d.run("seed", [{ stream: "s0", id: 1 }]);
  await d.cycle();
  const { ws, outputs } = await staged(d, ["a", "b"]);
  await ws.transition("collect", "folded");
  await uploadOutputs(d.deps, outputs, async () => {
    throw new Error("the producer is not done");
  });
  // Folded, not sealed: the loop did nothing and the phase did not move.
  expect(
    (
      await d.db.query<{ phase: string }>(
        "SELECT phase FROM workspaces WHERE operation=?",
        [ws.binding.operation],
      )
    ).map((r) => r.phase),
  ).toEqual(["folded"]);
  // And once sealed, no output can still be added.
  await sealOutputs(ws);
  const lease = await ws.acquire(128 * 1024 * 1024);
  await expect(
    outputProducer(d.deps, ws, lease).put("late", new Uint8Array([1])),
  ).rejects.toThrow();
  await lease.release();
  await runtimeAdmission.finish(d.db, ws.binding.operation);
}, 60_000);

it("an omitted upload: an upload row that is not the sealed output cannot make the workspace ready", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d");
  await d.run("seed", [{ stream: "s0", id: 1 }]);
  await d.cycle();
  const { ws } = await staged(d, ["a", "b"]);
  await ws.transition("collect", "folded");
  await sealOutputs(ws);
  // Nothing uploaded: not ready.
  await expect(ws.transition("sealed", "ready")).rejects.toThrow();
  // One object uploaded, the other omitted: still not ready.
  const lease = await ws.acquire(128 * 1024 * 1024);
  const cursor = ws.cursor("outputs");
  const first = (await cursor.next(lease))!;
  const row = first.value.row;
  await first.release();
  await cursor.close();
  const unit = await ws.unit(
    `upload:${row.objectKey}`,
    row.value.sha256,
    await ws.position(),
  );
  await unit.stage("uploads", { objectKey: row.objectKey, value: row.value });
  await unit.commit();
  await lease.release();
  await runtimeAdmission.finish(d.db, ws.binding.operation);
  await expect(ws.transition("sealed", "ready")).rejects.toThrow();
}, 60_000);

const OLD = "0xold";
const NEW = "0xnew";
async function sentWorkspace(d: Device, position: number, old: string | null) {
  const { ws, outputs } = await staged(d, ["a"]);
  await ws.transition("collect", "folded");
  await sealOutputs(ws);
  await uploadOutputs(d.deps, outputs, async () => {});
  await sendOutputs(outputs, position, old, NEW);
  return outputs;
}
const phaseOf = async (d: Device, o: OutputSet) =>
  (
    await d.db.query<{ phase: string }>(
      "SELECT phase FROM workspaces WHERE operation=?",
      [o.ws.binding.operation],
    )
  )[0]?.phase;

it.each([
  // Position 3 expects the registry at version 2 holding OLD.
  ["the old head still stands: a request may land yet", 3, OLD, 2, OLD, "sent"],
  ["the candidate's own row stands", 3, OLD, 3, NEW, "finished"],
  ["another row took the candidate's version", 3, OLD, 3, "0xother", "aborted"],
  ["the log moved past the candidate", 3, OLD, 4, "0xlater", "aborted"],
  ["the version before moved to another head", 3, OLD, 2, "0xother", "aborted"],
  ["the first row exists, and is the candidate", 1, null, 1, NEW, "finished"],
  ["no row yet for a first candidate", 1, null, 0, null, "sent"],
] as const)(
  "settles from the registry's head, never from a local claim: %s",
  async (_label, position, old, version, head, expected) => {
    const w = await world({ streams: 1 });
    const d = await w.device("d");
    await d.run("seed", [{ stream: "s0", id: 1 }]);
    await d.cycle();
    const outputs = await sentWorkspace(d, position, old);
    expect(
      await settleOutputs(d.deps, outputs, { kind: "head", version, head }),
    ).toBe(expected);
    // `sent` keeps its rows; an ended workspace is paged away to `clean`.
    expect(await phaseOf(d, outputs)).toBe(
      expected === "sent" ? "sent" : "clean",
    );
    const left = await d.db.query(
      "SELECT 1 FROM workspace_cells WHERE operation=?",
      [outputs.ws.binding.operation],
    );
    expect(left.length > 0).toBe(expected === "sent");
  },
  60_000,
);

it("a refusal is the registry's own reply to the request and aborts; settling twice changes nothing", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d");
  await d.run("seed", [{ stream: "s0", id: 1 }]);
  await d.cycle();
  const outputs = await sentWorkspace(d, 3, OLD);
  expect(await settleOutputs(d.deps, outputs, { kind: "refused" })).toBe(
    "aborted",
  );
  expect(
    await settleOutputs(d.deps, outputs, {
      kind: "head",
      version: 3,
      head: NEW,
    }),
  ).toBe("aborted"); // an ended workspace is not revived by a later read
}, 60_000);

it("an early cleanup of sent outputs: a sent workspace cannot be discarded, released or cleaned before a head observation settles it", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d");
  await d.run("seed", [{ stream: "s0", id: 1 }]);
  await d.cycle();
  const outputs = await sentWorkspace(d, 3, OLD);
  await expect(outputs.ws.discard()).rejects.toThrow();
  await expect(
    cleanupWorkspaceOne(d.db, outputs.ws.binding.operation),
  ).rejects.toThrow("workspace_live_cleanup");
  await releaseOutputs(d.deps, outputs); // leaves `sent` alone
  expect(await phaseOf(d, outputs)).toBe("sent");
  const rows = await d.db.query(
    "SELECT 1 FROM workspace_cells WHERE operation=?",
    [outputs.ws.binding.operation],
  );
  expect(rows.length).toBeGreaterThan(0);
  // Only ready may send, and a send repeated with other heads is a conflict.
  await expect(sendOutputs(outputs, 3, OLD, "0xother")).rejects.toThrow(
    "workspace_sent_conflict",
  );
  await sendOutputs(outputs, 3, OLD, NEW); // the same request again is the same
}, 60_000);

it.each([
  ["the candidate landed", 3, NEW, "finished"],
  ["another row took its version", 3, "0xother", "aborted"],
  ["the old head still stands", 2, OLD, "sent"],
] as const)(
  "a sent candidate outlives a local fence (generation bump, deletion): it is settled from the registry's head, never discarded or resent blind: %s",
  async (_label, version, head, expected) => {
    const w = await world({ streams: 1 });
    const d = await w.device("d");
    await d.run("seed", [{ stream: "s0", id: 1 }]);
    await d.cycle();
    const outputs = await sentWorkspace(d, 3, OLD);
    await d.db.batch([
      {
        sql: "UPDATE connections SET generation=generation+1, control_state='deleted' WHERE connection_id=?",
        params: [CONNECTION_ID],
      },
    ]);
    // The fence stops every write of the workspace itself...
    await expect(outputs.ws.unit("later", "digest", 0)).rejects.toThrow();
    // ...but a request already sent may still land, so only the head decides.
    expect(
      await settleOutputs(d.deps, outputs, { kind: "head", version, head }),
    ).toBe(expected);
    expect(await phaseOf(d, outputs)).toBe(
      expected === "sent" ? "sent" : "clean",
    );
  },
  60_000,
);

it("a workspace that never reached the registry is discarded and paged away", async () => {
  const w = await world({ streams: 1 });
  const d = await w.device("d");
  await d.run("seed", [{ stream: "s0", id: 1 }]);
  await d.cycle();
  const { ws, outputs } = await staged(d, ["a", "b"]);
  await ws.transition("collect", "folded");
  await sealOutputs(ws);
  await releaseOutputs(d.deps, outputs);
  expect(await phaseOf(d, outputs)).toBe("clean");
  expect(
    await d.db.query("SELECT 1 FROM body_values WHERE operation=?", [
      ws.binding.operation,
    ]),
  ).toEqual([]);
}, 60_000);
