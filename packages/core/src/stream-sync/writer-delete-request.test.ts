/**
 * The owner route answers `202` for a connection delete. That answer is only
 * honest if the delete intent is durable when `requestConnectionDelete`
 * resolves: the landing itself runs after the answer, and a later publish pass
 * finishes it when it fails. These tests pin that split.
 */
import { expect, it } from "vitest";
import { parseScope } from "@opendatalabs/personal-server-ts-stream-sync";
import {
  Rig,
  CONNECTOR,
  type RunSpec,
} from "../stream-sync-read/writer-rig.js";

const spec = (runId: string, otherDevice = false): RunSpec => ({
  runId,
  otherDevice,
  key: "id",
  version: "1.0.0",
  rows: [{ id: runId }],
  full: true,
});

async function publishedBase() {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  return r;
}

async function persistedState(r: Rig) {
  const bytes = await r.files.read("state.json");
  return bytes ? JSON.parse(new TextDecoder().decode(bytes)) : {};
}

/** Every write of `state.json` lands after a delay, so an unawaited write is visible. */
function slowStateWrites(r: Rig) {
  const write = r.files.write.bind(r.files);
  r.files.write = async (name, bytes) => {
    if (name === "state.json") {
      await new Promise((resolve) => setTimeout(resolve, 30));
    }
    return write(name, bytes);
  };
}

it("the delete id is returned only once its intent is durable (mutant: NO_INTENT_BEFORE_202)", async () => {
  const r = await publishedBase();
  slowStateWrites(r);
  const answered = await r.writer.requestConnectionDelete(CONNECTOR);
  expect(answered).not.toBeNull();
  // The answer exists, so the intent it names must already be on disk.
  const state = await persistedState(r);
  expect(state.deletes?.[CONNECTOR]?.id).toBe(answered!.deleteId);
});

it("the landing runs after the answer and clears its intent", async () => {
  const r = await publishedBase();
  await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    recordCount: 0,
  });
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("a connector with nothing in the registry is answered and its local state is purged (mutant: EMPTY_REGISTRY_REQUEST_KEEPS_LOCAL)", async () => {
  const r = new Rig({
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
  });
  await r.open();
  // Collected while the registry was out of reach: nothing is registered yet.
  await r.collect(spec("offline"));
  expect(r.gateway.log).toHaveLength(0);
  const answered = await r.writer.requestConnectionDelete(CONNECTOR);
  expect(answered.deleteId).toEqual(expect.any(String));
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
  expect((await persistedState(r)).seedTargets).toEqual({});
  expect(await r.files.list("runs")).toEqual([]);
  // The registry is reachable again: nothing of the deleted connection posts.
  await r.publish();
  expect(r.gateway.log).toHaveLength(0);
});

it("two requests for one delete land it once, from the intent as it is now (mutant: LANDING_FROM_STALE_INTENT)", async () => {
  const r = await publishedBase();
  const posts: string[] = [];
  r.gateway.beforePost = async (request) => {
    posts.push(parseScope(request.scope)?.kind ?? "other");
  };
  const [first, second] = await Promise.all([
    r.writer.requestConnectionDelete(CONNECTOR),
    r.writer.requestConnectionDelete(CONNECTOR),
  ]);
  expect(second.deleteId).toBe(first.deleteId);
  await r.publish();
  // One stream delete head and one control tombstone, no attempt beyond them.
  expect(posts).toEqual(["stream", "control"]);
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("a failed landing keeps its intent and the next pass finishes it", async () => {
  const r = await publishedBase();
  let down = true;
  r.gateway.beforePost = async (request) => {
    if (down && parseScope(request.scope)?.kind === "stream") {
      throw new Error("registry down");
    }
  };
  const answered = await r.writer.requestConnectionDelete(CONNECTOR);
  // The background landing and this pass both fail while the registry is down.
  await r.publish();
  expect((await persistedState(r)).deletes?.[CONNECTOR]?.id).toBe(
    answered!.deleteId,
  );
  down = false;
  await r.publish();
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
  expect(await r.registeredHead()).toMatchObject({ recordCount: 0 });
});

it("the owner delete also fences a declared stream with no registry row (mutant: ROWLESS_IMPORT_RESURRECTS)", async () => {
  const r = new Rig(undefined, CONNECTOR, ["items", "extra"]);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();
  expect(await r.registeredHead("extra")).toMatchObject({
    format: 3,
    recordCount: 0,
    lastDeleteVersion: 1,
  });
});
