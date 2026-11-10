/**
 * The owner route answers `202` for a connection delete. That answer is only
 * honest if the delete intent is durable when `requestConnectionDelete`
 * resolves: the landing itself runs after the answer, and a later publish pass
 * finishes it when it fails. These tests pin that split.
 */
import { expect, it } from "vitest";
import { parseScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { ConnectorNotVerifiedError } from "../localdb/delete.js";
import { ask } from "../stream-sync-read/service-fixture.js";
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
    format: 4,
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
    format: 4,
    recordCount: 0,
    lastDeleteVersion: 1,
  });
});

it("a delete that lists nothing clears the saved cursor, so the next import starts over (mutant: NOTHING_LISTED_KEEPS_STATE)", async () => {
  const r = await publishedBase();
  expect((await r.writer.runPlan(CONNECTOR)).checkpoint).not.toBeNull();
  // The registry now lists nothing of the connector (another device deleted it
  // and the rows are gone), while this device still holds its cursor.
  r.gateway.listControlRows = async () => [];
  r.gateway.listStreamRows = async () => [];
  const answered = await r.writer.requestConnectionDelete(CONNECTOR);
  expect(answered.deleteId).toEqual(expect.any(String));
  expect((await r.writer.runPlan(CONNECTOR)).checkpoint).toBeNull();
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("a second delete after a reconnect deletes the reconnect, not the old plan (mutant: REUSE_OPEN_INTENT)", async () => {
  const r = await publishedBase();
  // The first delete reaches the registry never: A is offline, its intent stays.
  r.gateway.beforePost = async () => {
    throw new Error("registry down");
  };
  const first = await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();
  expect((await persistedState(r)).deletes?.[CONNECTOR]?.id).toBe(
    first.deleteId,
  );
  r.gateway.beforePost = undefined;
  // Meanwhile another device deletes the connection, reconnects and syncs.
  await r.other.deleteConnection(CONNECTOR);
  const onB = { otherDevice: true, userConnect: true };
  await r.collect({ ...spec("learn", true), ...onB });
  await r.collect({ ...spec("reborn", true), ...onB });
  expect(await r.registeredHead()).toMatchObject({ recordCount: 2 });
  // A is back; the user deletes again. The registry has moved since the first
  // intent, so this delete is a new one and must erase what is there now.
  const second = await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({ recordCount: 0 });
  await r.sync();
  const served = await r.service.resolve(ask("pdpp.acme.items"));
  expect(["view", "local_pending"]).not.toContain(served.kind);
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
  expect(second.deleteId).not.toBe(first.deleteId);
});

it("an empty plan keeps the open intent and answers with its id (mutant: EMPTY_PLAN_CLEARS_OPEN)", async () => {
  const r = await publishedBase();
  r.gateway.beforePost = async (request) => {
    if (parseScope(request.scope)?.kind === "stream") {
      throw new Error("registry down");
    }
  };
  const first = await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();
  expect((await persistedState(r)).deletes?.[CONNECTOR]?.id).toBe(
    first.deleteId,
  );
  // The registry now lists nothing of the connector; the landing is still owed.
  r.gateway.listControlRows = async () => [];
  r.gateway.listStreamRows = async () => [];
  const second = await r.writer.requestConnectionDelete(CONNECTOR);
  expect(second.deleteId).toBe(first.deleteId);
  expect((await persistedState(r)).deletes?.[CONNECTOR]?.id).toBe(
    first.deleteId,
  );
});

it("refuses a pinned connector with no stream rows and no declared names, and persists no intent", async () => {
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  await r.collect({ ...spec("base"), otherDevice: true });
  await r.publish();
  r.gateway.listStreamRows = async () => [];
  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).rejects.toBeInstanceOf(ConnectorNotVerifiedError);
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("a repeated request for a delete in flight answers its id even when the manifest is no longer verified (mutant: PLAN_BEFORE_OPEN_INTENT)", async () => {
  const declared = ["items"];
  const r = new Rig(undefined, CONNECTOR, declared);
  await r.open();
  await r.collect({ ...spec("base"), otherDevice: true });
  await r.publish();
  r.gateway.beforePost = async (request) => {
    if (parseScope(request.scope)?.kind === "stream") {
      throw new Error("registry down");
    }
  };
  const first = await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();
  // The host restarts before its manifests verify: no names are declared.
  declared.length = 0;
  // The registry lists no stream row either: only the open intent answers.
  r.gateway.listStreamRows = async () => [];
  const second = await r.writer.requestConnectionDelete(CONNECTOR);
  expect(second.deleteId).toBe(first.deleteId);
  expect((await persistedState(r)).deletes?.[CONNECTOR]?.id).toBe(
    first.deleteId,
  );
});
