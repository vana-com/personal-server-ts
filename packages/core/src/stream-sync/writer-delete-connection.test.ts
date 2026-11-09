/**
 * The connection delete is the one delete path (§2.11). It erases every
 * stream row of the connector the registry lists, then tombstones the control
 * rows. These tests pin its recovery rule: a stream delete is done only when
 * the row's delete history reaches the pin; otherwise it is issued again on
 * top of whatever another device published since.
 */
import { expect, it } from "vitest";
import {
  controlScope,
  parseScope,
} from "@opendatalabs/personal-server-ts-stream-sync";
import { AmbiguousRegistryReplyError } from "./ports.js";
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
const control = (r: Rig) => r.gateway.read(controlScope(CONNECTOR, ""));

/** The first stream post of a delete is lost before it commits. */
function loseStreamPostOnce(r: Rig) {
  r.gateway.beforePost = async (request) => {
    if (parseScope(request.scope)?.kind !== "stream") return;
    r.gateway.beforePost = undefined;
    throw new Error("post lost");
  };
}

async function publishedBase() {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  return r;
}

/** Another device publishes `count` runs on top of the pinned version. */
async function otherPublishes(r: Rig, count: number) {
  for (let i = 1; i <= count; i += 1) await r.collect(spec(`b${i}`, true));
}

it.each([1, 2])(
  "a delete whose post was lost is re-issued after %s publish(es) by another device (mutants: DROP_WHEN_PAST_PIN, REDELETE_POLICY_SPLIT)",
  async (publishes) => {
    const r = await publishedBase();
    loseStreamPostOnce(r);
    await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
      "post lost",
    );
    await otherPublishes(r, publishes);
    const moved = 1 + publishes;
    expect(await r.registeredVersion()).toBe(moved);
    await r.restart();
    await r.publish();
    // The user's delete wins: one delete head on top of the other device's rows.
    expect(await r.registeredVersion()).toBe(moved + 1);
    expect(await r.registeredHead()).toMatchObject({
      format: 3,
      lastDeleteVersion: moved + 1,
      recordCount: 0,
    });
    expect(await control(r)).toMatchObject({ version: 2, deleted: false });
    const state = JSON.parse(
      new TextDecoder().decode((await r.files.read("state.json"))!),
    );
    expect(state.deletes ?? {}).toEqual({});
  },
);

it("a delete that landed is not issued again after a later publish (mutant: DELETE_LANDED_REISSUED)", async () => {
  const r = await publishedBase();
  r.gateway.afterPost = async (request) => {
    if (parseScope(request.scope)?.kind !== "stream") return;
    r.gateway.afterPost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost after commit");
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "reply lost after commit",
  );
  expect(await r.registeredVersion()).toBe(2);
  // The other device learns the delete, then collects again from the source.
  await r.collect(spec("learn", true));
  await r.collect(spec("fresh", true));
  const published = await r.registeredVersion();
  expect(published).toBe(3);
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(published);
  expect(await r.registeredHead()).toMatchObject({
    lastDeleteVersion: 2,
    recordCount: 1,
  });
});

it("a reconnect after the control tombstone keeps its data (mutant: RECONNECT_TOMBSTONED)", async () => {
  const r = await publishedBase();
  // The tombstone commits, the reply is lost: the intent stays open.
  r.gateway.afterPost = async (request) => {
    if (parseScope(request.scope)?.kind !== "control") return;
    r.gateway.afterPost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost after commit");
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "reply lost after commit",
  );
  expect(await control(r)).toMatchObject({ version: 2 });
  // An explicit connect on the other device starts a new generation.
  await r.collect({ ...spec("learn", true), userConnect: true });
  await r.collect({ ...spec("reborn", true), userConnect: true });
  expect(await control(r)).toMatchObject({ version: 3 });
  const published = await r.registeredVersion();
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(published);
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });
  expect(await control(r)).toMatchObject({ version: 3 });
  const state = JSON.parse(
    new TextDecoder().decode((await r.files.read("state.json"))!),
  );
  expect(state.deletes ?? {}).toEqual({});
});

it("a stream only another device wrote is deleted (mutant: UNSEEN_STREAM_SURVIVES)", async () => {
  const r = await publishedBase();
  await r.collect({ ...spec("theirs", true), stream: "extra" });
  expect(await r.registeredVersion("extra")).toBe(1);
  await r.writer.deleteConnection(CONNECTOR);
  for (const stream of ["items", "extra"]) {
    expect(await r.registeredHead(stream)).toMatchObject({
      format: 3,
      recordCount: 0,
      lastDeleteVersion: 2,
    });
  }
  expect(await control(r)).toMatchObject({ version: 2 });
});

it("stream deletes land before the control tombstone (mutant: RECONNECT_TOMBSTONED)", async () => {
  const r = await publishedBase();
  const order: string[] = [];
  const before = r.gateway.afterPost;
  r.gateway.afterPost = async (request) => {
    order.push(parseScope(request.scope)?.kind ?? "other");
    await before?.(request);
  };
  await r.writer.deleteConnection(CONNECTOR);
  expect(order).toEqual(["stream", "control"]);
});

it("deleting twice writes nothing the second time", async () => {
  const r = await publishedBase();
  await r.writer.deleteConnection(CONNECTOR);
  const posts = r.gateway.log.length;
  await r.writer.deleteConnection(CONNECTOR);
  expect(r.gateway.log).toHaveLength(posts);
});
