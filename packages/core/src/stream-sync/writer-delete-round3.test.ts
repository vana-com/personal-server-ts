import { deleteMetadataHash } from "./delete-metadata.js";
import { publicationMetadataHash } from "../publication/publish.js";
import { ask, body } from "../stream-sync-read/service-fixture.js";
import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { expect, it } from "vitest";
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
it("republishes a login-keyed stream at the same connector version (mutant: DELETE_HEAD_AS_BASE)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect({
    ...spec("base-login"),
    key: "login",
    rows: [{ login: "base" }],
  });
  await r.publish();
  await r.writer.deleteStreams(CONNECTOR, ["items"]);
  await r.collect({
    ...spec("fresh"),
    key: "login",
    rows: [{ login: "fresh" }],
  });
  expect(
    (await r.publish()).find((s) => s.runId === "fresh")?.outcome?.kind,
  ).toBe("checkpointed");
  expect(await r.registeredHead()).toMatchObject({
    primaryKey: ["login"],
    recordCount: 1,
    lastDeleteVersion: 2,
  });
});
it("ambiguous delete replay preserves a newer publish (mutant: REPLAY_REDELETES)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  r.gateway.afterPost = async () => {
    r.gateway.afterPost = undefined;
    throw new Error("reply lost");
  };
  await expect(r.writer.deleteStreams(CONNECTOR, ["items"])).rejects.toThrow(
    "reply lost",
  );
  await r.collect(spec("learn", true));
  await r.collect(spec("fresh", true));
  expect(await r.registeredVersion()).toBe(3);
  const hash = (await r.registeredHead())!;
  await r.restart();
  await r.publish();
  expect(await r.registeredVersion()).toBe(3);
  expect(await r.registeredHead()).toEqual(hash);
});

it("missing delete-head blob still reads deleted (mutant: FLOOR_ONLY_FROM_HEAD)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.sync();
  await r.other.deleteStreams(CONNECTOR, ["items"]);
  const scope = streamScope(CONNECTOR, "", "items");
  const row = await r.gateway.read(scope);
  if (!row.found) throw new Error("missing delete");
  r.blobMap.delete(`${scope}/h-${row.dataHash.slice(2)}`);
  await r.sync();
  expect(await r.service.resolve(ask("pdpp.acme.items"))).toMatchObject({
    kind: "unavailable",
    reason: "deleted",
  });
  await r.collect(spec("after-observation"));
  expect(
    (await r.publish()).find((s) => s.runId === "after-observation")?.outcome
      ?.kind,
  ).toBe("checkpointed");
});
it("an ordinary missing head keeps the previous readable view", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  await r.sync();
  await r.collect(spec("fresh", true));
  const scope = streamScope(CONNECTOR, "", "items");
  const row = await r.gateway.read(scope);
  if (!row.found) throw new Error("missing row");
  r.blobMap.delete(`${scope}/h-${row.dataHash.slice(2)}`);
  await r.sync();
  const read = await r.service.resolve(ask("pdpp.acme.items"));
  expect(read.kind).toBe("view");
  if (read.kind !== "view") throw new Error(read.kind);
  expect((await body(read)).data.records).toEqual([{ id: "base" }]);
});
it.each([
  ["github", "user"],
  ["icloud-notes", "folders"],
])(
  "refuses shared %s/%s before saving intent (mutant: SHARED_STREAM_DELETED)",
  async (connector, stream) => {
    const r = new Rig(undefined, connector);
    await r.open();
    await expect(r.writer.deleteStreams(connector, [stream])).rejects.toThrow(
      /shared/,
    );
    expect(r.gateway.log).toEqual([]);
    const state = await r.files.read("state.json");
    expect(
      state && JSON.parse(new TextDecoder().decode(state)).streamDeletes,
    ).toBeFalsy();
  },
);

it("delete metadata binds scope and version in its own hash domain", () => {
  const scope = streamScope(CONNECTOR, "", "items");
  expect(deleteMetadataHash(scope, 2)).toBe(deleteMetadataHash(scope, 2));
  expect(deleteMetadataHash(scope, 2)).not.toBe(deleteMetadataHash(scope, 3));
  expect(deleteMetadataHash(scope, 2)).not.toBe(
    deleteMetadataHash(streamScope(CONNECTOR, "", "other"), 2),
  );
  expect(deleteMetadataHash(scope, 2)).not.toBe(
    publicationMetadataHash(scope, "2", 0),
  );
});

it("a new user delete replaces the superseded intent (mutant: NEW_DELETE_REUSES_OLD_PIN)", async () => {
  const r = new Rig();
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  r.gateway.afterPost = async () => {
    r.gateway.afterPost = undefined;
    throw new Error("reply lost");
  };
  await expect(r.writer.deleteStreams(CONNECTOR, ["items"])).rejects.toThrow(
    "reply lost",
  );
  await r.collect(spec("learn", true));
  await r.collect(spec("fresh", true));
  expect(await r.registeredVersion()).toBe(3);
  await r.writer.deleteStreams(CONNECTOR, ["items"]);
  expect(await r.registeredVersion()).toBe(4);
  expect(await r.registeredHead()).toMatchObject({
    lastDeleteVersion: 4,
    recordCount: 0,
  });
});
