/**
 * The delete's declared names come from the host. A connector the host no
 * longer verifies (uninstalled, its manifest not retained) is deleted when the
 * host names its streams; without names the delete refuses and writes nothing.
 * A staged seed of a connector with no registry rows is erased too, so it
 * cannot return after a reconnect.
 */
import { expect, it } from "vitest";
import { ConnectorNotVerifiedError } from "./writer.js";
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

async function persistedState(r: Rig) {
  const bytes = await r.files.read("state.json");
  return bytes ? JSON.parse(new TextDecoder().decode(bytes)) : {};
}

it("an uninstalled connector with rows, whose streams come only from the host's declared names, deletes cleanly (202, then nothing remains)", async () => {
  // No manifest is verified for the connector: `items` is named by the host.
  const r = new Rig(undefined, CONNECTOR, ["items"]);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });

  const answered = await r.writer.requestConnectionDelete(CONNECTOR);
  expect(answered).not.toBeNull();
  await r.publish();

  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    recordCount: 0,
  });
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("without declared names, an uninstalled connector with rows is refused and nothing is deleted (503 CONNECTOR_NOT_VERIFIED)", async () => {
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  const posts = r.gateway.log.length;

  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).rejects.toBeInstanceOf(ConnectorNotVerifiedError);
  expect(r.gateway.log).toHaveLength(posts);
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("a staged seed of a connector with no registry rows does not return after a delete and a reconnect (mutant: ROWLESS_DECLARED_STREAM_UNFENCED)", async () => {
  // The host has staged a seed for the connector. The first identified run is
  // collected but never published, so the registry has no row and no control.
  const r = new Rig({
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
  });
  await r.open();
  await r.collect({ ...spec("unpublished"), userConnect: true });

  await r.writer.deleteConnection(CONNECTOR);
  await r.collect({ ...spec("learn"), userConnect: true });
  await r.publish();

  // The staged seed is not published: no row for `seed` exists.
  expect(await r.registeredHead("seed")).toBeNull();
});
