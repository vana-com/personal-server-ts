/**
 * The delete's declared names come from the host. A connector the host no
 * longer verifies (uninstalled, its manifest not retained) is deleted when the
 * host names its streams; without names the delete refuses and writes nothing.
 * A staged seed of a connector with no registry rows is erased too, so it
 * cannot return after a reconnect.
 */
import { expect, it } from "vitest";
import type { StreamSyncWriter } from "./writer.js";
import { ConnectorNotVerifiedError } from "./writer.js";
import {
  Rig,
  CONNECTOR,
  type RunSpec,
  type SeedRows,
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

const staleSeed = (): SeedRows => ({
  stream: "seed",
  key: "id",
  version: "1.0.0",
  rows: [{ id: "old" }],
  upload: "upload-1",
});

/**
 * Crash the writer right after its `n`th state write, so the delete throws at
 * that point and the driver is abandoned, as a process crash would leave it.
 */
function crashAfterStateWrite(writer: StreamSyncWriter, n: number) {
  const target = writer as unknown as {
    withState: (...args: unknown[]) => Promise<unknown>;
  };
  const original = target.withState.bind(writer);
  let writes = 0;
  target.withState = async (...args: unknown[]) => {
    const result = await original(...args);
    writes += 1;
    if (writes === n) throw new Error(`crash after state write ${n}`);
    return result;
  };
}

it.each([1, 2, 3])(
  "a crash after state write %s of a rowless delete does not publish the staged seed after restart (mutant: SKIP_AFTER_PURGE)",
  async (n) => {
    const r = new Rig(staleSeed());
    await r.open();
    await r.collect({ ...spec("unpublished"), userConnect: true });
    crashAfterStateWrite(r.writer, n);
    await expect(r.writer.requestConnectionDelete(CONNECTOR)).rejects.toThrow(
      `crash after state write ${n}`,
    );
    await r.restart();
    await r.collect({ ...spec("learn"), userConnect: true });
    await r.publish();
    expect(await r.registeredHead("seed")).toBeNull();
  },
);

it("a new seed staged after a delete publishes on reconnect (mutant: SKIP_BY_STREAM)", async () => {
  const seed = staleSeed();
  const r = new Rig(seed);
  await r.open();
  await r.collect({ ...spec("unpublished"), userConnect: true });
  await r.writer.deleteConnection(CONNECTOR);
  // The host stages a new upload for the same stream.
  seed.upload = "upload-2";
  seed.rows = [{ id: "new" }];
  await r.collect({ ...spec("learn"), userConnect: true });
  await r.publish();
  expect(await r.registeredHead("seed")).toMatchObject({ recordCount: 1 });
});
