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

const retainedManifest = JSON.stringify({
  connector_key: CONNECTOR,
  version: "1.0.0",
  streams: [{ name: "items", primary_key: ["id"] }],
});

it("a connector with rows and a retained declaration deletes when the host names nothing (202, nothing readable; mutant: RETAINED_DECLARATION_DROPPED)", async () => {
  // The host passes no declared names. The registry's stream list is emptied
  // too, so the retained manifest is the only source of `items`.
  const r = new Rig(undefined, CONNECTOR, [], [retainedManifest]);
  await r.open();
  await r.collect({ ...spec("base"), otherDevice: true });
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });
  r.gateway.listStreamRows = async () => [];

  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({
    deleteId: expect.any(String),
  });
  await r.publish();

  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    recordCount: 0,
  });
  expect((await persistedState(r)).deletes ?? {}).toEqual({});
});

it("the host's declared names and a retained manifest's streams are both fenced, each once (mutant: DECLARED_STREAMS_NOT_UNIONED)", async () => {
  // `other` has a row, so the delete is planned. `items` is named only by the
  // retained manifest and `extra` only by the host; neither has a row yet.
  const r = new Rig(undefined, CONNECTOR, ["extra"], [retainedManifest]);
  await r.open();
  await r.collect({ ...spec("base"), stream: "other" });
  await r.publish();

  await r.writer.requestConnectionDelete(CONNECTOR);
  await r.publish();

  expect(await r.registeredHead("items")).toMatchObject({
    format: 3,
    recordCount: 0,
  });
  expect(await r.registeredHead("extra")).toMatchObject({
    format: 3,
    recordCount: 0,
  });
});

it("rows written under a declaration, then a restart with the connector removed from config: the delete answers 202 and nothing stays readable", async () => {
  // The declaration names `items`. The writer records it with the first row.
  const r = new Rig(undefined, CONNECTOR, ["items"]);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });

  // The connector leaves config: neither the host nor a manifest names it.
  r.setConfig([], []);
  await r.restart();

  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await r.publish();

  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    recordCount: 0,
  });
});

it("pre-change rows (no durable name, connector absent from config) delete with 202 and tombstone the rows (mutant: PRECHANGE_ROWS_REFUSED)", async () => {
  // Rows from another device, whose declaration this writer never recorded:
  // the state an upgrade leaves behind: no name was ever recorded for them.
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  await r.collect({ ...spec("base"), otherDevice: true });
  await r.publish();

  // Restart with the connector absent from config: no host name, no manifest.
  r.setConfig([], []);
  await r.restart();

  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({
    format: 3,
    recordCount: 0,
  });
});

it("rows appended under a declaration and never published: after a restart without the connector, the delete answers 202 and no later publish brings them back", async () => {
  // The run appends under the declaration, then stops before finishRun: no
  // registry row exists, so only the durable name can fence the stream.
  const r = new Rig(undefined, CONNECTOR, ["items"]);
  await r.open();
  await r.collectUnfinished(spec("interrupted"));

  r.setConfig([], []);
  await r.restart();
  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await r.publish();
  await r.publish();

  const { pending, finished } = await r.writer.status();
  expect(pending).toEqual([]);
  expect(
    finished
      .flatMap((run) => Object.values(run.streams))
      .filter((s) => s.state === "committed"),
  ).toEqual([]);
  expect((await r.registeredHead())?.recordCount ?? 0).toBe(0);

  // Resume: a new run publishes its own rows and nothing else.
  await r.collect(spec("learn"));
  await r.publish();
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });
});

it("rows appended under a declaration, run still collecting when the delete lands: a later finish is refused and nothing publishes (mutant: UNFINISHED_RUN_STREAMS_IGNORED)", async () => {
  // The same process deletes while the run is open. The purge of the run is
  // the only fence: a finish after it must be refused, and nothing publishes.
  const r = new Rig(undefined, CONNECTOR, ["items"]);
  await r.open();
  await r.collectUnfinished(spec("open"));
  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).resolves.toMatchObject({ deleteId: expect.any(String) });
  await expect(
    r.writer.finishRun("open", { checkpointCandidate: { cursor: "open" } }),
  ).rejects.toThrow();
  await r.publish();
  await r.publish();

  expect(await r.files.list("runs")).toEqual([]);
  expect((await r.registeredHead())?.recordCount ?? 0).toBe(0);
});

it("a pinned connector with no stream rows and no declared names is refused (503 CONNECTOR_NOT_VERIFIED) and nothing is deleted", async () => {
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  await r.collect({ ...spec("base"), otherDevice: true });
  await r.publish();
  // The registry keeps the control pin but lists no stream row.
  r.gateway.listStreamRows = async () => [];
  const posts = r.gateway.log.length;

  await expect(
    r.writer.requestConnectionDelete(CONNECTOR),
  ).rejects.toBeInstanceOf(ConnectorNotVerifiedError);
  expect(r.gateway.log).toHaveLength(posts);
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

/**
 * A stream with registry rows, deleted, then a seed for the same stream on
 * reconnect. The seed object is the rig's staged upload: changing its `upload`
 * after the delete models the host staging a new upload.
 */
async function seedAfterRowsDelete(seed: SeedRows) {
  seed.staged = false;
  const r = new Rig(seed);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  expect(await r.registeredHead("items")).toMatchObject({ recordCount: 1 });
  // The upload is staged after the rows exist, and before the delete.
  seed.staged = true;
  await r.writer.deleteConnection(CONNECTOR);
  return r;
}

it("a seed staged before a delete with rows does not publish on reconnect", async () => {
  const seed: SeedRows = {
    stream: "items",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
    upload: "upload-1",
  };
  const r = await seedAfterRowsDelete(seed);
  await r.collect({ ...spec("learn"), userConnect: true });
  await r.publish();
  expect(await r.registeredHead("items")).toMatchObject({ recordCount: 1 });
});

it("a seed offered after a delete with rows is refused at a later generation: its status reads seed_skipped, nothing publishes, and an ordinary run then publishes (mutant: SEED_APPLIES_AFTER_DELETE)", async () => {
  const seed: SeedRows = {
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
    upload: "upload-1",
  };
  const r = await seedAfterRowsDelete(seed);
  // The host stages a new upload for the seed after the delete.
  seed.upload = "upload-2";
  seed.rows = [{ id: "seeded" }];
  await r.collect({ ...spec("learn"), userConnect: true });
  const runs = await r.publish();

  const statuses = runs.flatMap((run) => Object.entries(run.streams));
  expect(statuses).toContainEqual([
    "seed",
    expect.objectContaining({ terminal: "seed_skipped" }),
  ]);
  expect(await r.registeredHead("seed")).toBeNull();
  // The ordinary run publishes its own rows at the new generation.
  expect(await r.registeredHead("items")).toMatchObject({ recordCount: 1 });
});

it("a new upload staged after another device's stream delete publishes; the upload the delete saw does not (mutant: DELETE_SKIP_BY_STREAM)", async () => {
  const seed: SeedRows = {
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
    upload: "upload-1",
  };
  const r = new Rig(seed);
  await r.open();
  await r.collect({ ...spec("theirs", true), stream: "seed" });
  await r.deleteStreamHeadsOnly(r.other);
  await r.sync();
  await r.collect({ ...spec("learn"), userConnect: true });
  await r.publish();
  expect(await r.registeredHead("seed")).toMatchObject({ recordCount: 0 });

  seed.upload = "upload-2";
  seed.rows = [{ id: "new" }];
  await r.collect({ ...spec("next"), stream: "seed" });
  await r.publish();
  expect(await r.registeredHead("seed")).toMatchObject({ recordCount: 2 });
});
