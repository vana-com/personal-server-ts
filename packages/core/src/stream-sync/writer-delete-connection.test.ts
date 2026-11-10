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
import { ask } from "../stream-sync-read/service-fixture.js";
import { manifestStreamLister } from "./artifacts.js";
import { ConnectorNotVerifiedError } from "./writer.js";
import {
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  createStreamSyncKeyPorts,
  StreamSyncWriter,
} from "./index.js";
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
      format: 4,
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
      format: 4,
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

const BOTH = ["alpha", "beta"] as const;
/** One run that writes both streams. */
const bothStreams = (runId: string, extra: Partial<RunSpec> = {}): RunSpec => ({
  ...spec(runId),
  stream: BOTH[0],
  also: [
    { stream: BOTH[1], key: "id", version: "1.0.0", rows: [{ id: runId }] },
  ],
  ...extra,
});
async function publishedBoth() {
  const r = new Rig();
  await r.open();
  await r.collect(bothStreams("base"));
  await r.publish();
  return r;
}
async function expectReborn(r: Rig, versions: number[]) {
  for (const [i, stream] of BOTH.entries()) {
    expect(await r.registeredVersion(stream)).toBe(versions[i]);
    // The reconnect's records are still there, and no delete head follows them.
    const head = await r.registeredHead(stream);
    expect(head?.recordCount).toBeGreaterThan(0);
    expect(head?.lastDeleteVersion).toBeLessThan(versions[i]!);
  }
}

it("a resume does not erase a reconnect made on another device (mutant: RESUME_REDELETES_AFTER_FOREIGN_RECONNECT)", async () => {
  const r = await publishedBoth();
  // A's first stream delete never reaches the registry; A keeps its intent.
  r.gateway.beforePost = async () => {
    r.gateway.beforePost = undefined;
    throw new AmbiguousRegistryReplyError("no reply");
  };
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toThrow(
    "no reply",
  );
  // B deletes the connection, reconnects and publishes new data on both streams.
  await r.other.deleteConnection(CONNECTOR);
  const onB = { otherDevice: true, userConnect: true };
  await r.collect(bothStreams("learn", onB));
  await r.collect(bothStreams("reborn", onB));
  expect(await control(r)).toMatchObject({ version: 3, deleted: false });
  const versions = [
    await r.registeredVersion("alpha"),
    await r.registeredVersion("beta"),
  ];
  await r.restart();
  await r.publish();
  await expectReborn(r, versions);
  expect(await control(r)).toMatchObject({ version: 3, deleted: false });
  const state = JSON.parse(
    new TextDecoder().decode((await r.files.read("state.json"))!),
  );
  expect(state.deletes ?? {}).toEqual({});
});

it("a resume skips a stream already deleted before the intent, so a reconnect keeps its data (guard: streamsLanded)", async () => {
  const r = await publishedBoth();
  await r.writer.deleteConnection(CONNECTOR);
  // Connect again on this device; only `alpha` gets new data, `beta` stays deleted.
  const connect = { userConnect: true };
  await r.collect({ ...spec("learn"), ...connect, stream: "alpha" });
  await r.publish();
  await r.collect({ ...spec("alive"), ...connect, stream: "alpha" });
  await r.publish();
  // The other device deletes again: `beta` is already deleted, so it is not
  // signed. The control tombstone commits and its reply is lost.
  r.gateway.afterPost = async (request) => {
    if (parseScope(request.scope)?.kind !== "control") return;
    r.gateway.afterPost = undefined;
    throw new AmbiguousRegistryReplyError("reply lost after commit");
  };
  await expect(r.other.deleteConnection(CONNECTOR)).rejects.toThrow(
    "reply lost after commit",
  );
  // This device connects again and writes both streams; then the delete resumes.
  await r.collect(bothStreams("learn2", connect));
  await r.publish();
  await r.collect(bothStreams("reborn", connect));
  await r.publish();
  const versions = [
    await r.registeredVersion("alpha"),
    await r.registeredVersion("beta"),
  ];
  await r.other.publishPending();
  await expectReborn(r, versions);
});

it("a seed with no registry row does not return after a reconnect (mutant: SEED_SURVIVES_DELETE)", async () => {
  const r = new Rig({
    stream: "seed",
    key: "id",
    version: "1.0.0",
    rows: [{ id: "old" }],
  });
  await r.open();
  await r.collect(spec("theirs", true));
  await r.writer.deleteConnection(CONNECTOR);
  await r.collect({ ...spec("learn"), userConnect: true });
  await r.publish();
  await r.collect({ ...spec("again"), userConnect: true });
  await r.publish();
  expect(await r.registeredHead("seed")).toBeNull();
  expect((await r.writer.seedStatus(CONNECTOR)).skipped).toEqual([
    { stream: "seed", upload: "upload-1" },
  ]);
});

it("a head that lands under the old generation after the listing is not served after a reconnect", async () => {
  const r = await publishedBase();
  // After A listed its streams, the other device writes a new stream.
  r.gateway.beforePost = async () => {
    r.gateway.beforePost = undefined;
    await r.collect({ ...spec("late", true), stream: "late" });
  };
  await r.writer.deleteConnection(CONNECTOR);
  expect(await r.registeredVersion("late")).toBe(1);
  expect(await r.registeredHead("late")).toMatchObject({ recordCount: 1 });
  await r.collect({ ...spec("learn", true), userConnect: true });
  await r.collect({ ...spec("reborn", true), userConnect: true });
  expect(await control(r)).toMatchObject({ version: 3, deleted: false });
  await r.sync();
  const served = await r.service.resolve(ask("pdpp.acme.late"));
  expect(["view", "local_pending"]).not.toContain(served.kind);
  const items = await r.service.resolve(ask("pdpp.acme.items"));
  expect(items.kind).toBe("view");
});

/**
 * A connection deleted on device B; device A's delete starts after it. While A
 * works, B reconnects and publishes. `when` names the stream-row read of A at
 * which the reconnect lands: the 1st is the registry listing, the 2nd is the
 * read that A signs over.
 */
async function reconnectDuringDelete(when: 1 | 2) {
  const r = await publishedBase();
  await r.other.deleteConnection(CONNECTOR);
  expect(await control(r)).toMatchObject({ version: 2 });
  let reads = 0;
  r.gateway.beforeRead = async (scope) => {
    if (parseScope(scope)?.kind !== "stream") return;
    reads += 1;
    if (reads !== when) return;
    r.gateway.beforeRead = undefined;
    const onB = { otherDevice: true, userConnect: true };
    await r.collect({ ...spec("learn", true), ...onB });
    await r.collect({ ...spec("reborn", true), ...onB });
  };
  await r.writer.deleteConnection(CONNECTOR);
  expect(reads).toBe(when);
  return r;
}

it("a reconnect between the delete's control check and its stream read is not erased (mutant: CONTROL_READ_BEFORE_ROW)", async () => {
  const r = await reconnectDuringDelete(2);
  expect(await control(r)).toMatchObject({ version: 3, deleted: false });
  // Both runs of the reconnect are still there, and no delete head follows them.
  expect(await r.registeredHead()).toMatchObject({
    recordCount: 2,
    lastDeleteVersion: 2,
  });
});

it("a reconnect between the delete's control pin and its stream listing is not erased (mutant: STREAM_PIN_FROM_LATER_READ)", async () => {
  const r = await reconnectDuringDelete(1);
  expect(await control(r)).toMatchObject({ version: 3, deleted: false });
  expect(await r.registeredHead()).toMatchObject({
    recordCount: 2,
    lastDeleteVersion: 2,
  });
});

it("a delete with nothing in the registry still stops what this device collected (mutant: EMPTY_REGISTRY_DELETE_KEEPS_LOCAL)", async () => {
  const r = new Rig(
    { stream: "seed", key: "id", version: "1.0.0", rows: [{ id: "old" }] },
    CONNECTOR,
    ["items"],
  );
  await r.open();
  // Collected while the registry was out of reach: nothing is registered yet.
  await r.collect(spec("offline"));
  expect(r.gateway.log).toHaveLength(0);
  const seedTargets = async () =>
    JSON.parse(new TextDecoder().decode((await r.files.read("state.json"))!))
      .seedTargets;
  expect(Object.keys(await seedTargets())).toContain(CONNECTOR);
  await r.writer.deleteConnection(CONNECTOR);
  expect(await r.files.list("runs")).toEqual([]);
  expect(await r.files.list("results")).toEqual([]);
  expect(await seedTargets()).toEqual({});
  // A connection that never reached the registry gets no delete head, even
  // for a declared stream: there is nothing to fence.
  expect(r.gateway.log).toHaveLength(0);
  await r.publish();
  expect(r.gateway.log).toHaveLength(0);
});

it("a declared stream with no registry row gets a delete head, so an old record of it cannot publish (mutant: ROWLESS_IMPORT_RESURRECTS)", async () => {
  const r = new Rig(undefined, CONNECTOR, ["items", "extra"]);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  // A record of `extra` collected before the delete (collectedAt 0), unpublished.
  await r.collect({ ...spec("stale"), stream: "extra" });
  expect(await r.registeredHead("extra")).toBeNull();
  // The delete heads land; the control row is still active, so only the stream
  // fence stands between the old record and the registry.
  await r.deleteStreamHeadsOnly(r.other);
  expect(await r.registeredHead("extra")).toMatchObject({
    format: 4,
    recordCount: 0,
    lastDeleteVersion: 1,
  });
  const statuses = await r.publish();
  expect(statuses.find((s) => s.runId === "stale")?.outcome).toMatchObject({
    kind: "discarded",
  });
  expect(await r.registeredHead("extra")).toMatchObject({ recordCount: 0 });
});

it("the rowless streams come from the verified manifest: an old record of one cannot publish after a delete (mutant: DECLARED_OMITTED)", async () => {
  // The names are the host's `manifestStreamLister` over the manifest it
  // verified, not a list typed into the test.
  const manifest = JSON.stringify({
    connector_key: CONNECTOR,
    version: "1.0.0",
    streams: [
      { name: "items", primary_key: ["id"] },
      { name: "extra", primary_key: ["id"] },
    ],
  });
  const declared = manifestStreamLister([manifest])(CONNECTOR);
  expect(declared).toEqual(["items", "extra"]);
  const r = new Rig(undefined, CONNECTOR, declared);
  await r.open();
  await r.collect(spec("base"));
  await r.publish();
  // An unknown-start record of `extra`: a retained or imported one, which the
  // registry has no row for.
  await r.collect({ ...spec("legacy"), stream: "extra" });
  expect(await r.registeredHead("extra")).toBeNull();
  await r.deleteStreamHeadsOnly(r.other);
  expect(await r.registeredHead("extra")).toMatchObject({
    format: 4,
    lastDeleteVersion: 1,
  });
  await r.sync();
  const statuses = await r.publish();
  expect(statuses.find((s) => s.runId === "legacy")?.outcome).toMatchObject({
    kind: "discarded",
  });
  expect(await r.registeredHead("extra")).toMatchObject({ recordCount: 0 });
});

it("a writer built without declaredStreams is refused, so a host cannot forget the rowless streams (mutant: DECLARED_UNCHECKED)", () => {
  const rig = new Rig();
  const options = {
    ownerAddress: `0x${"11".repeat(20)}` as const,
    registry: rig.gateway,
    blobs: { put: async () => {}, get: async () => null },
    home: bindStreamSyncHome({
      ownerAddress: `0x${"11".repeat(20)}`,
      network: "test",
      open: () => createMemoryStreamSyncFiles(),
    }),
    keys: createStreamSyncKeyPorts(`0x${"1f".repeat(32)}${"2a".repeat(32)}1b`),
    signer: { signAddData: async () => `0x${"22".repeat(65)}` as const },
  };
  expect(() => new StreamSyncWriter(options as never)).toThrow(
    "needs declaredStreams",
  );
  expect(
    () => new StreamSyncWriter({ ...options, declaredStreams: () => [] }),
  ).not.toThrow();
});

it("refuses a pinned connector with no stream rows and no declared names, and writes nothing (mutant: EMPTY_DECLARED_ACCEPTED)", async () => {
  // The host verified no manifest for this connector, so it cannot name the
  // streams a delete must fence. With no stream row either, the pin alone
  // names nothing: deleting anyway would leave a rowless stream open to an old
  // record after a reconnect.
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  await r.collect({ ...spec("base"), otherDevice: true });
  await r.publish();
  r.gateway.listStreamRows = async () => [];
  const posts = r.gateway.log.length;
  await expect(r.writer.deleteConnection(CONNECTOR)).rejects.toBeInstanceOf(
    ConnectorNotVerifiedError,
  );
  expect(r.gateway.log).toHaveLength(posts);
  expect(await r.registeredHead()).toMatchObject({ recordCount: 1 });
  const state = JSON.parse(
    new TextDecoder().decode((await r.files.read("state.json"))!),
  );
  expect(state.deletes ?? {}).toEqual({});
  expect(await control(r)).toMatchObject({ deleted: false });
});

it("a connector with nothing in the registry is still deleted without declared names", async () => {
  const r = new Rig(undefined, CONNECTOR, []);
  await r.open();
  await r.collect(spec("offline"));
  await r.writer.deleteConnection(CONNECTOR);
  expect(await r.files.list("runs")).toEqual([]);
});
