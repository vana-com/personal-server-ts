// The legacy stage of a connection delete on a switched account, through the
// real deleter, the real seal and the real `deleteScope` worker, over a fake
// gateway that enforces cutover policy v3 (an exact tombstone over a live head,
// signed by the owner or a registered server) and a fake storage.
import { afterEach, describe, expect, it, vi } from "vitest";
import { logScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { LegacyWriteRefusedError } from "../../../core/src/api/legacy-write-gate.js";
import type {
  ConnectionDeleteStatus,
  DeleteBlockReason,
  LogErasurePorts,
} from "../../../core/src/localdb/index.js";
import { legacyScopesOfConnector } from "../../../core/src/legacy-projection/erase-connector.js";
import { legacyPortsOver } from "../../../core/src/test-utils/legacy-delete-ports.js";
import {
  createLegacyGatewayFake,
  FAKE_GATEWAY,
  type FakeCutover,
  type FakeSignerRole,
} from "../../../core/src/test-utils/legacy-gateway-fake.js";
import {
  CONNECTOR,
  OWNER,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const RETRY = { first: 5, max: 20 };
/** A connector with legacy scopes bound to it. */
const GH = "github";
const SCOPES = legacyScopesOfConnector(GH);
const PART_TARGET = 65536;
type World = Awaited<ReturnType<typeof world>>;

const DONE = { state: "done" } as const;
const PENDING = { state: "pending" } as const;
const blockedBy = (reason: DeleteBlockReason) =>
  ({ state: "blocked", reason }) as const;

/** The host's storage ports over a world: its gateway inventory and its storage. */
function erasurePorts(w: World): LogErasurePorts {
  return {
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
      tombstoneState: async () => ({
        finalized: "99",
        settling: false,
        rolledBack: null,
      }),
    },
    objects: {
      deleteBlobVersions: async (scope, names) => {
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
  };
}

/** A switched account whose `github` connection a device has collected and published. */
async function collected(
  options: {
    cutover?: FakeCutover;
    signer?: FakeSignerRole;
    big?: boolean;
  } & NonNullable<Parameters<typeof legacyPortsOver>[1]> = {},
) {
  const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
  const fake = createLegacyGatewayFake({
    owner: OWNER,
    cutover: options.cutover ?? "v3",
    signer: options.signer,
  });
  for (const scope of SCOPES) fake.seed(scope, 2);
  const legacy = await legacyPortsOver(fake, options);
  const a = await w.device("a", {
    erasure: () => erasurePorts(w),
    legacyDelete: () => legacy.ports,
    deleteRetryMs: RETRY,
  });
  await a.run(
    "run-1",
    [
      options.big
        ? { stream: sName(0), id: "big", pad: PART_TARGET * 2 + 1000 }
        : { stream: sName(0), id: "x", v: 0 },
    ],
    { connector: GH, observedAt: 1100 },
  );
  await a.cycle();
  return { w, a, fake, legacy };
}

const statusOf = (a: Awaited<ReturnType<World["device"]>>) =>
  a.sync.deleter.deleteStatus(GH);
const gatewayDeletes = (fake: ReturnType<typeof createLegacyGatewayFake>) =>
  fake.requests.filter(
    (r) => r.url.startsWith(FAKE_GATEWAY) && r.method === "DELETE",
  );
const allDone = (s: ConnectionDeleteStatus) =>
  s.fence.state === "done" &&
  s.legacy.state === "done" &&
  s.storage.state === "done";

describe("the legacy stage of a connection delete after the switch", () => {
  it("tombstones every bound legacy point through the seal, and the delete reads done in all three parts", async () => {
    expect(SCOPES.length).toBeGreaterThan(0);
    const { a, fake, legacy } = await collected();

    await a.sync.deleter.requestConnectionDelete(GH);

    await vi.waitFor(async () => expect(allDone(await statusOf(a))).toBe(true));
    for (const scope of SCOPES) {
      expect(fake.isLive(scope)).toBe(false);
      expect(fake.tombstones.get(scope)).toEqual([3]);
    }
    expect(legacy.retired.sort()).toEqual([...SCOPES].sort());
    // The removal is admitted; a legacy write that adds data still is not.
    await expect(
      legacy.seal.commit(async () => undefined),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
  });

  it("sends nothing while the control tombstone is not final, then retires once it is", async () => {
    const finality = {
      finalized: null as string | null,
      settling: true,
      rolledBack: null,
    };
    const { a, fake } = await collected({ finality: () => finality });

    await a.sync.deleter.requestConnectionDelete(GH);
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect(gatewayDeletes(fake)).toEqual([]);
    expect((await statusOf(a)).legacy).toEqual(PENDING);

    finality.finalized = "99";
    finality.settling = false;
    await vi.waitFor(async () =>
      expect((await statusOf(a)).legacy).toEqual(DONE),
    );
    expect(SCOPES.every((s) => !fake.isLive(s))).toBe(true);
  });

  it("answers blocked(tombstone_rolled_back) and sends nothing when the control tombstone failed", async () => {
    const { a, fake } = await collected({
      finality: {
        finalized: null,
        settling: false,
        rolledBack: {
          tombstoneVersion: "2",
          head: {
            expectedVersion: "1",
            dataHash: "0x00",
            metadataHash: "0x00",
          },
        },
      },
    });

    await a.sync.deleter.requestConnectionDelete(GH);

    await vi.waitFor(async () => {
      const s = await statusOf(a);
      expect(s.fence).toEqual(blockedBy("tombstone_rolled_back"));
      expect(s.legacy).toEqual(blockedBy("tombstone_rolled_back"));
    });
    expect(gatewayDeletes(fake)).toEqual([]);
  });

  it("leaves the legacy copy alone on an account that has not switched", async () => {
    const { a, fake } = await collected({ mode: "off" });

    await a.sync.deleter.requestConnectionDelete(GH);

    await vi.waitFor(async () =>
      expect((await statusOf(a)).storage).toEqual(DONE),
    );
    expect((await statusOf(a)).legacy).toEqual(DONE);
    expect(gatewayDeletes(fake)).toEqual([]);
    expect(SCOPES.every((s) => fake.isLive(s))).toBe(true);
  });

  it("sends nothing for a connection that was never published, and does not wait on it", async () => {
    const w = await world({ streams: 1 });
    const fake = createLegacyGatewayFake({ owner: OWNER, cutover: "v3" });
    for (const scope of SCOPES) fake.seed(scope, 2);
    const legacy = await legacyPortsOver(fake);
    const a = await w.device("a", {
      erasure: () => erasurePorts(w),
      legacyDelete: () => legacy.ports,
      deleteRetryMs: RETRY,
    });

    const answer = await a.sync.deleter.requestConnectionDelete(GH);

    expect(answer.fenced).toBe(true);
    await vi.waitFor(async () => expect(allDone(await statusOf(a))).toBe(true));
    expect(fake.requests).toEqual([]);
  });

  it("does nothing for a connector with no legacy scope bound to it", async () => {
    const w = await world({ streams: 1 });
    const fake = createLegacyGatewayFake({ owner: OWNER, cutover: "v3" });
    const legacy = await legacyPortsOver(fake);
    const a = await w.device("a", {
      erasure: () => erasurePorts(w),
      legacyDelete: () => legacy.ports,
      deleteRetryMs: RETRY,
    });
    await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
      observedAt: 1100,
    });
    await a.cycle();

    await a.sync.deleter.requestConnectionDelete(CONNECTOR);

    await vi.waitFor(async () =>
      expect(allDone(await a.sync.deleter.deleteStatus(CONNECTOR))).toBe(true),
    );
    expect(fake.requests).toEqual([]);
  });

  describe("a gateway answer that a retry cannot change", () => {
    it.each([
      ["a policy-v1 owner", "v1", "server", "owner_stream_sync_required"],
      ["a revoked server key", "v3", "revoked", "server_revoked"],
      [
        "an unregistered server key",
        "v3",
        "unregistered",
        "server_unregistered",
      ],
    ] as const)(
      "%s is blocked(%s) after one try per point, with no retry loop",
      async (_name, cutover, signer, reason) => {
        const { a, fake } = await collected({ cutover, signer });

        await a.sync.deleter.requestConnectionDelete(GH);

        await vi.waitFor(async () =>
          expect((await statusOf(a)).legacy).toEqual(blockedBy(reason)),
        );
        const tries = gatewayDeletes(fake).length;
        await new Promise((resolve) => setTimeout(resolve, 120));
        expect(gatewayDeletes(fake)).toHaveLength(tries);
        expect(tries).toBeLessThanOrEqual(SCOPES.length);
        expect(SCOPES.every((s) => fake.isLive(s))).toBe(true);
        // The fence and the storage objects are not held back by it.
        expect((await statusOf(a)).fence).toEqual(DONE);
        expect((await statusOf(a)).storage).toEqual(DONE);
      },
    );
  });

  it("retries a gateway that is down, and sends one tombstone per point", async () => {
    const { a, fake } = await collected();
    fake.state.gatewayDown = 3;

    await a.sync.deleter.requestConnectionDelete(GH);

    await vi.waitFor(async () =>
      expect((await statusOf(a)).legacy).toEqual(DONE),
    );
    for (const scope of SCOPES) expect(fake.tombstones.get(scope)).toEqual([3]);
  });

  it("reads pending while blob deletes are queued behind a rate limit, and done when they drain", async () => {
    const { a, fake, legacy } = await collected();
    fake.state.storageRateLimited = 1000;

    await a.sync.deleter.requestConnectionDelete(GH);

    // The tombstones landed; the blobs did not go.
    await vi.waitFor(() =>
      expect(SCOPES.every((s) => !fake.isLive(s))).toBe(true),
    );
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect((await statusOf(a)).legacy).toEqual(PENDING);
    expect((await legacy.pendingBlobDeletions.list()).length).toBeGreaterThan(
      0,
    );

    // The sync manager's drain finishes them; here the store is emptied.
    await legacy.pendingBlobDeletions.remove(
      await legacy.pendingBlobDeletions.list(),
    );
    await vi.waitFor(async () =>
      expect((await statusOf(a)).legacy).toEqual(DONE),
    );
  });

  it("never tombstones a head that moved after it was read", async () => {
    const { a, fake } = await collected();
    const scope = SCOPES[0]!;
    let moved = false;
    fake.state.beforeTombstone = async (s) => {
      if (s === scope && !moved) {
        moved = true;
        fake.moveHead(scope);
      }
    };

    await a.sync.deleter.requestConnectionDelete(GH);

    // The first try is refused; the next pass reads the head that is there.
    await vi.waitFor(async () =>
      expect((await statusOf(a)).legacy).toEqual(DONE),
    );
    expect(fake.tombstones.get(scope)).toEqual([4]);
  });

  describe("a delete that more than one device of the account sees", () => {
    it("ends with one tombstone per point when two devices send at once", async () => {
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const fake = createLegacyGatewayFake({ owner: OWNER, cutover: "v3" });
      for (const scope of SCOPES) fake.seed(scope, 2);
      const one = await legacyPortsOver(fake);
      const two = await legacyPortsOver(fake);
      const a = await w.device("a", {
        erasure: () => erasurePorts(w),
        legacyDelete: () => one.ports,
        deleteRetryMs: RETRY,
      });
      const b = await w.device("b", {
        erasure: () => erasurePorts(w),
        legacyDelete: () => two.ports,
        deleteRetryMs: RETRY,
      });
      await a.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
        connector: GH,
        observedAt: 1100,
      });
      await a.cycle();
      await b.cycle();
      // Both reach the gateway before either is answered.
      let arrived = 0;
      let release!: () => void;
      const together = new Promise<void>((resolve) => (release = resolve));
      fake.state.beforeTombstone = async () => {
        arrived += 1;
        if (arrived >= 2) release();
        await Promise.race([
          together,
          new Promise((resolve) => setTimeout(resolve, 100)),
        ]);
      };

      await a.sync.deleter.requestConnectionDelete(GH);
      await b.cycle();

      await vi.waitFor(async () => {
        expect((await statusOf(a)).legacy).toEqual(DONE);
        expect((await statusOf(b)).legacy).toEqual(DONE);
      });
      for (const scope of SCOPES)
        expect(fake.tombstones.get(scope)).toEqual([3]);
    });

    it("is finished by a device with the ports when the deleting one has none", async () => {
      const w = await world({ streams: 1, partTargetBytes: PART_TARGET });
      const fake = createLegacyGatewayFake({ owner: OWNER, cutover: "v3" });
      for (const scope of SCOPES) fake.seed(scope, 2);
      const legacy = await legacyPortsOver(fake);
      // The phone cannot delete at the gateway; the desktop can.
      const phone = await w.device("phone", { deleteRetryMs: RETRY });
      const desktop = await w.device("desktop", {
        erasure: () => erasurePorts(w),
        legacyDelete: () => legacy.ports,
        deleteRetryMs: RETRY,
      });
      await phone.run("run-1", [{ stream: sName(0), id: "x", v: 0 }], {
        connector: GH,
        observedAt: 1100,
      });
      await phone.cycle();
      await desktop.cycle();

      await phone.sync.deleter.requestConnectionDelete(GH);
      await vi.waitFor(async () =>
        expect((await statusOf(phone)).fence).toEqual(DONE),
      );
      // Said plainly: this device cannot do it.
      expect((await statusOf(phone)).legacy).toEqual(
        blockedBy("needs_another_device"),
      );
      expect((await statusOf(phone)).storage).toEqual(
        blockedBy("needs_another_device"),
      );
      expect(SCOPES.every((s) => fake.isLive(s))).toBe(true);

      await desktop.cycle();
      await vi.waitFor(async () =>
        expect(allDone(await statusOf(desktop))).toBe(true),
      );
      expect(SCOPES.every((s) => !fake.isLive(s))).toBe(true);
    });
  });

  it("does not touch what a connection added again writes: it lives in its own log, the legacy scopes accept no write", async () => {
    const { w, a, fake, legacy } = await collected();
    // The stage is held at the gateway while the person connects again.
    let reached!: () => void;
    const atGateway = new Promise<void>((resolve) => (reached = resolve));
    let proceed!: () => void;
    const held = new Promise<void>((resolve) => (proceed = resolve));
    let first = true;
    fake.state.beforeTombstone = async () => {
      if (!first) return;
      first = false;
      reached();
      await held;
    };

    await a.sync.deleter.requestConnectionDelete(GH);
    await atGateway;
    await a.run("run-2", [{ stream: sName(0), id: "new", v: 1 }], {
      connector: GH,
      connect: true,
      observedAt: 1200,
    });
    await a.cycle();
    proceed();

    await vi.waitFor(() =>
      expect(SCOPES.every((s) => !fake.isLive(s))).toBe(true),
    );
    // The legacy scopes took no write after the switch.
    await expect(
      legacy.seal.commit(async () => undefined),
    ).rejects.toBeInstanceOf(LegacyWriteRefusedError);
    // The new connection's log is untouched, and reads on another device.
    const newLog = logScope(GH, "");
    expect(
      w.innerBlobs.keys().some((key) => key.startsWith(`${newLog}/`)),
    ).toBe(true);
    const b = await w.device("b");
    await b.cycle();
    expect(await b.records()).toEqual(await a.records());
    expect((await b.records()).length).toBeGreaterThan(0);
  });

  it("reads storage as blocked(body_pieces_retained) when a body stays in storage", async () => {
    const { a } = await collected({ big: true });

    await a.sync.deleter.requestConnectionDelete(GH);

    await vi.waitFor(async () =>
      expect((await statusOf(a)).storage).toEqual(
        blockedBy("body_pieces_retained"),
      ),
    );
    expect((await statusOf(a)).legacy).toEqual(DONE);
    expect((await statusOf(a)).fence).toEqual(DONE);
  });
});
