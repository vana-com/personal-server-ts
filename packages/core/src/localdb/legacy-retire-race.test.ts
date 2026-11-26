import { afterEach, expect, it, vi } from "vitest";
import {
  closeWorldDrivers,
  world,
} from "../../../server/src/localdb/log-world.test-utils.js";
import {
  createLegacyGatewayFake,
  FAKE_CHAIN_ID,
  FAKE_GATEWAY,
  FAKE_STORAGE,
} from "../test-utils/legacy-gateway-fake.js";
import { legacyHeadFrom } from "./legacy-delete.js";
import {
  createLegacyRetirePipeline,
  type LegacyRetirePipelinePorts,
} from "./legacy-retire-pipeline.js";
import { createLegacyRetireRemote } from "./legacy-retire-remote.js";

afterEach(closeWorldDrivers);
const owner = `0x${"11".repeat(20)}` as const;
const scope = "github.events";
const check = () => {};

async function fixture() {
  const w = await world({ streams: 1 });
  const a = await w.device("a");
  const fake = createLegacyGatewayFake({ owner, cutover: "v3" });
  fake.seed(scope, 2);
  const finality = {
    finalized: null as string | null,
    settling: true,
    rolledBack: null,
  };
  let present = true;
  const erase = vi.fn(async () => {
    present = false;
  });
  const options = {
    gatewayUrl: FAKE_GATEWAY,
    dataPointFeed: fake.feed,
    serverOwner: owner,
    signer: fake.signer,
    storage: {
      endpoint: FAKE_STORAGE,
      chainId: FAKE_CHAIN_ID,
      signMessage: async () => `0x${"ab".repeat(65)}`,
    },
    fetch: fake.fetch,
  };
  const remote = createLegacyRetireRemote(options);
  const ports: LegacyRetirePipelinePorts = {
    mode: () => "switched",
    scopesOf: () => [scope],
    streamsOf: () => ["events"],
    head: legacyHeadFrom(fake.feed, owner),
    ...remote,
    versions: fake.inventory,
    finality: { tombstoneState: async () => finality },
    rows: {
      capture: async (save) =>
        save([
          {
            id: 1,
            path: "legacy.json",
            scope,
            collectedAt: "2026-01-01T00:00:00.000Z",
            createdAt: "2026-01-01T00:00:00.000Z",
            fileId: null,
            schemaId: null,
            sizeBytes: 1,
            version: 2,
            casRevision: 1,
            dataPointId: null,
          },
        ]),
      erase,
      absent: async () => !present,
    },
  };
  const pipeline = createLegacyRetirePipeline(a.deps, ports);
  const id = await pipeline.capture("github", check);
  const advance = () =>
    pipeline.advance(id, check, new AbortController().signal);
  const acknowledgement = async () => {
    const [row] = await a.db.query<{ manifest: string }>(
      "SELECT manifest FROM legacy_retire_manifests WHERE retire_id = ?",
      [id],
    );
    return JSON.parse(row.manifest).scopes[0].acknowledgement;
  };
  return { a, fake, ports, options, finality, erase, advance, acknowledgement };
}

it("completes on a finalized foreign pin+1 tombstone after an already-deleted rejection", async () => {
  const f = await fixture();
  f.fake.state.race = "already-deleted";
  await expect(f.advance()).resolves.toEqual({ state: "pending" });
  expect(await f.acknowledgement()).toBe("not-sent");
  expect(f.fake.requests.filter((r) => r.method === "DELETE")).toHaveLength(1);
  expect(f.erase).not.toHaveBeenCalled();
  expect(await f.a.db.query("SELECT state FROM legacy_retirements")).toEqual([
    { state: "open" },
  ]);
  // The 409 is not proof of finality: a second pass still waits.
  await expect(f.advance()).resolves.toEqual({ state: "pending" });
  expect(f.erase).not.toHaveBeenCalled();
  expect(f.fake.blobCount(scope)).toBe(2);
  f.finality.finalized = "3";
  f.finality.settling = false;
  await expect(f.advance()).resolves.toEqual({ state: "done" });
  expect(
    f.fake.requests.filter(
      (r) => r.url.startsWith(FAKE_GATEWAY) && r.method === "DELETE",
    ),
  ).toHaveLength(1);
  expect(f.fake.blobCount(scope)).toBe(0);
  expect(f.erase).toHaveBeenCalledTimes(1);
  expect(await f.a.db.query("SELECT state FROM legacy_retirements")).toEqual([
    { state: "done" },
  ]);
});

for (const failure of ["timeout", "unrelated-409", "already-deleted"] as const)
  it(`a ${failure} retry does not clear earlier uncertainty`, async () => {
    const f = await fixture();
    const timeout = async () => {
      throw Error("ambiguous timeout");
    };
    f.ports.tombstone = createLegacyRetireRemote({
      ...f.options,
      fetch: timeout,
    }).tombstone;
    await expect(f.advance()).rejects.toThrow("ambiguous timeout");
    expect(await f.acknowledgement()).toBe("unconfirmed");
    if (failure === "already-deleted") {
      f.fake.state.race = "already-deleted";
      f.ports.tombstone = createLegacyRetireRemote(f.options).tombstone;
      await expect(f.advance()).resolves.toEqual({ state: "pending" });
    } else {
      f.ports.tombstone = createLegacyRetireRemote({
        ...f.options,
        fetch:
          failure === "timeout"
            ? timeout
            : async () =>
                new Response(JSON.stringify({ code: "other_conflict" }), {
                  status: 409,
                }),
      }).tombstone;
      await expect(f.advance()).rejects.toThrow();
      f.fake.foreignTombstone(scope);
    }
    expect(await f.acknowledgement()).toBe("unconfirmed");
    await expect(f.advance()).resolves.toEqual({
      state: "blocked",
      reason: "legacy_tombstone_unacknowledged",
    });
    expect(f.erase).not.toHaveBeenCalled();
    expect(f.fake.blobCount(scope)).toBe(2);
  });
