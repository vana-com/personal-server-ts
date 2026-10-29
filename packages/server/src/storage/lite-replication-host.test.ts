/**
 * PS-Lite's replication factory (lite `replication-host.ts`): what a phone
 * shell gets from native persistence, native transfers and its retained
 * declarations, with the partition, bindings and ports derived as on Node.
 */
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import type { DeclarationSnapshot } from "@opendatalabs/personal-server-ts-core/pdpp";
import { createDpv2ReplicaTransport } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import { replicaDeclarationContext } from "@opendatalabs/personal-server-ts-core/replication/host-config";
import {
  REPLICA_LOCAL_WRITE_DEBOUNCE_MS,
  type ReplicationTimers,
} from "@opendatalabs/personal-server-ts-core/replication/host-driver";
import type { ReplicationNetworkPorts } from "@opendatalabs/personal-server-ts-core/replication/host-ports";
import { createTestReplicaSigner } from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import type { BoundedStorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import {
  createLiteReplication,
  LITE_REPLICATION_LIMITS,
  type LiteReplicaPersistence,
  type LiteReplication,
  type LiteReplicationInput,
} from "@opendatalabs/personal-server-ts-lite";
import { createMemoryReplicaObjectTransfers } from "../../../lite/src/test-support/replication.js";
import { createSqliteLiteReplicaPersistence } from "./lite-replica-sqlite.test-utils.js";
import {
  at,
  cleanupHarness,
  clock,
  network,
  owner,
  scratchDirectory,
} from "./pdpp-replica-contract.test-utils.js";
import { REPLICA_TEST_CHAIN_ID } from "./pdpp-replica-writer-identity.test-utils.js";

afterEach(() => cleanupHarness());

type Network = ReturnType<typeof network>;

const SOURCE = "https://registry.pdpp.dev/connectors/lite-host-test";
const declaration: DeclarationSnapshot = {
  source_id: SOURCE,
  source_kind: "connector" as DeclarationSnapshot["source_kind"],
  version: "1",
  digest: "d".repeat(64),
  streams: [
    {
      name: "messages",
      fields: ["id", "text"],
      required_fields: ["id"],
      primary_key: ["id"],
      schema: {
        type: "object",
        properties: { id: { type: "string" }, text: { type: "string" } },
        required: ["id"],
      },
    },
  ],
};
const binding = replicaDeclarationContext(owner, [declaration]).expected
  .declarations[0]!.binding;

/** Count every persistence transaction, to prove an inert boot opens none. */
function counted(inner: LiteReplicaPersistence) {
  let transactions = 0;
  const port: LiteReplicaPersistence = {
    ...inner,
    transaction(run) {
      transactions++;
      return inner.transaction(run);
    },
  };
  return { port, transactions: () => transactions };
}

/**
 * The DPv2 carrier over the factory's storage: object bytes go through the
 * phone's native transfers; registration, evidence and listing stay on the
 * simulated gateway.
 */
function dpv2(net: Network) {
  return (
    partition: `0x${string}`,
    storage: BoundedStorageAdapter,
  ): ReplicationNetworkPorts => {
    const bytes = createDpv2ReplicaTransport({
      owner: partition,
      masterKey: new Uint8Array(32).fill(5),
      storage,
      gateway: { registerDataPoint: () => Promise.reject(new Error("unused")) },
      feed: {
        listDataPointsByOwner: () => Promise.reject(new Error("unused")),
        getDataPoint: () => Promise.reject(new Error("unused")),
      },
      signer: { signAddData: () => Promise.reject(new Error("unused")) },
      evidence: () => Promise.reject(new Error("unused")),
    });
    return {
      transport: {
        ...net.port,
        putFragment: bytes.putFragment,
        getFragment: bytes.getFragment,
        hasFragment: bytes.hasFragment,
        put: bytes.put,
        get: bytes.get,
      },
      roster: net.roster.port,
    };
  };
}

/** One phone's boot inputs; each override replaces one shell input. */
function phone(net: Network, name: string) {
  const path = join(scratchDirectory("lite-host"), "native.sqlite");
  const native = createSqliteLiteReplicaPersistence(path);
  const persistence = counted(native.port);
  const memory = createMemoryReplicaObjectTransfers(persistence.port, {
    objects: net.blobs,
  }).port;
  const uploads: string[] = [];
  const signer = createTestReplicaSigner(name);
  net.roster.register(signer.address, owner);
  const input = (
    overrides: Partial<LiteReplicationInput> = {},
  ): LiteReplicationInput => ({
    door: { state: "on" },
    config: {
      enabled: true,
      owner,
      environment: "dev",
      chainId: REPLICA_TEST_CHAIN_ID,
      limits: LITE_REPLICATION_LIMITS,
    },
    persistence: persistence.port,
    transfers: {
      ...memory,
      async upload(request, call) {
        uploads.push(request.url);
        return memory.upload(request, call);
      },
    },
    declarations: [declaration],
    serverAccount: signer,
    objects: { urlForKey: (key) => `https://storage.test/${key}` },
    network: dpv2(net),
    engine: { now: clock.now, targetChunkBytes: 4000, maxBlobBytes: 8192 },
    ...overrides,
  });
  return { native, persistence, uploads, input };
}

function started(replication: LiteReplication) {
  if (replication.state !== "started")
    throw new Error(`${replication.state}: ${replication.reason}`);
  return replication;
}

/** A started phone with connection `conn` bound to the declaration. */
async function device(replication: LiteReplication) {
  const { canonical, engine } = started(replication);
  await canonical.provisionConnection("conn", {
    sourceId: SOURCE,
    methodId: "export",
  });
  const connection = {
    owner,
    sourceId: SOURCE,
    connectionId: "conn",
    methodId: "export",
    generation: 1 as const,
  };
  let writes = 0;
  return {
    engine,
    cycle: () => engine.cycle(),
    put: (text: string, id: string) =>
      canonical.commitLocal(`lite-${++writes}`, [
        ...(writes === 1
          ? [{ ...connection, kind: "connection-register" as const }]
          : []),
        {
          ...connection,
          kind: "upsert",
          declaration: binding,
          recordKey: id,
          emittedAt: at,
          data: { id, text },
          blobs: [],
        },
      ]),
    get: async (id: string) =>
      (await canonical.readRecord("conn", "messages", id))?.data,
  };
}

it("builds nothing with the door closed or the boot config off", async () => {
  const net = network();
  const a = phone(net, "phone-off");
  const ports = vi.fn(dpv2(net));
  const base = a.input({ network: ports });
  for (const input of [
    { ...base, door: { state: "never" as const } },
    { ...base, door: { state: "off" as const } },
    {
      ...base,
      door: { state: "refused" as const, refusal: "reenable_refused" as const },
    },
    { ...base, config: undefined },
    { ...base, config: { ...base.config!, enabled: false } },
  ]) {
    const replication = await createLiteReplication(input);
    expect(replication.state).toBe("off");
    replication.runtime.resume();
    expect(await replication.runtime.trigger("foreground")).toBeUndefined();
  }
  expect(ports).not.toHaveBeenCalled();
  expect(a.persistence.transactions()).toBe(0);
  expect(a.uploads).toEqual([]);
  a.native.close();
});

it("blocks with a reason when the partition cannot be derived", async () => {
  const net = network();
  const a = phone(net, "phone-blocked");
  const base = a.input();
  const reason = async (input: LiteReplicationInput) => {
    const replication = await createLiteReplication(input);
    expect(replication.state).toBe("blocked");
    return replication.state === "blocked" ? replication.reason : undefined;
  };
  expect(
    await reason({ ...base, config: { ...base.config!, chainId: 1 } }),
  ).toBe("unsupported_chain:1");
  expect(await reason({ ...base, declarations: [] })).toBe(
    "no_retained_declarations",
  );
  expect(
    await reason({ ...base, config: { ...base.config!, environment: "prod" } }),
  ).toBe("environment_mismatch");
  expect(
    await reason({
      ...base,
      config: { ...base.config!, owner: "0x1234" as `0x${string}` },
    }),
  ).toBe("invalid_owner");
  expect(
    await reason({
      ...base,
      network: () => {
        throw new Error("no RPC for chain 14800");
      },
    }),
  ).toBe("no RPC for chain 14800");
  expect(a.persistence.transactions()).toBe(0);
  a.native.close();
});

it("two phones built by the factory converge over DPv2 and native transfers", async () => {
  const net = network();
  const pa = phone(net, "phone-a");
  const pb = phone(net, "phone-b");
  const a = await device(await createLiteReplication(pa.input()));
  const b = await device(await createLiteReplication(pb.input()));
  // The first step binds each phone's writer before any local write.
  await a.cycle();
  await b.cycle();
  await a.put("from a", "a");
  await b.put("from b", "b");
  await a.put("a edit", "k");
  await b.put("b edit", "k");
  for (let i = 0; i < 12; i++) {
    clock.advance(10_000);
    await a.cycle();
    await b.cycle();
  }
  expect(await a.get("b")).toEqual({ id: "b", text: "from b" });
  expect(await b.get("a")).toEqual({ id: "a", text: "from a" });
  const shared = await a.get("k");
  expect(["a edit", "b edit"]).toContain(
    (shared as { text?: string } | undefined)?.text,
  );
  expect(await b.get("k")).toEqual(shared);
  // Both phones uploaded through their native transfers, at the shell's URLs.
  for (const uploads of [pa.uploads, pb.uploads]) {
    expect(uploads.length).toBeGreaterThan(0);
    expect(
      uploads.every((url) => url.startsWith("https://storage.test/")),
    ).toBe(true);
  }
  pa.native.close();
  pb.native.close();
}, 60_000);

it("rotates the writer identity at boot when the shell asks", async () => {
  const net = network();
  const pa = phone(net, "phone-rotate");
  const fresh = started(
    await createLiteReplication(pa.input({ rotateWriterIdentity: true })),
  );
  // Nothing to rotate before the first enable.
  expect(fresh.rotation).toBe("no_identity");
  const a = await device(fresh);
  await a.cycle();
  const again = started(
    await createLiteReplication(pa.input({ rotateWriterIdentity: true })),
  );
  expect(again.rotation).toBe("rotated");
  const plain = started(await createLiteReplication(pa.input()));
  expect(plain.rotation).toBe("not_requested");
  pa.native.close();
});

it("a local commit steps within the debounce window", async () => {
  const net = network();
  const pa = phone(net, "phone-write");
  const armed: { ms: number; run: () => void }[] = [];
  const timers: ReplicationTimers = {
    now: clock.now,
    setTimeout(run, ms) {
      armed.push({ ms, run });
      return armed.length;
    },
    clearTimeout: () => {},
  };
  const replication = started(
    await createLiteReplication(pa.input({ timers })),
  );
  const a = await device(replication);
  // Stopped: a write schedules nothing.
  await a.put("before start", "x");
  expect(armed).toEqual([]);
  replication.runtime.resume();
  while (replication.runtime.status().state === "on" && stepping(replication))
    await new Promise((resolve) => setImmediate(resolve));
  armed.length = 0;
  const before = replication.runtime.status();
  await a.put("from a", "a");
  // Only the debounced step: the idle wake was armed before the write.
  expect(armed.map((t) => t.ms)).toEqual([REPLICA_LOCAL_WRITE_DEBOUNCE_MS]);
  clock.advance(REPLICA_LOCAL_WRITE_DEBOUNCE_MS);
  armed[0]!.run();
  while (stepping(replication))
    await new Promise((resolve) => setImmediate(resolve));
  expect(replication.runtime.status()).toMatchObject({
    lastStepAt: clock.now(),
  });
  expect(before).not.toMatchObject({ lastStepAt: clock.now() });
  expect(await replication.runtime.stop(1_000)).toBe(true);
  pa.native.close();
});

function stepping(replication: { runtime: LiteReplication["runtime"] }) {
  const status = replication.runtime.status();
  return "stepping" in status && status.stepping;
}
