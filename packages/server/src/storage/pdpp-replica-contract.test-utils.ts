/**
 * Shared harness for the replica coordinator/visibility contract suite.
 * Test-only. Assertions live in the *.test.ts files; this module only builds
 * devices, injects process loss and reads durable state without interpretation.
 */
import Database from "better-sqlite3";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { captureWrites } from "./pdpp-replication-door.js";
import { tmpdir } from "node:os";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "./pdpp-replication-transport.js";
import { createTestReplicaRoster } from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import {
  readBoundedResponse,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";
import {
  enableReplicaTestIdentity,
  replicaTestAuthority,
} from "./pdpp-replica-writer-identity.test-utils.js";
import {
  createDpv2ReplicaTransport,
  replicaChainCommitment,
  type ReplicaFinalizedChainEvidence,
  type ReplicaCommitment,
  type ReplicaTransportPort,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  canonicalJson,
  type ReplicaOperation,
} from "@opendatalabs/personal-server-ts-core/replication/envelope";
import type { MergeContext } from "@opendatalabs/personal-server-ts-core/replication/merge-plan";
import {
  fragmentReplicaPayload,
  prepareReplicaManifest,
  replicaDigest,
  replicaScope,
  type Predecessor,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import type { ReplicaBatchFacts } from "@opendatalabs/personal-server-ts-core/replication/writer-identity";
import { createLiteCanonicalStore } from "../../../lite/src/canonical-store.js";
import type {
  LiteCanonicalPersistence,
  LiteCanonicalTransaction,
} from "../../../lite/src/canonical-persistence.js";
import {
  collectStagedBlob,
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
  storagePage,
} from "../../../lite/src/test-support/canonical-persistence.js";

// ---------------------------------------------------------------- constants

export const owner = "0x0000000000000000000000000000000000000001";
export const sourceId = "https://source.invalid/declaration";
export const at = "2026-10-20T00:00:00.000Z";
export const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
export const appendBinding = {
  ...binding,
  digest: `sha256:${"c".repeat(64)}`,
  semantics: "append_only" as const,
};
export const expected = { owner, declarations: [{ sourceId, binding }] };
export const credential = "replica-secret";

/** Deterministic clock shared by every device in a test. */
export const clock = {
  time: Date.parse(at),
  now: () => clock.time,
  advance(ms: number) {
    clock.time += ms;
  },
};

/**
 * Model a device on which `instance` was never provisioned. The fixture
 * deletes the binding inside a capture guard: a device reaches that state
 * without an uncaptured write, so the replication door must stay open.
 */
export function unprovisionConnection(db: Database.Database, instance: string) {
  db.transaction(() =>
    captureWrites(db, () =>
      db
        .prepare("DELETE FROM pdpp_instance_binding WHERE instance = ?")
        .run(instance),
    ),
  )();
}

const cleanups: (() => void)[] = [];
/** Call from afterEach in every contract test file. */
export function cleanupHarness() {
  for (const close of cleanups.splice(0).reverse()) close();
  clock.time = Date.parse(at);
}
export function scratchDirectory(prefix: string) {
  const directory = mkdtempSync(join(tmpdir(), `${prefix}-`));
  cleanups.push(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// ------------------------------------------------------------ process loss

/** Thrown at an injected crash point. After it, every database call fails too. */
export class SimulatedCrash extends Error {
  constructor(readonly point: string) {
    super(`simulated process loss at ${point}`);
    this.name = "SimulatedCrash";
  }
}

/**
 * Enumerates durable-write and external-effect points of a run, then kills the
 * "process" at one of them. Killing means: the call at that point throws, and
 * every later database or network call through this controller throws as well,
 * so no catch handler can persist anything. An open transaction rolls back.
 * Points are labelled "<kind>:<detail>#<ordinal>" from the actual trace, so a
 * new write in the implementation adds a new crash point automatically.
 */
export class CrashController {
  readonly trace: string[] = [];
  private armedAt: number | undefined;
  private counting = false;
  dead = false;
  /** Start recording points. crashAt = index into the recorded trace. */
  arm(crashAt?: number) {
    this.trace.length = 0;
    this.counting = true;
    this.armedAt = crashAt;
    this.dead = false;
  }
  /** Stop injecting. Also the "new process" after a crash: nothing is dead any more. */
  disarm() {
    this.counting = false;
    this.armedAt = undefined;
    this.dead = false;
  }
  point(label: string) {
    if (this.dead) throw new SimulatedCrash(`after-death:${label}`);
    if (!this.counting) return;
    const index = this.trace.length;
    this.trace.push(label);
    if (this.armedAt === index) {
      this.dead = true;
      throw new SimulatedCrash(`${label}#${index}`);
    }
  }
}

function mutationLabel(sql: string) {
  const match =
    /^\s*(INSERT(?:\s+OR\s+\w+)?\s+INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO)\s+(\w+)/i.exec(
      sql,
    );
  return match
    ? `${match[1].split(/\s+/)[0].toLowerCase()}:${match[2]}`
    : undefined;
}

/**
 * Wraps a real better-sqlite3 handle. Mutating statements get "before" and
 * "after" points; an outermost transaction gets "commit" (after COMMIT). Reads
 * pass through unless the controller is dead.
 */
export function crashableDatabase(
  real: Database.Database,
  controller: CrashController,
): Database.Database {
  const wrapStatement = (statement: Database.Statement, sql: string) => {
    const label = mutationLabel(sql);
    return new Proxy(statement, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver);
        if (typeof value !== "function") return value;
        if (property === "run" && label)
          return (...args: unknown[]) => {
            controller.point(`before-${label}`);
            const result = (value as (...a: unknown[]) => unknown).apply(
              target,
              args,
            );
            controller.point(`after-${label}`);
            return result;
          };
        if (["run", "get", "all", "iterate"].includes(String(property)))
          return (...args: unknown[]) => {
            if (controller.dead)
              throw new SimulatedCrash(`after-death:${String(property)}`);
            return (value as (...a: unknown[]) => unknown).apply(target, args);
          };
        return value.bind(target);
      },
    });
  };
  const wrapTransaction = (
    make: (fn: (...a: unknown[]) => unknown) => Database.Transaction,
  ) => {
    return (fn: (...a: unknown[]) => unknown) => {
      const transaction = make(fn);
      const outer =
        (variant?: "deferred" | "immediate" | "exclusive") =>
        (...args: unknown[]) => {
          if (controller.dead)
            throw new SimulatedCrash("after-death:transaction");
          const outermost = !real.inTransaction;
          const call = variant ? transaction[variant] : transaction;
          const result = call(...args);
          if (outermost) controller.point("commit");
          return result;
        };
      return Object.assign(outer(), {
        deferred: outer("deferred"),
        immediate: outer("immediate"),
        exclusive: outer("exclusive"),
        default: outer(),
      });
    };
  };
  return new Proxy(real, {
    get(target, property, receiver) {
      if (property === "prepare")
        return (sql: string) => {
          if (controller.dead) throw new SimulatedCrash("after-death:prepare");
          return wrapStatement(target.prepare(sql), sql);
        };
      if (property === "exec")
        return (sql: string) => {
          const label = mutationLabel(sql);
          if (label) controller.point(`before-exec-${label}`);
          else if (controller.dead)
            throw new SimulatedCrash("after-death:exec");
          return target.exec(sql);
        };
      if (property === "transaction")
        return wrapTransaction((fn) => target.transaction(fn));
      const value = Reflect.get(target, property, receiver);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

// ---------------------------------------------------------------- network

/** The `<scope>/<version>` key of one registered slot. */
/** The batch id inside a fragment or manifest plaintext. */
export function batchOfPlaintext(bytes: Uint8Array) {
  const data = (
    JSON.parse(new TextDecoder().decode(bytes)) as {
      data: { fragment?: { batch: string }; manifest?: { batch: string } };
    }
  ).data;
  return (data.fragment ?? data.manifest)!.batch;
}
export const slotKey = (scope: string, version: number | string) =>
  `${scope}/${version}`;
const slotParts = (slot: string) => {
  const at = slot.lastIndexOf("/");
  return { scope: slot.slice(0, at), version: Number(slot.slice(at + 1)) };
};

/**
 * Storage cap + DPv2 version guard + independent Gateway head and finalized
 * chain. Registry state is kept per slot (`<scope>/<version>`): `head` holds
 * every slot the Gateway accepted and `chain` every finalized slot. Storage
 * and its call logs use the exact object keys: manifests at `<scope>/<version>`
 * and fragments at `<scope>/fragments/<sha256>`.
 */
export function network(
  opts: { cap?: number; crash?: CrashController; realCrypto?: boolean } = {},
) {
  const cap = opts.cap ?? 8192;
  const crash = opts.crash;
  const blobs = new Map<string, Uint8Array>();
  const head = new Map<string, ReplicaCommitment>();
  const chain = new Map<string, ReplicaFinalizedChainEvidence>();
  const versionsOf = (map: Map<string, unknown>, scope: string) =>
    [...map.keys()]
      .map(slotParts)
      .filter((p) => p.scope === scope)
      .map((p) => p.version);
  const latest = (map: Map<string, unknown>, scope: string) =>
    Math.max(0, ...versionsOf(map, scope));
  /** Finalized chain evidence of one slot; absent slots read as zero. */
  const chainRow = (
    slot: string,
    row?: ReplicaCommitment,
  ): ReplicaFinalizedChainEvidence => {
    const { scope, version } = slotParts(slot);
    return {
      owner,
      scope,
      version: String(version),
      currentVersion: row ? String(version) : "0",
      status: row ? "Active" : "None",
      commitment: row
        ? replicaChainCommitment(
            row.dataHash as `0x${string}`,
            row.metadataHash as `0x${string}`,
          )
        : `0x${"0".repeat(64)}`,
      chainId: 14800,
      registry: `0x${"2".repeat(40)}`,
      blockNumber: 123n,
      blockHash: `0x${"3".repeat(64)}`,
      blockTimestamp: 1000n,
    };
  };
  /** Slots whose registration stays out of finalized chain evidence. */
  const pending = new Set<string>();
  const calls = {
    puts: [] as string[],
    gets: [] as string[],
    registrations: [] as string[],
    evidence: [] as string[],
    lists: 0,
    encrypts: 0,
  };
  const faults = {
    put: new Set<string>(),
    evidence: undefined as undefined | ((slot: string) => unknown),
    get: undefined as undefined | ((key: string) => unknown),
    encrypt: undefined as undefined | ((scope: string) => unknown),
    list: undefined as undefined | (() => unknown),
    loseRegistrationResponse: false,
  };
  let pageSize = 1000;
  const storage = {
    async upload(key: string, data: Uint8Array) {
      if (data.length > cap) throw new Error("413 storage MAX_BLOB_SIZE");
      crash?.point(`net-before-put:${key}`);
      calls.puts.push(key);
      if (faults.put.has(key)) throw new Error("offline");
      blobs.set(key, new Uint8Array(data));
      crash?.point(`net-after-put:${key}`);
      return key;
    },
    urlForKey: (key: string) => key,
    async download(key: string) {
      crash?.point(`net-get:${key}`);
      calls.gets.push(key);
      if (faults.get) {
        const error = faults.get(key);
        if (error) throw error;
      }
      const bytes = blobs.get(key);
      if (!bytes) throw Object.assign(new Error("404"), { status: 404 });
      return new Uint8Array(bytes);
    },
    /** The production bounded reader over this storage's bytes. */
    async downloadBounded(key: string, budget: ByteBudget) {
      return readBoundedResponse(
        new Response(await storage.download(key)),
        budget,
      );
    },
    delete: async () => false,
    exists: async (key: string) => blobs.has(key),
  };
  const adapter = createDpv2ReplicaTransport({
    owner,
    masterKey: new Uint8Array(32).fill(5),
    storage,
    signer: { signAddData: async () => "0x1234" as const },
    gateway: {
      async registerDataPoint(input) {
        const slot = slotKey(input.scope, input.expectedVersion);
        crash?.point(`net-before-register:${slot}`);
        calls.registrations.push(slot);
        const max = Math.max(
          latest(head, input.scope),
          latest(chain, input.scope),
        );
        if (Number(input.expectedVersion) !== max + 1)
          throw new Error(
            `Gateway error: 409 Stale expectedVersion; stored value ${max}`,
          );
        const row = {
          owner: input.ownerAddress,
          scope: input.scope,
          version: input.expectedVersion,
          dataHash: input.dataHash,
          metadataHash: input.metadataHash,
          deleted: false,
        };
        head.set(slot, row);
        if (!pending.has(slot)) chain.set(slot, chainRow(slot, row));
        crash?.point(`net-after-register:${slot}`);
        if (faults.loseRegistrationResponse) {
          faults.loseRegistrationResponse = false;
          throw new Error("response lost after commit");
        }
        return { dataPointId: slot } as never;
      },
    },
    feed: {
      async listDataPointsByOwner(_owner, cursor) {
        crash?.point("net-list");
        calls.lists++;
        if (faults.list) {
          const error = faults.list();
          if (error) throw error;
        }
        const scopes = [
          ...new Set([...head.keys()].map((k) => slotParts(k).scope)),
        ]
          .sort()
          .filter((scope) => cursor === null || scope > cursor);
        const selected = scopes.slice(0, pageSize);
        return {
          dataPoints: selected.map((scope) => ({
            scope,
            expectedVersion: String(latest(head, scope)),
          })) as never,
          cursor: scopes.length > pageSize ? selected.at(-1)! : null,
        };
      },
      getDataPoint: async () => {
        throw new Error("head-only lookup must never be used");
      },
    },
    evidence: async (scope, version) => {
      const slot = slotKey(scope, version);
      crash?.point(`net-evidence:${slot}`);
      calls.evidence.push(slot);
      if (faults.evidence) {
        const error = faults.evidence(slot);
        if (error) throw error;
      }
      const top = latest(head, scope);
      const final = latest(chain, scope);
      const known = chain.get(slot);
      const newest = chain.get(slotKey(scope, final));
      return {
        head: head.get(slotKey(scope, top)) ?? null,
        chain: {
          ...(known ?? chainRow(slot)),
          ...(!known && newest && { status: newest.status }),
          currentVersion: String(final),
        },
        pending: pending.has(slot),
      };
    },
  });
  const key = randomBytes(32);
  const fast = {
    async encrypt(scope: string, bytes: Uint8Array) {
      calls.encrypts++;
      if (faults.encrypt) {
        const error = faults.encrypt(scope);
        if (error) throw error;
      }
      const iv = randomBytes(12);
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      return new Uint8Array(
        Buffer.concat([
          iv,
          cipher.update(bytes),
          cipher.final(),
          cipher.getAuthTag(),
        ]),
      );
    },
    async decrypt(_scope: string, bytes: Uint8Array) {
      const decipher = createDecipheriv("aes-256-gcm", key, bytes.slice(0, 12));
      decipher.setAuthTag(bytes.slice(-16));
      return new Uint8Array(
        Buffer.concat([
          decipher.update(bytes.slice(12, -16)),
          decipher.final(),
        ]),
      );
    },
  };
  const port: ReplicaTransportPort = {
    ...adapter,
    ...(opts.realCrypto ? {} : fast),
  };
  return {
    port,
    /** The owner's gateway server roster. */
    roster: createTestReplicaRoster(),
    blobs,
    head,
    chain,
    chainRow,
    pending,
    calls,
    faults,
    /** Accepted registrations per writer scope: what the relayer pays for. */
    registrationsOf(scope: string) {
      return versionsOf(head, scope).length;
    },
    /** Move every pending registration into finalized evidence at a block. */
    finalizeAll(blockNumber = 124n) {
      for (const slot of pending) {
        const row = head.get(slot);
        if (row) chain.set(slot, { ...chainRow(slot, row), blockNumber });
      }
      pending.clear();
    },
    pageSize(n: number) {
      pageSize = n;
    },
    /**
     * Capture the whole in-memory network state; the returned function puts it
     * back in place (same maps, arrays and fault slots, so references held by
     * the transport adapter stay valid).
     */
    snapshot() {
      const saved = {
        blobs: [...blobs].map(([k, v]) => [k, new Uint8Array(v)] as const),
        head: [...head],
        chain: [...chain],
        pending: [...pending],
        calls: {
          puts: [...calls.puts],
          gets: [...calls.gets],
          registrations: [...calls.registrations],
          evidence: [...calls.evidence],
          lists: calls.lists,
          encrypts: calls.encrypts,
        },
        faults: { ...faults, put: new Set(faults.put) },
        pageSize,
      };
      return () => {
        blobs.clear();
        for (const [k, v] of saved.blobs) blobs.set(k, new Uint8Array(v));
        head.clear();
        for (const [k, v] of saved.head) head.set(k, v);
        chain.clear();
        for (const [k, v] of saved.chain) chain.set(k, v);
        pending.clear();
        for (const k of saved.pending) pending.add(k);
        calls.puts.splice(0, calls.puts.length, ...saved.calls.puts);
        calls.gets.splice(0, calls.gets.length, ...saved.calls.gets);
        calls.registrations.splice(
          0,
          calls.registrations.length,
          ...saved.calls.registrations,
        );
        calls.evidence.splice(
          0,
          calls.evidence.length,
          ...saved.calls.evidence,
        );
        calls.lists = saved.calls.lists;
        calls.encrypts = saved.calls.encrypts;
        faults.put.clear();
        for (const k of saved.faults.put) faults.put.add(k);
        faults.evidence = saved.faults.evidence;
        faults.get = saved.faults.get;
        faults.encrypt = saved.faults.encrypt;
        faults.list = saved.faults.list;
        faults.loseRegistrationResponse = saved.faults.loseRegistrationResponse;
        pageSize = saved.pageSize;
      };
    },
  };
}
export type Network = ReturnType<typeof network>;

/**
 * Publish a hand-built batch straight to the network, as another registered
 * server of the owner could: its fragments unregistered, its manifest at the
 * next version of `writer`'s scope. `sign` gets the facts of exactly that
 * manifest and slot, and returns the statement the manifest carries.
 */
export async function injectReplicaBatch(
  net: Network,
  input: {
    writer: string;
    operations: ReplicaOperation[];
    sign: (facts: ReplicaBatchFacts) => Promise<unknown>;
    sequence?: number;
    previous?: Predecessor | null;
  },
) {
  const batch = randomBytes(16).toString("hex");
  const statement = {
    owner,
    writer: input.writer,
    batch,
    sequence: input.sequence ?? 1,
    previous: input.previous ?? null,
    collectedAt: at,
  };
  const bytes = Buffer.from(
    canonicalJson({ envelope: envelope(input.operations, batch), blobs: [] }),
  );
  const fragments = await fragmentReplicaPayload({
    ...statement,
    bytes,
    encrypt: net.port.encrypt,
  });
  for (const fragment of fragments) await net.port.putFragment(fragment);
  const scope = replicaScope(input.writer);
  const version = net.registrationsOf(scope) + 1;
  const prepared = await prepareReplicaManifest({
    ...statement,
    version,
    digest: replicaDigest(bytes),
    totalBytes: bytes.length,
    fragments: fragments.map((f) => ({
      digest: f.digest,
      bytes: f.encrypted.length,
    })),
    sign: input.sign,
    encrypt: net.port.encrypt,
  });
  const manifest = { ...prepared, version };
  await net.port.put(manifest);
  await net.port.register(manifest);
  return { batch, slot: slotKey(scope, version), manifest };
}

// ------------------------------------------------------- transport devices

export type TransportWorker = ReturnType<typeof createReplicaTransportWorker>;
export type Receiver = ReturnType<typeof createReplicaReceiver>;

/** One SQLite device: record store + receiver + transport worker on one file. */
export function transportDevice(
  net: Network,
  opts: {
    chunk?: number;
    cap?: number;
    /** Operations per batch (worker maxBatchOperations). */
    pageSize?: number;
    enabled?: boolean;
    preexisting?: string;
    crash?: CrashController;
    instance?: string;
    /** Extra worker deps, passed through (e.g. coordinator quanta). */
    worker?: Record<string, unknown>;
  } = {},
) {
  const directory = scratchDirectory("replica-contract");
  const path = join(directory, "records.sqlite");
  const instance = opts.instance ?? "conn";
  let real = new Database(path);
  let db = opts.crash ? crashableDatabase(real, opts.crash) : real;
  let store = createReplicaRecordStore(db);
  store.registerConnection({
    instance,
    sourceId,
    method: "export",
    label: "C",
  });
  const put = (text: string, id = "a") =>
    store.ingestBatch(
      [
        {
          instance,
          stream: "messages",
          key: id,
          data: { id, text },
          emitted_at: at,
        },
      ],
      () => "mutable_state",
      () => ["id"],
      { method: "export", generation: 1 },
    );
  // Drawn from node:crypto, so a seeded run gets the same keys and writers.
  const authority = replicaTestAuthority(
    net.roster,
    randomBytes(16).toString("hex"),
  );
  enableReplicaTestIdentity(db, {
    owner,
    roster: net.roster,
    authority,
    serverId: `0x${randomBytes(32).toString("hex")}`,
    nonce: `0x${randomBytes(16).toString("hex")}`,
  });
  if (opts.preexisting) put(opts.preexisting);
  store.replication.beginBaseline(expected);
  let declarations = expected.declarations;
  let receiver: Receiver;
  const make = () => {
    receiver = createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (c) => (c === credential ? owner : undefined),
      declarations: () =>
        declarations.map((d) => ({
          ...d,
          validateData: (data: Record<string, unknown>) =>
            typeof data.id === "string",
        })),
    });
    return createReplicaTransportWorker({
      db,
      exporter: store.replication,
      receiver,
      credential,
      enabled: opts.enabled ?? true,
      expected: () => ({ owner, declarations }),
      transport: net.port,
      authority,
      now: clock.now,
      targetChunkBytes: opts.chunk ?? 4000,
      maxBlobBytes: opts.cap ?? 8192,
      maxBatchOperations: opts.pageSize,
      ...(opts.worker ?? {}),
    });
  };
  let worker = make();
  const device = {
    path,
    instance,
    /** The server key and roster this device signs and checks with. */
    authority,
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    get receiver() {
      return receiver;
    },
    get worker() {
      return worker;
    },
    put,
    get(id = "a") {
      return store.getRecord(instance, "messages", id)?.data;
    },
    cycle: () => worker.cycle(),
    /** worker.step when the coordinator exists; otherwise one cycle and `undefined`. */
    async step(budget?: { units: number; bytes?: number }) {
      const step = (worker as { step?: (input: unknown) => Promise<unknown> })
        .step;
      if (typeof step === "function")
        return step.call(worker, { budget }) as Promise<unknown>;
      await worker.cycle();
      return undefined;
    },
    declarations(entries: typeof declarations) {
      declarations = entries;
    },
    /** Orderly restart: close, reopen the same file, rebuild all components. */
    reopen() {
      if (real.open) real.close();
      real = new Database(path);
      db = opts.crash ? crashableDatabase(real, opts.crash) : real;
      store = createReplicaRecordStore(db);
      worker = make();
    },
    /** Process loss: drop every component without cleanup, reopen without injection. */
    crashReopen() {
      if (real.open) real.close();
      opts.crash?.disarm();
      real = new Database(path);
      db = real;
      store = createReplicaRecordStore(db);
      worker = make();
    },
    /** The device's own database file as bytes (WAL content included). */
    image() {
      return real.serialize();
    },
    /**
     * Put this same device's file back to an image taken from it earlier, then
     * rebuild every component on it. It never takes an image of another device.
     */
    restore(image: Uint8Array) {
      if (real.open) real.close();
      for (const suffix of ["-wal", "-shm", "-journal"])
        rmSync(path + suffix, { force: true });
      writeFileSync(path, image);
      device.reopen();
    },
    close() {
      if (real.open) real.close();
    },
  };
  cleanups.push(() => device.close());
  return device;
}
export type TransportDevice = ReturnType<typeof transportDevice>;

/**
 * Record the exact state of these devices, their network and the clock, and
 * return a function that puts all of it back. Each device gets back its own
 * file; no image is ever shared between devices.
 */
export function checkpoint(
  net: Network,
  devices: TransportDevice[],
  crash?: CrashController,
) {
  const restoreNetwork = net.snapshot();
  const images = devices.map((d) => d.image());
  const time = clock.time;
  return () => {
    crash?.disarm();
    devices.forEach((d, i) => d.restore(images[i]!));
    restoreNetwork();
    clock.time = time;
  };
}

const isEffect = (label: string) => label.startsWith("net-");
/** A label without the ids that change from run to run ("net-get:<scope>" is "net-get"). */
const labelKind = (label: string) =>
  isEffect(label) ? label.replace(/:.*/, "") : label;

/**
 * The pull-request subset of a recorded trace, derived from its labels.
 *
 * The trace is cut into steps. A step is the writes since the last boundary and
 * the boundary that ends it: a transaction commit or one network effect. Steps
 * with the same label sequence are the same code path run again (one per
 * fragment, per scope, per page). For the first, the middle and the last run of
 * every distinct step, the tier takes:
 * - the step's first write;
 * - its last write, the last point where the transaction still rolls back;
 * - its boundary: the commit, or the network effect itself. Both sides of an
 *   effect are steps of their own ("net-before-put", "net-after-put").
 * It always includes the first and last point of the window.
 */
export function pullRequestTier(trace: readonly string[]): number[] {
  const steps: number[][] = [];
  let current: number[] = [];
  trace.forEach((label, i) => {
    current.push(i);
    if (label === "commit" || isEffect(label)) {
      steps.push(current);
      current = [];
    }
  });
  if (current.length) steps.push(current);
  const runs = new Map<string, number[][]>();
  for (const step of steps) {
    const key = step.map((i) => labelKind(trace[i]!)).join(">");
    runs.set(key, [...(runs.get(key) ?? []), step]);
  }
  const picked = new Set<number>([0, trace.length - 1]);
  for (const list of runs.values())
    for (const step of new Set([
      list[0]!,
      list[Math.floor((list.length - 1) / 2)]!,
      list.at(-1)!,
    ])) {
      picked.add(step[0]!);
      picked.add(step.at(-1)!);
      picked.add(step.at(-2) ?? step[0]!);
    }
  return [...picked].sort((x, y) => x - y);
}

/** Advance the clock and cycle every device n times. */
export async function cycles(devices: TransportDevice[], n = 12, ms = 10000) {
  for (let i = 0; i < n; i++) {
    clock.advance(ms);
    for (const d of devices) await d.cycle();
  }
}

// ----------------------------------------------------- durable inspection

/** Logical work record. Absent schema fields stay undefined (red until S2). */
export interface WorkRecord {
  table: string;
  id: string;
  writer?: string;
  state?: string;
  outcome?: string | null;
  reason?: string | null;
  cause?: unknown;
  dependency?: string | null;
  attempts?: number;
  nextEligible?: number;
  waitSince?: number | null;
  checkedBlock?: string | null;
  error?: string | null;
  prepared?: number;
  admission?: unknown;
}

function columns(db: Database.Database, table: string) {
  return new Set(
    (db.prepare(`PRAGMA table_info(${table})`).all() as { name: string }[]).map(
      (c) => c.name,
    ),
  );
}
const parseJson = (value: unknown) =>
  typeof value === "string" ? (JSON.parse(value) as unknown) : value;

/** Every per-item scheduling record the worker persisted, by table. */
export function workRecords(db: Database.Database): WorkRecord[] {
  const out: WorkRecord[] = [];
  const read = (
    table: string,
    idColumn: string,
    extra: (row: Record<string, unknown>) => Partial<WorkRecord> = () => ({}),
  ) => {
    const cols = columns(db, table);
    if (!cols.size) return;
    const pick = [...cols].filter(
      (c) =>
        !["fragment_json", "manifest_json", "plaintext", "encrypted"].includes(
          c,
        ),
    );
    const rows = db
      .prepare(`SELECT ${pick.join(",")} FROM ${table} ORDER BY rowid`)
      .all() as Record<string, unknown>[];
    for (const row of rows)
      out.push({
        table,
        id: String(row[idColumn]),
        state: row.state as string | undefined,
        outcome: cols.has("outcome")
          ? (row.outcome as string | null)
          : undefined,
        reason: cols.has("reason") ? (row.reason as string | null) : undefined,
        cause: cols.has("cause_json") ? parseJson(row.cause_json) : undefined,
        dependency: cols.has("dependency")
          ? (row.dependency as string | null)
          : undefined,
        attempts: row.attempts as number | undefined,
        nextEligible: row.next_attempt as number | undefined,
        waitSince: cols.has("wait_since")
          ? (row.wait_since as number | null)
          : undefined,
        checkedBlock: cols.has("checked_block")
          ? (row.checked_block as string | null)
          : undefined,
        error: row.error as string | null | undefined,
        ...extra(row),
      });
  };
  read("pdpp_transport_batches", "batch", (row) => ({
    prepared: row.prepared as number,
    admission: parseJson(row.admission_json),
  }));
  read("pdpp_transport_fragments_out", "batch", (row) => ({
    id: `${String(row.batch)}:${String(row.position)}`,
  }));
  // A manifest's work id is its slot, the key of its finality dependency.
  read("pdpp_transport_manifests_out", "batch", (row) => ({
    id: `${String(row.scope)}/${String(row.version)}`,
  }));
  read("pdpp_transport_manifests_in", "slot", (row) => ({
    writer: row.writer as string,
  }));
  read("pdpp_transport_fragments_in", "slot", (row) => ({
    id: `${String(row.slot)}#${String(row.position)}`,
  }));
  read("pdpp_transport_import_work", "batch", (row) => ({
    writer: row.writer as string,
  }));
  return out;
}

/** Deep-comparable durable snapshot of tables (scheduling columns optional). */
export function durableSnapshot(
  db: Database.Database,
  tables: string[],
  omit: string[] = [],
) {
  const snapshot: Record<string, unknown[]> = {};
  for (const table of tables) {
    const cols = [...columns(db, table)].filter((c) => !omit.includes(c));
    if (!cols.length) {
      snapshot[table] = [];
      continue;
    }
    snapshot[table] = db
      .prepare(`SELECT ${cols.join(",")} FROM ${table} ORDER BY rowid`)
      .all();
  }
  return snapshot;
}
export const SCHEDULING_COLUMNS = [
  "attempts",
  "next_attempt",
  "wait_since",
  "checked_block",
  "error",
  "outcome",
  "reason",
  "cause_json",
  "dependency",
  "evidence_checked",
];

/**
 * Impossible mixed tuples after process loss. Returns human-readable violations.
 * Pre-commit expectation is the old atomic state; post-commit is exactly the new.
 */
export function transportInvariantViolations(d: TransportDevice): string[] {
  const db = d.db;
  const violations: string[] = [];
  const has = (table: string) => columns(db, table).size > 0;
  if (has("pdpp_transport_manifests_in")) {
    const orphanImported = db
      .prepare(
        `SELECT slot FROM pdpp_transport_manifests_in i WHERE state='imported' AND NOT EXISTS (
          SELECT 1 FROM pdpp_transport_imported m WHERE m.writer=i.writer AND m.batch=i.batch)`,
      )
      .all() as { slot: string }[];
    if (orphanImported.length)
      violations.push(
        `slot imported without receipt: ${orphanImported.map((r) => r.slot).join(",")}`,
      );
  }
  if (has("pdpp_transport_batches")) {
    const prepared = db
      .prepare(
        `SELECT batch FROM pdpp_transport_batches b WHERE prepared=1 AND (
          NOT EXISTS (SELECT 1 FROM pdpp_transport_manifests_out m WHERE m.batch=b.batch)
          OR NOT EXISTS (SELECT 1 FROM pdpp_transport_fragments_out f WHERE f.batch=b.batch))`,
      )
      .all() as { batch: string }[];
    if (prepared.length)
      violations.push(
        `prepared batch without manifest or fragments: ${prepared.map((r) => r.batch).join(",")}`,
      );
    const unprepared = db
      .prepare(
        `SELECT DISTINCT o.batch FROM (SELECT batch FROM pdpp_transport_manifests_out UNION ALL SELECT batch FROM pdpp_transport_fragments_out) o
          JOIN pdpp_transport_batches b ON b.batch=o.batch WHERE b.prepared<>1`,
      )
      .all() as { batch: string }[];
    if (unprepared.length)
      violations.push(
        `outbound rows for unprepared batch: ${unprepared.map((r) => r.batch).join(",")}`,
      );
    const versions = db
      .prepare(
        "SELECT count(*) AS n, coalesce(max(version),0) AS top FROM pdpp_transport_manifests_out",
      )
      .get() as { n: number; top: number };
    if (versions.n !== versions.top)
      violations.push(
        `manifest versions not contiguous: ${versions.n} rows, top ${versions.top}`,
      );
    const state = db
      .prepare("SELECT sequence FROM pdpp_transport_state WHERE id=1")
      .get() as { sequence: number } | undefined;
    const max = db
      .prepare(
        "SELECT coalesce(max(sequence),0) AS n FROM pdpp_transport_batches",
      )
      .get() as { n: number };
    if (state && state.sequence !== max.n)
      violations.push(
        `writer sequence ${state.sequence} != retained batches ${max.n}`,
      );
  }
  // A live public record must have verified bytes for every referenced blob.
  const live = db
    .prepare(
      "SELECT instance,stream,record_key,blob_id FROM pdpp_records WHERE deleted=0 AND blob_id IS NOT NULL",
    )
    .all() as { blob_id: string }[];
  for (const row of live)
    if (!d.store.getBlobBytes(row.blob_id))
      violations.push(`live record without bytes: ${row.blob_id}`);
  return violations;
}

// ----------------------------------------------- canonical store adapters

export type Surface =
  | "point"
  | "list"
  | "changes"
  | "blob"
  | "completion"
  | "integrityEpoch"
  | "bindingConflict";
export type SurfaceSupport = Record<Surface, "supported" | "unsupported">;

/** Uniform retained-import adapter over Node SQLite and the Lite store. */
export interface CanonicalAdapter {
  name: string;
  surfaces: SurfaceSupport;
  connectionId: string;
  declare(context: MergeContext): void;
  provision(
    connectionId: string,
    mapping: { sourceId: string; methodId: string },
  ): Promise<void>;
  send(ops: ReplicaOperation[], id?: string): Promise<unknown>;
  retry(): Promise<unknown>;
  reopen(): void;
  point(
    connectionId: string,
    stream: string,
    key: string,
  ): Promise<{ deleted: boolean; data?: unknown } | undefined>;
  /** Node only. Lite has no public list/changes/completion surfaces. */
  list?(
    connectionId: string,
    stream: string,
    options?: { limit?: number; cursor?: string },
  ): Promise<{
    data: { recordKey: string; data: unknown }[];
    nextCursor?: string;
  }>;
  changes?(
    connectionId: string,
    stream: string,
    options?: { limit?: number; cursor?: string; changesSince?: string },
  ): Promise<{
    data: unknown[];
    nextCursor?: string;
    nextChangesSince?: string;
  }>;
  blob?(blobId: string): Promise<Uint8Array | undefined>;
  completion?(connectionId: string, stream: string): Promise<unknown>;
  integrityEpoch?(connectionId: string): number;
  bindingConflict?(connectionId: string): boolean;
}

/** Real disk SQLite implementation of the Lite port. No native-file claims. */
function liteSqlitePort() {
  const directory = scratchDirectory("lite-contract");
  const path = join(directory, "native.sqlite");
  let db: Database.Database;
  let queue = Promise.resolve();
  const open = () => {
    db = new Database(path);
    db.pragma("journal_mode=WAL");
    db.exec(
      "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, bytes BLOB NOT NULL); CREATE TABLE IF NOT EXISTS staging (id TEXT PRIMARY KEY, descriptor TEXT NOT NULL, bytes BLOB NOT NULL)",
    );
  };
  open();
  const port: LiteCanonicalPersistence = {
    transaction<T>(run: (tx: LiteCanonicalTransaction) => Promise<T>) {
      const work = queue.then(async () => {
        db.exec("BEGIN IMMEDIATE");
        let committed = false;
        try {
          const tx: LiteCanonicalTransaction = {
            async get(key) {
              return (
                db.prepare("SELECT value FROM kv WHERE key=?").get(key) as
                  { value: string } | undefined
              )?.value;
            },
            async put(key, value) {
              if (Buffer.byteLength(value) > 256 * 1024)
                throw new Error("native value exceeds 256 KiB");
              db.prepare(
                "INSERT INTO kv VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
              ).run(key, value);
            },
            async delete(key) {
              db.prepare("DELETE FROM kv WHERE key=?").run(key);
            },
            async scan(prefix, after) {
              const entries = db
                .prepare(
                  "SELECT key,value FROM kv WHERE substr(key,1,length(?))=? AND key>? ORDER BY key LIMIT 101",
                )
                .all(prefix, prefix, after ?? "") as {
                key: string;
                value: string;
              }[];
              const page = storagePage(entries, after);
              if (entries.length === 101 && !page.after)
                page.after = page.entries.at(-1)!.key;
              return page;
            },
            async attachBlob(id, descriptor) {
              const staged = db
                .prepare("SELECT * FROM staging WHERE id=?")
                .get(id) as { descriptor: string; bytes: Buffer } | undefined;
              if (!staged || staged.descriptor !== canonicalJson(descriptor))
                throw new Error("unknown staged blob");
              db.prepare("INSERT OR IGNORE INTO blobs VALUES (?,?,?)").run(
                descriptor.blobId,
                staged.descriptor,
                staged.bytes,
              );
            },
            async blob(id) {
              const row = db
                .prepare("SELECT descriptor FROM blobs WHERE id=?")
                .get(id) as { descriptor: string } | undefined;
              return row ? JSON.parse(row.descriptor) : undefined;
            },
          };
          const result = await run(tx);
          db.exec("COMMIT");
          committed = true;
          return result;
        } catch (error) {
          if (!committed) db.exec("ROLLBACK");
          throw error;
        }
      });
      queue = work.then(
        () => undefined,
        () => undefined,
      );
      return work;
    },
    async stageBlob(descriptor, chunks) {
      const value = await collectStagedBlob(descriptor, chunks);
      const id = globalThis.crypto.randomUUID();
      db.prepare("INSERT INTO staging VALUES (?,?,?)").run(
        id,
        canonicalJson(value.descriptor),
        value.bytes,
      );
      return id;
    },
    async *readBlob(id) {
      const row = db.prepare("SELECT bytes FROM blobs WHERE id=?").get(id) as
        { bytes: Buffer } | undefined;
      if (!row) throw new Error("missing committed blob");
      yield new Uint8Array(row.bytes);
    },
  };
  cleanups.push(() => {
    if (db.open) db.close();
  });
  return {
    port,
    reopen() {
      db.close();
      open();
    },
  };
}
function liteMemoryPort() {
  const disk = fakeCanonicalDisk();
  let current = createFakeCanonicalPersistence(disk);
  return {
    get port() {
      return current.port;
    },
    reopen() {
      current = createFakeCanonicalPersistence(disk);
    },
  };
}

const liteSurfaces: SurfaceSupport = {
  point: "supported",
  list: "unsupported",
  changes: "unsupported",
  blob: "supported",
  completion: "unsupported",
  integrityEpoch: "unsupported",
  bindingConflict: "unsupported",
};
const nodeSurfaces: SurfaceSupport = {
  point: "supported",
  list: "supported",
  changes: "supported",
  blob: "supported",
  completion: "supported",
  integrityEpoch: "supported",
  bindingConflict: "supported",
};

/** Envelope for retained-import tests. ids must be unique per batch on Lite. */
export function envelope(ops: ReplicaOperation[], batchId = "batch") {
  return {
    format: "vana-pdpp-replica",
    version: 1,
    owner: ops[0]?.owner ?? owner,
    batchId,
    operations: ops,
  };
}

export async function liteAdapter(
  kind: "memory" | "sqlite",
  context: MergeContext,
  provisioned?: { connectionId: string; sourceId: string; methodId: string },
): Promise<CanonicalAdapter> {
  const persistence = kind === "memory" ? liteMemoryPort() : liteSqlitePort();
  let known = context;
  const make = () =>
    createLiteCanonicalStore({
      persistence: persistence.port,
      enabled: true,
      context: () => known,
      authenticateReplica: (c) => (c === credential ? known.owner : undefined),
    });
  let store = make();
  let batches = 0;
  if (provisioned)
    await store.provisionConnection(provisioned.connectionId, {
      sourceId: provisioned.sourceId,
      methodId: provisioned.methodId,
    });
  const adapter: CanonicalAdapter = {
    name: `lite-${kind}`,
    surfaces: liteSurfaces,
    connectionId: provisioned?.connectionId ?? "",
    declare(next) {
      known = next;
    },
    async provision(connectionId, mapping) {
      await store.provisionConnection(connectionId, mapping);
    },
    send(ops, id = `batch-${++batches}`) {
      return store.import({ id, envelope: envelope(ops, id), credential });
    },
    retry() {
      return store.retry({ credential });
    },
    reopen() {
      persistence.reopen();
      store = make();
    },
    async point(connectionId, stream, key) {
      const row = await store.readRecord(connectionId, stream, key);
      return row as { deleted: boolean; data?: unknown } | undefined;
    },
    async blob(blobId) {
      try {
        const parts: Uint8Array[] = [];
        for await (const part of store.readBlob(blobId)) parts.push(part);
        return new Uint8Array(Buffer.concat(parts));
      } catch {
        return undefined;
      }
    },
  };
  return adapter;
}

export function nodeAdapter(
  context: MergeContext,
  provisioned?: { connectionId: string; sourceId: string; methodId: string },
): CanonicalAdapter {
  const directory = scratchDirectory("node-contract");
  const path = join(directory, "records.sqlite");
  let known = context;
  let db = new Database(path);
  let store = createReplicaRecordStore(db);
  if (provisioned)
    store.registerConnection({
      instance: provisioned.connectionId,
      sourceId: provisioned.sourceId,
      method: provisioned.methodId,
      label: "fixture",
    });
  store.replication.beginBaseline({
    owner: context.owner,
    declarations: context.declarations.map(({ sourceId, binding }) => ({
      sourceId,
      binding,
    })),
  });
  const receiver = () =>
    createReplicaReceiver({
      db,
      store,
      owner: known.owner,
      authenticate: (c) => (c === credential ? known.owner : undefined),
      declarations: () => known.declarations,
    });
  cleanups.push(() => {
    if (db.open) store.close();
  });
  const epoch = () =>
    (store as { replicaIntegrityEpoch?: (key: string) => number })
      .replicaIntegrityEpoch;
  const conflict = () =>
    (store as { replicaBindingConflict?: (key: string) => boolean })
      .replicaBindingConflict;
  return {
    name: "node-sqlite",
    surfaces: nodeSurfaces,
    connectionId: provisioned?.connectionId ?? "",
    declare(next) {
      known = next;
    },
    async provision(connectionId, mapping) {
      store.registerConnection({
        instance: connectionId,
        sourceId: mapping.sourceId,
        method: mapping.methodId,
        label: "fixture",
      });
    },
    async send(ops, id = "batch") {
      return receiver().import({ credential, envelope: envelope(ops, id) });
    },
    async retry() {
      return receiver().retry({ credential });
    },
    reopen() {
      store.close();
      db = new Database(path);
      store = createReplicaRecordStore(db);
    },
    async point(connectionId, stream, key) {
      const row = store.getRecord(connectionId, stream, key);
      return row ? { deleted: false, data: row.data } : undefined;
    },
    async list(connectionId, stream, options = {}) {
      const page = store.listRecords(stream, {
        instanceIds: [connectionId],
        limit: options.limit ?? 100,
        order: "asc",
        cursor: options.cursor,
      });
      return {
        data: page.data.map((r) => ({ recordKey: r.recordKey, data: r.data })),
        nextCursor: page.nextCursor,
      };
    },
    async changes(connectionId, stream, options = {}) {
      return store.changesSince(stream, {
        instanceIds: [connectionId],
        limit: options.limit ?? 100,
        cursor: options.cursor,
        changesSince: options.changesSince,
      });
    },
    async blob(blobId) {
      return store.getBlobBytes(blobId);
    },
    async completion(connectionId, stream) {
      return store
        .listStreamCompletions(connectionId)
        .find((c) => c.stream === stream);
    },
    integrityEpoch(connectionId) {
      const read = epoch();
      if (typeof read !== "function")
        throw new Error("store.replicaIntegrityEpoch is missing");
      return read.call(store, connectionId);
    },
    bindingConflict(connectionId) {
      const read = conflict();
      if (typeof read !== "function")
        throw new Error("store.replicaBindingConflict is missing");
      return read.call(store, connectionId);
    },
  };
}

/** The three adapters every shared case runs against. */
export const adapterFactories: Record<
  string,
  (
    context: MergeContext,
    provisioned?: { connectionId: string; sourceId: string; methodId: string },
  ) => Promise<CanonicalAdapter>
> = {
  "Node SQLite": async (context, provisioned) =>
    nodeAdapter(context, provisioned),
  "Lite memory": (context, provisioned) =>
    liteAdapter("memory", context, provisioned),
  "Lite SQLite port": (context, provisioned) =>
    liteAdapter("sqlite", context, provisioned),
};
