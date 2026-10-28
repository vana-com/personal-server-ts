import Database from "better-sqlite3";
import { keccak256, stringToHex } from "viem";
import { afterEach, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { createReplicaRecordStore } from "./pdpp-replica-canonical-port.js";
import { createReplicaReceiver } from "./pdpp-replication-receiver.js";
import { retireReplication } from "./pdpp-replication-door.js";
import {
  createReplicaTransportWorker,
  ReplicaCarrierMismatchError,
} from "./pdpp-replication-transport.js";
import { unprovisionConnection } from "./pdpp-replica-contract.test-utils.js";
import { binaryWriter, readBinary } from "./pdpp-binary-chunks.js";
import {
  readBoundedResponse,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";
import { createTestReplicaRoster } from "@opendatalabs/personal-server-ts-core/replication/writer-identity.test-utils";
import {
  enableReplicaTestIdentity,
  replicaTestAuthority,
} from "./pdpp-replica-writer-identity.test-utils.js";
import {
  createDpv2ReplicaTransport,
  replicaChainCommitment,
  type ReplicaFinalizedChainEvidence,
  type ReplicaCommitment,
} from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  REPLICA_MAX_BLOB_BYTES,
  decodeReplicaManifest,
  decodeReplicaFragment,
  fragmentReplicaPayload,
  replicaDigest,
  replicaFragmentKey,
  replicaScope,
  prepareReplicaManifest,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  REPLICA_MAX_OPERATIONS,
  REPLICA_MAX_TOTAL_BYTES,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import {
  admit,
  ReplicaByteBudget,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import { remoteReplicaTestWriter } from "./pdpp-replica-writer-identity.test-utils.js";
import type { ReplicaTransportPort } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import {
  encodeReplicaPayload,
  assembleReplicaStream,
  DEFAULT_REPLICA_STREAMED_LIMITS,
  inspectReplicaPayload,
} from "@opendatalabs/personal-server-ts-core/replication/stream";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";

const owner = "0x0000000000000000000000000000000000000001";
const sourceId = "https://source.invalid/declaration";
const at = "2026-10-20T00:00:00.000Z";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const expected = { owner, declarations: [{ sourceId, binding }] };
const directories: string[] = [];
const devices: ReturnType<typeof device>[] = [];
let time = Date.parse(at);

const slotKey = (scope: string, version: number | string) =>
  `${scope}/${version}`;
const slotParts = (slot: string) => {
  const cut = slot.lastIndexOf("/");
  return { scope: slot.slice(0, cut), version: Number(slot.slice(cut + 1)) };
};
const isFragmentKey = (key: string) => key.includes("/fragments/");
/** The batch id inside a fragment or manifest plaintext. */
function batchOfPlaintext(bytes: Uint8Array) {
  const data = (
    JSON.parse(new TextDecoder().decode(bytes)) as {
      data: { fragment?: { batch: string }; manifest?: { batch: string } };
    }
  ).data;
  return (data.fragment ?? data.manifest)!.batch;
}

/**
 * Storage cap + DPv2 version guard, plus independent Gateway head and
 * finalized chain stores. Registry state is per slot (`<scope>/<version>`).
 * Storage keys are exact: manifests at `<scope>/<version>`, fragments at
 * `<scope>/fragments/<sha256>`.
 */
function network(realCrypto = false, cap = 8192) {
  const blobs = new Map<string, Uint8Array>();
  const head = new Map<string, ReplicaCommitment>();
  const chain = new Map<string, ReplicaFinalizedChainEvidence>();
  const latest = (map: Map<string, unknown>, scope: string) =>
    Math.max(
      0,
      ...[...map.keys()]
        .map(slotParts)
        .filter((p) => p.scope === scope)
        .map((p) => p.version),
    );
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
  const puts: { key: string; bytes: Uint8Array }[] = [];
  const gets: string[] = [];
  const registrations: string[] = [];
  const failPut = new Set<string>();
  const failGet = new Set<string>();
  let loseRegistrationResponse = false;
  let failGetAfter = Infinity;
  let pageSize = 1000;
  let beforePut = (_key: string, _bytes: Uint8Array) => {};
  const storage = {
    async upload(key: string, data: Uint8Array) {
      if (data.length > cap) throw new Error("413 storage MAX_BLOB_SIZE");
      beforePut(key, data);
      puts.push({ key, bytes: new Uint8Array(data) });
      if (failPut.has(key)) throw new Error("offline");
      blobs.set(key, new Uint8Array(data));
      return key;
    },
    urlForKey: (key: string) => key,
    async download(key: string) {
      gets.push(key);
      if (gets.length > failGetAfter || failGet.has(key))
        throw new Error("download disconnected");
      const bytes = blobs.get(key);
      if (!bytes) throw new Error("404");
      return new Uint8Array(bytes);
    },
    async downloadBounded(key: string, budget: ByteBudget) {
      return readBoundedResponse(
        new Response(await storage.download(key)),
        budget,
      );
    },
    delete: async () => false,
    exists: async (key: string) => blobs.has(key),
  };
  const signAddData = vi.fn(async (msg: { expectedVersion: bigint }) => {
    expect(msg.expectedVersion).toBeGreaterThan(0n);
    return "0x1234" as const;
  });
  const adapter = createDpv2ReplicaTransport({
    owner,
    masterKey: new Uint8Array(32).fill(5),
    storage,
    signer: { signAddData },
    gateway: {
      async registerDataPoint(input) {
        const slot = slotKey(input.scope, input.expectedVersion);
        registrations.push(slot);
        const max = Math.max(
          latest(head, input.scope),
          latest(chain, input.scope),
        );
        if (Number(input.expectedVersion) <= max)
          throw new Error(
            `Gateway error: 409 Stale expectedVersion; stored value ${max}`,
          );
        if (Number(input.expectedVersion) !== max + 1)
          throw new Error(
            `Gateway error: 409 Gap in version sequence; next valid version is ${max + 1}`,
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
        if (loseRegistrationResponse) {
          loseRegistrationResponse = false;
          throw new Error("response lost after commit");
        }
        return { dataPointId: slot } as never;
      },
    },
    feed: {
      async listDataPointsByOwner(_owner, cursor) {
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
      const known = chain.get(slot);
      return {
        head: head.get(slotKey(scope, latest(head, scope))) ?? null,
        chain: known ?? {
          ...chainRow(slot),
          currentVersion: String(latest(chain, scope)),
        },
        pending: pending.has(slot),
      };
    },
  });
  // Fast authenticated codec for high-cardinality/fault cases; one oracle below uses real SDK OpenPGP.
  const key = randomBytes(32);
  const fast = {
    async encrypt(_scope: string, bytes: Uint8Array) {
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
    ...(realCrypto ? {} : fast),
  };
  return {
    port,
    roster: createTestReplicaRoster(),
    blobs,
    head,
    chainRow,
    chain,
    pending,
    puts,
    gets,
    registrations,
    signAddData,
    failPut,
    failGet,
    /** Move every pending slot into finalized chain evidence. */
    finalizeAll(blockNumber = 123n) {
      for (const slot of pending) {
        const row = head.get(slot);
        if (row) chain.set(slot, { ...chainRow(slot, row), blockNumber });
      }
      pending.clear();
    },
    loseNextRegistrationResponse() {
      loseRegistrationResponse = true;
    },
    failDownloadsAfter(n: number) {
      failGetAfter = n;
    },
    pageSize(n: number) {
      pageSize = n;
    },
    beforePut(fn: typeof beforePut) {
      beforePut = fn;
    },
  };
}
function device(
  net: ReturnType<typeof network>,
  opts: {
    chunk?: number;
    cap?: number;
    pageSize?: number;
    enabled?: boolean;
    preexisting?: string;
    /** Open a copy of another device's database, with its server key. */
    copyOf?: ReturnType<typeof device>;
    /** Extra worker deps, passed through (e.g. coordinator quanta). */
    worker?: Record<string, unknown>;
    /** Runs on the database before the first worker opens it. */
    beforeOpen?: (db: Database.Database) => void;
  } = {},
) {
  const dir = mkdtempSync(join(tmpdir(), "replica-transport-"));
  directories.push(dir);
  const path = join(dir, "records.sqlite");
  if (opts.copyOf) writeFileSync(path, opts.copyOf.db.serialize());
  let db = new Database(path);
  let store = createReplicaRecordStore(db);
  if (!opts.copyOf)
    store.registerConnection({
      instance: "conn",
      sourceId,
      method: "export",
      label: "C",
    });
  const put = (text: string, id = "a") =>
    store.ingestBatch(
      [
        {
          instance: "conn",
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
  const authority = opts.copyOf?.authority ?? replicaTestAuthority(net.roster);
  if (!opts.copyOf) {
    enableReplicaTestIdentity(db, { owner, roster: net.roster, authority });
    if (opts.preexisting) put(opts.preexisting);
    store.replication.beginBaseline(expected);
  }
  let declarations = expected.declarations;
  function worker() {
    const receiver = createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (c) => (c === "replica-secret" ? owner : undefined),
      declarations: () =>
        declarations.map((d) => ({
          ...d,
          validateData: (data) => typeof data.id === "string",
        })),
    });
    return createReplicaTransportWorker({
      db,
      exporter: store.replication,
      receiver,
      credential: "replica-secret",
      enabled: opts.enabled ?? true,
      expected: () => ({ owner, declarations }),
      transport: net.port,
      authority,
      now: () => time,
      targetChunkBytes: opts.chunk ?? 4000,
      maxBlobBytes: opts.cap ?? 8192,
      maxBatchOperations: opts.pageSize,
      ...opts.worker,
    });
  }
  opts.beforeOpen?.(db);
  let engine = worker();
  const d = {
    authority,
    get db() {
      return db;
    },
    get store() {
      return store;
    },
    put,
    step: () => engine.step(),
    get(id = "a") {
      return store.getRecord("conn", "messages", id)?.data;
    },
    cycle: () => engine.cycle(),
    notify: (key: string) => engine.onDependencyChanged(key),
    readmitFragments: () => engine.readmitFragments(),
    get scope() {
      const { writer } = db
        .prepare("SELECT writer FROM pdpp_transport_state WHERE id=1")
        .get() as { writer: string };
      return replicaScope(writer);
    },
    declarations(entries: typeof declarations) {
      declarations = entries;
    },
    reopen() {
      store.close();
      db = new Database(path);
      store = createReplicaRecordStore(db);
      engine = worker();
    },
    close() {
      if (db.open) store.close();
    },
  };
  devices.push(d);
  return d;
}
async function cycles(ds: ReturnType<typeof device>[], n = 12) {
  for (let i = 0; i < n; i++) {
    time += 10000;
    for (const d of ds) await d.cycle();
  }
}
/** The sender's registered unit: one manifest per batch, at one slot. */
function outbox(d: ReturnType<typeof device>) {
  return (
    d.db
      .prepare("SELECT * FROM pdpp_transport_manifests_out ORDER BY version")
      .all() as {
      batch: string;
      scope: string;
      version: number;
      state: string;
      encrypted: Buffer;
      plaintext: Buffer;
      attempts: number;
      next_attempt: number;
      checked_block: string | null;
      outcome: string | null;
    }[]
  ).map((row) => ({ ...row, slot: slotKey(row.scope, row.version) }));
}
/** The sender's unregistered fragment uploads. */
function fragmentsOut(d: ReturnType<typeof device>) {
  return d.db
    .prepare(
      "SELECT * FROM pdpp_transport_fragments_out ORDER BY batch,position",
    )
    .all() as {
    batch: string;
    position: number;
    digest: string;
    encrypted: Buffer;
    state: string;
    attempts: number;
  }[];
}
function importWork(d: ReturnType<typeof device>) {
  return d.db.prepare("SELECT * FROM pdpp_transport_import_work").all() as {
    outcome: string | null;
    reason: string | null;
    dependency: string | null;
    error: string | null;
  }[];
}
/** The receiver's discovered slots. */
function inbox(d: ReturnType<typeof device>) {
  return d.db
    .prepare("SELECT * FROM pdpp_transport_manifests_in ORDER BY slot")
    .all() as {
    slot: string;
    state: string;
    manifest_json: string | null;
    reason: string | null;
    error: string | null;
    attempts: number;
    next_attempt: number;
  }[];
}
/** The receiver's retained fragments of slots not imported yet. */
function fragmentsIn(d: ReturnType<typeof device>) {
  return d.db.prepare("SELECT * FROM pdpp_transport_fragments_in").all() as {
    slot: string;
    position: number;
    fragment_json: string | null;
    state: string;
  }[];
}
afterEach(() => {
  for (const d of devices.splice(0)) d.close();
  for (const dir of directories.splice(0))
    rmSync(dir, { recursive: true, force: true });
  time = Date.parse(at);
});

it("two SQLite devices converge through real SDK OpenPGP + DPv2 signing/storage, without echo", async () => {
  const net = network(true);
  const a = device(net),
    b = device(net);
  a.put("from A");
  b.put("from B");
  const journalCount = (d: typeof a) =>
    (
      d.db
        .prepare("SELECT COUNT(*) AS n FROM pdpp_replica_operations")
        .get() as { n: number }
    ).n;
  const aCount = journalCount(a),
    bCount = journalCount(b);
  await cycles([a, b], 4);
  expect(a.get()).toEqual(b.get());
  expect(a.get()).toBeDefined();
  expect(journalCount(a)).toBe(aCount);
  expect(journalCount(b)).toBe(bCount);
  const count = net.registrations.length;
  await cycles([a, b], 2);
  expect(net.registrations).toHaveLength(count);
  expect(net.signAddData).toHaveBeenCalled();
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
}, 30000);

it("resumes uncertain publication with identical durable ciphertext, adopting only its verified slot", async () => {
  const net = network();
  const a = device(net, { preexisting: "baseline", chunk: 600 });
  net.beforePut((key, bytes) => {
    const durable = isFragmentKey(key)
      ? fragmentsOut(a).find(
          (r) => replicaFragmentKey(a.scope, r.digest) === key,
        )
      : outbox(a).find((r) => r.slot === key);
    expect(durable?.encrypted).toEqual(Buffer.from(bytes));
    expect(a.store.replication.getBaselineCheckpoint()).toBeGreaterThan(0);
    // The registration stays unconfirmed: its outcome is uncertain.
    net.pending.add(key);
  });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const original = outbox(a);
  const fragments = fragmentsOut(a);
  expect(fragments.length).toBeGreaterThan(1);
  expect(original.some((r) => r.state === "ready")).toBe(true);
  a.reopen();
  net.finalizeAll();
  await cycles([a], 2);
  expect(outbox(a).map((r) => r.encrypted)).toEqual(
    original.map((r) => r.encrypted),
  );
  expect(fragmentsOut(a).map((r) => r.encrypted)).toEqual(
    fragments.map((r) => r.encrypted),
  );
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
  expect(net.registrations.filter((s) => s === original[0]!.slot)).toHaveLength(
    1,
  );
});

it("does not resubmit a registration while accepted evidence is temporarily hidden", async () => {
  const net = network();
  const a = device(net);
  const originalRegister = net.port.register;
  const calls: string[] = [];
  let hidden: Parameters<ReplicaTransportPort["register"]>[0] | undefined;
  net.port.register = async (manifest) => {
    calls.push(slotKey(manifest.scope, manifest.version));
    await originalRegister(manifest);
    hidden = manifest;
    const slot = slotKey(manifest.scope, manifest.version);
    net.head.delete(slot);
    net.chain.delete(slot);
  };

  await a.cycle();
  const slot = outbox(a)[0]!.slot;
  expect(calls).toEqual([slot]);
  expect(outbox(a)[0]?.outcome).toBe("wait");
  const batchesBeforeSuccessor = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  const intentsBeforeSuccessor = (
    a.db
      .prepare("SELECT count(*) AS n FROM pdpp_transport_registration_intents")
      .get() as { n: number }
  ).n;
  const putsBeforeSuccessor = net.puts.length;
  a.put("successor while registration is unresolved", "second");
  a.reopen();

  for (let poll = 0; poll < 5; poll++) {
    time += 1_000;
    await a.cycle();
  }
  expect(calls).toEqual([slot]);
  expect(outbox(a).map((row) => row.version)).toEqual([1]);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as {
        n: number;
      }
    ).n,
  ).toBe(batchesBeforeSuccessor);
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_registration_intents",
        )
        .get() as { n: number }
    ).n,
  ).toBe(intentsBeforeSuccessor);
  expect(net.puts).toHaveLength(putsBeforeSuccessor);

  const manifest = hidden!;
  const registered = {
    owner,
    scope: manifest.scope,
    version: String(manifest.version),
    dataHash: manifest.dataHash,
    metadataHash: manifest.metadataHash,
    deleted: false,
  };
  net.head.set(slot, registered);
  net.chain.set(slot, net.chainRow(slot, registered));
  await cycles([a], 2);
  expect(outbox(a).find((row) => row.slot === slot)?.state).toBe("published");
});

it("S1 blocks a new slot when post-registration evidence retries", async () => {
  const net = network();
  const a = device(net);
  const originalEvidence = net.port.evidence;
  let evidenceCalls = 0;
  net.port.evidence = async (scope, version) => {
    evidenceCalls++;
    if (evidenceCalls >= 2) throw new Error("evidence lookup unavailable");
    return originalEvidence(scope, version);
  };

  a.put("predecessor", "first");
  await a.cycle();
  const predecessor = outbox(a)[0]!;
  expect(predecessor.version).toBe(1);
  expect(predecessor.outcome).toBe("retry");
  expect(net.registrations).toEqual([predecessor.slot]);

  const putsBeforeSuccessor = net.puts.length;
  const batchesBeforeSuccessor = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  a.put("successor", "second");
  await cycles([a], 3);

  expect(outbox(a).map((row) => row.version)).toEqual([1]);
  expect(net.registrations).toEqual([predecessor.slot]);
  expect(net.puts).toHaveLength(putsBeforeSuccessor);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as { n: number }
    ).n,
  ).toBe(batchesBeforeSuccessor);
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_registration_intents",
        )
        .get() as { n: number }
    ).n,
  ).toBe(1);
});

it("S2 blocks an unknown prepared state by default", async () => {
  const net = network();
  const a = device(net);
  net.port.encrypt = async () => {
    throw new Error("preparation unavailable");
  };
  a.put("unknown state predecessor", "first");
  await a.cycle();
  const predecessor = a.db
    .prepare("SELECT batch,prepared FROM pdpp_transport_batches")
    .get() as { batch: string; prepared: number };
  expect(predecessor.prepared).toBe(0);
  a.db
    .prepare("UPDATE pdpp_transport_batches SET prepared=2 WHERE batch=?")
    .run(predecessor.batch);

  const batchesBeforeSuccessor = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  a.put("successor", "second");
  await cycles([a], 3);

  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as { n: number }
    ).n,
  ).toBe(batchesBeforeSuccessor);
  expect(
    a.db
      .prepare("SELECT count(*) AS n FROM pdpp_transport_registration_intents")
      .get(),
  ).toEqual({ n: 0 });
  expect(net.puts).toEqual([]);
  expect(net.registrations).toEqual([]);
});

it("S3 keeps a retrying prepared batch ahead of later source operations", async () => {
  const net = network();
  const a = device(net);
  net.port.encrypt = async () => {
    throw new Error("preparation unavailable");
  };
  a.put("prepared retry", "first");
  await a.cycle();
  expect(
    a.db.prepare("SELECT prepared,outcome FROM pdpp_transport_batches").get(),
  ).toMatchObject({ prepared: 0, outcome: "retry" });
  const batches = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  a.put("later operation", "second");
  await cycles([a], 3);

  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as { n: number }
    ).n,
  ).toBe(batches);
  expect(outbox(a)).toEqual([]);
  expect(net.puts).toEqual([]);
  expect(net.registrations).toEqual([]);
});

it("S3 keeps an uploaded batch ahead of later operations while a fragment retries", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((key) => {
    if (isFragmentKey(key)) net.failPut.add(key);
  });
  a.put("fragment retry", "first");
  await a.cycle();
  expect(outbox(a)).toHaveLength(1);
  expect(fragmentsOut(a).some((row) => row.outcome === "retry")).toBe(true);
  const batches = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  const intents = (
    a.db
      .prepare("SELECT count(*) AS n FROM pdpp_transport_registration_intents")
      .get() as { n: number }
  ).n;
  const putsBefore = net.puts.length;
  const putKeys = new Set(net.puts.map(({ key }) => key));

  a.put("later operation", "second");
  await cycles([a], 3);

  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as { n: number }
    ).n,
  ).toBe(batches);
  expect(outbox(a).map((row) => row.version)).toEqual([1]);
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_registration_intents",
        )
        .get() as { n: number }
    ).n,
  ).toBe(intents);
  expect(net.puts.slice(putsBefore).every(({ key }) => putKeys.has(key))).toBe(
    true,
  );
  expect(net.registrations).toEqual([]);
});

it("reports a pending predecessor and re-registers that same slot after authoritative absence", async () => {
  const net = network();
  const a = device(net, {
    pageSize: 1,
    worker: { registrationIntentTimeoutMs: 5_000 },
  });
  const originalRegister = net.port.register;
  const calls: string[] = [];
  net.port.register = async (manifest) => {
    calls.push(slotKey(manifest.scope, manifest.version));
    await originalRegister(manifest);
  };

  net.beforePut((key) => net.pending.add(key));
  a.put("first", "first");
  await a.cycle();
  const predecessor = outbox(a)[0]!;
  expect(predecessor.version).toBe(1);
  const batchesBeforeSuccessor = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  const intentsBeforeSuccessor = (
    a.db
      .prepare("SELECT count(*) AS n FROM pdpp_transport_registration_intents")
      .get() as { n: number }
  ).n;
  const putsBeforeSuccessor = net.puts.length;

  // Later source operations accumulate without claiming a successor slot.
  a.put("second", "second");
  for (let poll = 0; poll < 8; poll++) {
    time += 1_000;
    await a.cycle();
  }
  expect(outbox(a).map((row) => row.version)).toEqual([1]);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as {
        n: number;
      }
    ).n,
  ).toBe(batchesBeforeSuccessor);
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_transport_registration_intents",
        )
        .get() as { n: number }
    ).n,
  ).toBe(intentsBeforeSuccessor);
  expect(net.puts).toHaveLength(putsBeforeSuccessor);

  const waitingRow = outbox(a).find((row) => row.version === 1)!;
  time = Math.max(time, waitingRow.next_attempt);
  const status = await a.step();
  const pending = status.waits.find((wait) => wait.id === predecessor.slot);
  expect(pending?.dependency).toMatchObject({
    kind: "registration_pending",
    version: 1,
    since: expect.any(Number),
  });
  expect(pending?.ageMs).toEqual(expect.any(Number));
  expect(pending!.dependency.since).toBeLessThanOrEqual(time);

  net.head.delete(predecessor.slot);
  net.chain.delete(predecessor.slot);
  net.pending.delete(predecessor.slot);
  net.beforePut(() => {});
  time += 5_000;
  await cycles([a], 4);

  expect(calls.filter((value) => value === predecessor.slot)).toHaveLength(2);
  expect(outbox(a).find((row) => row.version === 1)?.state).toBe("published");
  expect(outbox(a).find((row) => row.version === 2)?.state).toBe("published");
});

it("S4 treats a finalized immutable conflict as a settled predecessor slot", async () => {
  const net = network();
  const a = device(net);
  const originalEvidence = net.port.evidence;
  let conflictInserted = false;
  net.port.evidence = async (scope, version) => {
    if (version === 1 && !conflictInserted) {
      const slot = slotKey(scope, version);
      net.chain.set(slot, {
        ...net.chainRow(slot),
        currentVersion: "1",
        status: "Active",
        commitment: `0x${"4".repeat(64)}`,
      });
      conflictInserted = true;
    }
    return originalEvidence(scope, version);
  };

  a.put("conflicting predecessor", "first");
  await a.cycle();
  expect(outbox(a)[0]).toMatchObject({
    version: 1,
    state: "quarantined",
    outcome: "quarantine",
    reason: "immutable_registration_conflict",
  });

  a.put("successor after settled conflict", "second");
  await cycles([a], 3);

  expect(outbox(a).map((row) => [row.version, row.state])).toContainEqual([
    2,
    "published",
  ]);
  expect(net.registrations).toContain(slotKey(a.scope, 2));
});

it("P5 backs off absent registration evidence and its waiting successor over two hours", async () => {
  const net = network();
  const a = device(net);
  const evidenceAt: number[] = [];
  const evidenceSlots = new Map<string, number>();
  const originalEvidence = net.port.evidence;
  net.port.evidence = async (scope, version) => {
    const slot = slotKey(scope, version);
    evidenceSlots.set(slot, (evidenceSlots.get(slot) ?? 0) + 1);
    evidenceAt.push(time);
    return originalEvidence(scope, version);
  };
  const originalRegister = net.port.register;
  net.port.register = async (manifest) => {
    await originalRegister(manifest);
    const slot = slotKey(manifest.scope, manifest.version);
    net.head.delete(slot);
    net.chain.delete(slot);
  };

  a.put("uncertain predecessor", "first");
  await a.cycle();
  const predecessor = outbox(a)[0]!;
  expect(predecessor.outcome).toBe("wait");
  const successorBatch = "test-waiting-successor";
  a.db
    .prepare(
      `INSERT INTO pdpp_transport_manifests_out
        (batch,scope,version,plaintext,encrypted,data_hash,metadata_hash,state,
         outcome,dependency,next_attempt,wait_since)
       SELECT ?,scope,version+1,plaintext,encrypted,data_hash,metadata_hash,'ready',
         'wait',?,next_attempt,wait_since
       FROM pdpp_transport_manifests_out WHERE batch=?`,
    )
    .run(
      successorBatch,
      `registration_pending:${predecessor.slot}`,
      predecessor.batch,
    );
  const successorSlot = slotKey(predecessor.scope, predecessor.version + 1);
  const start = time;
  const horizon = 2 * 60 * 60 * 1000;
  let observedLongInterval = false;
  for (let elapsed = 0; elapsed < horizon; elapsed += 2_000) {
    time = start + elapsed + 2_000;
    await a.cycle();
    const rows = outbox(a);
    const predecessorRow = rows.find((row) => row.version === 1)!;
    const successorRow = rows.find((row) => row.version === 2)!;
    expect(
      successorRow.next_attempt,
      `elapsed=${elapsed}, now=${time}, predecessor=${predecessorRow.next_attempt}`,
    ).toBe(predecessorRow.next_attempt);
    if (
      time - start >= 600_000 &&
      predecessorRow.next_attempt - time === 30_000
    )
      observedLongInterval = true;
  }

  const periodicChecks =
    Math.ceil(600_000 / 16_000) + Math.ceil((horizon - 600_000) / 30_000);
  const retryChecks = Math.ceil(horizon / 300_000);
  expect(
    evidenceAt.length,
    JSON.stringify({
      start,
      first: evidenceAt.slice(0, 20),
      last: evidenceAt.slice(-5),
      rows: outbox(a).map((row) => ({
        version: row.version,
        next_attempt: row.next_attempt,
        wait_since: row.wait_since,
        checked_block: row.checked_block,
        outcome: row.outcome,
      })),
    }),
  ).toBeLessThanOrEqual(2 + periodicChecks + retryChecks);
  expect(evidenceSlots.get(successorSlot) ?? 0).toBe(0);
  expect(observedLongInterval).toBe(true);
}, 30_000);

it("aborts later outbound writes when the door closes after a fragment upload", async () => {
  const net = network();
  const a = device(net);
  const originalPutFragment = net.port.putFragment;
  net.port.putFragment = async (fragment) => {
    await originalPutFragment(fragment);
    retireReplication(a.db);
  };
  const manifestPut = vi.spyOn(net.port, "put");
  const register = vi.spyOn(net.port, "register");

  await a.cycle();

  expect(net.puts.some(({ key }) => key.includes("/fragments/"))).toBe(true);
  expect(manifestPut).not.toHaveBeenCalled();
  expect(register).not.toHaveBeenCalled();
  expect(outbox(a)[0]?.state).toBe("ready");
});

it("does not let a stale outbound receipt overwrite a newer quarantine", async () => {
  const net = network();
  const a = device(net);
  const originalPutFragment = net.port.putFragment;
  net.port.putFragment = async (fragment) => {
    await originalPutFragment(fragment);
    a.db
      .prepare(
        "UPDATE pdpp_transport_fragments_out SET state='quarantined',outcome='quarantine',reason='fragment_mismatch' WHERE digest=?",
      )
      .run(fragment.digest);
  };

  await a.cycle();

  expect(fragmentsOut(a)[0]).toMatchObject({
    state: "quarantined",
    outcome: "quarantine",
    reason: "fragment_mismatch",
  });
});

it("retries absence after a failed PUT at the same address with exact persisted bytes", async () => {
  const net = network();
  const a = device(net);
  let failed = false;
  net.beforePut((key) => {
    if (!failed) {
      failed = true;
      net.failPut.add(key);
    }
  });
  await a.cycle();
  const original = fragmentsOut(a)[0]!;
  expect(original.state).toBe("ready");
  expect(original.attempts).toBe(1);
  expect(outbox(a)[0]!.state).toBe("ready");
  expect(net.registrations).toHaveLength(0);
  a.reopen();
  await a.cycle();
  expect(net.puts).toHaveLength(1); // durable backoff survives restart
  net.failPut.clear();
  await cycles([a], 2);
  const attempts = net.puts.filter(
    (p) => p.key === replicaFragmentKey(a.scope, original.digest),
  );
  expect(attempts).toHaveLength(2);
  expect(attempts[0]!.bytes).toEqual(attempts[1]!.bytes);
  expect(outbox(a)[0]!.state).toBe("published");
});

it("fragments large JSON and resumes a partial download in reverse/duplicate listing order", async () => {
  const net = network();
  const a = device(net, { preexisting: "😺".repeat(15000), chunk: 1800 });
  await cycles([a], 3);
  const slot = outbox(a)[0]!.slot;
  const total = fragmentsOut(a).length;
  expect(total).toBeGreaterThan(4);
  // Reverse order + duplicates exercises slot admission, not arrival order.
  const list = net.port.list;
  net.port.list = async (cursor) => {
    const page = await list(cursor);
    return {
      ...page,
      points: [...page.points].reverse().flatMap((p) => [p, p]),
    };
  };
  // Two of the sender's fragments arrive, then the connection drops.
  const getFragment = net.port.getFragment;
  let served = 0;
  net.port.getFragment = async (scope, digest, read) => {
    if (scope === a.scope && served++ >= 2)
      throw new Error("download disconnected");
    return getFragment(scope, digest, read);
  };
  const b = device(net, { chunk: 1800 });
  await cycles([b], 2);
  const retained = fragmentsIn(b).filter(
    (r) => r.slot === slot && r.fragment_json,
  );
  expect(retained).toHaveLength(2);
  b.reopen();
  net.port.getFragment = getFragment;
  const resumed = net.gets.length;
  await cycles([b], 8);
  expect(b.get()).toEqual(a.get());
  // Fragments retained before the restart are not fetched again.
  const refetched = net.gets
    .slice(resumed)
    .filter((k) => isFragmentKey(k) && k.startsWith(`${a.scope}/`));
  expect(refetched).toHaveLength(total - 2);
  expect(net.puts.every((p) => p.bytes.length <= 8192)).toBe(true);
});

it("rejects tampered manifest ciphertext and imports only after the correct manifest is restored", async () => {
  const net = network();
  const a = device(net, { preexisting: "authentic", chunk: 600 });
  await cycles([a], 2);
  const b = device(net);
  const slot = outbox(a)[0]!.slot,
    original = net.blobs.get(slot)!;
  const corrupt = new Uint8Array(original);
  corrupt[20] = corrupt[20]! ^ 1;
  net.blobs.set(slot, corrupt);
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(inbox(b).find((r) => r.slot === slot)).toMatchObject({
    state: "ready",
    manifest_json: null,
  });
  net.blobs.set(slot, original);
  await cycles([b], 5);
  expect(b.get()).toEqual(a.get());
});

it("quarantines a fragment whose stored bytes differ from the finalized manifest", async () => {
  const net = network();
  const a = device(net, { preexisting: "authentic", chunk: 600 });
  await cycles([a], 2);
  const slot = outbox(a)[0]!.slot;
  const key = net.puts.find((p) => isFragmentKey(p.key))!.key;
  const original = net.blobs.get(key)!;
  const corrupt = new Uint8Array(original);
  corrupt[20] = corrupt[20]! ^ 1;
  net.blobs.set(key, corrupt);
  const b = device(net);
  await cycles([b], 3);
  expect(b.get()).toBeUndefined();
  expect(inbox(b).find((r) => r.slot === slot)).toMatchObject({
    state: "quarantined",
    reason: "fragment_mismatch",
  });
  net.blobs.set(key, original);
  expect(b.readmitFragments()).toBe(1);
  await cycles([b], 4);
  expect(b.get()).toEqual(a.get());
});

it("holds Gateway head disagreements pending, then heals without rebase or PUT", async () => {
  const net = network();
  const a = device(net, { preexisting: "authentic" });
  // The acknowledgement is lost and the check right after it fails too, so
  // the sender holds an unconfirmed registration.
  net.loseNextRegistrationResponse();
  const evidence = net.port.evidence;
  let unavailable = true;
  net.port.evidence = async (scope, version) => {
    if (unavailable && net.registrations.length > 0) {
      unavailable = false;
      throw new Error("transient RPC");
    }
    return evidence(scope, version);
  };
  await a.cycle();
  const slot = outbox(a)[0]!.slot;
  expect(outbox(a)[0]!.state).toBe("ready");
  const authentic = net.head.get(slot)!;
  const b = device(net);
  const putCount = net.puts.filter((p) => p.key === slot).length;
  // A head at a later version is no disagreement: only the latest version has
  // a head, and the finalized commitment binds this slot.
  for (const mutation of [
    { ...authentic, owner: "other" },
    { ...authentic, scope: "other" },
    { ...authentic, deleted: true },
    { ...authentic, dataHash: `0x${"f".repeat(64)}` },
    { ...authentic, metadataHash: `0x${"f".repeat(64)}` },
    null,
  ]) {
    if (mutation) net.head.set(slot, mutation);
    else net.head.delete(slot);
    await cycles([a, b], 2);
    expect(outbox(a).find((r) => r.slot === slot)?.state).toBe("ready");
    expect(b.get()).toBeUndefined();
    expect(net.puts.filter((p) => p.key === slot)).toHaveLength(putCount);
    expect(net.registrations.filter((s) => s === slot)).toHaveLength(1);
  }
  net.head.set(slot, authentic);
  time += 3600000; // allow the bounded pending backoff to expire
  await cycles([a, b], 3);
  expect(outbox(a).find((r) => r.slot === slot)?.state).toBe("published");
  expect(b.get()).toEqual(a.get());
  expect(net.puts.filter((p) => p.key === slot)).toHaveLength(putCount);
});

it("a finalized later version leaves a confirmed slot published and importable", async () => {
  const net = network();
  const a = device(net, { preexisting: "immutable" });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const slot = outbox(a)[0]!.slot;
  // Commitments are write-once per version: a later current version does not
  // change what this slot commits to.
  net.chain.set(slot, { ...net.chain.get(slot)!, currentVersion: "9" });
  const b = device(net);
  const putCount = net.puts.filter((p) => p.key === slot).length;
  await cycles([a, b], 3);
  expect(outbox(a).find((r) => r.slot === slot)?.state).toBe("published");
  expect(b.get()).toEqual(a.get());
  expect(net.puts.filter((p) => p.key === slot)).toHaveLength(putCount);
  expect(net.registrations.filter((s) => s === slot)).toHaveLength(1);
});

it("pending chain settlement and Gateway deletion never trigger re-upload", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((key) => net.pending.add(key));
  await a.cycle();
  expect(outbox(a).every((r) => r.state === "ready")).toBe(true);
  net.finalizeAll();
  await cycles([a], 1);
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
  // A Gateway-only tombstone can roll back; hold the durable batch pending.
  net.beforePut(() => {});
  a.put("next");
  net.loseNextRegistrationResponse();
  await a.cycle();
  const next = outbox(a).find((r) => r.state === "ready")!;
  net.head.set(next.slot, { ...net.head.get(next.slot)!, deleted: true });
  const n = net.puts.length;
  await cycles([a], 1);
  expect(outbox(a).find((r) => r.slot === next.slot)?.state).toBe("ready");
  expect(net.puts).toHaveLength(n);
});

it("failing first 50 fragment uploads cannot starve later runnable fragments", async () => {
  // A larger cap, so the manifest of about 80 fragments fits one object.
  const net = network(false, 32768);
  const a = device(net, {
    preexisting: "x".repeat(40000),
    chunk: 500,
    cap: 32768,
  });
  let blocked = 0;
  net.beforePut((key) => {
    if (blocked++ < 50) net.failPut.add(key);
  });
  await a.cycle();
  expect(fragmentsOut(a).length).toBeGreaterThan(50);
  time += 10000; // the oldest failures are due again, so fairness must select untouched rows
  await a.cycle();
  expect(fragmentsOut(a).some((r) => r.state === "stored")).toBe(true);
  expect(net.puts.slice(50).some((p) => !net.failPut.has(p.key))).toBe(true);
  // The manifest waits for every fragment: nothing is registered yet.
  expect(net.registrations).toHaveLength(0);
});

it("rescans first pages to find late settled registrations behind an earlier page boundary", async () => {
  const net = network();
  const a = device(net, { preexisting: "record", chunk: 600 });
  await cycles([a], 2);
  const hidden = outbox(a)[0]!.slot,
    row = net.head.get(hidden)!;
  net.head.delete(hidden);
  net.pageSize(1);
  const b = device(net);
  await b.cycle();
  net.head.set(hidden, row); // inserted behind saved cursor
  await cycles([b], 8);
  expect(b.get()).toEqual(a.get());
});

it("imports before checkpoint atomically and retries retained fragments after a crash", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const b = device(net);
  b.db.exec(
    "CREATE TRIGGER interrupt_import BEFORE INSERT ON pdpp_transport_imported BEGIN SELECT RAISE(ABORT,'crash before checkpoint'); END;",
  );
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(
    b.db.prepare("SELECT * FROM pdpp_replica_received").all(),
  ).toHaveLength(0);
  b.reopen();
  b.db.exec("DROP TRIGGER interrupt_import");
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
  expect(inbox(b).filter((r) => r.state === "imported").length).toBeGreaterThan(
    0,
  );
});

it("keeps unknown declarations pending and refuses wrong owner/declaration binding", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const b = device(net);
  b.declarations([]);
  await b.cycle();
  expect(b.get()).toBeUndefined();
  // The unknown declaration is a durable Wait on the batch's import work.
  expect(
    importWork(b).some((r) => r.dependency?.startsWith("declaration:")),
  ).toBe(true);
  b.declarations(expected.declarations);
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
  const c = device(net);
  const slot = outbox(a)[0]!.slot;
  net.head.set(slot, { ...net.head.get(slot)!, owner: "other-owner" });
  await c.cycle();
  expect(c.get()).toBeUndefined();
  expect(inbox(c).find((r) => r.slot === slot)?.state).toBe("ready");
});

it("E6 replay after attach creates no second stage or custody copy", async () => {
  const net = network();
  const a = device(net);
  const blob = a.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes: new Uint8Array([7, 8, 9]),
    mimeType: "application/octet-stream",
  });
  a.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "replayed",
        data: {
          id: "replayed",
          blob_ref: { blob_id: blob.blobId, mime_type: blob.mimeType },
        },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([a], 4);
  const b = device(net);
  await cycles([b], 12);

  const stageCount = (
    b.db
      .prepare("SELECT count(*) AS count FROM pdpp_transport_staged_objects")
      .get() as { count: number }
  ).count;
  const importedCount = (
    b.db
      .prepare("SELECT count(*) AS count FROM pdpp_transport_imported")
      .get() as { count: number }
  ).count;
  expect(stageCount).toBe(1);
  expect(importedCount).toBeGreaterThan(0);
  expect(
    (
      b.db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_binary_manifests WHERE namespace='staging'",
        )
        .get() as { count: number }
    ).count,
  ).toBe(0);
  await cycles([b], 4);
  expect(
    (
      b.db
        .prepare("SELECT count(*) AS count FROM pdpp_transport_staged_objects")
        .get() as { count: number }
    ).count,
  ).toBe(stageCount);
  expect(
    (
      b.db
        .prepare("SELECT count(*) AS count FROM pdpp_transport_imported")
        .get() as { count: number }
    ).count,
  ).toBe(importedCount);
  expect(b.store.getBlobBytes(blob.blobId)).toEqual(new Uint8Array([7, 8, 9]));
});

it("E7 retries resource_busy with P backoff, then imports when budget is free", async () => {
  const net = network();
  const a = device(net, { preexisting: "resource busy" });
  await cycles([a], 4);
  const budget = new ReplicaByteBudget(1_000_000);
  const release = budget.reserve(budget.maxBytes);
  if (typeof release !== "function")
    throw new Error("expected budget reservation");
  const b = device(net, { worker: { resourceBudget: budget } });
  await cycles([b], 8);

  const busy = b.db
    .prepare(
      "SELECT outcome,reason,attempts,next_attempt FROM pdpp_transport_manifests_in WHERE outcome='retry'",
    )
    .get() as
    | {
        outcome: string;
        reason: string;
        attempts: number;
        next_attempt: number;
      }
    | undefined;
  expect(busy).toMatchObject({ outcome: "retry", reason: "resource_busy" });
  expect(busy?.attempts).toBeGreaterThan(1);
  release();

  await cycles([b], 12);
  expect(b.get()).toEqual(a.get());
  expect(budget.reserved).toBe(0);
});

it("E8 re-evaluates an older resource_unsupported outcome after the limits version changes", async () => {
  const net = network();
  const a = device(net, { preexisting: "recheck limits" });
  await cycles([a], 12);
  const b = device(net);
  b.declarations([]);
  await cycles([b], 12);
  const retained = b.db
    .prepare(
      `SELECT m.slot,m.writer,m.batch FROM pdpp_transport_manifests_in m
       JOIN pdpp_transport_fragments_in f ON f.slot=m.slot
       WHERE f.fragment_json IS NOT NULL LIMIT 1`,
    )
    .get() as { slot: string; writer: string; batch: string } | undefined;
  expect(retained).toBeDefined();
  if (!retained) throw new Error("expected retained manifest and fragments");
  b.db
    .prepare(
      `UPDATE pdpp_transport_manifests_in
       SET outcome='unsupported',reason='resource_unsupported',resource_limits_version=0
       WHERE slot=?`,
    )
    .run(retained.slot);
  b.db
    .prepare(
      `UPDATE pdpp_transport_import_work
       SET outcome='unsupported',reason='resource_unsupported'
       WHERE writer=? AND batch=?`,
    )
    .run(retained.writer, retained.batch);
  b.declarations(expected.declarations);
  b.reopen();

  expect(
    b.db
      .prepare(
        "SELECT outcome,resource_limits_version FROM pdpp_transport_manifests_in WHERE slot=?",
      )
      .get(retained.slot),
  ).toEqual({ outcome: null, resource_limits_version: null });
  await cycles([b], 12);
  expect(b.get()).toEqual(a.get());
});

it("is disabled by default and rejects a configured limit above the real storage cap", async () => {
  const net = network();
  const a = device(net, { enabled: false });
  await a.cycle();
  expect(net.puts).toHaveLength(0);
  expect(outbox(a)).toHaveLength(0);
  expect(() => device(net, { cap: REPLICA_MAX_BLOB_BYTES + 1 })).toThrow(
    "storage cap",
  );
});

it("E11 leaves admission schema and staging cleanup untouched when replication is off", async () => {
  const net = network();
  const a = device(net, { enabled: false });
  const writer = binaryWriter(a.db, "staging", "flag-off-stale");
  writer.write(new Uint8Array([4, 5, 6]));
  writer.finish();

  await a.cycle();

  expect(
    a.db
      .prepare(
        "SELECT name FROM sqlite_master WHERE name='pdpp_transport_staged_objects'",
      )
      .get(),
  ).toBeUndefined();
  expect(
    (
      a.db.prepare("PRAGMA table_info(pdpp_transport_manifests_in)").all() as {
        name: string;
      }[]
    ).some((column) => column.name === "resource_limits_version"),
  ).toBe(false);
  expect(readBinary(a.db, "staging", "flag-off-stale")).toEqual(
    new Uint8Array([4, 5, 6]),
  );
});

it("E1 rejects declared totals before fetching fragments or retaining evidence", async () => {
  const net = network();
  const remote = remoteReplicaTestWriter(net.roster, owner);
  const scope = replicaScope(remote.writers.transport);
  const version = 1;
  const collectedAt = at;
  const prepared = await prepareReplicaManifest({
    owner,
    writer: remote.writers.transport,
    version,
    batch: "d".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt,
    digest: `sha256:${"1".repeat(64)}`,
    totalBytes: REPLICA_MAX_TOTAL_BYTES + 1,
    fragments: [{ digest: `sha256:${"2".repeat(64)}`, bytes: 1 }],
    sign: remote.sign,
    encrypt: net.port.encrypt,
  });
  const slot = slotKey(scope, version);
  expect(
    admit(
      decodeReplicaManifest(prepared.plaintext, scope, owner),
      new ReplicaByteBudget(Number.MAX_SAFE_INTEGER),
      {
        repositoryId: "test",
        owner,
        manifestDigest: `sha256:${"3".repeat(64)}`,
      },
    ),
  ).toMatchObject({ kind: "resource_unsupported", limit: "total_bytes" });
  net.blobs.set(slot, prepared.encrypted);
  const commitment = {
    owner,
    scope,
    version: BigInt(version),
    dataHash: prepared.dataHash,
    metadataHash: prepared.metadataHash,
    deleted: false,
  };
  net.head.set(slot, commitment);
  net.chain.set(slot, {
    ...net.chainRow(slot, commitment),
    blockNumber: 123n,
  });
  const receiver = device(net);
  await cycles([receiver], 3);

  const outcome = receiver.db
    .prepare(
      "SELECT outcome,reason,state,resource_limits_version FROM pdpp_transport_manifests_in WHERE slot=?",
    )
    .get(slot);
  expect(outcome).toEqual({
    outcome: "unsupported",
    reason: "resource_unsupported",
    state: "ready",
    resource_limits_version: 1,
  });
  expect(
    net.gets.filter((key) => key.startsWith(`${scope}/fragments/`)),
  ).toHaveLength(0);
  expect(
    (
      receiver.db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_transport_fragments_in WHERE slot=?",
        )
        .get(slot) as { count: number }
    ).count,
  ).toBe(0);
});

it("E3 admits the largest batch produced by real Node sender preparation", async () => {
  const net = network(false, REPLICA_MAX_BLOB_BYTES);
  const sender = device(net, { cap: REPLICA_MAX_BLOB_BYTES });
  sender.store.ingestBatch(
    Array.from({ length: REPLICA_MAX_OPERATIONS - 1 }, (_, index) => ({
      instance: "conn",
      stream: "messages",
      key: `largest-${index}`,
      data: { id: `largest-${index}`, text: `value-${index}` },
      emitted_at: at,
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([sender], 36);
  const prepared = sender.db
    .prepare(
      `SELECT m.batch,m.scope,m.encrypted,m.version
       FROM pdpp_transport_manifests_out m
       JOIN pdpp_transport_batches b ON b.batch=m.batch
       WHERE b.prepared=1 ORDER BY b.total_bytes DESC LIMIT 1`,
    )
    .get() as
    | { batch: string; scope: string; encrypted: Buffer; version: number }
    | undefined;
  expect(prepared).toBeDefined();
  if (!prepared) throw new Error("sender did not prepare a batch");

  const manifest = decodeReplicaManifest(
    await net.port.decrypt(prepared.scope, new Uint8Array(prepared.encrypted)),
    prepared.scope,
    owner,
  );
  const ciphertextBytes = manifest.fragments.reduce(
    (size, fragment) => size + fragment.bytes,
    0,
  );
  const budget = new ReplicaByteBudget(ciphertextBytes * 4);
  const admission = admit(manifest, budget, {
    repositoryId: "e3-sender-repository",
    owner,
    manifestDigest: manifest.digest,
  });
  expect(admission).not.toHaveProperty("kind");
  if ("kind" in admission) throw new Error("sender produced a refused batch");

  const encryptedFragments = sender.db
    .prepare(
      "SELECT encrypted FROM pdpp_transport_fragments_out WHERE batch=? ORDER BY position",
    )
    .all(prepared.batch) as { encrypted: Buffer }[];
  const fragments = await Promise.all(
    encryptedFragments.map(async ({ encrypted }) => {
      const plaintext = await net.port.decrypt(
        prepared.scope,
        new Uint8Array(encrypted),
      );
      return decodeReplicaFragment(plaintext, prepared.scope, owner);
    }),
  );
  const payload = await inspectReplicaPayload(
    () =>
      assembleReplicaStream(
        async function* () {
          yield* fragments;
        },
        { maxBytes: admission.payloadBytes },
      ),
    undefined,
  );
  // The baseline connection registration is a separate batch; this tail batch
  // contains every record operation the configured sender limit can admit.
  expect(payload.envelope.operations).toHaveLength(REPLICA_MAX_OPERATIONS - 1);
  expect(payload.envelope.operations.length).toBeLessThanOrEqual(
    DEFAULT_REPLICA_STREAMED_LIMITS.maxOperations,
  );
  expect(
    Math.max(
      ...payload.envelope.operations.map(
        (operation) =>
          new TextEncoder().encode(canonicalJson(operation)).length,
      ),
    ),
  ).toBeLessThanOrEqual(DEFAULT_REPLICA_STREAMED_LIMITS.maxOperationBytes);
  expect(
    payload.blobs.reduce((total, blob) => total + blob.sizeBytes, 0),
  ).toBeLessThanOrEqual(DEFAULT_REPLICA_STREAMED_LIMITS.maxBlobTotalBytes);
  expect(admission.payloadBytes).toBeLessThanOrEqual(
    DEFAULT_REPLICA_STREAMED_LIMITS.maxPayloadBytes,
  );
  expect(budget.reserved).toBe(admission.reservedBytes);
  admission.release();
  expect(budget.reserved).toBe(0);
}, 60000);

it("E1 rejects declared aggregate ciphertext over its limit before fragment GET", async () => {
  const net = network();
  const remote = remoteReplicaTestWriter(net.roster, owner);
  const scope = replicaScope(remote.writers.transport);
  const version = 1;
  const prepared = await prepareReplicaManifest({
    owner,
    writer: remote.writers.transport,
    version,
    batch: "e".repeat(32),
    sequence: 1,
    previous: null,
    collectedAt: at,
    digest: `sha256:${"3".repeat(64)}`,
    totalBytes: 900 * 1024 * 1024,
    fragments: Array.from({ length: 11 }, (_, index) => ({
      digest: `sha256:${String(index + 1).padStart(64, "0")}`,
      bytes: REPLICA_MAX_BLOB_BYTES,
    })),
    sign: remote.sign,
    encrypt: net.port.encrypt,
  });
  const slot = slotKey(scope, version);
  expect(
    admit(
      decodeReplicaManifest(prepared.plaintext, scope, owner),
      new ReplicaByteBudget(Number.MAX_SAFE_INTEGER),
      {
        repositoryId: "test",
        owner,
        manifestDigest: `sha256:${"3".repeat(64)}`,
      },
    ),
  ).toMatchObject({
    kind: "resource_unsupported",
    limit: "aggregate_ciphertext_bytes",
  });
  net.blobs.set(slot, prepared.encrypted);
  const commitment = {
    owner,
    scope,
    version: BigInt(version),
    dataHash: prepared.dataHash,
    metadataHash: prepared.metadataHash,
    deleted: false,
  };
  net.head.set(slot, commitment);
  net.chain.set(slot, { ...net.chainRow(slot, commitment), blockNumber: 123n });
  const receiver = device(net);
  await cycles([receiver], 3);

  expect(
    receiver.db
      .prepare(
        "SELECT outcome,reason FROM pdpp_transport_manifests_in WHERE slot=?",
      )
      .get(slot),
  ).toEqual({ outcome: "unsupported", reason: "resource_unsupported" });
  expect(
    net.gets.filter((key) => key.startsWith(`${scope}/fragments/`)),
  ).toHaveLength(0);
  expect(
    (
      receiver.db
        .prepare(
          "SELECT count(*) AS count FROM pdpp_transport_fragments_in WHERE slot=?",
        )
        .get(slot) as { count: number }
    ).count,
  ).toBe(0);
});

it("E1 refuses an authenticated payload over the streamed operation limit without quarantine", async () => {
  const net = network(false, REPLICA_MAX_BLOB_BYTES);
  const remote = remoteReplicaTestWriter(net.roster, owner);
  const batch = "f".repeat(32);
  const envelope = {
    format: "vana-pdpp-replica" as const,
    version: 1 as const,
    owner,
    batchId: batch,
    operations: Array.from(
      { length: REPLICA_MAX_OPERATIONS + 1 },
      (_, index) => ({
        owner,
        sourceId,
        connectionId: "a".repeat(32),
        methodId: "export",
        generation: 1 as const,
        kind: "connection-register" as const,
        revision: {
          counter: 1,
          writerId: remote.writers.operation,
          operationId: `op-${index}`,
        },
      }),
    ),
  };
  const payloadParts: Uint8Array[] = [];
  for await (const bytes of encodeReplicaPayload(
    envelope,
    async function* () {},
  ))
    payloadParts.push(bytes);
  const payload = new Uint8Array(Buffer.concat(payloadParts));
  const fragments = await fragmentReplicaPayload({
    owner,
    writer: remote.writers.transport,
    batch,
    sequence: 1,
    previous: null,
    bytes: payload,
    collectedAt: at,
    encrypt: net.port.encrypt,
    maxBlobBytes: REPLICA_MAX_BLOB_BYTES,
    targetChunkBytes: 4 * 1024 * 1024,
  });
  const scope = replicaScope(remote.writers.transport);
  for (const fragment of fragments)
    net.blobs.set(
      replicaFragmentKey(scope, fragment.digest),
      fragment.encrypted,
    );
  const prepared = await prepareReplicaManifest({
    owner,
    writer: remote.writers.transport,
    version: 1,
    batch,
    sequence: 1,
    previous: null,
    collectedAt: at,
    digest: replicaDigest(payload),
    totalBytes: payload.length,
    fragments: fragments.map((fragment) => ({
      digest: fragment.digest,
      bytes: fragment.encrypted.length,
    })),
    sign: remote.sign,
    encrypt: net.port.encrypt,
  });
  const slot = slotKey(scope, 1);
  net.blobs.set(slot, prepared.encrypted);
  const commitment = {
    owner,
    scope,
    version: 1n,
    dataHash: prepared.dataHash,
    metadataHash: prepared.metadataHash,
    deleted: false,
  };
  net.head.set(slot, commitment);
  net.chain.set(slot, { ...net.chainRow(slot, commitment), blockNumber: 123n });
  const resourceBudget = new ReplicaByteBudget(100_000_000);
  const receiver = device(net, {
    cap: REPLICA_MAX_BLOB_BYTES,
    worker: { resourceBudget },
  });
  await cycles([receiver], 12);

  expect(
    receiver.db
      .prepare(
        "SELECT outcome,reason FROM pdpp_transport_import_work WHERE writer=? AND batch=?",
      )
      .get(remote.writers.transport, batch),
  ).toEqual({ outcome: "unsupported", reason: "resource_unsupported" });
  expect(
    receiver.db
      .prepare("SELECT count(*) AS count FROM pdpp_transport_staged_objects")
      .get(),
  ).toEqual({ count: 0 });
  expect(
    receiver.db
      .prepare(
        "SELECT count(*) AS count FROM pdpp_transport_imported WHERE batch=?",
      )
      .get(batch),
  ).toEqual({ count: 0 });
  expect(
    receiver.db
      .prepare(
        "SELECT count(*) AS count FROM pdpp_transport_manifests_in WHERE slot=? AND state='quarantined'",
      )
      .get(slot),
  ).toEqual({ count: 0 });
  expect(resourceBudget.reserved).toBe(0);
});

it("E2 routes an overlength fragment through fragment_mismatch and releases admission", async () => {
  const net = network(false, REPLICA_MAX_BLOB_BYTES);
  const remote = remoteReplicaTestWriter(net.roster, owner);
  const batch = "8".repeat(32);
  const envelope = {
    format: "vana-pdpp-replica" as const,
    version: 1 as const,
    owner,
    batchId: batch,
    operations: [
      {
        owner,
        sourceId,
        connectionId: "a".repeat(32),
        methodId: "export",
        generation: 1 as const,
        kind: "connection-register" as const,
        revision: {
          counter: 1,
          writerId: remote.writers.operation,
          operationId: "single-operation",
        },
      },
    ],
  };
  const payloadParts: Uint8Array[] = [];
  for await (const bytes of encodeReplicaPayload(
    envelope,
    async function* () {},
  ))
    payloadParts.push(bytes);
  const payload = new Uint8Array(Buffer.concat(payloadParts));
  const totalBytes = payload.length - 1;
  const digest = replicaDigest(payload.subarray(0, totalBytes));
  const scope = replicaScope(remote.writers.transport);
  const [preparedFragment] = await fragmentReplicaPayload({
    owner,
    writer: remote.writers.transport,
    batch,
    sequence: 1,
    previous: null,
    bytes: payload,
    collectedAt: at,
    encrypt: net.port.encrypt,
    maxBlobBytes: REPLICA_MAX_BLOB_BYTES,
    targetChunkBytes: REPLICA_MAX_BLOB_BYTES,
  });
  if (!preparedFragment) throw new Error("expected one encoded fragment");
  const fragmentWrapper = JSON.parse(
    new TextDecoder().decode(preparedFragment.plaintext),
  ) as {
    data: { fragment: { totalBytes: number; digest: string } };
  };
  fragmentWrapper.data.fragment.totalBytes = totalBytes;
  fragmentWrapper.data.fragment.digest = digest;
  const malformedPlaintext = new TextEncoder().encode(
    canonicalJson(fragmentWrapper),
  );
  const malformedCiphertext = await net.port.encrypt(scope, malformedPlaintext);
  const fragmentDigest = replicaDigest(malformedCiphertext);
  net.blobs.set(replicaFragmentKey(scope, fragmentDigest), malformedCiphertext);
  const manifest = await prepareReplicaManifest({
    owner,
    writer: remote.writers.transport,
    version: 1,
    batch,
    sequence: 1,
    previous: null,
    collectedAt: at,
    digest,
    totalBytes,
    fragments: [{ digest: fragmentDigest, bytes: malformedCiphertext.length }],
    sign: remote.sign,
    encrypt: net.port.encrypt,
  });
  const slot = slotKey(scope, 1);
  net.blobs.set(slot, manifest.encrypted);
  const commitment = {
    owner,
    scope,
    version: 1n,
    dataHash: manifest.dataHash,
    metadataHash: manifest.metadataHash,
    deleted: false,
  };
  net.head.set(slot, commitment);
  net.chain.set(slot, { ...net.chainRow(slot, commitment), blockNumber: 123n });
  const resourceBudget = new ReplicaByteBudget(10_000_000);
  let reservations = 0;
  let releases = 0;
  const reserve = resourceBudget.reserve.bind(resourceBudget);
  vi.spyOn(resourceBudget, "reserve").mockImplementation((bytes) => {
    const release = reserve(bytes);
    if (typeof release !== "function") return release;
    reservations++;
    let released = false;
    return () => {
      if (released) throw new Error("admission reservation released twice");
      released = true;
      releases++;
      release();
    };
  });
  const receiver = device(net, { worker: { resourceBudget } });
  await cycles([receiver], 12);

  expect(
    receiver.db
      .prepare(
        "SELECT state,reason FROM pdpp_transport_manifests_in WHERE slot=?",
      )
      .get(slot),
  ).toEqual({ state: "quarantined", reason: "fragment_mismatch" });
  expect(resourceBudget.reserved).toBe(0);
  expect(releases).toBe(reservations);
  expect(
    receiver.db
      .prepare("SELECT count(*) AS count FROM pdpp_transport_staged_objects")
      .get(),
  ).toEqual({ count: 0 });
  expect(
    receiver.db
      .prepare(
        "SELECT count(*) AS count FROM pdpp_transport_imported WHERE batch=?",
      )
      .get(batch),
  ).toEqual({ count: 0 });
});

it("refuses a database that holds per-fragment carrier state, before creating any table", () => {
  const net = network();
  let opened: Database.Database | undefined;
  expect(() =>
    device(net, {
      beforeOpen(db) {
        opened = db;
        db.exec("CREATE TABLE pdpp_transport_outbox (scope TEXT PRIMARY KEY)");
      },
    }),
  ).toThrow(ReplicaCarrierMismatchError);
  expect(
    opened!
      .prepare(
        "SELECT name FROM sqlite_master WHERE name='pdpp_transport_manifests_out'",
      )
      .get(),
  ).toBeUndefined();
  expect(net.puts).toHaveLength(0);
});

it("reassembles binary bytes with their content digest, MIME and generation-bound claim", async () => {
  const net = network();
  const a = device(net, { chunk: 1000 });
  const b = device(net, { chunk: 1000 });
  const bytes = new Uint8Array(17000);
  for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
  const blob = a.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  a.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "binary",
        emitted_at: at,
        data: {
          id: "binary",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: bytes.length,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([a, b], 6);
  expect(
    Buffer.from(b.store.getBlobBytes(blob.blobId)!).equals(Buffer.from(bytes)),
  ).toBe(true);
  expect(b.store.getBlobMeta(blob.blobId)).toEqual(
    a.store.getBlobMeta(blob.blobId),
  );
  expect(b.get("binary")).toEqual(a.get("binary"));
});

it("a record and its blob claim share one batch even when the blob exceeds the byte bound", async () => {
  const net = network();
  const a = device(net, { chunk: 1000, worker: { maxBatchBytes: 2000 } });
  const bytes = new Uint8Array(17000);
  for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
  const blob = a.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  a.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "binary",
        emitted_at: at,
        data: {
          id: "binary",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: bytes.length,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([a], 6);
  // The baseline batch, then one batch for the record, its claim and the
  // blob: the blob bytes travel once.
  expect(net.registrations).toHaveLength(2);
  expect(
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get(),
  ).toEqual({ n: 2 });
  const b = device(net, { chunk: 1000 });
  await cycles([b], 6);
  expect(b.get("binary")).toEqual(a.get("binary"));
});

it("recovers pending imported operations after local connection authority arrives", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const b = device(net);
  // Provisioning is a separate authority. Transport must not invent a missing connection.
  unprovisionConnection(b.db, "conn");
  await b.cycle();
  expect(b.get()).toBeUndefined();
  expect(inbox(b).some((r) => r.state === "imported")).toBe(true);
  b.reopen();
  b.store.registerConnection({
    instance: "conn",
    sourceId,
    method: "export",
    label: "C",
  });
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
});

it("holds a successor batch until its predecessor arrives, then imports the retained bytes", async () => {
  const net = network();
  const a = device(net);
  await cycles([a], 2);
  a.put("tail record");
  await cycles([a], 3);
  const [first, second] = outbox(a);
  expect(second).toBeDefined();
  // The predecessor's manifest is unreachable for a while.
  net.failGet.add(first!.slot);
  const b = device(net);
  await cycles([b], 2);
  expect(
    inbox(b).find((r) => r.slot === second!.slot)?.manifest_json,
  ).not.toBeNull();
  expect(b.get()).toBeUndefined();
  net.failGet.clear();
  await cycles([b], 3);
  expect(b.get()).toEqual(a.get());
});

it("a permanently failing preparation blocks claiming a later version", async () => {
  const net = network();
  const encrypt = net.port.encrypt;
  let stuckBatch: string | undefined;
  net.port.encrypt = async (scope, bytes) => {
    stuckBatch ??= batchOfPlaintext(bytes);
    if (batchOfPlaintext(bytes) === stuckBatch)
      throw new Error("encryption service unavailable");
    return encrypt(scope, bytes);
  };
  const a = device(net);
  a.put("later tail");
  await a.cycle();
  const first = a.db
    .prepare("SELECT batch,prepared,outcome FROM pdpp_transport_batches")
    .get() as { batch: string; prepared: number; outcome: string | null };
  expect(first).toMatchObject({ prepared: 0, outcome: "retry" });
  const batchesBeforeSuccessor = (
    a.db.prepare("SELECT count(*) AS n FROM pdpp_transport_batches").get() as {
      n: number;
    }
  ).n;
  a.reopen();
  a.put("blocked successor", "second");
  await cycles([a], 3);
  expect(stuckBatch).toBe(first.batch);
  expect(net.registrations).toEqual([]);
  expect(outbox(a)).toEqual([]);
  expect(net.puts).toEqual([]);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as { n: number }
    ).n,
  ).toBe(batchesBeforeSuccessor);
  expect(
    a.db
      .prepare("SELECT error FROM pdpp_transport_batches WHERE prepared=0")
      .all().length,
  ).toBeGreaterThan(0);
});

it("rejects a validly encrypted manifest whose plaintext/metadata commitment differs", async () => {
  const net = network();
  const a = device(net, { preexisting: "record" });
  await cycles([a], 2);
  const { scope, slot } = outbox(a)[0]!;
  const plaintext = await net.port.decrypt(scope, net.blobs.get(slot)!);
  const wrapper = JSON.parse(new TextDecoder().decode(plaintext));
  wrapper.collectedAt = "2026-10-21T00:00:00.000Z";
  wrapper.data.manifest.collectedAt = wrapper.collectedAt;
  const { canonicalJson } =
    await import("@opendatalabs/personal-server-ts-core/replication/envelope");
  net.blobs.set(
    slot,
    await net.port.encrypt(
      scope,
      new TextEncoder().encode(canonicalJson(wrapper)),
    ),
  );
  const b = device(net);
  await b.cycle();
  expect(b.get()).toBeUndefined();
  const row = inbox(b).find((r) => r.slot === slot);
  expect(row?.manifest_json).toBeNull();
  expect(row?.reason).toBe("commitment_mismatch");
});

it("a cloned writer cannot replace a published slot", async () => {
  const net = network();
  const a = device(net, { preexisting: "accepted" });
  await cycles([a], 2);
  const b = device(net);
  await cycles([b], 2);
  expect(b.get()).toEqual(a.get());
  // A copied database that was not rotated keeps A's writer and versions.
  const clone = device(net, { copyOf: a });
  a.put("accepted next");
  await cycles([a, b], 2);
  expect(b.get()).toEqual({ id: "a", text: "accepted next" });
  const slot = outbox(a).at(-1)!.slot;
  const published = net.blobs.get(slot)!;
  clone.put("conflicting clone");
  await cycles([clone, b], 2);
  // The clone claims A's next version, finds another commitment there and stops:
  // terminal, with no PUT over the published manifest.
  expect(outbox(clone).find((r) => r.slot === slot)?.state).toBe("quarantined");
  expect(net.puts.filter((p) => p.key === slot)).toHaveLength(1);
  expect(net.blobs.get(slot)).toEqual(published);
  expect(b.get()).toEqual(a.get());
  const c = device(net);
  await cycles([c], 3);
  expect(c.get()).toEqual(a.get());
});

it("the gateway oracle enforces chain-backed continuity even when the head is missing", async () => {
  const net = network();
  const scope = "pdpp_replica_v1.test";
  const slot = slotKey(scope, 1);
  net.chain.set(
    slot,
    net.chainRow(slot, {
      owner,
      scope,
      version: "1",
      dataHash: `0x${"a".repeat(64)}`,
      metadataHash: `0x${"b".repeat(64)}`,
      deleted: false,
    }),
  );
  await expect(
    net.port.register({
      scope,
      version: 1,
      plaintext: new Uint8Array(),
      encrypted: new Uint8Array(),
      dataHash: `0x${"a".repeat(64)}`,
      metadataHash: `0x${"b".repeat(64)}`,
    }),
  ).rejects.toThrow();
  expect(net.head.has(slot)).toBe(false);
});

it("retries durable imports while owner discovery is unavailable", async () => {
  const net = network();
  const a = device(net, { preexisting: "retained record" });
  await cycles([a], 2);
  const b = device(net);
  b.db.exec(
    "CREATE TRIGGER pause_import BEFORE INSERT ON pdpp_transport_imported BEGIN SELECT RAISE(ABORT,'pause'); END;",
  );
  await b.cycle();
  expect(b.get()).toBeUndefined();
  b.db.exec("DROP TRIGGER pause_import");
  b.reopen();
  net.port.list = async () => {
    throw new Error("gateway listing offline");
  };
  // The failed import is due again after its first backoff, not every cycle.
  time += 1000;
  await b.cycle().catch(() => undefined);
  expect(b.get()).toEqual(a.get());
});

it("holds a soft-deleted slot pending and imports after chain status reactivation", async () => {
  const net = network();
  const a = device(net, { preexisting: "retained" });
  net.loseNextRegistrationResponse();
  await a.cycle();
  const slot = outbox(a)[0]!.slot;
  net.chain.set(slot, { ...net.chain.get(slot)!, status: "Unavailable" });
  expect(net.head.get(slot)?.deleted).toBe(false);
  const putCount = net.puts.filter((p) => p.key === slot).length;
  const b = device(net);
  await cycles([a, b], 2);
  expect(outbox(a).find((r) => r.slot === slot)?.state).toBe("ready");
  expect(inbox(b).find((r) => r.slot === slot)?.state).toBe("ready");
  expect(b.get()).toBeUndefined();
  expect(net.puts.filter((p) => p.key === slot)).toHaveLength(putCount);
  net.chain.set(slot, { ...net.chain.get(slot)!, status: "Active" });
  await cycles([a, b], 3);
  expect(outbox(a).find((r) => r.slot === slot)?.state).toBe("published");
  expect(b.get()).toEqual(a.get());
  expect(net.puts.filter((p) => p.key === slot)).toHaveLength(putCount);
});

it("quarantines a finalized slot commitment mismatch including a tombstone pair", async () => {
  for (const commitment of [
    `0x${"f".repeat(64)}` as const,
    replicaChainCommitment(
      keccak256(stringToHex("vana.data-point.tombstone.v1")),
      keccak256(stringToHex("vana.data-point.tombstone.metadata.v1")),
    ),
  ]) {
    const net = network();
    const a = device(net, { preexisting: "durable hash pair" });
    net.loseNextRegistrationResponse();
    await a.cycle();
    const slot = outbox(a)[0]!.slot;
    net.chain.set(slot, { ...net.chain.get(slot)!, commitment });
    const putCount = net.puts.length;
    await cycles([a], 2);
    expect(outbox(a).find((r) => r.slot === slot)?.state).toBe("quarantined");
    expect(net.puts).toHaveLength(putCount);
    expect(net.registrations.filter((s) => s === slot)).toHaveLength(1);
  }
});

function visibility(d: ReturnType<typeof device>, reader: "owner" | "grant") {
  const receiver = createReplicaReceiver({
    db: d.db,
    store: d.store,
    owner,
    enabled: true,
    authenticate: (c) => (c === "replica-secret" ? owner : undefined),
    declarations: () =>
      expected.declarations.map((d) => ({ ...d, validateData: () => true })),
  });
  return receiver.readVisibleRecords({
    reader,
    connectionId: "conn",
    stream: "messages",
  });
}

it("fetches nothing before the manifest finalizes, then shows the batch once", async () => {
  const net = network();
  const a = device(net),
    b = device(net);
  await cycles([a, b], 2);
  const before = net.gets.length;
  net.beforePut((key) => net.pending.add(key));
  a.put("awaiting finality");
  await cycles([a, b], 3);
  // The receiver trusts a fragment only through a finalized manifest, so an
  // unfinalized batch is neither fetched nor shown, even to the owner.
  const slot = outbox(a).at(-1)!.slot;
  expect(
    net.gets.slice(before).filter((k) => k.startsWith(`${a.scope}/`)),
  ).toEqual([]);
  expect(visibility(b, "owner")).toEqual([]);
  expect(visibility(b, "grant")).toEqual([]);
  b.reopen();
  await cycles([b], 2);
  expect(b.get()).toBeUndefined();
  net.beforePut(() => {});
  net.finalizeAll();
  await cycles([a, b], 4);
  expect(net.gets).toContain(slot);
  expect(visibility(b, "grant")).toMatchObject([
    { data: { text: "awaiting finality" } },
  ]);
  expect(visibility(b, "owner")[0].confirmation).toBeUndefined();
  const history = b.db.prepare("SELECT * FROM pdpp_record_changes").all();
  await cycles([a, b], 3);
  expect(b.db.prepare("SELECT * FROM pdpp_record_changes").all()).toEqual(
    history,
  );
});

it("never shows a batch whose finalized commitment differs from the Gateway head", async () => {
  const net = network();
  net.beforePut((key) => net.pending.add(key));
  const a = device(net),
    b = device(net);
  a.put("will-diverge");
  await cycles([a, b], 3);
  for (const [slot, head] of net.head)
    if (slot.startsWith(`${a.scope}/`))
      net.chain.set(slot, {
        ...net.chainRow(slot, head),
        commitment: `0x${"f".repeat(64)}`,
      });
  net.pending.clear();
  await cycles([b], 3);
  expect(visibility(b, "owner")).toEqual([]);
  expect(visibility(b, "grant")).toEqual([]);
  expect(b.get()).toBeUndefined();
  b.reopen();
  expect(visibility(b, "owner")).toEqual([]);
});

it("finality waits survive restart without inflating a later transient error delay", async () => {
  const net = network();
  const a = device(net);
  net.beforePut((key) => net.pending.add(key));
  await a.cycle();
  for (let i = 0; i < 16; i++) {
    time += 10000;
    await a.cycle();
  }
  a.reopen();
  expect(outbox(a).length).toBeGreaterThan(0);
  expect(outbox(a).every((r) => r.attempts === 0)).toBe(true);
  time = Math.max(time, ...outbox(a).map((row) => row.next_attempt));
  const original = net.port.evidence;
  net.port.evidence = async () => {
    throw new Error("transient RPC");
  };
  await a.cycle();
  expect(
    outbox(a).every((r) => r.attempts === 1 && r.next_attempt <= time + 1000),
  ).toBe(true);
  net.port.evidence = original;
  net.finalizeAll();
  time += 1000;
  await a.cycle();
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
});

it("uses advancing finalized-head hints to wake waiting rows but still verifies evidence", async () => {
  const net = network();
  let finalized = 123n;
  net.port.finality = { head: vi.fn(async () => finalized) };
  const original = net.port.evidence;
  const evidence = vi.fn(original);
  net.port.evidence = evidence;
  // Imported slots are rechecked on the host's sweep interval, not here.
  const sweep = { worker: { revalidateIntervalMs: 3_600_000 } };
  const a = device(net, sweep),
    b = device(net, sweep);
  await cycles([a, b], 2);
  a.put("head wake");
  net.beforePut((key) => net.pending.add(key));
  await a.cycle();
  await b.cycle();
  time += 2000;
  await a.cycle();
  await b.cycle(); // records inclusion hints without checking unchanged finalized slots
  const count = evidence.mock.calls.length;
  for (let i = 0; i < 5; i++) {
    time += 2000;
    await a.cycle();
    await b.cycle();
  }
  expect(evidence.mock.calls).toHaveLength(count);
  a.reopen();
  b.reopen();
  finalized = 140n;
  time += 2000;
  await a.cycle();
  await b.cycle();
  // A lying scheduling hint is insufficient to confirm, publish or import.
  const waitingRows = outbox(a);
  expect(waitingRows.map(({ version, state }) => [version, state])).toEqual([
    [1, "published"],
    [2, "ready"],
  ]);
  expect(b.get()).toBeUndefined();
  for (const waiting of waitingRows) {
    const received = inbox(b).find((r) => r.slot === waiting.slot);
    if (waiting.state === "ready")
      expect(received?.manifest_json ?? null).toBeNull();
    else expect(received?.manifest_json).toBeDefined();
  }
  net.beforePut(() => {});
  net.finalizeAll(148n);
  finalized = 148n;
  time += 30000;
  await a.cycle();
  await b.cycle();
  expect(b.get()).toEqual({ id: "a", text: "head wake" });
  expect(outbox(a).every((r) => r.state === "published")).toBe(true);
});

it("finality hints never shorten a genuine RPC error retry", async () => {
  const net = network();
  net.port.finality = { head: async () => 1000n };
  const a = device(net);
  const evidence = vi.fn(async () => {
    throw new Error("RPC unavailable");
  });
  net.port.evidence = evidence;
  await a.cycle();
  for (let i = 0; i < 5; i++) {
    time += 100000;
    await a.cycle();
  }
  const count = evidence.mock.calls.length;
  time += 2000;
  await a.cycle();
  expect(evidence.mock.calls.length).toBe(count);
});

it("filters parked finality waits before the receiver's download budget", async () => {
  const net = network();
  net.port.finality = { head: async () => 123n };
  const a = device(net, { pageSize: 1 });
  for (let i = 0; i < 10; i++) a.put(`record ${i}`, `r${i}`);
  await cycles([a], 14);
  expect(outbox(a).length).toBeGreaterThan(8);
  // Every slot so far stops being final: the receiver parks them all, more
  // than its download budget of four per step.
  for (const slot of [...net.chain.keys()])
    if (slot.startsWith(`${a.scope}/`)) {
      net.chain.delete(slot);
      net.pending.add(slot);
    }
  const b = device(net, { worker: { quantum: { download: 4 } } });
  await cycles([b], 3);
  expect(acceptedSlots(b, a)).toBe(0);
  const parked = new Set(inbox(b).map((r) => r.slot));
  expect(parked.size).toBeGreaterThan(8);
  // A later slot is final at once and must not wait behind the parked ones.
  a.put("after the parked slots", "late");
  net.pending.clear();
  for (const [slot, head] of net.head)
    if (parked.has(slot)) net.pending.add(slot);
    else net.chain.set(slot, net.chainRow(slot, head));
  await cycles([a], 3);
  const late = outbox(a).at(-1)!.slot;
  expect(parked.has(late)).toBe(false);
  time += 2000;
  await b.cycle();
  expect(inbox(b).find((r) => r.slot === late)?.manifest_json).not.toBeNull();
});

it("a receiver evidence error after many finality waits starts at one second", async () => {
  const net = network();
  const a = device(net, { preexisting: "late download" }),
    b = device(net);
  net.beforePut((key) => net.pending.add(key));
  await a.cycle();
  for (let i = 0; i < 16; i++) {
    time += 2000;
    await b.cycle();
  }
  const waiting = inbox(b).filter((r) => r.slot.startsWith(`${a.scope}/`));
  expect(waiting.length).toBeGreaterThan(0);
  expect(waiting.every((r) => r.attempts === 0)).toBe(true);
  net.finalizeAll();
  const original = net.port.evidence;
  net.port.evidence = async () => {
    throw new Error("RPC unavailable");
  };
  time = Math.max(time, ...waiting.map((row) => row.next_attempt));
  await b.cycle();
  net.port.evidence = original;
  const errors = inbox(b).filter((r) => r.error !== null);
  expect(errors.length).toBeGreaterThan(0);
  expect(
    errors.every((r) => r.attempts === 1 && r.next_attempt === time + 1000),
  ).toBe(true);
  time += 1000;
  await cycles([b], 2);
  expect(b.get()).toEqual({ id: "a", text: "late download" });
});

it("rolls staged binary and import acknowledgement back together, then retries without trusting cached bytes", async () => {
  const net = network(false, 8 * 1024 * 1024);
  const a = device(net, { cap: 8 * 1024 * 1024, chunk: 1024 * 1024 });
  const b = device(net, { cap: 8 * 1024 * 1024, chunk: 1024 * 1024 });
  const bytes = new Uint8Array(2 * 1024 * 1024).fill(31);
  const blob = a.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes,
    mimeType: "application/octet-stream",
  });
  a.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "binary",
        data: {
          id: "binary",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: bytes.length,
          },
        },
        emitted_at: at,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([a], 2);
  b.db.exec(
    "CREATE TRIGGER reject_binary BEFORE INSERT ON pdpp_records WHEN NEW.record_key='binary' BEGIN SELECT RAISE(ABORT,'fault after binary staging'); END",
  );
  await cycles([b], 3);
  expect(b.get("binary")).toBeUndefined();
  expect(b.store.getBlobBytes(blob.blobId)).toBeUndefined();
  // No custody survives the failed attempt. Its hidden staging scratch is
  // reclaimed at the next step start, not by the failed transaction.
  expect(
    (
      b.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_manifests WHERE namespace IN ('received','canonical','pending')",
        )
        .get() as { n: number }
    ).n,
  ).toBe(0);
  // The failure is a durable Retry on the batch's import work, with a closed
  // problem code and no exception text.
  expect(importWork(b)).toContainEqual(
    expect.objectContaining({ outcome: "retry", reason: "import_failed" }),
  );
  expect(JSON.stringify(importWork(b))).not.toContain("fault after binary");
  b.db.exec("DROP TRIGGER reject_binary");
  time += 3_600_000;
  await b.cycle();
  expect(
    Buffer.from(b.store.getBlobBytes(blob.blobId)!).equals(Buffer.from(bytes)),
  ).toBe(true);
  b.db
    .prepare(
      "UPDATE pdpp_binary_chunks SET bytes=zeroblob(length(bytes)) WHERE namespace='canonical' AND blob_id=? AND position=0",
    )
    .run(blob.blobId);
  // Reads rehash current rows, so corruption is never served.
  expect(b.store.getBlobBytes(blob.blobId)).toBeUndefined();
  // Canonical reconcile reads all retained history, so it runs on a dependency
  // change, not every cycle. When it runs it rehashes and detects the
  // replacement without a verification cache.
  await b.cycle();
  b.notify(`declaration:${sourceId}:messages`);
  await expect(b.cycle()).rejects.toThrow("Replica transport cycle incomplete");
  expect(b.store.getBlobBytes(blob.blobId)).toBeUndefined();
}, 30000);

it("reclaims only hidden crash staging on restart and preserves committed payloads", async () => {
  const net = network();
  const a = device(net);
  a.put("retained");
  await a.cycle();
  const { binaryWriter } = await import("./pdpp-binary-chunks.js");
  for (const namespace of ["staging", "payload"] as const) {
    const writer = binaryWriter(a.db, namespace, "orphan");
    writer.write(new Uint8Array([1, 2, 3]));
    writer.finish();
  }
  a.db
    .prepare(
      "INSERT INTO pdpp_transport_staged_fragments (token,position,digest,encrypted) VALUES (?,?,?,?)",
    )
    .run("orphan", 0, "digest", new Uint8Array([1]));
  a.reopen();
  await a.cycle();
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_chunks WHERE blob_id='orphan'",
        )
        .get() as { n: number }
    ).n,
  ).toBe(0);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_staged_fragments")
        .get() as { n: number }
    ).n,
  ).toBe(0);
  expect(
    (
      a.db
        .prepare(
          "SELECT count(*) AS n FROM pdpp_binary_manifests WHERE namespace='payload'",
        )
        .get() as { n: number }
    ).n,
  ).toBeGreaterThan(0);
});

it("bounds repeated high hints and never regresses the verified checked height", async () => {
  const net = network();
  net.port.finality = { head: async () => 1000n };
  const a = device(net, { preexisting: "pending" });
  net.beforePut((key) => net.pending.add(key));
  const original = net.port.evidence;
  let verified = 123n;
  const evidence = vi.fn(async (scope: string, version: number) => {
    const e = await original(scope, version);
    return { ...e, chain: e.chain && { ...e.chain, blockNumber: verified } };
  });
  net.port.evidence = evidence;
  await a.cycle();
  time += 2000;
  await a.cycle(); // high hint, unchanged verified head: durable cooldown
  const count = evidence.mock.calls.length;
  for (let i = 0; i < 14; i++) {
    time += 2000;
    await a.cycle();
  }
  expect(evidence.mock.calls).toHaveLength(count);
  verified = 120n;
  time += 2000;
  await a.cycle();
  const rows = outbox(a);
  expect(rows.length).toBeGreaterThan(0);
  expect(
    rows.map(({ slot, checked_block, attempts, next_attempt }) => ({
      slot,
      checked_block,
      attempts,
      next_attempt,
    })),
  ).toEqual(
    rows.map(({ slot }) => ({
      slot,
      checked_block: "123",
      attempts: 0,
      next_attempt: time + 30000,
    })),
  );
  expect(acceptedSlots(a, a)).toBe(0);
});

/** Slots of `writer` whose manifest `d` accepted under finalized evidence. */
function acceptedSlots(
  d: ReturnType<typeof device>,
  writer: ReturnType<typeof device>,
) {
  return (
    d.db
      .prepare(
        "SELECT count(*) AS n FROM pdpp_transport_manifests_in WHERE scope=? AND manifest_json IS NOT NULL",
      )
      .get(writer.scope) as { n: number }
  ).n;
}

it("does not acknowledge export when persisted payload chunks change before cursor commit", async () => {
  const net = network(),
    a = device(net);
  a.put("retained source");
  a.db.exec(
    "CREATE TRIGGER corrupt_payload_stage AFTER INSERT ON pdpp_binary_manifests WHEN NEW.namespace='payload' BEGIN UPDATE pdpp_binary_chunks SET bytes=zeroblob(length(bytes)) WHERE namespace='payload' AND blob_id=NEW.blob_id AND position=0; END",
  );
  await expect(a.cycle()).rejects.toBeInstanceOf(AggregateError);
  expect(a.store.replication.getBaselineCheckpoint()).toBe(0);
  expect(
    (
      a.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get() as { n: number }
    ).n,
  ).toBe(0);
  a.db.exec("DROP TRIGGER corrupt_payload_stage");
  await cycles([a], 2);
  expect(a.store.replication.getBaselineCheckpoint()).toBeGreaterThan(0);
  expect(outbox(a).length).toBeGreaterThan(0);
});

it("does not promote a prepared batch whose staged fragment set became incomplete", async () => {
  const net = network(),
    a = device(net);
  a.put("retained source");
  a.db.exec(
    "CREATE TRIGGER drop_prepared_stage AFTER INSERT ON pdpp_transport_staged_fragments BEGIN DELETE FROM pdpp_transport_staged_fragments WHERE token=NEW.token AND position=NEW.position; END",
  );
  await a.cycle();
  expect(
    (
      a.db
        .prepare(
          "SELECT prepared FROM pdpp_transport_batches ORDER BY sequence LIMIT 1",
        )
        .get() as { prepared: number }
    ).prepared,
  ).toBe(0);
  expect(outbox(a)).toHaveLength(0);
  a.db.exec("DROP TRIGGER drop_prepared_stage");
  await cycles([a], 2);
  expect(outbox(a).length).toBeGreaterThan(0);
  expect(outbox(a).every((row) => row.state === "published")).toBe(true);
});

it("reclaims a prior container's stale same-PID token and keeps making progress", async () => {
  const net = network(),
    a = device(net);
  a.put("restart");
  a.db
    .prepare("INSERT INTO pdpp_transport_lock VALUES (1,?,?)")
    .run(process.pid, "prior-container-token");
  for (let cycle = 0; cycle < 3; cycle++)
    await expect(a.cycle()).resolves.toBeUndefined();
  expect(outbox(a).every((row) => row.state === "published")).toBe(true);
});

it("recovers a same-process stale lock after SQL lock release fails", async () => {
  const net = network(),
    a = device(net);
  a.put("release retry");
  a.db.exec(
    "CREATE TRIGGER reject_lock_release BEFORE DELETE ON pdpp_transport_lock BEGIN SELECT RAISE(ABORT,'release unavailable'); END",
  );
  await expect(a.cycle()).rejects.toThrow();
  expect(a.db.prepare("SELECT 1 FROM pdpp_transport_lock").get()).toBeDefined();
  a.db.exec("DROP TRIGGER reject_lock_release");
  await expect(a.cycle()).resolves.toBeUndefined();
});

it("protects a live same-process writer opened through a different directory alias", async () => {
  const net = network(),
    a = device(net);
  a.put("live writer");
  let unpause!: () => void, ready!: () => void;
  const paused = new Promise<void>((resolve) => {
    ready = resolve;
  });
  const resumed = new Promise<void>((resolve) => {
    unpause = resolve;
  });
  const encrypt = net.port.encrypt;
  let first = true;
  net.port.encrypt = async (scope, bytes) => {
    if (first) {
      first = false;
      ready();
      await resumed;
    }
    return encrypt(scope, bytes);
  };
  const aliasRoot = mkdtempSync(join(tmpdir(), "replica-alias-"));
  directories.push(aliasRoot);
  symlinkSync(dirname(a.db.name), join(aliasRoot, "alias"), "dir");
  const aliasDb = new Database(join(aliasRoot, "alias", "records.sqlite"));
  const aliasStore = createReplicaRecordStore(aliasDb);
  const aliasWorker = createReplicaTransportWorker({
    db: aliasDb,
    enabled: true,
    expected: () => expected,
    exporter: aliasStore.replication,
    receiver: createReplicaReceiver({
      db: aliasDb,
      store: aliasStore,
      owner,
      authenticate: () => owner,
      declarations: () => expected.declarations,
    }),
    credential: "replica-secret",
    transport: net.port,
    authority: a.authority,
  });
  const running = a.cycle();
  try {
    await paused;
    await expect(aliasWorker.cycle()).rejects.toMatchObject({
      code: "replica_worker_active",
    });
  } finally {
    unpause();
    await running;
    aliasStore.close();
  }
});
