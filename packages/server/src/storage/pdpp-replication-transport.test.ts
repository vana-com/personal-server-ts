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
  REPLICA_BATCH_OPERATIONS,
  REPLICA_BATCH_BYTES,
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
  fragmentReplicaPayload,
  replicaDigest,
  replicaFragmentKey,
  replicaScope,
  prepareReplicaManifest,
} from "@opendatalabs/personal-server-ts-core/replication/transport";
import {
  REPLICA_MAX_OPERATIONS,
  REPLICA_MAX_TOTAL_BYTES,
  REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES,
  REPLICA_MAX_OPERATION_ENVELOPE_BYTES,
  REPLICA_MAX_PAYLOAD_ENVELOPE_BYTES,
  REPLICA_DEFAULT_FRAGMENT_BYTES,
  REPLICA_DEFAULT_BYTE_BUDGET_BYTES,
  REPLICA_DEFAULT_LIMITS,
  REPLICA_LIMITS_VERSION,
  replicaFramedBytesBound,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import {
  admit,
  ReplicaByteBudget,
  ReplicaResourceLimitError,
} from "@opendatalabs/personal-server-ts-core/replication/limits";
import { remoteReplicaTestWriter } from "./pdpp-replica-writer-identity.test-utils.js";
import type { ReplicaTransportPort } from "@opendatalabs/personal-server-ts-core/replication/dpv2";
import * as replicaStream from "@opendatalabs/personal-server-ts-core/replication/stream";
import { encodeReplicaPayload } from "@opendatalabs/personal-server-ts-core/replication/stream";
import { assembleReplicaStream } from "@opendatalabs/personal-server-ts-core/replication/stream";
import { canonicalJson } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { createReplicaStagingStore } from "./pdpp-replica-staging.js";
import { ReplicaFramingUnsupported } from "@opendatalabs/personal-server-ts-core/replication/outcome";
import { defaultReplicaBackoff } from "@opendatalabs/personal-server-ts-core/replication/schedule";
import {
  MAX_BLOB_UPLOAD_BYTES,
  MAX_INGEST_BODY_BYTES,
} from "../routes/pdpp-records.js";

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
    encryptedByteLength: (bytes: number) => bytes + 28,
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
  // Report order follows the persisted phase rotation; select the publish wait.
  const pending = status.waits.find(
    (wait) => wait.id === predecessor.slot && wait.phase === "publish",
  );
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

it("S4 a holder lookup mismatch retries and does not free the predecessor slot", async () => {
  const net = network();
  const a = device(net);
  const originalEvidence = net.port.evidence;
  let conflictInserted = false;
  net.port.evidence = async (scope, version) => {
    if (version === 1 && !conflictInserted) {
      const slot = slotKey(scope, version);
      // The new conflict boundary reads the holder before deciding whether
      // this is a recoverable squat. Supply bytes that disprove this slot.
      const held = a.db
        .prepare(
          "SELECT encrypted FROM pdpp_transport_manifests_out WHERE scope=? AND version=?",
        )
        .get(scope, version) as { encrypted: Buffer };
      net.blobs.set(slot, held.encrypted);
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
    state: "ready",
    outcome: "retry",
    reason: "commitment_mismatch",
  });

  a.put("successor after settled conflict", "second");
  await cycles([a], 3);

  expect(outbox(a).map((row) => row.version)).toEqual([1]);
  expect(net.registrations).not.toContain(slotKey(a.scope, 2));
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
    (r) => r.slot === slot && r.fragment_json !== null,
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
  const budget = new ReplicaByteBudget(512 * 1024 * 1024);
  const release = budget.reserve(256 * 1024 * 1024);
  if (typeof release !== "function")
    throw new Error("expected budget reservation");
  const b = device(net, { worker: { resourceBudget: budget } });
  const intervals: { attempt: number; delay: number; next: number }[] = [];
  for (let attempt = 0; attempt < 64; attempt++) {
    await b.cycle();
    const busy = b.db
      .prepare(
        "SELECT outcome,reason,attempts,next_attempt FROM pdpp_transport_manifests_in WHERE outcome='retry' AND reason='resource_busy'",
      )
      .get() as
      | {
          outcome: string;
          reason: string;
          attempts: number;
          next_attempt: number;
        }
      | undefined;
    if (!busy) continue;
    if (intervals.at(-1)?.next !== busy.next_attempt) {
      intervals.push({
        attempt: busy.attempts,
        delay: busy.next_attempt - time,
        next: busy.next_attempt,
      });
      time = busy.next_attempt;
    }
  }
  expect(intervals.length).toBeGreaterThanOrEqual(3);
  const pClassCap = defaultReplicaBackoff(Number.MAX_SAFE_INTEGER);
  expect(
    intervals
      .slice(1)
      .every((at, index) =>
        intervals[index]!.delay < pClassCap
          ? at.delay > intervals[index]!.delay
          : at.delay === pClassCap,
      ),
  ).toBe(true);
  expect(
    intervals.every(
      ({ attempt, delay }) => delay === defaultReplicaBackoff(attempt),
    ),
  ).toBe(true);
  expect(intervals.at(-1)?.delay).toBe(pClassCap);
  expect(intervals.every(({ delay }) => delay <= pClassCap)).toBe(true);
  release();
  time = Math.max(time, ...intervals.map(({ next }) => next));
  await cycles([b], 12);
  expect(b.get()).toEqual(a.get());
  expect(budget.reserved).toBe(0);
});

it("M4 overlaps per-fragment reservations and admits a batch larger than the budget", async () => {
  const net = network(false, 64 * 1024);
  const source = device(net, { chunk: 3000, cap: 64 * 1024 });
  await cycles([source], 24);
  const template = device(net);
  await cycles([template], 24);
  const largeBlob = source.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes: new Uint8Array(20_000).fill(3),
    mimeType: "application/octet-stream",
  });
  source.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "large-blob",
        emitted_at: at,
        data: {
          id: "large-blob",
          blob_ref: {
            blob_id: largeBlob.blobId,
            mime_type: largeBlob.mimeType,
            size_bytes: 20_000,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([source], 24);
  const outbound = source.db
    .prepare(
      `SELECT m.scope,m.encrypted,b.batch FROM pdpp_transport_manifests_out m
     JOIN pdpp_transport_batches b ON b.batch=m.batch WHERE b.prepared=1
     ORDER BY m.version DESC LIMIT 1`,
    )
    .get() as { scope: string; encrypted: Buffer; batch: string };
  const manifest = decodeReplicaManifest(
    await net.port.decrypt(outbound.scope, new Uint8Array(outbound.encrypted)),
    outbound.scope,
    owner,
  );
  expect(manifest.fragments.length).toBeGreaterThan(1);
  const fragmentBytes = manifest.fragments[0]!.bytes;
  const budget = new ReplicaByteBudget(fragmentBytes * 6);
  let maximumReserved = 0;
  const reserve = budget.reserve.bind(budget);
  vi.spyOn(budget, "reserve").mockImplementation((bytes, group) => {
    const result = reserve(bytes, group);
    maximumReserved = Math.max(maximumReserved, budget.reserved);
    return result;
  });
  expect(outbound.encrypted.length * 4).toBeLessThan(budget.maxBytes / 2);
  const limits = { maxManifestCiphertextBytes: outbound.encrypted.length };
  const a = device(net, {
    copyOf: template,
    worker: { resourceBudget: budget, resourceLimits: limits },
  });
  const b = device(net, {
    copyOf: template,
    worker: { resourceBudget: budget, resourceLimits: limits },
  });
  const originalDecrypt = net.port.decrypt.bind(net.port);
  let releaseFirst!: () => void;
  let started!: () => void;
  const firstReadStarted = new Promise<void>((resolve) => {
    started = resolve;
  });
  const holdFirstRead = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let held = false;
  net.port.decrypt = async (...args) => {
    const plaintext = await originalDecrypt(...args);
    const decoded = JSON.parse(new TextDecoder().decode(plaintext)) as {
      data?: { fragment?: unknown };
    };
    if (!held && decoded.data?.fragment) {
      held = true;
      started();
      await holdFirstRead;
    }
    return plaintext;
  };
  const firstImport = cycles([a], 12);
  await Promise.race([
    firstReadStarted,
    new Promise<void>((resolve) => setTimeout(resolve, 5000)),
  ]);
  if (!held) {
    releaseFirst();
    await firstImport;
    throw new Error(
      `fragment decrypt barrier was not reached: ${JSON.stringify(
        a.db
          .prepare(
            "SELECT state,outcome,reason FROM pdpp_transport_manifests_in",
          )
          .all(),
      )}`,
    );
  }
  expect(budget.reserved).toBe(fragmentBytes * 4);
  await cycles([b], 12);
  const refused = b.db
    .prepare(
      `SELECT count(*) AS count FROM pdpp_transport_fragments_in
     WHERE outcome='retry' AND reason='resource_busy'
     UNION ALL SELECT count(*) AS count FROM pdpp_transport_manifests_in
     WHERE outcome='retry' AND reason='resource_busy'`,
    )
    .all() as { count: number }[];
  expect(fragmentBytes * 4).toBeGreaterThan(budget.maxBytes / 2);
  const refusalRows = b.db
    .prepare(
      `SELECT state,outcome,reason FROM pdpp_transport_manifests_in
     UNION ALL SELECT state,outcome,reason FROM pdpp_transport_fragments_in`,
    )
    .all();
  if (!refused.some((row) => row.count > 0)) {
    releaseFirst();
    await firstImport;
    throw new Error(
      `second import did not see resource_busy: ${JSON.stringify(refusalRows)}`,
    );
  }
  releaseFirst();
  await firstImport;
  net.port.decrypt = originalDecrypt;
  time += 60_000;
  await cycles([a, b], 36);
  expect(a.get()).toEqual(source.get());
  expect(b.get()).toEqual(source.get());
  expect(a.store.getBlobBytes(largeBlob.blobId)).toEqual(
    new Uint8Array(20_000).fill(3),
  );
  expect(manifest.totalBytes * 4).toBeGreaterThan(budget.maxBytes);
  expect(maximumReserved).toBeLessThanOrEqual(budget.maxBytes);
  expect(budget.reserved).toBe(0);
}, 60000);

it("M2 releases a read reservation when stagingStore throws after admission", async () => {
  const net = network();
  const a = device(net, { preexisting: "staging store failure" });
  await cycles([a], 8);
  const budget = new ReplicaByteBudget(REPLICA_DEFAULT_BYTE_BUDGET_BYTES);
  let calls = 0;
  let reservedAtThrow: number | undefined;
  let successfulReservations = 0;
  const reserve = budget.reserve.bind(budget);
  vi.spyOn(budget, "reserve").mockImplementation((bytes) => {
    const result = reserve(bytes);
    if (typeof result === "function") successfulReservations++;
    return result;
  });
  const isReadyToImport = (
    input: Parameters<typeof createReplicaStagingStore>[0],
  ) =>
    Boolean(
      input.db
        .prepare(
          `SELECT 1 FROM pdpp_transport_manifests_in m
           WHERE m.manifest_json IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM pdpp_transport_fragments_in f
             WHERE f.slot=m.slot AND f.fragment_json IS NULL
           ) LIMIT 1`,
        )
        .get(),
    );
  const b = device(net, {
    worker: {
      resourceBudget: budget,
      createStagingStore: (
        input: Parameters<typeof createReplicaStagingStore>[0],
      ) => {
        if (calls === 0 && isReadyToImport(input)) {
          calls++;
          reservedAtThrow = budget.reserved;
          expect(budget.reserved).toBe(0);
          throw new Error("staging store failed");
        }
        return createReplicaStagingStore(input);
      },
    },
  });
  for (let i = 0; i < 12 && calls === 0; i++) await cycles([b], 1);
  expect(calls).toBe(1);
  expect(reservedAtThrow).toBe(0);
  expect(budget.reserved).toBe(0);
  await cycles([b], 12);
  expect(calls).toBe(1);
  expect(b.get()).toEqual(a.get());
  expect(successfulReservations).toBeGreaterThan(0);
  expect(budget.reserved).toBe(0);
});

it("M1 charges and releases an envelope larger than the free budget", async () => {
  const net = network(false, 64 * 1024);
  const source = device(net, { chunk: 2000 });
  await cycles([source], 24);
  const template = device(net);
  await cycles([template], 24);
  source.put("x".repeat(5000));
  await cycles([source], 80);
  const budget = new ReplicaByteBudget(8 * 1024);
  let maximumReserved = 0;
  const reserve = budget.reserve.bind(budget);
  vi.spyOn(budget, "reserve").mockImplementation((bytes, group) => {
    const result = reserve(bytes, group);
    maximumReserved = Math.max(maximumReserved, budget.reserved);
    return result;
  });
  const receiver = device(net, {
    copyOf: template,
    worker: {
      resourceBudget: budget,
      resourceLimits: { maxManifestCiphertextBytes: 1024 },
    },
  });

  await cycles([receiver], 36);

  const sourceWriter = (
    source.db
      .prepare("SELECT writer FROM pdpp_transport_state WHERE id=1")
      .get() as {
      writer: string;
    }
  ).writer;
  const oversizedBatch = source.db
    .prepare("SELECT batch FROM pdpp_transport_batches WHERE total_bytes>5000")
    .get() as { batch: string };
  const importedOversized = receiver.db
    .prepare(
      "SELECT outcome,reason FROM pdpp_transport_import_work WHERE writer=? AND batch=?",
    )
    .get(sourceWriter, oversizedBatch.batch);
  expect(importedOversized).toMatchObject({ outcome: "progress" });
  expect(maximumReserved).toBeGreaterThan(budget.maxBytes);
  expect(budget.reserved).toBe(0);
});

it("M2 releases a read reservation when reclaimAdmission throws", async () => {
  const net = network();
  const a = device(net, { preexisting: "reclaim failure" });
  await cycles([a], 8);
  const budget = new ReplicaByteBudget(REPLICA_DEFAULT_BYTE_BUDGET_BYTES);
  let calls = 0;
  let reservedAtThrow: number | undefined;
  let successfulReservations = 0;
  const reserve = budget.reserve.bind(budget);
  vi.spyOn(budget, "reserve").mockImplementation((bytes) => {
    const result = reserve(bytes);
    if (typeof result === "function") successfulReservations++;
    return result;
  });
  const isReadyToImport = (
    input: Parameters<typeof createReplicaStagingStore>[0],
  ) =>
    Boolean(
      input.db
        .prepare(
          `SELECT 1 FROM pdpp_transport_manifests_in m
           WHERE m.manifest_json IS NOT NULL AND NOT EXISTS (
             SELECT 1 FROM pdpp_transport_fragments_in f
             WHERE f.slot=m.slot AND f.fragment_json IS NULL
           ) LIMIT 1`,
        )
        .get(),
    );
  const b = device(net, {
    worker: {
      resourceBudget: budget,
      createStagingStore: (
        input: Parameters<typeof createReplicaStagingStore>[0],
      ) => {
        const store = createReplicaStagingStore(input);
        if (calls === 0 && isReadyToImport(input)) {
          return {
            ...store,
            reclaimAdmission: () => {
              calls++;
              reservedAtThrow = budget.reserved;
              expect(budget.reserved).toBe(0);
              throw new Error("reclaim failed");
            },
          };
        }
        return store;
      },
    },
  });
  for (let i = 0; i < 12 && calls === 0; i++) await cycles([b], 1);
  expect(calls).toBe(1);
  expect(reservedAtThrow).toBe(0);
  expect(budget.reserved).toBe(0);
  await cycles([b], 12);
  expect(calls).toBe(1);
  expect(b.get()).toEqual(a.get());
  expect(successfulReservations).toBeGreaterThan(0);
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
    resource_limits_version: REPLICA_LIMITS_VERSION,
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

it("H3 prepares, admits and imports one exact maximum honest batch", async () => {
  const net = network(false, 64 * 1024);
  const limits = {
    maxSourceBlobBytes: 1024,
    maxRecordJsonBytes: 1024,
    maxManifestCiphertextBytes: 64 * 1024,
    maxFragmentCiphertextBytes: 64 * 1024,
    maxAggregateCiphertextBytes: 256 * 1024,
    maxFragments: 256,
    maxEvidenceRows: 256,
    maxTotalBytes: 64 * 1024,
    maxOperations: 2,
    maxOperationBytes: 8 * 1024,
    maxSingleBlobBytes: 1024,
    maxBlobTotalBytes: 1024,
  };
  const sender = device(net, {
    cap: 64 * 1024,
    worker: {
      maxBatchOperations: 2,
      maxBatchBytes: 16 * 1024,
      resourceLimits: limits,
    },
  });
  await cycles([sender], 12);
  const id = "large-operation";
  const blob = sender.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes: new Uint8Array(1024).fill(7),
    mimeType: "application/octet-stream",
  });
  const fixedRecordBytes = new TextEncoder().encode(
    JSON.stringify({
      id,
      text: "",
      blob_ref: {
        blob_id: blob.blobId,
        mime_type: blob.mimeType,
        size_bytes: 1024,
      },
    }),
  ).length;
  const maxRecordText = "x".repeat(1024 - fixedRecordBytes);
  const maxRecord = {
    id,
    text: maxRecordText,
    blob_ref: {
      blob_id: blob.blobId,
      mime_type: blob.mimeType,
      size_bytes: 1024,
    },
  };
  expect(new TextEncoder().encode(JSON.stringify(maxRecord)).length).toBe(1024);
  sender.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: id,
        emitted_at: at,
        data: maxRecord,
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  await cycles([sender], 24);

  const batches = sender.db
    .prepare(
      "SELECT batch,total_bytes FROM pdpp_transport_batches WHERE prepared=1 AND total_bytes>1000 ORDER BY total_bytes DESC",
    )
    .all() as { batch: string; total_bytes: number }[];
  expect(batches, JSON.stringify(batches)).toHaveLength(1);
  const batch = batches[0];
  if (!batch) throw new Error("sender did not prepare the maximum batch");
  const outgoing = sender.db
    .prepare(
      "SELECT scope,encrypted FROM pdpp_transport_manifests_out WHERE batch=?",
    )
    .get(batch.batch) as { scope: string; encrypted: Buffer };
  const manifest = decodeReplicaManifest(
    await net.port.decrypt(outgoing.scope, new Uint8Array(outgoing.encrypted)),
    outgoing.scope,
    owner,
  );
  const admission = admit(
    manifest,
    new ReplicaByteBudget(1_000_000),
    {
      repositoryId: "h3-maximum",
      owner,
      manifestDigest: manifest.digest,
    },
    limits,
  );
  expect(admission).not.toHaveProperty("kind");

  const encryptedFragments = sender.db
    .prepare(
      "SELECT encrypted FROM pdpp_transport_fragments_out WHERE batch=? ORDER BY position",
    )
    .all(batch.batch) as { encrypted: Buffer }[];
  const fragments = [];
  for (let index = 0; index < encryptedFragments.length; index++) {
    const plaintext = await net.port.decrypt(
      outgoing.scope,
      new Uint8Array(encryptedFragments[index]!.encrypted),
    );
    fragments.push(
      (
        JSON.parse(new TextDecoder().decode(plaintext)) as {
          data: { fragment: (typeof fragments)[number] };
        }
      ).data.fragment,
    );
  }
  const payloadParts: Uint8Array[] = [];
  for await (const bytes of assembleReplicaStream(async function* () {
    yield* fragments;
  }))
    payloadParts.push(bytes);
  const payload = JSON.parse(
    new TextDecoder().decode(Buffer.concat(payloadParts)),
  ) as {
    envelope: { operations: { data?: unknown }[] };
    blobs: { bytes: string }[];
  };
  expect(payload.envelope.operations).toHaveLength(2);
  expect(
    new TextEncoder().encode(
      JSON.stringify(
        payload.envelope.operations.find((operation) => operation.data)!.data,
      ),
    ).length,
  ).toBe(1024);
  expect(Buffer.from(payload.blobs[0]!.bytes, "base64")).toHaveLength(1024);

  const receiver = device(net, {
    worker: {
      maxBatchOperations: 2,
      maxBatchBytes: 16 * 1024,
      resourceLimits: limits,
    },
  });
  await cycles([receiver], 36);
  expect(receiver.get(id)).toBeDefined();
  expect(receiver.store.getBlobBytes(blob.blobId)).toEqual(
    new Uint8Array(1024).fill(7),
  );
}, 60000);

it("H4 persists sender resource_unsupported, releases the empty batch and permits later writer batches", async () => {
  const net = network();
  const limits = { maxAggregateCiphertextBytes: 1 };
  const sender = device(net, {
    preexisting: "oversized for configured replication limit",
    worker: { resourceLimits: limits },
  });
  await cycles([sender], 24);
  const refused = sender.db
    .prepare(
      "SELECT outcome,reason FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
    )
    .all();
  expect(refused.length).toBeGreaterThan(0);
  expect(
    refused.every(
      (row) =>
        (row as { outcome: string; reason: string }).outcome ===
          "unsupported" &&
        (row as { reason: string }).reason === "resource_unsupported",
    ),
  ).toBe(true);
  expect(
    sender.db.prepare("SELECT state FROM pdpp_transport_preparation").get(),
  ).toEqual({ state: "released" });
  expect(net.puts).toHaveLength(0);
  limits.maxAggregateCiphertextBytes = REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES;
  sender.reopen();
  sender.put("later batch", "later");
  await cycles([sender], 12);
  expect(outbox(sender).at(-1)).toMatchObject({
    version: 1,
    state: "published",
  });
  expect(
    sender.db
      .prepare(
        "SELECT outcome,reason FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
      )
      .all(),
  ).toEqual(refused);
});

async function expectOperationUnsupported(
  sender: ReturnType<typeof device>,
  limit: string,
) {
  await cycles([sender], 24);
  const refused = sender.db
    .prepare(
      "SELECT batch,position,outcome,reason,admission_json FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
    )
    .all() as { outcome: string; reason: string; admission_json: string }[];
  expect(refused.length).toBeGreaterThan(0);
  for (const row of refused) {
    expect(row).toMatchObject({
      outcome: "unsupported",
      reason: "resource_unsupported",
    });
    expect(JSON.parse(row.admission_json)).toMatchObject({
      reason: "resource_unsupported",
      limit,
    });
  }
  expect(
    sender.db
      .prepare(
        "SELECT 1 FROM pdpp_transport_batches WHERE outcome IN ('retry','quarantine')",
      )
      .get(),
  ).toBeUndefined();
  const count = outbox(sender).length;
  sender.reopen();
  sender.put("later writer batch", "later");
  await cycles([sender], 12);
  expect(outbox(sender).length).toBeGreaterThan(count);
  expect(outbox(sender).at(-1)?.state).toBe("published");
  expect(
    sender.db
      .prepare(
        "SELECT batch,position,outcome,reason,admission_json FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
      )
      .all(),
  ).toEqual(refused);
}

it("H4 persists resource_unsupported for a sender operation-count breach", async () => {
  const net = network();
  const sender = device(net, {
    worker: {
      maxBatchOperations: 1,
      resourceLimits: { maxOperations: 1 },
    },
  });
  await cycles([sender], 12);
  sender.put("first", "first");
  sender.put("second", "second");
  const readTailPage = sender.store.replication.readTailPage.bind(
    sender.store.replication,
  );
  vi.spyOn(sender.store.replication, "readTailPage").mockImplementation(
    (input) => {
      // Simulate an exporter breaching the requested count with two distinct
      // real operations, rather than duplicating an operation identity.
      return readTailPage({ ...input, limit: input.limit + 1 });
    },
  );

  await expectOperationUnsupported(sender, "operation_count");
});

it("H4 persists resource_unsupported for a sender single-blob breach", async () => {
  const net = network();
  const sender = device(net, {
    worker: {
      maxBatchOperations: 2,
      resourceLimits: { maxOperations: 2, maxSingleBlobBytes: 1 },
    },
  });
  await cycles([sender], 12);
  const blob = sender.store.storeBlobBytesForInstance({
    instance: "conn",
    method: "export",
    generation: 1,
    bytes: new Uint8Array([1, 2]),
    mimeType: "application/octet-stream",
  });
  sender.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "large-blob",
        emitted_at: at,
        data: {
          id: "large-blob",
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: 2,
          },
        },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );

  await expectOperationUnsupported(sender, "single_blob_bytes");
});

it("H4 persists resource_unsupported for sender aggregate-blob breach", async () => {
  const net = network();
  const sender = device(net, {
    worker: {
      maxBatchOperations: 2,
      resourceLimits: {
        maxOperations: 2,
        maxSingleBlobBytes: 4,
        maxBlobTotalBytes: 3,
      },
    },
  });
  await cycles([sender], 12);
  const blobs = [1, 2].map((generation) =>
    sender.store.storeBlobBytesForInstance({
      instance: "conn",
      method: "export",
      generation: 1,
      bytes: new Uint8Array([generation, generation]),
      mimeType: "application/octet-stream",
    }),
  );
  sender.store.ingestBatch(
    blobs.map((blob, index) => ({
      instance: "conn",
      stream: "messages",
      key: `blob-${index}`,
      emitted_at: at,
      data: {
        id: `blob-${index}`,
        blob_ref: {
          blob_id: blob.blobId,
          mime_type: blob.mimeType,
          size_bytes: 2,
        },
      },
    })),
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );

  await expectOperationUnsupported(sender, "aggregate_blob_bytes");
});

it("H2 derives limits above the honest worst case from the exported write caps", () => {
  expect(MAX_BLOB_UPLOAD_BYTES).toBe(REPLICA_DEFAULT_LIMITS.maxSourceBlobBytes);
  expect(MAX_INGEST_BODY_BYTES).toBe(REPLICA_DEFAULT_LIMITS.maxRecordJsonBytes);
  expect(REPLICA_BATCH_OPERATIONS).toBe(REPLICA_MAX_OPERATIONS);
  const maximumBlobBase64 = 4 * Math.ceil(MAX_BLOB_UPLOAD_BYTES / 3);
  const maximumSingleOperation =
    maximumBlobBase64 +
    MAX_INGEST_BODY_BYTES +
    REPLICA_MAX_OPERATION_ENVELOPE_BYTES;
  const honestPayload =
    Math.max(
      REPLICA_BATCH_BYTES + maximumSingleOperation,
      REPLICA_BATCH_OPERATIONS * REPLICA_BATCH_BYTES,
    ) + REPLICA_MAX_PAYLOAD_ENVELOPE_BYTES;
  const fragmentCount = Math.ceil(
    honestPayload / REPLICA_DEFAULT_FRAGMENT_BYTES,
  );
  const honestCiphertext = replicaFramedBytesBound(
    honestPayload,
    fragmentCount,
  );

  expect(REPLICA_MAX_TOTAL_BYTES).toBeGreaterThanOrEqual(honestPayload);
  expect(REPLICA_MAX_AGGREGATE_CIPHERTEXT_BYTES).toBeGreaterThanOrEqual(
    honestCiphertext,
  );
  expect(REPLICA_DEFAULT_LIMITS.maxOperationBytes).toBeGreaterThanOrEqual(
    maximumSingleOperation,
  );
  expect(REPLICA_DEFAULT_LIMITS.maxSingleBlobBytes).toBeGreaterThanOrEqual(
    MAX_BLOB_UPLOAD_BYTES,
  );
}, 30000);

it("M3 defaults the per-process object budget to 512 MiB", () => {
  expect(REPLICA_DEFAULT_BYTE_BUDGET_BYTES).toBe(512 * 1024 * 1024);
  expect(
    100 * 1024 * 1024 * 4,
    "the #500 per-object cap times the copy factor fits the budget",
  ).toBeLessThanOrEqual(REPLICA_DEFAULT_BYTE_BUDGET_BYTES);
});

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
  const resourceLimits = { maxAggregateCiphertextBytes: 1_000_000_000 };
  expect(
    admit(
      decodeReplicaManifest(prepared.plaintext, scope, owner),
      new ReplicaByteBudget(Number.MAX_SAFE_INTEGER),
      {
        repositoryId: "test",
        owner,
        manifestDigest: `sha256:${"3".repeat(64)}`,
      },
      { ...REPLICA_DEFAULT_LIMITS, ...resourceLimits },
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
  const receiver = device(net, { worker: { resourceLimits } });
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
  const resourceBudget = new ReplicaByteBudget(512 * 1024 * 1024);
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
  const resourceBudget = new ReplicaByteBudget(512 * 1024 * 1024);
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
  // A typed owner wait stops the fork, with no PUT over the published manifest.
  expect(outbox(clone).find((r) => r.slot === slot)).toMatchObject({
    outcome: "wait",
    reason: "own_key_conflict",
    next_attempt: Number.MAX_SAFE_INTEGER,
  });
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

it("retries an unauthenticated holder mismatch including a tombstone pair", async () => {
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
    expect(outbox(a).find((r) => r.slot === slot)).toMatchObject({
      state: "ready",
      outcome: "retry",
      reason: "commitment_mismatch",
    });
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

it("A3b-1 releases envelope reservations even when staging abort throws and the next oversized import proceeds", async () => {
  const net = network(false, 64 * 1024);
  const source = device(net, { chunk: 2000 });
  await cycles([source], 12);
  const template = device(net);
  await cycles([template], 12);
  source.put("x".repeat(5000));
  await cycles([source], 24);
  const budget = new ReplicaByteBudget(8 * 1024);
  let abortThrows = 0;
  let heldAtAbort = 0;
  const receiver = device(net, {
    copyOf: template,
    worker: {
      resourceBudget: budget,
      resourceLimits: { maxManifestCiphertextBytes: 1024 },
      createStagingStore(
        input: Parameters<typeof createReplicaStagingStore>[0],
      ) {
        const store = createReplicaStagingStore(input);
        return {
          ...store,
          abort(admission: Parameters<typeof store.abort>[0]) {
            if (budget.reserved > budget.maxBytes && abortThrows === 0) {
              abortThrows++;
              heldAtAbort = budget.reserved;
              throw new Error("SQLite writer locked during abort");
            }
            return store.abort(admission);
          },
        };
      },
    },
  });
  receiver.declarations([]);
  for (let i = 0; i < 24 && abortThrows === 0; i++) await cycles([receiver], 1);
  expect(abortThrows).toBe(1);
  expect(heldAtAbort).toBeGreaterThan(budget.maxBytes);
  expect(budget.reserved).toBe(0);
  receiver.declarations(expected.declarations);
  await cycles([receiver], 24);
  expect(receiver.get()).toEqual(source.get());
  expect(budget.reserved).toBe(0);
});

it.each(["oversized first", "small first"])(
  "A3b-3 envelope barrier: %s",
  async (order) => {
    const net = network(false, 64 * 1024);
    const source = device(net, { chunk: 2000 });
    await cycles([source], 12);
    const template = device(net);
    await cycles([template], 12);
    source.put("x".repeat(5000));
    await cycles([source], 24);
    const budget = new ReplicaByteBudget(8 * 1024);
    const options = {
      copyOf: template,
      worker: {
        resourceBudget: budget,
        resourceLimits: { maxManifestCiphertextBytes: 1024 },
      },
    };
    const a = device(net, options);
    const b = device(net, options);
    // B needs only the small baseline; A needs the oversized successor.
    b.db.prepare("DELETE FROM pdpp_transport_manifests_in").run();
    let release!: () => void;
    let started!: () => void;
    const held = new Promise<void>((resolve) => {
      started = resolve;
    });
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const inspect = replicaStream.inspectReplicaPayload;
    let blocked = false;
    // Publish the small writer before enabling the inspection barrier.
    const small = device(net);
    small.put("small", "small");
    await cycles([small], 12);
    const spy = vi
      .spyOn(replicaStream, "inspectReplicaPayload")
      .mockImplementation(async (...args) => {
        const payload = await inspect(...args);
        const large =
          canonicalJson(payload.envelope).length > budget.maxBytes / 2;
        if (!blocked && large === (order === "oversized first")) {
          blocked = true;
          started();
          await gate;
        }
        return payload;
      });
    // A receives a large envelope; B receives a small independent writer's batch.
    const largeWriter = source.scope;
    const smallWriter = small.scope;
    const filter = (d: ReturnType<typeof device>, scope: string) => {
      d.db
        .prepare("DELETE FROM pdpp_transport_manifests_in WHERE scope<>?")
        .run(scope);
    };
    // Restrict discovery per receiver without changing what the sender registered.
    const list = net.port.list;
    let selected = order === "oversized first" ? largeWriter : smallWriter;
    net.port.list = async (...args) => {
      const page = await list(...args);
      return {
        ...page,
        points: page.points.filter((p) => p.scope === selected),
      };
    };
    filter(a, largeWriter);
    filter(b, smallWriter);
    const first = order === "oversized first" ? a : b;
    const second = first === a ? b : a;
    const running = cycles([first], 12);
    try {
      await Promise.race([
        held,
        new Promise((_, reject) =>
          setTimeout(
            () => reject(new Error("envelope barrier not reached")),
            3000,
          ),
        ),
      ]);
      expect(budget.reserved).toBeGreaterThan(0);
      if (first === a) expect(budget.reserved).toBeGreaterThan(budget.maxBytes);
      else expect(budget.reserved).toBeLessThan(budget.maxBytes);
      selected = first === a ? smallWriter : largeWriter;
      await cycles([second], 12);
      expect(
        second.db
          .prepare(
            "SELECT 1 FROM pdpp_transport_manifests_in WHERE reason='resource_busy' UNION ALL SELECT 1 FROM pdpp_transport_fragments_in WHERE reason='resource_busy' UNION ALL SELECT 1 FROM pdpp_transport_import_work WHERE reason='resource_busy'",
          )
          .get(),
      ).toBeDefined();
    } finally {
      release();
      await running;
      spy.mockRestore();
      net.port.list = list;
    }
    await cycles([a, b], 24);
    expect(a.get()).toEqual(source.get());
    expect(b.get("small")).toEqual(small.get("small"));
    expect(budget.reserved).toBe(0);
  },
);

it.each(["framing", "resource"])(
  "A3b-4 preserves the distinct %s Unsupported outcome",
  async (kind) => {
    const net = network();
    const source = device(net, { preexisting: "cannot prepare" });
    net.port.encrypt = async () => {
      if (kind === "framing")
        throw new ReplicaFramingUnsupported(9000, 8192, "manifest_bytes");
      throw new ReplicaResourceLimitError(
        "aggregate_ciphertext_bytes",
        9000,
        8192,
      );
    };
    await cycles([source], 1);
    expect(
      source.db
        .prepare("SELECT prepared,outcome,reason FROM pdpp_transport_batches")
        .get(),
    ).toEqual({
      prepared: kind === "framing" ? -1 : -2,
      outcome: "unsupported",
      reason:
        kind === "framing"
          ? "replica_framing_unsupported"
          : "resource_unsupported",
    });
    expect(net.puts).toHaveLength(0);
    expect(net.registrations).toHaveLength(0);
  },
);

it("A3b-5 uses the exported default fragment size", async () => {
  const net = network(false, 64 * 1024);
  const inputs: number[] = [];
  const fragment = replicaStream.fragmentReplicaStream;
  const spy = vi
    .spyOn(replicaStream, "fragmentReplicaStream")
    .mockImplementation((input) => {
      inputs.push(input.targetChunkBytes!);
      return fragment(input);
    });
  try {
    const source = device(net, {
      preexisting: "default chunk",
      worker: { targetChunkBytes: undefined },
    });
    await cycles([source], 1);
    expect(inputs).toEqual([REPLICA_DEFAULT_FRAGMENT_BYTES]);
  } finally {
    spy.mockRestore();
  }
});

it("A5b-1 one bad op is Unsupported while the other ops commit at the same version and later batches flow", async () => {
  const net = network();
  const source = device(net, {
    worker: { resourceLimits: { maxOperationBytes: 1200 } },
  });
  await cycles([source], 4);
  source.put("good one", "one");
  source.put("x".repeat(2000), "bad");
  source.put("good two", "two");
  await cycles([source], 12);
  const unsupported = source.db
    .prepare(
      "SELECT position,outcome,reason FROM pdpp_transport_operation_outcomes WHERE outcome='unsupported'",
    )
    .all();
  expect(unsupported).toEqual([
    { position: 1, outcome: "unsupported", reason: "resource_unsupported" },
  ]);
  expect(outbox(source).map((row) => [row.version, row.state])).toEqual([
    [1, "published"],
    [2, "published"],
  ]);
  const receiver = device(net);
  await cycles([receiver], 12);
  expect(receiver.get("one")).toEqual(source.get("one"));
  expect(receiver.get("two")).toEqual(source.get("two"));
  expect(receiver.get("bad")).toBeUndefined();
  source.put("later", "later");
  await cycles([source, receiver], 12);
  expect(receiver.get("later")).toEqual(source.get("later"));
  expect(outbox(source).at(-1)?.version).toBe(3);
});

it("A5b-2 all bad ops release the illegal empty batch and the next batch reuses its version and sequence", async () => {
  const net = network();
  const source = device(net, {
    worker: { resourceLimits: { maxOperationBytes: 1200 } },
  });
  await cycles([source], 4);
  source.put("x".repeat(2000), "bad");
  await cycles([source], 1);
  expect(
    source.db
      .prepare("SELECT state FROM pdpp_transport_preparation WHERE version=2")
      .get(),
  ).toEqual({ state: "prep_failed_permanent" });
  await cycles([source], 1);
  expect(
    source.db
      .prepare("SELECT state FROM pdpp_transport_preparation WHERE version=2")
      .get(),
  ).toEqual({ state: "released" });
  await cycles([source], 6);
  expect(
    source.db
      .prepare(
        "SELECT version,state FROM pdpp_transport_preparation WHERE state='released'",
      )
      .all(),
  ).toEqual([{ version: 2, state: "released" }]);
  expect(
    source.db
      .prepare(
        "SELECT outcome,reason FROM pdpp_transport_operation_outcomes WHERE outcome IS NOT NULL",
      )
      .all(),
  ).toEqual([{ outcome: "unsupported", reason: "resource_unsupported" }]);
  expect(outbox(source)).toHaveLength(1);
  source.put("good", "good");
  await cycles([source], 8);
  expect(outbox(source).map((row) => [row.version, row.state])).toEqual([
    [1, "published"],
    [2, "published"],
  ]);
  const receiver = device(net);
  await cycles([receiver], 8);
  expect(receiver.get("good")).toEqual(source.get("good"));
  expect(receiver.get("bad")).toBeUndefined();
});

it("A5b-3 unknown preparation failures retain Retry with P backoff to the cap and a visible typed wait", async () => {
  const net = network();
  net.port.encrypt = async () => {
    throw new RangeError("unknown encryption failure");
  };
  const source = device(net, { preexisting: "unknown" });
  const delays: number[] = [];
  for (let attempt = 1; attempt <= 15; attempt++) {
    const report = await source.step();
    const row = source.db
      .prepare(
        "SELECT prepared,outcome,reason,attempts,next_attempt FROM pdpp_transport_batches",
      )
      .get() as {
      prepared: number;
      outcome: string;
      reason: string;
      attempts: number;
      next_attempt: number;
    };
    expect(row).toMatchObject({
      prepared: 0,
      outcome: "retry",
      reason: "prepare_failed",
      attempts: attempt,
    });
    expect(report.waits).toContainEqual({
      id: expect.any(String),
      phase: "prepare",
      dependency: {
        kind: "preparation",
        key: expect.any(String),
        reason: "unknown",
      },
    });
    expect(
      source.db.prepare("SELECT state FROM pdpp_transport_preparation").get(),
    ).toEqual({ state: "prep_failed_unknown" });
    delays.push(row.next_attempt - time);
    expect(delays.at(-1)).toBe(defaultReplicaBackoff(attempt));
    source.put(`later ${attempt}`, "later");
    expect(outbox(source)).toHaveLength(0);
    expect(
      source.db
        .prepare("SELECT count(*) AS n FROM pdpp_transport_batches")
        .get(),
    ).toEqual({ n: 1 });
    time = row.next_attempt;
  }
  expect(delays.at(-1)).toBe(3_600_000);
  expect(
    delays.slice(0, 13).every((delay, i) => i === 0 || delay > delays[i - 1]!),
  ).toBe(true);
  expect(
    source.db
      .prepare(
        "SELECT 1 FROM pdpp_transport_operation_outcomes WHERE outcome='unsupported'",
      )
      .get(),
  ).toBeUndefined();
  expect(net.puts).toHaveLength(0);
});

it("A5b-4 an unknown preparation failure later commits the same version without Unsupported rows", async () => {
  const net = network();
  const encrypt = net.port.encrypt;
  net.port.encrypt = async () => {
    throw new Error("transient crypto failure");
  };
  const source = device(net, { preexisting: "recover" });
  await source.step();
  const claim = source.db
    .prepare("SELECT batch,version FROM pdpp_transport_preparation")
    .get();
  source.reopen();
  net.port.encrypt = encrypt;
  time += 1000;
  await cycles([source], 4);
  expect(
    source.db
      .prepare("SELECT batch,version FROM pdpp_transport_preparation")
      .get(),
  ).toEqual(claim);
  expect(outbox(source)[0]).toMatchObject({ version: 1, state: "published" });
  expect(
    source.db
      .prepare("SELECT state,wait_json FROM pdpp_transport_preparation")
      .get(),
  ).toEqual({ state: "prepared", wait_json: null });
  expect(
    source.db
      .prepare(
        "SELECT 1 FROM pdpp_transport_operation_outcomes WHERE outcome='unsupported'",
      )
      .get(),
  ).toBeUndefined();
});

it("A5b H4 aggregate ciphertext attributes the breach to the bad op and preserves later good ops", async () => {
  const net = network();
  const source = device(net, {
    worker: { resourceLimits: { maxAggregateCiphertextBytes: 4000 } },
  });
  await cycles([source], 4);
  source.put("good one", "one");
  source.put("x".repeat(5000), "bad");
  source.put("good two", "two");
  await cycles([source], 16);
  expect(
    source.db
      .prepare(
        "SELECT position FROM pdpp_transport_operation_outcomes WHERE outcome='unsupported'",
      )
      .all(),
  ).toEqual([{ position: 1 }]);
  const receiver = device(net);
  await cycles([receiver], 8);
  expect(receiver.get("one")).toEqual(source.get("one"));
  expect(receiver.get("two")).toEqual(source.get("two"));
  expect(receiver.get("bad")).toBeUndefined();
});

it.each(["oversized first", "small first"])(
  "F5 preloaded envelope barrier requires import resource_busy: %s",
  async (order) => {
    const net = network(false, 64 * 1024);
    const largeSource = device(net, { chunk: 700 });
    await cycles([largeSource], 8);
    const template = device(net);
    await cycles([template], 8);
    largeSource.put("x".repeat(12000));
    await cycles([largeSource], 8);
    const smallSource = device(net);
    smallSource.put("small", "small");
    await cycles([smallSource], 8);
    const budget = new ReplicaByteBudget(16 * 1024);
    const quantum = { import: 0 };
    const a = device(net, {
      copyOf: template,
      worker: { resourceBudget: budget, quantum },
    });
    const b = device(net, {
      copyOf: template,
      worker: { resourceBudget: budget, quantum },
    });
    const list = net.port.list;
    let selected = largeSource.scope;
    net.port.list = async (...args) => {
      const page = await list(...args);
      return {
        ...page,
        points: page.points.filter((point) => point.scope === selected),
      };
    };
    await cycles([a], 8);
    selected = smallSource.scope;
    await cycles([b], 8);
    for (const [receiver, scope] of [
      [a, largeSource.scope],
      [b, smallSource.scope],
    ] as const) {
      expect(
        receiver.db
          .prepare(
            "SELECT 1 FROM pdpp_transport_manifests_in WHERE scope=? AND manifest_json IS NOT NULL AND state='ready'",
          )
          .get(scope),
      ).toBeDefined();
      expect(
        receiver.db
          .prepare(
            "SELECT 1 FROM pdpp_transport_fragments_in f JOIN pdpp_transport_manifests_in m ON m.slot=f.slot WHERE m.scope=? AND f.fragment_json IS NULL",
          )
          .get(scope),
      ).toBeUndefined();
    }
    net.port.list = async () => ({ points: [], cursor: null });
    quantum.import = 50;
    a.reopen();
    b.reopen();
    const reads = net.gets.length;
    const inspect = replicaStream.inspectReplicaPayload;
    let release!: () => void;
    let entered!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const barrier = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let held = false;
    const spy = vi
      .spyOn(replicaStream, "inspectReplicaPayload")
      .mockImplementation(async (...args) => {
        const payload = await inspect(...args);
        const large =
          new TextEncoder().encode(canonicalJson(payload.envelope)).length * 2 >
          budget.maxBytes;
        if (!held && large === (order === "oversized first")) {
          held = true;
          entered();
          await gate;
        }
        return payload;
      });
    const first = order === "oversized first" ? a : b;
    const second = first === a ? b : a;
    const secondScope = second === a ? largeSource.scope : smallSource.scope;
    const running = first.step();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        barrier,
        new Promise((_, reject) => {
          timer = setTimeout(
            () =>
              reject(new Error("envelope reservation barrier was not reached")),
            3000,
          );
        }),
      ]);
      expect(budget.reserved).toBeGreaterThan(0);
      if (first === a) expect(budget.reserved).toBeGreaterThan(budget.maxBytes);
      else expect(budget.reserved).toBeLessThan(budget.maxBytes);
      const report = await second.step();
      expect(report.problems).toContainEqual(
        expect.objectContaining({ phase: "import", problem: "resource_busy" }),
      );
      expect(
        second.db
          .prepare(
            "SELECT 1 FROM pdpp_transport_import_work w JOIN pdpp_transport_manifests_in m ON m.writer=w.writer AND m.batch=w.batch WHERE m.scope=? AND w.reason='resource_busy'",
          )
          .get(secondScope),
      ).toBeDefined();
      expect(net.gets).toHaveLength(reads);
    } finally {
      if (timer) clearTimeout(timer);
      release();
      await running;
      spy.mockRestore();
      net.port.list = list;
    }
    await cycles([a, b], 16);
    expect(a.get()).toEqual(largeSource.get());
    expect(b.get("small")).toEqual(smallSource.get("small"));
    expect(budget.reserved).toBe(0);
  },
  20_000,
);
