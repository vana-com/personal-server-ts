/** Dev-only two-process replica acceptance harness. Never loads env/config/key files. */
import assert from "node:assert/strict";
import { fork, execFileSync, type ChildProcess } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  mkdtempSync,
  mkdirSync,
  existsSync,
  rmSync,
  writeFileSync,
  readFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";
import { createPublicClient, http, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  createGatewayClient,
  deriveMasterKey,
  MASTER_KEY_MESSAGE,
  serverRegistrationDomain,
  SERVER_REGISTRATION_TYPES,
} from "@opendatalabs/vana-sdk/node";
import type {
  ReplicaOperation,
  ReplicaEnvelope,
} from "../packages/core/src/replication/envelope.js";
import { createReplicaEvidenceAdapter } from "../packages/core/src/replication/evidence.js";
import { createDpv2ReplicaTransport } from "../packages/core/src/replication/dpv2.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import type { SignTypedDataParams } from "../packages/core/src/keys/server-account.js";
import { createServerSigner } from "../packages/core/src/signing/signer.js";
import { createVanaSyncStorageAdapter } from "../packages/core/src/storage/adapters/vana.js";
import { createGatewayDataPointFeed } from "../packages/core/src/sync/data-point-feed.js";
import { createSqliteRecordStore } from "../packages/server/src/storage/pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "../packages/server/src/storage/pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "../packages/server/src/storage/pdpp-replication-transport.js";
import {
  assertCanonicalRecordsEqual,
  CANONICAL_RECORD_COLUMNS,
  canonicalRecordsEqual,
  projectCanonicalRecords,
  type CanonicalRecord,
} from "./pdpp-replica-record-oracle.js";

// This Linux harness samples /proc and must not persist keys in a crash dump.
if (process.platform !== "linux")
  throw new Error("Live harness requires Linux");
execFileSync("prlimit", ["--pid", String(process.pid), "--core=0:0"]);

const gatewayUrl = "https://dp-rpc-dev.vana.org";
const storageUrl = "https://storage-dev.vana.org";
const rpcUrl = "https://rpc.moksha.vana.org";
const registry = "0x8f1eFCdff3d0d5BB535e32620721c7EBed151867";
const config = ServerConfigSchema.parse({
  gateway: { url: gatewayUrl, chainId: 14800 },
  storage: { backend: "vana", config: { vana: { apiUrl: storageUrl } } },
  tunnel: { enabled: false },
  devUi: { enabled: false },
});
const sourceId = "https://replica-journey.invalid/declaration";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const digest = (bytes: Uint8Array | string) =>
  createHash("sha256").update(bytes).digest("hex");
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const nativeFetch = globalThis.fetch;
const boundedFetch: typeof fetch = (input, init) =>
  nativeFetch(input, {
    ...init,
    signal: AbortSignal.timeout(25_000),
    redirect: "error",
  });
globalThis.fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (![gatewayUrl, storageUrl, rpcUrl].includes(url.origin))
    throw new Error("Harness refused non-dev network origin");
  return boundedFetch(input, init);
};
function serverAccount(key: Hex) {
  const account = privateKeyToAccount(key);
  return {
    address: account.address,
    publicKey: account.publicKey,
    signMessage: (message: string) => account.signMessage({ message }),
    signTypedData: (params: SignTypedDataParams) =>
      account.signTypedData(
        params as Parameters<typeof account.signTypedData>[0],
      ),
  };
}
type Init = {
  root: string;
  owner: Hex;
  master: number[];
  serverKey: Hex;
  scriptSha256: string;
  oracleSha256: string;
};
type HostRequest = {
  id: number;
  command: string;
  args?: Record<string, unknown>;
};
type Snapshot = {
  records: Record<string, unknown>;
  canonicalRecords: CanonicalRecord[];
  blobs: Record<
    string,
    { sha256: string; bytes: number } | { unavailable: true }
  >;
  published: number;
  importedFragments: number;
  stagedFragments: number;
  pid: number;
  evidence: {
    head: { scope: string } | null;
    chain: {
      status: string;
      currentVersion: string;
      blockNumber: string;
      blockHash: string;
      commitment: string;
    } | null;
  }[];
  importedScopes: string[];
  importedBatches: number;
  received: number;
  journal: number;
  history: number;
  pending: number;
  errors: { error: string; n: number }[];
  peakRssKiB: number;
  generation: number;
  writer: string;
  operations: ReplicaOperation[];
  receivedOperations: ReplicaOperation[];
  staged: { scope: string; writer: string; batch: string }[];
  gets: { scope: string; attempts: number }[];
  puts: { scope: string; sha256: string; attempts: number }[];
  inboxErrors: unknown[];
  quarantines: number;
  wire: unknown[];
};

function assertReplicaSnapshotsEqual(expected: Snapshot, actual: Snapshot) {
  assertCanonicalRecordsEqual(
    expected.canonicalRecords,
    actual.canonicalRecords,
  );
  assertBlobBytesAvailable(expected.blobs);
  assertBlobBytesAvailable(actual.blobs);
  assert.deepEqual(expected.blobs, actual.blobs);
}

function assertBlobBytesAvailable(blobs: Snapshot["blobs"]) {
  const unavailable = Object.entries(blobs)
    .filter(([, value]) => "unavailable" in value)
    .map(([blobId]) => blobId);
  assert.deepEqual(
    unavailable,
    [],
    "Referenced blob bytes failed verification",
  );
}

function blobMapsEqual(left: Snapshot["blobs"], right: Snapshot["blobs"]) {
  const stable = (blobs: Snapshot["blobs"]) =>
    Object.fromEntries(
      Object.entries(blobs).sort(([leftId], [rightId]) =>
        leftId < rightId ? -1 : leftId > rightId ? 1 : 0,
      ),
    );
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}

function blobMatches(blobs: Snapshot["blobs"], blobId: string, sha256: string) {
  const blob = blobs[blobId];
  return !!blob && "sha256" in blob && blob.sha256 === sha256;
}

function blobsVerified(blobs: Snapshot["blobs"]) {
  return Object.values(blobs).every((value) => !("unavailable" in value));
}

async function host() {
  const init = await new Promise<Init>((resolve) =>
    process.once("message", (m) => resolve(m as Init)),
  );
  assert.equal(
    digest(readFileSync(fileURLToPath(import.meta.url))),
    init.scriptSha256,
    "Harness changed during run",
  );
  assert.equal(
    digest(
      readFileSync(
        fileURLToPath(
          new URL("./pdpp-replica-record-oracle.ts", import.meta.url),
        ),
      ),
    ),
    init.oracleSha256,
    "Canonical oracle changed during run",
  );
  mkdirSync(init.root, { recursive: true, mode: 0o700 });
  const db = new Database(join(init.root, "records.sqlite"));
  db.pragma("journal_mode = WAL");
  const store = createSqliteRecordStore(db);
  // Trusted host provisioning is explicit and local; replicated metadata never provisions authority.
  if (
    !db
      .prepare("SELECT 1 FROM pdpp_instance_binding WHERE instance='conn'")
      .get()
  )
    store.registerConnection({
      instance: "conn",
      sourceId,
      method: "export",
      label: "Ephemeral harness",
    });
  const expected = { owner: init.owner, declarations: [{ sourceId, binding }] };
  store.replication.beginBaseline(expected);
  const receiver = createReplicaReceiver({
    db,
    store,
    owner: init.owner,
    authenticate: (c) => (c === "isolated-harness" ? init.owner : undefined),
    declarations: () => [
      {
        sourceId,
        binding,
        validateData: (data) => typeof data.id === "string",
      },
    ],
  });
  const account = serverAccount(init.serverKey);
  // The SDK captures global fetch at construction, so install before creating storage.
  let bodyBarrier: { url: string; scope: string } | undefined;
  const hostFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const response = await hostFetch(input, init);
    const url = input instanceof Request ? input.url : String(input);
    if (
      bodyBarrier &&
      url === bodyBarrier.url &&
      (init?.method ?? "GET") === "GET"
    ) {
      assert(response.ok && response.body);
      const first = await response.body.getReader().read();
      assert(!first.done && first.value.length > 0);
      process.send?.({
        checkpoint: "download",
        scope: bodyBarrier.scope,
        bytesStarted: first.value.length,
      });
      await new Promise(() => {});
    }
    return response;
  };
  const storage = createVanaSyncStorageAdapter({
    config,
    serverOwner: init.owner,
    serverAccount: account,
  });
  const transport = createDpv2ReplicaTransport({
    owner: init.owner,
    masterKey: new Uint8Array(init.master),
    storage,
    gateway: createGatewayClient(gatewayUrl),
    signer: createServerSigner(account, config.gateway),
    feed: createGatewayDataPointFeed({ gatewayUrl, fetch: boundedFetch }),
    evidence: createReplicaEvidenceAdapter({
      owner: init.owner,
      gatewayUrl,
      chainId: 14800,
      registry,
      fetch: boundedFetch,
      rpc: createPublicClient({
        transport: http(rpcUrl, { timeout: 25_000, retryCount: 0 }),
      }),
    }),
  });
  db.exec(
    "CREATE TABLE IF NOT EXISTS harness_evidence (scope TEXT PRIMARY KEY, json TEXT NOT NULL)",
  );
  const evidence = transport.evidence;
  transport.evidence = async (scope) => {
    const result = await evidence(scope);
    db.prepare("INSERT OR REPLACE INTO harness_evidence VALUES (?,?)").run(
      scope,
      JSON.stringify(result, (_key, value) =>
        typeof value === "bigint" ? value.toString() : value,
      ),
    );
    return result;
  };
  db.exec(
    "CREATE TABLE IF NOT EXISTS harness_gets (scope TEXT PRIMARY KEY, attempts INTEGER NOT NULL)",
  );
  db.exec(
    "CREATE TABLE IF NOT EXISTS harness_puts (scope TEXT NOT NULL, sha256 TEXT NOT NULL)",
  );
  let killPut = false;
  const putFragment = transport.put;
  transport.put = async (part) => {
    db.prepare("INSERT INTO harness_puts VALUES (?,?)").run(
      part.scope,
      digest(part.encrypted),
    );
    await putFragment(part);
    if (killPut) {
      process.send?.({ checkpoint: "put-complete", scope: part.scope });
      await new Promise(() => {});
    }
  };
  let killImportRecord: string | undefined;
  const importReplica = receiver.import;
  receiver.import = (input) => {
    const result = importReplica(input);
    if (
      killImportRecord &&
      (input.envelope as ReplicaEnvelope).operations.some(
        (op) => op.kind === "upsert" && op.recordKey === killImportRecord,
      )
    )
      process.kill(process.pid, "SIGKILL");
    return result;
  };
  let killScopes = new Set<string>();
  let stopAtDownload = 0,
    downloads = 0;
  const get = transport.get;
  transport.get = async (scope) => {
    db.prepare(
      "INSERT INTO harness_gets VALUES (?,1) ON CONFLICT(scope) DO UPDATE SET attempts=attempts+1",
    ).run(scope);
    if (
      stopAtDownload &&
      killScopes.has(scope) &&
      ++downloads === stopAtDownload
    ) {
      bodyBarrier = { url: storage.urlForKey(`${scope}/1`), scope };
    }
    return get(scope);
  };
  const worker = createReplicaTransportWorker({
    db,
    exporter: store.replication,
    receiver,
    credential: "isolated-harness",
    enabled: true,
    expected: () => expected,
    transport,
    targetChunkBytes: 4 * 1024 * 1024,
  });
  function put(id: string, data: Record<string, unknown>) {
    return store.ingestBatch(
      [
        {
          instance: "conn",
          stream: "messages",
          key: id,
          data: { id, ...data },
          emitted_at: new Date().toISOString(),
        },
      ],
      () => "mutable_state",
      () => ["id"],
      {
        method: "export",
        generation: store.getInstanceBinding("conn").generation,
      },
    );
  }
  function snapshot(): Snapshot {
    const n = (table: string, where = "") =>
      (
        db.prepare(`SELECT COUNT(*) AS n FROM ${table} ${where}`).get() as {
          n: number;
        }
      ).n;
    const canonicalRecords = projectCanonicalRecords(
      db
        .prepare(
          `SELECT ${CANONICAL_RECORD_COLUMNS.join(", ")} FROM pdpp_records ORDER BY instance, stream, record_key`,
        )
        .all() as Record<string, unknown>[],
    );
    const records: Record<string, unknown> = {};
    for (const row of canonicalRecords) {
      if (row.deleted === 0) records[row.record_key] = JSON.parse(row.data!);
    }
    const blobs: Snapshot["blobs"] = {};
    for (const row of canonicalRecords) {
      if (row.deleted === 0 && row.blob_id) {
        const bytes = store.getBlobBytes(row.blob_id);
        if (bytes) {
          blobs[row.blob_id] = {
            sha256: digest(bytes),
            bytes: bytes.length,
          };
        } else {
          blobs[row.blob_id] = { unavailable: true };
        }
      }
    }
    return {
      pid: process.pid,
      importedScopes: (
        db
          .prepare(
            "SELECT scope FROM pdpp_transport_inbox WHERE state='imported'",
          )
          .all() as { scope: string }[]
      ).map((r) => r.scope),
      receivedOperations: (
        db
          .prepare("SELECT operation_json FROM pdpp_replica_received")
          .all() as { operation_json: string }[]
      ).map((r) => JSON.parse(r.operation_json) as ReplicaOperation),
      staged: db
        .prepare(
          "SELECT scope,json_extract(fragment_json,'$.writer') AS writer,json_extract(fragment_json,'$.batch') AS batch FROM pdpp_transport_inbox WHERE fragment_json IS NOT NULL AND state='ready'",
        )
        .all() as Snapshot["staged"],
      gets: db.prepare("SELECT * FROM harness_gets").all() as Snapshot["gets"],
      puts: db
        .prepare(
          "SELECT scope,sha256,COUNT(*) AS attempts FROM harness_puts GROUP BY scope,sha256",
        )
        .all() as Snapshot["puts"],
      inboxErrors: db
        .prepare(
          "SELECT state,error,COUNT(*) AS n FROM pdpp_transport_inbox WHERE error IS NOT NULL OR state='quarantined' GROUP BY state,error",
        )
        .all(),
      quarantines:
        n("pdpp_replica_quarantined_keys") +
        n("pdpp_replica_quarantined_connections"),
      evidence: (
        db
          .prepare("SELECT json FROM harness_evidence ORDER BY scope")
          .all() as { json: string }[]
      ).map((r) => JSON.parse(r.json)),
      records,
      canonicalRecords,
      blobs,
      published: n("pdpp_transport_outbox", "WHERE state='published'"),
      importedFragments: n("pdpp_transport_inbox", "WHERE state='imported'"),
      stagedFragments: n(
        "pdpp_transport_inbox",
        "WHERE fragment_json IS NOT NULL AND state='ready'",
      ),
      importedBatches: n("pdpp_transport_imported"),
      received: n("pdpp_replica_received"),
      journal: n("pdpp_replica_operations"),
      history: n("pdpp_record_changes"),
      pending: n("pdpp_transport_outbox", "WHERE state!='published'"),
      errors: db
        .prepare(
          "SELECT error,COUNT(*) AS n FROM pdpp_transport_outbox WHERE error IS NOT NULL GROUP BY error",
        )
        .all() as Snapshot["errors"],
      peakRssKiB: process.resourceUsage().maxRSS,
      generation: store.getInstanceBinding("conn").generation,
      writer:
        (
          db.prepare("SELECT writer FROM pdpp_transport_state").get() as
            { writer: string } | undefined
        )?.writer ?? "",
      operations: (
        db
          .prepare("SELECT operation_json FROM pdpp_replica_operations")
          .all() as { operation_json: string }[]
      ).map((r) => JSON.parse(r.operation_json) as ReplicaOperation),
      wire: db
        .prepare(
          "SELECT scope,batch,state,length(encrypted) AS bytes FROM pdpp_transport_outbox ORDER BY rowid",
        )
        .all(),
    };
  }
  process.on("message", async (raw) => {
    const { id, command, args = {} } = raw as HostRequest;
    try {
      let result: unknown;
      if (command === "cycle") {
        await worker.cycle();
        result = snapshot();
      } else if (command === "snapshot") result = snapshot();
      else if (command === "put")
        result = put(String(args.id), { text: args.text });
      else if (command === "blob") {
        const bytes = Buffer.alloc(Number(args.size));
        for (let offset = 0; offset < bytes.length; offset += 65536)
          bytes.set(
            randomBytes(Math.min(65536, bytes.length - offset)),
            offset,
          );
        const sha256 = digest(bytes);
        const blob = store.storeBlobBytesForInstance({
          instance: "conn",
          method: "export",
          generation: store.getInstanceBinding("conn").generation,
          bytes,
          mimeType: "application/octet-stream",
        });
        put(String(args.id), {
          blob_ref: {
            blob_id: blob.blobId,
            mime_type: blob.mimeType,
            size_bytes: bytes.length,
          },
        });
        result = { blobId: blob.blobId, sha256, bytes: bytes.length };
      } else if (command === "armKill") {
        stopAtDownload = Number(args.after);
        killScopes = new Set(args.scopes as string[]);
        downloads = 0;
        result = true;
      } else if (command === "armPutKill") {
        killPut = true;
        result = true;
      } else if (command === "armImportKill") {
        killImportRecord = String(args.id);
        result = true;
      } else if (command === "delete")
        result = store.deleteRecord(
          "conn",
          "messages",
          String(args.id),
          new Date().toISOString(),
          "mutable_state",
        );
      else if (command === "reset")
        result = store.resetInstanceBinding({
          instance: "conn",
          expectedMethod: "export",
          expectedGeneration: store.getInstanceBinding("conn").generation,
          nextMethod: "export",
        });
      else throw new Error("Unknown harness command");
      process.send?.({ id, result });
    } catch (error) {
      process.send?.({
        id,
        error: error instanceof Error ? error.message : "Host failed",
      });
    }
  });
  process.send?.({ ready: true });
}

class Device {
  child!: ChildProcess;
  private sequence = 0;
  private pending = new Map<
    number,
    {
      resolve: (v: unknown) => void;
      reject: (e: Error) => void;
      timer: NodeJS.Timeout;
    }
  >();
  checkpoint?: () => void;
  private sample?: NodeJS.Timeout;
  private failure = "";
  peakRssKiB = 0;
  constructor(readonly init: Init) {}
  async start() {
    this.failure = "";
    this.child = fork(fileURLToPath(import.meta.url), ["--host"], {
      execArgv: ["--max-old-space-size=2048", "--import", "tsx"],
      stdio: ["ignore", "ignore", "pipe", "ipc"],
      env: {
        PATH: process.env.PATH,
        HOME: this.init.root,
        TMPDIR: this.init.root,
      },
    });
    // Do not forward SDK diagnostics: failures are returned over IPC without secrets.
    this.child.stderr?.on("data", (bytes: Buffer) => {
      if (/heap out of memory/i.test(bytes.toString()))
        this.failure = "Node heap exhausted";
    });
    this.sample = setInterval(() => {
      try {
        const status = readFileSync(`/proc/${this.child.pid}/status`, "utf8");
        const peak = Number(/VmHWM:\s+(\d+)/.exec(status)?.[1] ?? 0);
        this.peakRssKiB = Math.max(this.peakRssKiB, peak);
        if (peak > 3 * 1024 * 1024) {
          this.failure = "3 GiB host RSS budget exceeded";
          this.child.kill("SIGKILL");
        }
      } catch {
        /* Process may exit between samples. */
      }
    }, 100);
    this.child.on("exit", (code, signal) => {
      clearInterval(this.sample);
      for (const p of this.pending.values()) {
        clearTimeout(p.timer);
        p.reject(new Error(this.failure || `Host exited (${signal ?? code})`));
      }
      this.pending.clear();
    });
    const ready = new Promise<void>((resolve, reject) => {
      this.child.once("error", reject);
      this.child.once("exit", () =>
        reject(new Error("Host exited before ready")),
      );
      this.child.on("message", (raw) => {
        const m = raw as {
          ready?: boolean;
          checkpoint?: string;
          id: number;
          result?: unknown;
          error?: string;
        };
        if (m.ready) resolve();
        else if (m.checkpoint) this.checkpoint?.();
        else {
          const p = this.pending.get(m.id);
          if (!p) return;
          this.pending.delete(m.id);
          clearTimeout(p.timer);
          if (m.error) p.reject(new Error(m.error));
          else p.resolve(m.result);
        }
      });
    });
    this.child.send(this.init);
    await ready;
  }
  async call<T = Snapshot>(
    command: string,
    args: Record<string, unknown> = {},
  ): Promise<T> {
    if (!this.child.connected) throw new Error("Host IPC disconnected");
    const id = ++this.sequence;
    const value = await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Host command timed out: ${command}`));
      }, 15 * 60_000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.send({ id, command, args });
    });
    if (value && typeof value === "object" && "peakRssKiB" in value)
      this.peakRssKiB = Math.max(this.peakRssKiB, Number(value.peakRssKiB));
    return value as T;
  }
  async kill() {
    if (
      !this.child ||
      this.child.exitCode !== null ||
      this.child.signalCode !== null
    )
      return;
    const exited = new Promise<void>((resolve) =>
      this.child.once("exit", () => resolve()),
    );
    this.child.kill("SIGKILL");
    await exited;
  }
}

async function main() {
  const parent = join(homedir(), ".tmp");
  mkdirSync(parent, { recursive: true });
  const root = mkdtempSync(join(parent, "replica-live-"));
  const reportPath =
    process.argv[2] ?? join(parent, `replica-live-${Date.now()}.json`);
  const harnessFile = fileURLToPath(import.meta.url);
  const oracleFile = fileURLToPath(
    new URL("./pdpp-replica-record-oracle.ts", import.meta.url),
  );
  const scriptSha256 = digest(readFileSync(harnessFile));
  const oracleSha256 = digest(readFileSync(oracleFile));
  const ownerAccount = privateKeyToAccount(generatePrivateKey());
  const owner = ownerAccount.address;
  const master = [
    ...deriveMasterKey(
      await ownerAccount.signMessage({ message: MASTER_KEY_MESSAGE }),
    ),
  ];
  const devices = ["A", "B"].map(
    (name) =>
      new Device({
        root: join(root, name),
        owner,
        master,
        serverKey: generatePrivateKey(),
        scriptSha256,
        oracleSha256,
      }),
  );
  const [a, b] = devices;
  const report: Record<string, unknown> = {
    run: randomUUID(),
    owner,
    gatewayUrl,
    storageUrl,
    rpcUrl,
    chainId: 14800,
    base: "723c4854ee5ee83d8e83baa20cc2b0d30b99fea3",
    head: execFileSync("git", ["rev-parse", "HEAD"], {
      encoding: "utf8",
    }).trim(),
    harnessSha256: scriptSha256,
    oracleSha256,
    node: process.version,
    dirtyTree: execFileSync(
      "git",
      [
        "status",
        "--porcelain",
        "--",
        "packages",
        "scripts/pdpp-replica-live-journey.ts",
        "scripts/pdpp-replica-record-oracle.ts",
      ],
      { encoding: "utf8" },
    ).trim(),
    retryableCycleErrors: {} as Record<string, number>,
    hostHeapMiB: 2048,
    hostRssBudgetKiB: 3 * 1024 * 1024,
    chunkBytes: 4 * 1024 * 1024,
    cases: [],
    startedAt: new Date().toISOString(),
  };
  const cases = report.cases as unknown[];
  const save = () =>
    writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n", {
      mode: 0o600,
    });
  async function settle(
    label: string,
    predicate: (x: Snapshot, y: Snapshot) => boolean,
    ds = devices,
  ) {
    const start = Date.now();
    let x!: Snapshot, y!: Snapshot;
    const leftDevice = ds[0] ?? a;
    const rightDevice = ds[1] ?? leftDevice;
    while (Date.now() - start < 12 * 60_000) {
      for (const d of ds) {
        try {
          await d.call("cycle");
        } catch (error) {
          if (!d.child.connected) throw error;
          (report.retryableCycleErrors as Record<string, number>)[label] =
            ((report.retryableCycleErrors as Record<string, number>)[label] ??
              0) + 1;
          console.log(
            JSON.stringify({
              stage: label,
              retryableCycleError:
                error instanceof Error ? error.message : "cycle failed",
            }),
          );
        }
      }
      x = await leftDevice.call("snapshot");
      y = rightDevice === leftDevice ? x : await rightDevice.call("snapshot");
      console.log(
        JSON.stringify({
          stage: label,
          elapsedMs: Date.now() - start,
          A: {
            published: x.published,
            pending: x.pending,
            imported: x.importedFragments,
            errors: x.errors,
          },
          B: {
            published: y.published,
            pending: y.pending,
            imported: y.importedFragments,
            errors: y.errors,
          },
        }),
      );
      const replicasMatch =
        rightDevice === leftDevice ||
        (canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
          blobMapsEqual(x.blobs, y.blobs) &&
          blobsVerified(x.blobs) &&
          blobsVerified(y.blobs));
      if (predicate(x, y) && replicasMatch)
        return { elapsedMs: Date.now() - start, A: x, B: y };
      await pause(5000);
    }
    report.lastA = x;
    report.lastB = y;
    if (rightDevice !== leftDevice) {
      try {
        assertReplicaSnapshotsEqual(x, y);
      } catch (error) {
        throw new Error(
          `Timed out: ${label}; ${error instanceof Error ? error.message : "replica state differs"}`,
        );
      }
    }
    throw new Error(`Timed out: ${label}`);
  }
  try {
    // Fresh public-read preflight, before any registration or upload.
    const rpc = createPublicClient({
      transport: http(rpcUrl, { timeout: 25_000, retryCount: 0 }),
    });
    assert.equal(await rpc.getChainId(), 14800);
    for (const url of [gatewayUrl, storageUrl]) {
      const r = await boundedFetch(`${url}/health`);
      await r.body?.cancel();
      assert(r.ok);
    }
    for (let i = 0; i < devices.length; i++) {
      const account = serverAccount(devices[i].init.serverKey);
      const message = {
        ownerAddress: owner,
        serverAddress: account.address,
        publicKey: account.publicKey,
        serverUrl: `https://replica-${i}-${report.run}.invalid`,
      };
      const signature = await ownerAccount.signTypedData({
        domain: serverRegistrationDomain(config.gateway),
        types: SERVER_REGISTRATION_TYPES,
        primaryType: "ServerRegistration",
        message,
      });
      const r = await boundedFetch(`${gatewayUrl}/v1/servers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Web3Signed ${signature}`,
        },
        body: JSON.stringify(message),
      });
      const body = await r.text();
      if (!r.ok)
        throw new Error(
          `Dev server ${i} registration failed: HTTP ${r.status}: ${body.slice(0, 800)}`,
        );
      console.log(
        JSON.stringify({
          stage: "registered",
          device: i,
          server: account.address,
          status: r.status,
        }),
      );
    }
    await a.start();
    await b.start();
    if (process.argv.includes("--put-retry-only")) {
      await a.call("put", {
        id: "retry",
        text: "exact durable ciphertext retry",
      });
      await a.call("armPutKill");
      const checkpoint = new Promise<void>((resolve) => {
        a.checkpoint = resolve;
      });
      const interrupted = a.call("cycle").catch((error: unknown) => error);
      await Promise.race([
        checkpoint,
        interrupted.then(() => {
          throw new Error("No PUT checkpoint");
        }),
      ]);
      const before = await a.call("snapshot");
      assert.equal(before.puts.length, 1);
      assert.equal(before.puts[0].attempts, 1);
      await a.kill();
      await interrupted;
      a.checkpoint = undefined;
      await a.start();
      const retained = await a.call("snapshot");
      assert.notEqual(retained.pid, before.pid);
      assert.equal(retained.writer, before.writer);
      assert.deepEqual(retained.wire, before.wire);
      assertReplicaSnapshotsEqual(before, retained);
      const resumed = await settle(
        "exact PUT retry",
        (x, y) =>
          !!y.records.retry &&
          canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
          x.pending === 0,
      );
      const retried = resumed.A.puts.filter(
        (row) => row.scope === before.puts[0].scope,
      );
      assert.equal(retried.length, 1);
      assert.equal(retried[0].sha256, before.puts[0].sha256);
      assert.equal(retried[0].attempts, 2);
      assert.deepEqual(resumed.A.records, resumed.B.records);
      assertReplicaSnapshotsEqual(resumed.A, resumed.B);
      cases.push({
        case: "exact-byte-put-retry",
        status: "passed",
        killedPid: before.pid,
        restartedPid: retained.pid,
        retried,
        ...resumed,
      });
      report.status = "passed";
      return;
    }
    await a.call("put", { id: "a", text: "A to B" });
    const blob = await a.call<{
      blobId: string;
      sha256: string;
      bytes: number;
    }>("blob", { id: "small", size: 32768 });
    const localA = await a.call("snapshot");
    const forward = await settle(
      "A to B",
      (x, y) =>
        !!y.records.a &&
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        blobMatches(y.blobs, blob.blobId, blob.sha256) &&
        x.pending === 0,
    );
    assert.equal(forward.A.journal, localA.journal);
    assert.deepEqual(forward.A.records, forward.B.records);
    assertReplicaSnapshotsEqual(forward.A, forward.B);
    assert.deepEqual(forward.A.blobs, forward.B.blobs);
    cases.push({ case: 1, status: "passed", ...forward, blob });
    save();
    await b.call("put", { id: "b", text: "B to A" });
    const reverseBlob = await b.call<typeof blob>("blob", {
      id: "reverse",
      size: 65536,
    });
    const localB = await b.call("snapshot");
    const reverse = await settle(
      "B to A",
      (x, y) =>
        !!x.records.b &&
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        blobMatches(x.blobs, reverseBlob.blobId, reverseBlob.sha256) &&
        y.pending === 0,
    );
    assert.equal(reverse.A.journal, localA.journal);
    assert.equal(reverse.B.journal, localB.journal);
    assert.deepEqual(reverse.A.records, reverse.B.records);
    assertReplicaSnapshotsEqual(reverse.A, reverse.B);
    assert.deepEqual(reverse.A.blobs, reverse.B.blobs);
    cases.push({ case: 2, status: "passed", ...reverse, blob: reverseBlob });
    save();
    // Publisher progresses while receiver is offline; >100 MiB of incompressible source bytes.
    const started = Date.now();
    const large = await a.call<typeof blob>("blob", {
      id: "large",
      size: 101 * 1024 * 1024,
    });
    const publishedLarge = await settle(
      "publish large",
      (x) => x.pending === 0 && x.wire.length > reverse.A.wire.length + 1,
      [a],
    );
    const largeFragments = publishedLarge.A.wire.slice(
      reverse.A.wire.length,
    ) as { scope: string; batch: string; bytes: number }[];
    const largeOperations = publishedLarge.A.operations.filter(
      (op) =>
        (op.kind === "blob-claim" && op.blob.blobId === large.blobId) ||
        (op.kind === "upsert" && op.recordKey === "large"),
    );
    assert.equal(
      largeOperations.filter((op) => op.kind === "upsert").length,
      1,
    );
    await b.call("armKill", {
      after: 3,
      scopes: largeFragments.map((r) => r.scope),
    });
    const checkpoint = new Promise<void>((resolve) => {
      b.checkpoint = resolve;
    });
    const interrupted = b.call("cycle").then(
      () => {
        throw new Error("No interruption checkpoint");
      },
      (error: unknown) => error,
    );
    await Promise.race([
      checkpoint,
      interrupted.then(() => {
        throw new Error("Host failed before kill checkpoint");
      }),
    ]);
    const partial = await b.call("snapshot");
    assert(partial.stagedFragments >= 2);
    assert(
      partial.staged.every(
        (row) =>
          row.writer === publishedLarge.A.writer &&
          row.batch === largeFragments[0].batch,
      ),
    );
    assert.equal(partial.records.large, undefined);
    assertReplicaSnapshotsEqual(reverse.B, partial);
    await b.kill();
    await interrupted;
    b.checkpoint = undefined;
    await b.start();
    const retained = await b.call("snapshot");
    assert.notEqual(retained.pid, partial.pid);
    assert.equal(retained.stagedFragments, partial.stagedFragments);
    assert.equal(retained.received, partial.received);
    assert.equal(retained.history, partial.history);
    assertReplicaSnapshotsEqual(partial, retained);
    await b.call("armImportKill", { id: "large" });
    const transactionPid = b.child.pid;
    const importKillDeadline = Date.now() + 12 * 60_000;
    while (b.child.connected && Date.now() < importKillDeadline) {
      try {
        await b.call("cycle");
      } catch {
        if (!b.child.connected) break;
      }
      if (b.child.connected) await pause(5000);
    }
    assert(!b.child.connected, "Import SIGKILL deadline exceeded");
    assert.equal(b.child.signalCode, "SIGKILL");
    await b.start();
    const rolledBack = await b.call("snapshot");
    assert.notEqual(rolledBack.pid, transactionPid);
    assert.equal(rolledBack.records.large, undefined);
    assert.equal(rolledBack.received, partial.received);
    assert.equal(rolledBack.history, partial.history);
    assert.equal(rolledBack.importedBatches, partial.importedBatches);
    assertReplicaSnapshotsEqual(partial, rolledBack);
    const resumed = await settle(
      "restart large",
      (x, y) =>
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        blobMatches(y.blobs, large.blobId, large.sha256) &&
        x.pending === 0,
    );
    assertReplicaSnapshotsEqual(resumed.A, resumed.B);
    assert.deepEqual(resumed.A.records, resumed.B.records);
    assert.deepEqual(resumed.A.blobs, resumed.B.blobs);
    const largeWire = resumed.A.wire.slice(reverse.A.wire.length) as {
      bytes: number;
    }[];
    assert(largeWire.length > 1);
    assert(largeWire.every((row) => row.bytes <= 100 * 1024 * 1024));
    const rssBudgetKiB = 3 * 1024 * 1024;
    assert(
      a.peakRssKiB <= rssBudgetKiB && b.peakRssKiB <= rssBudgetKiB,
      "3 GiB per-device RSS budget exceeded",
    );
    assert.equal(resumed.B.history - partial.history, 1);
    assert.equal(resumed.B.received - partial.received, largeOperations.length);
    for (const row of partial.staged)
      assert.equal(
        resumed.B.gets.find((r) => r.scope === row.scope)?.attempts,
        partial.gets.find((r) => r.scope === row.scope)?.attempts,
      );
    const before = resumed.B;
    await b.call("cycle");
    const after = await b.call("snapshot");
    assertReplicaSnapshotsEqual(before, after);
    assert.equal(after.received, before.received);
    assert.equal(after.history, before.history);
    assert.equal(after.importedBatches, before.importedBatches);
    cases.push({
      case: 3,
      status: "passed",
      signal: "SIGKILL",
      killedPid: partial.pid,
      restartedPid: retained.pid,
      transactionKilledPid: transactionPid,
      transactionRestartedPid: rolledBack.pid,
      transactionHistoryBefore: partial.history,
      transactionHistoryAfterRollback: rolledBack.history,
      historyAfterImport: resumed.B.history,
      expectedNewHistoryRows: 1,
      expectedNewOperations: largeOperations.length,
      checkpoint: "third download (two fragments durable)",
      stagedBeforeKill: partial.stagedFragments,
      stagedAfterRestart: retained.stagedFragments,
      receivedBeforeKill: partial.received,
      receivedAfterRestart: retained.received,
      receivedBeforeReplay: before.received,
      receivedAfterReplay: after.received,
      historyBeforeReplay: before.history,
      historyAfterReplay: after.history,
    });
    cases.push({
      case: 4,
      status: "passed",
      ...resumed,
      elapsedMs: Date.now() - started,
      blob: large,
      fragmentCount: largeWire.length,
      maxEncryptedFragmentBytes: Math.max(...largeWire.map((r) => r.bytes)),
      rssBudgetKiB,
    });
    save();
    // No cycle during edits: both stores are offline, with persisted Lamport/writer/op ordering.
    await a.call("put", { id: "conflict", text: "offline A" });
    await b.call("put", { id: "conflict", text: "offline B" });
    const offlineA = await a.call("snapshot"),
      offlineB = await b.call("snapshot");
    const contenders = [...offlineA.operations, ...offlineB.operations].filter(
      (op) => op.kind === "upsert" && op.recordKey === "conflict",
    );
    assert.equal(contenders.length, 2);
    assert.equal(
      contenders[0].revision.counter,
      contenders[1].revision.counter,
      "Writer tie-break must be exercised",
    );
    contenders.sort((left, right) => {
      for (const key of ["counter", "writerId", "operationId"] as const) {
        if (left.revision[key] < right.revision[key]) return -1;
        if (left.revision[key] > right.revision[key]) return 1;
      }
      return 0;
    });
    const winner = contenders.at(-1)!;
    assert(winner.kind === "upsert");
    const receivedBoth = (x: Snapshot, y: Snapshot) =>
      contenders.every(
        (op) =>
          [...x.operations, ...x.receivedOperations].some(
            (r) =>
              r.revision.writerId === op.revision.writerId &&
              r.revision.operationId === op.revision.operationId,
          ) &&
          [...y.operations, ...y.receivedOperations].some(
            (r) =>
              r.revision.writerId === op.revision.writerId &&
              r.revision.operationId === op.revision.operationId,
          ),
      );
    const conflict = await settle(
      "concurrent edits",
      (x, y) =>
        receivedBoth(x, y) &&
        !!x.records.conflict &&
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        JSON.stringify(x.records.conflict) ===
          JSON.stringify(y.records.conflict) &&
        x.pending === 0 &&
        y.pending === 0,
    );
    assert.equal(conflict.A.journal, offlineA.journal);
    assert.equal(conflict.B.journal, offlineB.journal);
    assert.deepEqual(conflict.A.records.conflict, winner.data);
    assert.deepEqual(conflict.B.records.conflict, winner.data);
    assertReplicaSnapshotsEqual(conflict.A, conflict.B);
    await a.call("delete", { id: "conflict" });
    const deletion = await settle(
      "delete",
      (x, y) =>
        !x.records.conflict &&
        !y.records.conflict &&
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        x.pending === 0,
    );
    assertReplicaSnapshotsEqual(deletion.A, deletion.B);
    for (const rows of [
      deletion.A.canonicalRecords,
      deletion.B.canonicalRecords,
    ]) {
      assert.equal(
        rows.find(
          (row) =>
            row.instance === "conn" &&
            row.stream === "messages" &&
            row.record_key === "conflict",
        )?.deleted,
        1,
        "Deletion checkpoint must retain the canonical tombstone",
      );
    }
    await b.call("reset");
    const reset = await settle(
      "reset",
      (x, y) =>
        x.generation === 2 &&
        y.generation === 2 &&
        Object.keys(x.records).length === 0 &&
        Object.keys(y.records).length === 0 &&
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        y.pending === 0,
    );
    await a.call("cycle");
    await b.call("cycle");
    const resetA = await a.call<Snapshot>("snapshot");
    const resetB = await b.call<Snapshot>("snapshot");
    assert.deepEqual(resetA.records, {});
    assert.deepEqual(resetB.records, {});
    assertReplicaSnapshotsEqual(resetA, resetB);
    assert.deepEqual(resetA.canonicalRecords, []);
    assert.deepEqual(resetB.canonicalRecords, []);
    await a.call("put", { id: "generation2", text: "after reset" });
    const generation2 = await settle(
      "generation 2",
      (x, y) =>
        x.generation === 2 &&
        y.generation === 2 &&
        !!y.records.generation2 &&
        canonicalRecordsEqual(x.canonicalRecords, y.canonicalRecords) &&
        x.pending === 0,
    );
    assert.deepEqual(generation2.A.records, generation2.B.records);
    assertReplicaSnapshotsEqual(generation2.A, generation2.B);
    assert.deepEqual(Object.keys(generation2.A.records), ["generation2"]);
    cases.push({
      case: 5,
      status: "passed",
      resetClaim:
        "Live canonical view and generation converge; retained transport/history bytes are not erased",
      counterTie: true,
      revisions: contenders.map((op) => op.revision),
      winner: winner.revision,
      conflict,
      deletion,
      reset,
      generation2,
    });
    for (const d of devices) {
      const final = await d.call("snapshot");
      const scopes = [
        ...final.importedScopes,
        ...(final.wire as { scope: string; state: string }[])
          .filter((r) => r.state === "published")
          .map((r) => r.scope),
      ];
      for (const scope of scopes) {
        const evidence = final.evidence.find(
          (row) => row.head?.scope === scope,
        );
        assert(evidence?.chain);
        assert.equal(evidence.chain.status, "Active");
        assert.equal(evidence.chain.currentVersion, "1");
        assert(/^\d+$/.test(evidence.chain.blockNumber));
        assert(/^0x[0-9a-fA-F]{64}$/.test(evidence.chain.blockHash));
      }
      assert.equal(final.quarantines, 0);
      assert.deepEqual(final.inboxErrors, []);
    }
    report.status = "passed";
  } catch (error) {
    report.status = "failed";
    report.error = error instanceof Error ? error.message : "Journey failed";
    console.error(
      JSON.stringify({
        status: report.status,
        error: report.error,
        reportPath,
      }),
    );
    process.exitCode = 1;
  } finally {
    report.finishedAt = new Date().toISOString();
    report.peakRssKiB = {
      parent: process.resourceUsage().maxRSS,
      A: a.peakRssKiB,
      B: b.peakRssKiB,
    };
    for (const device of devices) await device.kill();
    let attempted = 0;
    let deleted = 0;
    let notFound = 0;
    const cleanupFailures: { device: string; scope: string; reason: string }[] =
      [];
    for (const device of devices) {
      const dbPath = join(device.init.root, "records.sqlite");
      if (!existsSync(dbPath)) continue;
      let db: Database.Database | undefined;
      const name = device === a ? "A" : "B";
      try {
        db = new Database(dbPath, { readonly: true, fileMustExist: true });
        const hasPutTable = db
          .prepare(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='harness_puts'",
          )
          .get();
        if (!hasPutTable) continue;
        const scopes = db
          .prepare("SELECT DISTINCT scope FROM harness_puts")
          .all() as { scope: string }[];
        let storage: ReturnType<typeof createVanaSyncStorageAdapter>;
        try {
          storage = createVanaSyncStorageAdapter({
            config,
            serverOwner: owner,
            serverAccount: serverAccount(device.init.serverKey),
          });
        } catch {
          cleanupFailures.push({ device: name, scope: "", reason: "adapter" });
          continue;
        }
        for (const { scope } of scopes) {
          attempted++;
          const url = storage.urlForKey(`${scope}/1`);
          let cleaned = false;
          for (let attempt = 0; attempt < 3 && !cleaned; attempt++) {
            try {
              if (await storage.delete(url)) {
                deleted++;
                cleaned = true;
                continue;
              }
            } catch {
              // Verify absence after a failed or transient delete.
            }
            try {
              if (!(await storage.exists(url))) {
                notFound++;
                cleaned = true;
                continue;
              }
            } catch {
              // Retry the delete and existence check within the same bound.
            }
            if (attempt < 2) await pause(250 * 2 ** attempt);
          }
          if (!cleaned)
            cleanupFailures.push({ device: name, scope, reason: "delete" });
        }
      } catch {
        cleanupFailures.push({ device: name, scope: "", reason: "scope-read" });
      } finally {
        db?.close();
      }
    }
    report.remoteBlobCleanup = {
      attempted,
      deleted,
      notFound,
      errors: cleanupFailures.length,
      failures: cleanupFailures,
    };
    if (cleanupFailures.length > 0) {
      report.status = "failed";
      report.cleanupErrorCount = cleanupFailures.length;
      report.cleanupError = "Remote test blob cleanup was not fully confirmed";
      if (!report.error) report.error = report.cleanupError;
      report.cleanupRetainedRoot = root;
      process.exitCode = 1;
    }
    save();
    if (cleanupFailures.length === 0)
      rmSync(root, { recursive: true, force: true });
    console.log(
      JSON.stringify({
        status: report.status,
        reportPath,
        peakRssKiB: report.peakRssKiB,
      }),
    );
  }
}
if (process.argv.includes("--host")) await host();
else await main();
