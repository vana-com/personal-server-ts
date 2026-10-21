/** Dev-only Lite/Node journey. Random owner; never loads env, accounts or key files. */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
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
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import { createServerSigner } from "../packages/core/src/signing/signer.js";
import { createVanaSyncStorageAdapter } from "../packages/core/src/storage/adapters/vana.js";
import { createGatewayDataPointFeed } from "../packages/core/src/sync/data-point-feed.js";
import { createReplicaEvidenceAdapter } from "../packages/core/src/replication/evidence.js";
import { createDpv2ReplicaTransport } from "../packages/core/src/replication/dpv2.js";
import type { SignTypedDataParams } from "../packages/core/src/keys/server-account.js";
import { createSqliteRecordStore } from "../packages/server/src/storage/pdpp-records-sqlite-store.js";
import { createReplicaReceiver } from "../packages/server/src/storage/pdpp-replication-receiver.js";
import { createReplicaTransportWorker } from "../packages/server/src/storage/pdpp-replication-transport.js";
import { createLiteCanonicalStore } from "../packages/lite/src/canonical-store.js";
import { createLiteReplicaWorker } from "../packages/lite/src/replication.js";
import { createLiteReplicaHostTransport } from "../packages/lite/src/replication-host.js";
import {
  createFakeCanonicalPersistence,
  fakeCanonicalDisk,
} from "../packages/lite/src/test-support/canonical-persistence.js";

const gatewayUrl = "https://dp-rpc-dev.vana.org";
const storageUrl = "https://storage-dev.vana.org";
const rpcUrl = "https://rpc.moksha.vana.org";
const registry = "0x8f1eFCdff3d0d5BB535e32620721c7EBed151867";
const realFetch = globalThis.fetch;
globalThis.fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  if (![gatewayUrl, storageUrl, rpcUrl].includes(url.origin))
    throw new Error("non-dev request refused");
  return realFetch(input, {
    ...init,
    redirect: "error",
    signal: AbortSignal.timeout(25000),
  });
};
const config = ServerConfigSchema.parse({
  gateway: { url: gatewayUrl, chainId: 14800 },
  storage: { backend: "vana", config: { vana: { apiUrl: storageUrl } } },
  tunnel: { enabled: false },
  devUi: { enabled: false },
});
const ownerAccount = privateKeyToAccount(generatePrivateKey());
const owner = ownerAccount.address.toLowerCase() as Hex;
const masterKey = deriveMasterKey(
  await ownerAccount.signMessage({ message: MASTER_KEY_MESSAGE }),
);
const rpc = createPublicClient({
  transport: http(rpcUrl, { timeout: 25000, retryCount: 0 }),
});
const sourceId = "https://replica-lite-live.invalid/declaration";
const binding = {
  digest: `sha256:${"a".repeat(64)}`,
  version: "1",
  stream: "messages",
  semantics: "mutable_state" as const,
  primaryKey: ["id"],
  schemaDigest: `sha256:${"b".repeat(64)}`,
};
const expected = { owner, declarations: [{ sourceId, binding }] };
const context = () => ({
  owner,
  declarations: [
    {
      sourceId,
      binding,
      validateData: (data: Record<string, unknown>) =>
        typeof data.id === "string",
    },
  ],
});
const root = mkdtempSync(join(homedir(), ".tmp/replica-lite-live-"));
const reportPath =
  process.argv[2] ?? join(homedir(), ".tmp/replica-lite-live-result.json");
const report: Record<string, unknown> = {
  owner,
  gatewayUrl,
  storageUrl,
  rpcUrl,
  chainId: 14800,
  startedAt: new Date().toISOString(),
  native:
    "Node fake with native transaction/frame semantics; not a phone process",
};
let db: Database.Database | undefined;
async function transport(index: number) {
  const account = privateKeyToAccount(generatePrivateKey());
  const message = {
    ownerAddress: owner,
    serverAddress: account.address,
    publicKey: account.publicKey,
    serverUrl: `https://replica-lite-${index}-${crypto.randomUUID()}.invalid`,
  };
  const signature = await ownerAccount.signTypedData({
    domain: serverRegistrationDomain(config.gateway),
    types: SERVER_REGISTRATION_TYPES,
    primaryType: "ServerRegistration",
    message,
  });
  const registered = await fetch(`${gatewayUrl}/v1/servers`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Web3Signed ${signature}`,
    },
    body: JSON.stringify(message),
  });
  await registered.body?.cancel();
  if (!registered.ok)
    throw new Error(`dev server registration HTTP ${registered.status}`);
  const serverAccount = {
    address: account.address,
    publicKey: account.publicKey,
    signMessage: (message: string) => account.signMessage({ message }),
    signTypedData: (params: SignTypedDataParams) =>
      account.signTypedData(
        params as Parameters<typeof account.signTypedData>[0],
      ),
  };
  return {
    owner,
    masterKey,
    storage: createVanaSyncStorageAdapter({
      config,
      serverOwner: owner,
      serverAccount,
    }),
    gateway: createGatewayClient(gatewayUrl),
    feed: createGatewayDataPointFeed({ gatewayUrl }),
    signer: createServerSigner(serverAccount, {
      chainId: 14800,
      contracts: config.gateway.contracts,
    }),
    registry: registry as Hex,
    chainId: 14800,
    rpc,
    fetch: globalThis.fetch,
    gatewayUrl,
  };
}
try {
  assert.equal(await rpc.getChainId(), 14800);
  const phoneTransport = createLiteReplicaHostTransport(await transport(0));
  const nodePorts = await transport(1);
  const nodeTransport = createDpv2ReplicaTransport({
    ...nodePorts,
    evidence: createReplicaEvidenceAdapter(nodePorts),
  });
  const disk = fakeCanonicalDisk();
  const credential = Symbol("replica host");
  function phone() {
    const native = createFakeCanonicalPersistence(disk);
    const store = createLiteCanonicalStore({
      enabled: true,
      transportEnabled: true,
      persistence: native.port,
      context,
      authenticateReplica: (c) => (c === credential ? owner : undefined),
    });
    const worker = createLiteReplicaWorker({
      enabled: true,
      persistence: native.port,
      store,
      transport: phoneTransport,
      expected: () => expected,
      credential,
    });
    return { store, worker };
  }
  let lite = phone();
  await lite.store.provisionConnection("conn", {
    sourceId,
    methodId: "export",
  });
  function node() {
    db = new Database(join(root, "node.sqlite"));
    const store = createSqliteRecordStore(db);
    store.registerConnection({
      instance: "conn",
      sourceId,
      method: "export",
      label: "Ephemeral dev",
    });
    store.replication.beginBaseline(expected);
    const receiver = createReplicaReceiver({
      db,
      store,
      owner,
      authenticate: (c) => (c === credential ? owner : undefined),
      declarations: () => context().declarations,
    });
    const worker = createReplicaTransportWorker({
      db,
      enabled: true,
      expected: () => expected,
      exporter: store.replication,
      receiver,
      credential,
      transport: nodeTransport,
    });
    return { store, worker };
  }
  let desktop = node();
  const identity = {
    owner,
    sourceId,
    connectionId: "conn",
    methodId: "export",
    generation: 1 as const,
  };
  const emittedAt = new Date().toISOString();
  await lite.store.commitLocal("phone-local", [
    { ...identity, kind: "connection-register" },
    {
      ...identity,
      kind: "upsert",
      declaration: binding,
      recordKey: "phone",
      emittedAt,
      data: { id: "phone", text: "phone to Node" },
      blobs: [],
    },
  ]);
  desktop.store.ingestBatch(
    [
      {
        instance: "conn",
        stream: "messages",
        key: "node",
        emitted_at: emittedAt,
        data: { id: "node", text: "Node to phone" },
      },
    ],
    () => "mutable_state",
    () => ["id"],
    { method: "export", generation: 1 },
  );
  const deadline = Date.now() + 5 * 60_000;
  let settled = false;
  while (Date.now() < deadline) {
    await lite.worker.cycle();
    await desktop.worker.cycle();
    const status = await lite.worker.status();
    console.log(JSON.stringify({ state: "pending", ...status }));
    if (
      desktop.store.getRecord("conn", "messages", "phone") &&
      (await lite.store.readRecord("conn", "messages", "node"))
    ) {
      settled = true;
      break;
    }
    await new Promise((resolve) => setTimeout(resolve, 5000));
  }
  report.liteStatus = await lite.worker.status();
  report.nodeErrors = db!
    .prepare(
      "SELECT error,COUNT(*) AS n FROM pdpp_transport_outbox WHERE error IS NOT NULL GROUP BY error",
    )
    .all();
  if (!settled)
    throw new Error("dev replication did not finalize within five minutes");
  const beforePhone = await lite.store.readRecord("conn", "messages", "node");
  const beforeNode = desktop.store.getRecord("conn", "messages", "phone");
  db!.close();
  db = undefined;
  lite = phone();
  desktop = node();
  await lite.worker.cycle();
  await desktop.worker.cycle();
  assert.deepEqual(
    await lite.store.readRecord("conn", "messages", "node"),
    beforePhone,
  );
  assert.deepEqual(
    desktop.store.getRecord("conn", "messages", "phone"),
    beforeNode,
  );
  report.state = "passed";
  report.directions = 2;
  report.restart = "same rows and versions";
} catch (error) {
  report.state = "unproven";
  report.error = error instanceof Error ? error.message : "dev journey failed";
  process.exitCode = 1;
} finally {
  db?.close();
  rmSync(root, { recursive: true, force: true });
  report.finishedAt = new Date().toISOString();
  writeFileSync(reportPath, JSON.stringify(report, null, 2) + "\n", {
    mode: 0o600,
  });
  console.log(JSON.stringify({ state: report.state, reportPath }));
}
