/** Disposable native enclave/Gateway proof. No production, hardware attestation or real settlement.
 * node --import tsx scripts/verify-additions-enclave.mjs /path/to/data-gateway
 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { spawn, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  keccak256,
  stringToHex,
  encodeAbiParameters,
  parseAbi,
  decodeFunctionData,
  encodeFunctionResult,
  zeroAddress,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createDataFileEnvelope,
  deriveScopeKey,
  encryptWithPassword,
  decryptWithPassword,
  deriveMasterKey,
  verifyWeb3Signed,
  buildWeb3SignedHeader,
  MASTER_KEY_MESSAGE,
} from "@opendatalabs/vana-sdk/node";
import {
  createDurableAdditions,
  additionsLedgerScope,
} from "../packages/core/src/additions/durable.ts";
import { createVersionInventoryClient } from "../packages/core/src/additions/version-inventory.ts";
import { createFakeDstackClient } from "../packages/enclave/src/dstack/fake.ts";
import {
  deriveEnclaveIdentity,
  deriveEnclaveAccount,
} from "../packages/enclave/src/identity/wallet.ts";
import { userPsId } from "../packages/enclave/src/identity/paths.ts";
import { createAgentServer } from "../packages/enclave/src/agent/http.ts";
import { createEnclaveAdditionsPorts } from "../packages/server/src/enclave-main.ts";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.ts";

const gatewayRoot = resolve(process.argv[2]);
const gatewayHead = execFileSync("git", ["rev-parse", "HEAD"], {
  cwd: gatewayRoot,
  encoding: "utf8",
}).trim();
assert.ok(
  gatewayHead.startsWith("d8ed3c0"),
  `Expected approved Gateway d8ed3c0, got ${gatewayHead}`,
);
const requireGateway = createRequire(join(gatewayRoot, "package.json"));
const { default: EmbeddedPostgres } = await import(
  pathToFileURL(requireGateway.resolve("embedded-postgres"))
);
const root = await mkdtemp(resolve("../enclave-recovery-proof-"));
const servers = [];
const owner = privateKeyToAccount(`0x${randomBytes(32).toString("hex")}`);
const stranger = privateKeyToAccount(`0x${randomBytes(32).toString("hex")}`);
const chainId = 14800;
const contract = "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C";
const source = "test.conversations";
const ownerSignature = await owner.signMessage({ message: MASTER_KEY_MESSAGE });
const masterKey = deriveMasterKey(ownerSignature);
const password = (scope) =>
  Buffer.from(deriveScopeKey(masterKey, scope)).toString("hex");
const idFor = (scope) =>
  keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "string" }],
      [owner.address, scope],
    ),
  );
const blobPath = (key) => join(root, encodeURIComponent(key));
const chainVersions = new Map();
const consumedStorageProofs = new Set();
let revoked = false,
  inventoryCalls = 0,
  registrations = 0,
  uploadCount = 0;
let db, schema, pg, versionsHandler, dataHandler;
const dstack = createFakeDstackClient({
  appId: "0000000000000000000000000000000000000003",
});
const epoch = 2;
const identity = await deriveEnclaveIdentity(
  dstack,
  userPsId(chainId, owner.address),
  epoch,
);
const serverId = keccak256(stringToHex("local-enclave-recovery-registration"));
const serverUrl = "https://disposable-enclave.invalid";
const serverRecord = {
  id: serverId,
  owner: owner.address,
  serverAddress: identity.address,
  publicKey: identity.publicKey,
  url: serverUrl,
};
const rpcAbi = parseAbi([
  "function getActiveServerByAddress(address serverAddress) view returns ((bytes32 id, address owner, address serverAddress, string publicKey, string url))",
  "function currentVersion(address ownerAddress, string scope) view returns (uint256)",
  "function operationKey(string name) view returns (bytes32)",
  "function fees(bytes32 operation) view returns ((uint256 amount, address asset, address payee, bool enabled))",
]);
async function listen(server) {
  servers.push(server);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${server.address().port}`;
}
async function bytesOf(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    assert.ok(size < 8 * 1024 * 1024);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
const origin = await listen(
  createServer(async (request, response) => {
    try {
      const url = new URL(request.url, "http://localhost");
      if (url.pathname === "/rpc") {
        const input = JSON.parse((await bytesOf(request)).toString());
        function answer(call) {
          let result;
          if (call.method === "eth_chainId")
            result = `0x${chainId.toString(16)}`;
          else if (call.method === "eth_getBlockByNumber")
            result = {
              number: "0x64",
              hash: `0x${"ab".repeat(32)}`,
              parentHash: `0x${"cd".repeat(32)}`,
              timestamp: `0x${Math.floor(Date.now() / 1000).toString(16)}`,
              nonce: "0x0000000000000000",
              difficulty: "0x0",
              gasLimit: "0x1c9c380",
              gasUsed: "0x0",
              miner: zeroAddress,
              extraData: "0x",
              mixHash: `0x${"00".repeat(32)}`,
              stateRoot: `0x${"00".repeat(32)}`,
              receiptsRoot: `0x${"00".repeat(32)}`,
              transactionsRoot: `0x${"00".repeat(32)}`,
              logsBloom: `0x${"00".repeat(256)}`,
              transactions: [],
              uncles: [],
              size: "0x100",
              baseFeePerGas: "0x1",
              totalDifficulty: "0x0",
            };
          else if (call.method === "eth_call") {
            const decoded = decodeFunctionData({
              abi: rpcAbi,
              data: call.params[0].data,
            });
            let value;
            if (decoded.functionName === "getActiveServerByAddress")
              value = revoked
                ? { ...serverRecord, id: `0x${"00".repeat(32)}` }
                : serverRecord;
            else if (decoded.functionName === "currentVersion")
              value = BigInt(chainVersions.get(decoded.args[1]) ?? 0);
            else if (decoded.functionName === "operationKey")
              value = keccak256(stringToHex(decoded.args[0]));
            else if (decoded.functionName === "fees")
              value = {
                amount: 0n,
                asset: zeroAddress,
                payee: zeroAddress,
                enabled: false,
              };
            else throw new Error(`Unexpected RPC call ${decoded.functionName}`);
            result = encodeFunctionResult({
              abi: rpcAbi,
              functionName: decoded.functionName,
              result: value,
            });
          } else throw new Error(`Unexpected RPC method ${call.method}`);
          return { jsonrpc: "2.0", id: call.id, result };
        }
        response.setHeader("content-type", "application/json");
        response.end(
          JSON.stringify(
            Array.isArray(input) ? input.map(answer) : answer(input),
          ),
        );
        return;
      }
      const blob = url.pathname.match(
        /^\/v1\/chains\/14800\/blobs\/(0x[0-9a-f]+)\/(.+)$/,
      );
      if (blob) {
        assert.equal(blob[1], owner.address.toLowerCase());
        const key = blob[2].split("/").map(decodeURIComponent).join("/");
        if (request.method === "PUT") {
          const bytes = await bytesOf(request);
          const auth = await verifyWeb3Signed({
            headerValue: request.headers.authorization,
            expectedOrigin: origin,
            expectedMethod: "PUT",
            expectedPath: request.url,
            bodyBytes: bytes,
          });
          assert.equal(
            auth.signer.toLowerCase(),
            identity.address.toLowerCase(),
          );
          assert.ok(!revoked);
          assert.ok(key.startsWith("vana.system.additions"));
          const replay = request.headers.authorization;
          assert.ok(!consumedStorageProofs.has(replay));
          consumedStorageProofs.add(replay);
          await writeFile(blobPath(key), bytes);
          uploadCount++;
          response.end();
          return;
        }
        if (request.method === "GET") {
          response.end(await readFile(blobPath(key)));
          return;
        }
        response.statusCode = 405;
        response.end();
        return;
      }
      const query = Object.fromEntries(url.searchParams);
      const match = url.pathname.match(/^\/v1\/data\/(0x[0-9a-f]+)\/versions$/);
      if (match) {
        query.dataPointId = match[1];
        inventoryCalls++;
      } else assert.equal(url.pathname, "/v1/data");
      const body =
        request.method === "POST"
          ? JSON.parse((await bytesOf(request)).toString())
          : undefined;
      let payload;
      const req = {
        method: request.method,
        headers: request.headers,
        query,
        body,
      };
      const res = {
        status(code) {
          response.statusCode = code;
          return this;
        },
        setHeader(name, value) {
          response.setHeader(name, value);
        },
        json(value) {
          payload = value;
          return this;
        },
        end() {
          return this;
        },
      };
      await (match ? versionsHandler : dataHandler)(req, res);
      if (request.method === "POST" && response.statusCode === 201) {
        // Only settlement is simulated. Parsing, recovery, owner/server authorization,
        // expected-version sequencing and SQL writes ran through the real handler.
        // Prove actual POST-created commitments before simulating only status.
        const inserted = await db.$client.query(
          "SELECT data_hash, metadata_hash, signature, signer_address, status FROM data_point_versions WHERE id=$1 AND expected_version=$2",
          [idFor(body.scope), body.expectedVersion],
        );
        assert.deepEqual(inserted.rows, [
          {
            data_hash: body.dataHash,
            metadata_hash: body.metadataHash,
            signature: request.headers.authorization.slice(
              "Web3Signed ".length,
            ),
            signer_address: identity.address,
            status: "pending",
          },
        ]);
        const head = await db.$client.query(
          "SELECT owner_address, scope, expected_version, data_hash, metadata_hash, signature, signer_address FROM data_points WHERE id=$1",
          [idFor(body.scope)],
        );
        assert.deepEqual(head.rows, [
          {
            owner_address: owner.address,
            scope: body.scope,
            expected_version: body.expectedVersion,
            data_hash: body.dataHash,
            metadata_hash: body.metadataHash,
            signature: inserted.rows[0].signature,
            signer_address: identity.address,
          },
        ]);
        await db.$client.query(
          "UPDATE data_point_versions SET status='confirmed' WHERE id=$1 AND expected_version=$2",
          [idFor(body.scope), body.expectedVersion],
        );
        await db.$client.query(
          "UPDATE data_points SET status='confirmed' WHERE id=$1",
          [idFor(body.scope)],
        );
        chainVersions.set(body.scope, Number(body.expectedVersion));
        registrations++;
      }
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(payload));
    } catch (error) {
      console.error(
        "LOCAL HTTP FIXTURE ERROR",
        request.method,
        request.url,
        error,
      );
      response.statusCode = 500;
      response.end(String(error));
    }
  }),
);
const probe = createServer();
await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
const pgPort = probe.address().port;
await new Promise((resolve) => probe.close(resolve));
pg = new EmbeddedPostgres({
  databaseDir: join(root, "pg"),
  port: pgPort,
  user: "gateway",
  password: "gateway",
  persistent: false,
  initdbFlags: ["--encoding=UTF8"],
  onLog() {},
  onError() {},
});
async function run(command, args) {
  const child = spawn(command, args, {
    cwd: gatewayRoot,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (data) => (output += data));
  child.stderr.on("data", (data) => (output += data));
  await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(output)),
    );
  });
}
try {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("gateway");
  Object.assign(process.env, {
    NEON_URL: `postgres://gateway:gateway@127.0.0.1:${pgPort}/gateway`,
    USE_LOCAL_DB: "1",
    GATEWAY_PUBLIC_ORIGIN: origin,
    CHAIN_ID: String(chainId),
    DATA_REGISTRY_CONTRACT: contract,
    DATA_PORTABILITY_SERVER_CONTRACT:
      "0x1111111111111111111111111111111111111111",
    FEE_REGISTRY_CONTRACT: "0x2222222222222222222222222222222222222222",
    GATEWAY_PRIVATE_KEY: `0x${"33".repeat(32)}`,
    RPC_URL: `${origin}/rpc`,
  });
  await run("npm", ["run", "db:push", "--", "--force"]);
  const load = (file) => import(pathToFileURL(join(gatewayRoot, file)));
  ({ db, schema } = await load("db/index.ts"));
  ({ default: versionsHandler } = await load(
    "api/v1/data/[dataPointId]/versions.ts",
  ));
  ({ default: dataHandler } = await load("api/v1/data.ts"));
  await db.insert(schema.servers).values({
    id: serverId,
    ownerAddress: owner.address,
    serverAddress: identity.address,
    publicKey: identity.publicKey,
    serverUrl,
    signature: "disposable-confirmed-registration",
    status: "confirmed",
    paymentStatus: "paid",
  });
  const versions = [
    { conversations: [{ id: "permanent-a" }] },
    { conversations: [{ id: "permanent-a" }, { id: "permanent-b" }] },
    {
      conversations: [
        { id: "permanent-a" },
        { id: "permanent-b" },
        { id: "permanent-c" },
      ],
    },
  ];
  for (const [index, data] of versions.entries()) {
    const collectedAt = `2026-10-0${index + 1}T12:00:00.000Z`;
    const envelope = createDataFileEnvelope(source, collectedAt, data);
    const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
    const encrypted = await encryptWithPassword(plaintext, password(source));
    await writeFile(blobPath(`${source}/${index + 1}`), encrypted);
    const row = {
      id: idFor(source),
      expectedVersion: String(index + 1),
      dataHash: keccak256(plaintext),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope: source,
            collectedAt,
            sizeBytes: encrypted.byteLength,
          }),
        ),
      ),
      signature: "disposable-source-fixture",
      signerAddress: owner.address,
      status: "confirmed",
      addedAt: new Date(collectedAt),
    };
    await db.insert(schema.dataPointVersions).values(row);
    if (index === versions.length - 1)
      await db.insert(schema.dataPoints).values({
        ...row,
        ownerAddress: owner.address,
        scope: source,
        chainState: "active",
      });
  }
  chainVersions.set(source, versions.length);
  let lookup = {
    kind: "active",
    key: "disposable-placement",
    generation: 1,
    identity: { userPsId: userPsId(chainId, owner.address), epoch },
  };
  const agent = await listen(
    createAgentServer({
      client: dstack,
      secret: "disposable-host-secret",
      jobs: {
        nodeId: "local",
        chainId,
        storageApiUrl: origin,
        additions: { gatewayUrl: origin, dataRegistry: contract },
        activeCount: () => 1,
        draining: () => false,
        drain: async () => {},
        sandboxDebug: false,
        listSandboxes: async () => [],
        sandboxLogs: async () => undefined,
        lookupSandboxJob: () => ({ kind: "unauthorized" }),
        lookupSandbox: (token) =>
          token === "disposable-sandbox" ? lookup : { kind: "unauthorized" },
        postAccessRecords: async () => {},
        prewarm: () => {},
      },
    }),
  );
  const config = ServerConfigSchema.parse({});
  config.gateway.url = origin;
  config.gateway.chainId = chainId;
  config.gateway.contracts.dataRegistry = contract;
  config.storage.config.vana = { apiUrl: origin };
  const env = {
    ownerSignature,
    accessToken: "disposable-sandbox",
    serverAddress: identity.address,
    serverPublicKey: identity.publicKey,
    agentUrl: agent,
  };
  async function newService() {
    const ports = await createEnclaveAdditionsPorts(config, env);
    const inventory = createVersionInventoryClient({
      gatewayUrl: origin,
      ownerAddress: owner.address,
      ownerSigner: ports.additionsInventorySigner,
    });
    return {
      ports,
      inventory,
      service: createDurableAdditions({
        ownerAddress: owner.address,
        network: `vana:${chainId}:${origin}`,
        masterKey,
        inventory,
        ...ports.additionsWriter,
      }),
    };
  }
  const query = {
    timezone: "Asia/Kathmandu",
    days: 7,
    now: new Date("2026-10-04T00:00:00Z"),
  };
  const first = await newService();
  assert.equal(
    (await first.inventory.list(source)).versions.length,
    versions.length,
  );
  const summary = await first.service.summarize(query);
  assert.equal(summary.coverage, "complete", JSON.stringify(summary));
  assert.equal(summary.total, 3);
  assert.equal(summary.through[source], "3");
  assert.equal(
    summary.days.reduce((sum, row) => sum + row.added, 0),
    3,
  );
  const ledgerScope = additionsLedgerScope(source);
  const ledger = await first.inventory.list(ledgerScope);
  assert.equal(ledger.versions.length, 1);
  const ledgerCiphertext = await readFile(blobPath(`${ledgerScope}/1`));
  assert.ok(!ledgerCiphertext.includes(Buffer.from("permanent-a")));
  const ledgerPlaintext = await decryptWithPassword(
    new Uint8Array(ledgerCiphertext),
    password(ledgerScope),
  );
  assert.equal(keccak256(ledgerPlaintext), ledger.versions[0].dataHash);
  const ledgerDocument = JSON.parse(new TextDecoder().decode(ledgerPlaintext));
  assert.equal(ledgerDocument.scope, ledgerScope);
  assert.equal(ledgerDocument.data.scope, source);
  assert.equal(ledgerDocument.data.through, "3");
  assert.equal(ledgerDocument.data.currentTotal, 3);
  assert.equal(ledgerDocument.data.owner, owner.address.toLowerCase());
  assert.equal(registrations, 2);
  assert.equal(uploadCount, 2);
  const storedRegistration = await db.$client.query(
    "SELECT signer_address FROM data_point_versions WHERE id=$1",
    [idFor(ledgerScope)],
  );
  assert.equal(storedRegistration.rows[0].signer_address, identity.address);
  for (let version = 1; version <= versions.length; version++)
    await rm(blobPath(`${source}/${version}`));
  const restarted = await newService();
  const recovered = await restarted.service.summarize(query);
  assert.equal(recovered.coverage, "complete");
  assert.equal(recovered.total, 3);
  assert.deepEqual(recovered.days, summary.days);
  assert.equal(recovered.through[source], "3");
  const wrongOwner = await fetch(`${agent}/agent/v1/additions/sign`, {
    method: "POST",
    headers: {
      Authorization: "Bearer disposable-sandbox",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      kind: "inventory",
      owner: stranger.address,
      chainId,
      scope: source,
      after: "0",
      limit: "100",
    }),
  });
  assert.equal(wrongOwner.status, 403);
  await wrongOwner.body?.cancel();
  const account = await deriveEnclaveAccount(
    dstack,
    userPsId(chainId, owner.address),
    epoch,
  );
  const strangerId = keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "string" }],
      [stranger.address, source],
    ),
  );
  const strangerUri = `/v1/data/${strangerId}/versions?${new URLSearchParams({ user: stranger.address.toLowerCase(), scope: source, after: "0", limit: "100" })}`;
  const strangerProof = await buildWeb3SignedHeader({
    signMessage: account.signMessage,
    aud: origin,
    method: "GET",
    uri: strangerUri,
    nonce: crypto.randomUUID(),
  });
  const wrongOwnerGateway = await fetch(`${origin}${strangerUri}`, {
    headers: { Authorization: strangerProof },
  });
  assert.equal(wrongOwnerGateway.status, 403);
  await wrongOwnerGateway.body?.cancel();
  revoked = true;
  // The SQL row is still active: fresh chain registry evidence independently
  // refuses a previously successful server before local revocation arrives.
  await assert.rejects(restarted.inventory.list(source), /403/);
  revoked = false;
  assert.equal((await restarted.inventory.list(source)).versions.length, 3);
  await db.$client.query("UPDATE servers SET revoked_at=NOW() WHERE id=$1", [
    serverId,
  ]);
  await assert.rejects(restarted.inventory.list(source), /403/);
  await assert.rejects(
    restarted.ports.additionsWriter.signer.signAddData({
      ownerAddress: owner.address,
      scope: ledgerScope,
      expectedVersion: 2n,
      dataHash: ledger.versions[0].dataHash,
      metadataHash: ledger.versions[0].metadataHash,
    }),
    /403/,
  );
  const unavailable = await restarted.service.summarize(query);
  assert.notEqual(unavailable.coverage, "complete");
  await db.$client.query("UPDATE servers SET revoked_at=NULL WHERE id=$1", [
    serverId,
  ]);
  assert.equal((await restarted.inventory.list(source)).versions.length, 3);
  lookup = { kind: "stale" };
  await assert.rejects(restarted.inventory.list(source), /403/);
  console.log(
    JSON.stringify({
      result: "PASS",
      gatewayHead,
      sourceVersions: versions.length,
      total: summary.total,
      coverage: summary.coverage,
      inventoryCalls,
      checkpointAddDataPosts: registrations,
      signedCheckpointUploads: uploadCount,
      encryptedLedgerCommitmentVerified: true,
      enclaveServerSqlSignerVerified: true,
      restartAfterSourcePruning: true,
      wrongOwnerRejected: true,
      wrongOwnerGatewayRejected: true,
      freshChainRevocationRejected: true,
      revokedRegistrationRejected: true,
      stalePlacementRejected: true,
      limitations:
        "Disposable PostgreSQL and HTTP storage; real Gateway handlers/AddData authentication/SQL, fake local JSON-RPC registry and simulated settlement, fake dstack key derivation; no production or hardware attestation",
    }),
  );
} finally {
  await Promise.all(
    servers.map(
      (server) =>
        new Promise((resolve) => {
          server.closeAllConnections();
          server.close(resolve);
        }),
    ),
  );
  if (db) await db.$client.end();
  if (pg) await pg.stop();
  await rm(root, { recursive: true, force: true });
}
