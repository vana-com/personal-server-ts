/** Local-only reproducible producer proof. Run:
 * node --import tsx scripts/verify-additions-browser.mjs ../data-gateway
 * Gateway checkout must be exactly accepted local d8ed3c0; npm ci in both repos first.
 * All SQL/HTTP/blob state is disposable. No chain or production calls occur.
 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";
import { spawn, execFileSync } from "node:child_process";
import { build } from "esbuild";
import { encrypt, createMessage, enums } from "openpgp";
import { randomBytes } from "node:crypto";
import { keccak256, stringToHex, encodeAbiParameters } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  createDataFileEnvelope,
  deriveScopeKey,
  deriveMasterKey,
  encryptWithPassword,
  decryptWithPassword,
  buildWeb3SignedHeader,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";

import { createDurableAdditions } from "../packages/core/src/additions/durable.ts";
import { createVersionInventoryClient } from "../packages/core/src/additions/version-inventory.ts";
import { createServerSigner } from "../packages/core/src/signing/signer.ts";

const gatewayRoot = resolve(process.argv[2] ?? "../data-gateway");
assert.equal(
  execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: gatewayRoot,
    encoding: "utf8",
  }).trim(),
  "d8ed3c09952a4151ab94df30aa905423eca6a29d",
);
const requireGateway = createRequire(join(gatewayRoot, "package.json"));
const { default: EmbeddedPostgres } = await import(
  pathToFileURL(requireGateway.resolve("embedded-postgres"))
);
const root = await mkdtemp(join(tmpdir(), "ps-gateway-additions-"));
const count = 40;
const journalRegression = process.argv.includes("--journal-regression");
const blobPutHistory = [];
let browserSession = `vana12-proof-${process.pid}`;
let browserRestarts = 0;
let profileName = "browser-profile";
let fullRuntimeEquality = false;
let browserBundle, workerBundle;
const lastRegistered = new Map();
let fixturePost = 0;
let blobPuts = 0;
let fault = "",
  faultVersion = String(count + 5),
  verificationArmed = false,
  stalledClosed = 0,
  stalledActive = 0,
  servedBlobBytes = 0;
const account = privateKeyToAccount(`0x${"11".repeat(32)}`);
const ownerSignature = await account.signMessage({
  message: "vana-master-key-v1",
});
const masterKey = deriveMasterKey(ownerSignature);
const source = "test.conversations";
const keyPassword = (scope) =>
  Buffer.from(deriveScopeKey(masterKey, scope)).toString("hex");
const idFor = (scope) =>
  keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "string" }],
      [account.address, scope],
    ),
  );
const blobPath = (key) => join(root, encodeURIComponent(key));
let versionsHandler, listingHandler;
let inventoryCalls = 0,
  blobBytes = 0;
const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url, "http://localhost");
    if (url.pathname === "/") {
      response.setHeader("content-type", "text/html");
      response.end('<script type="module" src="/browser.js"></script>');
      return;
    }
    if (url.pathname === "/browser.js") {
      response.setHeader("content-type", "application/javascript");
      response.end(browserBundle);
      return;
    }
    if (url.pathname === "/additions-worker.js") {
      response.setHeader("content-type", "application/javascript");
      response.end(workerBundle);
      return;
    }
    if (url.pathname === "/rpc") {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = JSON.parse(Buffer.concat(chunks));
      const answer = (item) => ({
        jsonrpc: "2.0",
        id: item.id,
        result:
          item.params?.[0]?.to?.toLowerCase() === `0x${"44".repeat(20)}`
            ? `0x${"00".repeat(128)}`
            : `0x${"00".repeat(32)}`,
      });
      response.setHeader("content-type", "application/json");
      response.end(
        JSON.stringify(Array.isArray(body) ? body.map(answer) : answer(body)),
      );
      return;
    }
    if (url.pathname.startsWith("/v1/chains/")) {
      const parts = url.pathname.split("/");
      const scope = decodeURIComponent(parts[6]);
      const version = parts[7];
      const key = `${scope}/${version}`;
      if (request.method === "PUT") {
        const chunks = [];
        for await (const chunk of request) chunks.push(chunk);
        const bytes = Buffer.concat(chunks);
        const verified = await verifyWeb3Signed({
          headerValue: request.headers.authorization,
          expectedOrigin: origin,
          expectedMethod: "PUT",
          expectedPath: url.pathname,
          bodyBytes: bytes,
        });
        assert.equal(
          verified.signer.toLowerCase(),
          account.address.toLowerCase(),
        );
        await writeFile(blobPath(key), bytes);
        blobPuts++;
        blobPutHistory.push({
          scope,
          version,
          hash: keccak256(bytes),
          bytes: bytes.length,
        });
        if (fault === "put-503") {
          response.statusCode = 503;
          response.end("{}");
          return;
        }
        if (fault === "put") {
          response.destroy();
          return;
        }
        response.end("{}");
        return;
      }
      const bytes = await readFile(blobPath(key));
      if (scope === source && version === faultVersion) {
        if (fault === "declared-length") {
          response.setHeader("content-length", "1000000000");
          response.end(bytes);
          return;
        }
        if (fault === "lying-length") {
          response.setHeader("content-length", "1");
          response.end(bytes);
          return;
        }
        if (fault === "missing-length") {
          response.write(bytes);
          response.end();
          return;
        }
        if (fault === "stream-overflow") {
          const chunk = Buffer.alloc(65536);
          let sent = 0;
          const pump = () => {
            while (!response.destroyed && sent < 10 * 1024 * 1024) {
              sent += chunk.length;
              if (!response.write(chunk)) {
                response.once("drain", pump);
                return;
              }
            }
            if (!response.destroyed) response.end();
          };
          pump();
          return;
        }
      }
      servedBlobBytes += bytes.length;
      if (fault === "stall" && scope === source && version === faultVersion) {
        fault = "";
        stalledActive++;
        response.on("close", () => {
          stalledActive--;
          stalledClosed++;
        });
        response.write(
          bytes.subarray(0, Math.min(256 * 1024, bytes.length - 1)),
        );
        return;
      }
      response.end(bytes);
      return;
    }
    if (url.pathname.startsWith("/blob/")) {
      const bytes = await readFile(
        blobPath(decodeURIComponent(url.pathname.slice(6))),
      );
      response.end(bytes);
      return;
    }
    const query = Object.fromEntries(url.searchParams);
    const match = url.pathname.match(/^\/v1\/data\/(0x[a-f0-9]+)\/versions$/);
    if (match && fault === "verify" && verificationArmed) {
      response.destroy();
      return;
    }
    const dropRegistration = request.method === "POST" && fault === "register";
    const handler = match ? versionsHandler : listingHandler;
    if (match) {
      query.dataPointId = match[1];
      inventoryCalls++;
    }
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    const bodyBytes = Buffer.concat(chunks);
    const req = {
      method: request.method,
      headers: request.headers,
      query,
      body: bodyBytes.length ? JSON.parse(bodyBytes) : undefined,
    };
    const res = {
      status(code) {
        response.statusCode = code;
        return this;
      },
      setHeader(name, value) {
        response.setHeader(name, value);
      },
      json(body) {
        response.setHeader("content-type", "application/json");
        if (!dropRegistration) response.end(JSON.stringify(body));
        return this;
      },
      end() {
        response.end();
      },
    };
    await handler(req, res);
    if (request.method === "POST" && response.statusCode < 300) {
      fixturePost++;
      // Simulated local settlement of the ACTUAL handler-accepted signed row.
      // This proves POST/signing/SQL compatibility, not an on-chain transaction.
      const id = idFor(req.body.scope);
      const selector = and(
        eq(schema.dataPointVersions.id, id),
        eq(schema.dataPointVersions.expectedVersion, req.body.expectedVersion),
      );
      const [created] = await db
        .select()
        .from(schema.dataPointVersions)
        .where(selector);
      assert.ok(created, "POST returned success without inserting SQL version");
      assert.equal(created.dataHash, req.body.dataHash);
      assert.equal(created.metadataHash, req.body.metadataHash);
      assert.equal(created.signature, request.headers.authorization.slice(11));
      assert.equal(
        created.signerAddress.toLowerCase(),
        account.address.toLowerCase(),
      );
      await db
        .update(schema.dataPointVersions)
        .set({ status: "confirmed" })
        .where(selector);
      await db
        .update(schema.dataPoints)
        .set({ status: "confirmed", chainState: "active" })
        .where(eq(schema.dataPoints.id, id));
      lastRegistered.set(req.body.scope, req.body);
      if (fault === "verify") verificationArmed = true;
      if (dropRegistration) {
        fault = "";
        response.destroy();
      }
    }
  } catch (error) {
    response.statusCode = 500;
    response.end(String(error));
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const portProbe = createServer();
await new Promise((resolve) => portProbe.listen(0, "127.0.0.1", resolve));
const pgPort = portProbe.address().port;
await new Promise((resolve) => portProbe.close(resolve));
const pg = new EmbeddedPostgres({
  databaseDir: join(root, "pg"),
  port: pgPort,
  user: "gateway",
  password: "gateway",
  persistent: false,
  initdbFlags: ["--encoding=UTF8"],
  onLog() {},
  onError() {},
});
const run = (command, args, env) =>
  new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: gatewayRoot,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve() : reject(new Error(output)),
    );
  });
const command = (args) =>
  new Promise((resolve, reject) => {
    const child = spawn(
      "agent-browser",
      [
        "--session",
        browserSession,
        "--profile",
        join(root, profileName),
        ...args,
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    let output = "";
    child.stdout.on("data", (chunk) => (output += chunk));
    child.stderr.on("data", (chunk) => (output += chunk));
    child.on("error", reject);
    child.on("exit", (code) =>
      code === 0 ? resolve(output) : reject(Error(output)),
    );
  });
let db, schema, register;
const { eq, and } = await import(
  pathToFileURL(requireGateway.resolve("drizzle-orm"))
);
try {
  await pg.initialise();
  await pg.start();
  await pg.createDatabase("gateway");
  Object.assign(process.env, {
    NEON_URL: `postgres://gateway:gateway@127.0.0.1:${pgPort}/gateway`,
    USE_LOCAL_DB: "1",
    GATEWAY_PUBLIC_ORIGIN: origin,
    CHAIN_ID: "14800",
    RPC_URL: `${origin}/rpc`,
    FEE_REGISTRY_CONTRACT: `0x${"44".repeat(20)}`,
    DATA_REGISTRY_CONTRACT: "0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C",
    GATEWAY_PRIVATE_KEY: `0x${"33".repeat(32)}`,
  });
  await run("npm", ["run", "db:push", "--", "--force"], process.env);
  const load = (file) => import(pathToFileURL(join(gatewayRoot, file)));
  ({ db, schema } = await load("db/index.ts"));
  ({ default: versionsHandler } = await load(
    "api/v1/data/[dataPointId]/versions.ts",
  ));
  ({ default: listingHandler } = await load("api/v1/data.ts"));
  const storage = {
    urlForKey: (key) => `${origin}/blob/${encodeURIComponent(key)}`,
    async upload(key, bytes) {
      await writeFile(blobPath(key), bytes);
      return this.urlForKey(key);
    },
    async download(url) {
      assert.equal(new URL(url).origin, origin);
      const response = await fetch(url);
      assert.equal(response.status, 200);
      return new Uint8Array(await response.arrayBuffer());
    },
    async delete() {
      return false;
    },
    async exists() {
      return true;
    },
  };
  // Confirmed SQL fixtures model retained chain-settled rows. Checkpoint writes
  // use this same test registry, not POST AddData/chain settlement authority.
  register = async function (params) {
    lastRegistered.set(params.scope, params);
    const id = idFor(params.scope);
    const row = {
      id,
      expectedVersion: String(params.expectedVersion),
      dataHash: params.dataHash,
      metadataHash: params.metadataHash,
      signature: params.signature,
      signerAddress: account.address,
      status: "confirmed",
      addedAt: new Date(),
    };
    await db
      .insert(schema.dataPointVersions)
      .values(row)
      .onConflictDoUpdate({
        target: [
          schema.dataPointVersions.id,
          schema.dataPointVersions.expectedVersion,
        ],
        set: row,
      });
    const head = {
      ...row,
      ownerAddress: account.address,
      scope: params.scope,
      chainState: "active",
    };
    await db
      .insert(schema.dataPoints)
      .values(head)
      .onConflictDoUpdate({ target: schema.dataPoints.id, set: head });
    return { success: true };
  };
  for (let version = 1; version <= (journalRegression ? 0 : count); version++) {
    const collectedAt = new Date(
      Date.UTC(2026, 9, 1, 12, 0, version),
    ).toISOString();
    const data = {
      conversations: [
        { id: "old" },
        ...(version === count ? [{ id: "new" }] : []),
      ],
    };
    data.padding = randomBytes(64 * 1024).toString("base64");
    const envelope = createDataFileEnvelope(source, collectedAt, data);
    const plain = new TextEncoder().encode(JSON.stringify(envelope));
    const encrypted = await encryptWithPassword(plain, keyPassword(source));
    blobBytes += encrypted.byteLength;
    await storage.upload(`${source}/${version}`, encrypted);
    await register({
      scope: source,
      expectedVersion: String(version),
      dataHash: keccak256(plain),
      metadataHash: keccak256(
        stringToHex(
          JSON.stringify({
            scope: source,
            collectedAt,
            sizeBytes: encrypted.byteLength,
          }),
        ),
      ),
      signature: "local-settled-fixture",
    });
  }
  const entry = `
import { privateKeyToAccount } from 'viem/accounts';
import { keccak256, stringToHex } from 'viem';
import { createServerSigner } from './packages/core/src/signing/signer.ts';
import { ServerConfigSchema } from './packages/core/src/schemas/server-config.ts';
import { createIndexedDbPsLiteStateStore } from './packages/lite/src/state.ts';
import { createPsLiteSyncManager } from './packages/lite/src/sync.ts';
import { createPersistentPsLiteStorage } from './packages/lite/src/storage.ts';
const account=privateKeyToAccount('0x'+'11'.repeat(32));
const origin=location.origin;
const ownerSignature=await account.signMessage({message:'vana-master-key-v1'});
const config=ServerConfigSchema.parse({gateway:{url:origin,chainId:14800,contracts:{dataRegistry:'0x8C8788f98385F6ba1adD4234e551ABba0f82Cb7C'}},storage:{config:{vana:{apiUrl:origin}}}});
const signer=createServerSigner({address:account.address,publicKey:account.publicKey,signTypedData:p=>account.signTypedData(p),signMessage:m=>account.signMessage({message:m})},config.gateway);
const stateStore=createIndexedDbPsLiteStateStore({dbName:'local-additions-proof'});
let active=0,started=0,terminated=0,hostBytesCharged=0;const errors=[];
let failSign=false;
const ownerSigner={async signMessageBounded(message,signal){signal?.throwIfAborted();const r=await account.signMessage({message});signal?.throwIfAborted();return r},async signAddDataBounded(message,signal){signal?.throwIfAborted();if(failSign){failSign=false;throw Error('injected interrupted owner signing')}const r=await signer.signAddData(message);signal?.throwIfAborted();return r}};
 const storage=await createPersistentPsLiteStorage({kind:"indexeddb"});
 const composition=await createPsLiteSyncManager({config,stateStore,storage,ownerSignature,serverAccount:{address:account.address,publicKey:account.publicKey,signMessage:m=>account.signMessage({message:m}),signTypedData:p=>account.signTypedData(p)},ownerSyncSigner:{...signer,...ownerSigner,signMessage:m=>account.signMessage({message:m})},additionsWorkerFactory:()=>{const w=new Worker('/additions-worker.js',{type:'module'});started++;active++;w.addEventListener('error',e=>errors.push(e.message));w.addEventListener('message',e=>{if(e.data.kind==='error')errors.push(e.data.error)});const post=w.postMessage.bind(w);w.postMessage=(message,transfer)=>{if(message.kind==='response')hostBytesCharged+=message.spent??0;return post(message,transfer)};const terminate=w.terminate.bind(w);w.terminate=()=>{if(!w.stopped){w.stopped=true;active--;terminated++;terminate()}};return w}});
 await composition.syncManager.stop();
 const session=composition.additions;if(!session)throw Error("production additions composition unavailable");
window.proof=async function(signFailure=false){
 failSign=signFailure;
 hostBytesCharged=0;
 const start=performance.now();
 const result=await session.summarize({timezone:'Asia/Kathmandu',days:7,now:new Date('2026-10-04T00:00:00Z')});
 return {hostBytesCharged,errors,result,elapsedMs:performance.now()-start,active,started,terminated};
};
window.uploadNoClone=async()=>{let touched=0;await session.recordUpload({scope:'test.conversations',collectedAt:'2026-10-01T00:00:00Z',get data(){touched++;throw Error('unbounded data cloned')}},{get envelope(){touched++;throw Error('unbounded proof cloned')},encryptedSize:1024*1024*1024});return {touched,active}};
window.journal=async scope=>{const binding=JSON.stringify([account.address.toLowerCase(),'vana:14800:'+origin,scope]);const value=await stateStore.get('additions-publication-v1:'+keccak256(stringToHex(binding)));return value ? {exists:true,version:value.version??1,bytes:value.ciphertext.length} : {exists:false}};
window.ready=true;
`;
  workerBundle = (
    await build({
      entryPoints: ["packages/lite/src/additions-worker.ts"],
      bundle: true,
      write: false,
      platform: "browser",
      format: "esm",
      target: "es2022",
    })
  ).outputFiles[0].text;
  browserBundle = (
    await build({
      stdin: {
        contents: entry,
        resolveDir: process.cwd(),
        sourcefile: "browser-proof.js",
      },
      bundle: true,
      write: false,
      platform: "browser",
      format: "esm",
      target: "es2022",
    })
  ).outputFiles[0].text;
  await command(["open", origin]);
  await command(["wait", "--fn", "window.ready === true"]);
  async function assertFullEquality(expected) {
    const inventory = createVersionInventoryClient({
      gatewayUrl: origin,
      ownerAddress: account.address,
      ownerSigner: {
        signRequest: (params) =>
          buildWeb3SignedHeader({
            ...params,
            signMessage: (message) => account.signMessage({ message }),
          }),
      },
    });
    const full = createDurableAdditions({
      ownerAddress: account.address,
      network: `vana:14800:${origin}`,
      masterKey,
      inventory,
      storageAdapter: storage,
      signer: createServerSigner(
        {
          address: account.address,
          publicKey: account.publicKey,
          signTypedData: (params) => account.signTypedData(params),
          signMessage: (message) => account.signMessage({ message }),
        },
        {
          chainId: 14800,
          contracts: { dataRegistry: process.env.DATA_REGISTRY_CONTRACT },
        },
      ),
      gateway: {
        async registerDataPoint(params) {
          const { signature, ...body } = params;
          const response = await fetch(`${origin}/v1/data`, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              authorization: `Web3Signed ${signature}`,
            },
            body: JSON.stringify(body),
          });
          assert.ok(response.ok);
          return response.json();
        },
      },
    });
    const actual = await full.summarize({
      timezone: "Asia/Kathmandu",
      days: 7,
      now: new Date("2026-10-04T00:00:00Z"),
    });
    assert.equal(actual.coverage, "complete");
    assert.equal(actual.total, expected.total);
    assert.deepEqual(actual.days, expected.days);
    assert.deepEqual(actual.through, expected.through);
    fullRuntimeEquality = true;
  }
  if (journalRegression) {
    const decode = (output) => {
      const value = JSON.parse(output).data.result;
      assert.ok(value.elapsedMs < 10250);
      assert.ok(value.hostBytesCharged <= 8 * 1024 * 1024);
      assert.equal(value.active, 0);
      return value;
    };
    const invoke = async () =>
      decode(
        await command(["eval", "--json", "(async()=>await window.proof())()"]),
      );
    const journal = async (scope) =>
      JSON.parse(
        await command([
          "eval",
          "--json",
          `(async()=>await window.journal(${JSON.stringify(scope)}))()`,
        ]),
      ).data.result;
    const restart = async () => {
      await command(["close"]);
      browserSession = `vana12-proof-${process.pid}-${++browserRestarts}`;
      await command(["open", origin]);
      await command(["wait", "--fn", "window.ready === true"]);
    };
    const seed = async (scope, records, version = "1") => {
      const collectedAt = "2026-10-01T12:00:00.000Z";
      const plain = new TextEncoder().encode(
        JSON.stringify(
          createDataFileEnvelope(scope, collectedAt, {
            conversations: Array.from({ length: records }, (_, i) => ({
              id: `id-${i}`,
            })),
          }),
        ),
      );
      const encrypted = await encryptWithPassword(plain, keyPassword(scope));
      await storage.upload(`${scope}/${version}`, encrypted);
      await register({
        scope,
        expectedVersion: version,
        dataHash: keccak256(plain),
        metadataHash: keccak256(
          stringToHex(
            JSON.stringify({
              scope,
              collectedAt,
              sizeBytes: encrypted.byteLength,
            }),
          ),
        ),
        signature: "local-settled-fixture",
      });
    };
    const scenarios = [
      { stage: "put-503", records: 650 },
      { stage: "register", records: 650 },
      { stage: "verify", records: 650 },
      { stage: "put-503", records: 750 },
      { stage: "put-503", records: 650, scopes: 2 },
      { stage: "oversized", records: 850 },
    ];
    for (const [index, scenario] of scenarios.entries()) {
      await db.delete(schema.dataPointVersions);
      await db.delete(schema.dataPoints);
      lastRegistered.clear();
      blobPutHistory.length = 0;
      profileName = `journal-profile-${index}`;
      await restart();
      const scopes = Array.from({ length: scenario.scopes ?? 1 }, (_, i) =>
        i === 0 ? source : `test.conversations.${i}`,
      );
      const ledgerScope = (scope) => `vana.system.additions.${scope}`;
      if (scenario.stage === "oversized") {
        await seed(source, 1);
        const baseline = await invoke();
        assert.equal(baseline.result.coverage, "complete");
        const previous = lastRegistered.get(ledgerScope(source));
        await seed(source, scenario.records, "2");
        const tooLarge = await invoke();
        assert.equal(tooLarge.result.coverage, "behind");
        assert.equal(tooLarge.result.total, 1);
        assert.equal(tooLarge.result.through[source], "1");
        assert.equal((await journal(ledgerScope(source))).exists, false);
        assert.deepEqual(lastRegistered.get(ledgerScope(source)), previous);
        console.log(
          JSON.stringify({ scenario, stage: "not-admitted", ...tooLarge }),
        );
        continue;
      }
      for (const scope of scopes) await seed(scope, scenario.records);
      const putsBefore = blobPuts;
      fault = scenario.stage;
      verificationArmed = false;
      const initial = await invoke();
      assert.equal(initial.result.coverage, "behind");
      assert.equal(initial.result.through[source], "1");
      assert.ok(
        blobPuts > putsBefore,
        "large candidate was not initially admitted",
      );
      const candidates = [...blobPutHistory];
      assert.ok(
        candidates[0].bytes > 48000,
        "regression did not exercise a large journal",
      );
      assert.equal(
        (await journal(ledgerScope(source))).exists,
        true,
        "interrupted intent was lost",
      );
      console.log(
        JSON.stringify({
          scenario,
          stage: "interrupted",
          candidates,
          ...initial,
        }),
      );
      fault = "";
      verificationArmed = false;
      let resumed;
      for (let retry = 0; retry < 5; retry++) {
        await restart();
        resumed = await invoke();
        console.log(
          JSON.stringify({
            scenario,
            stage: "restart",
            attempt: retry + 1,
            blobPuts,
            ...resumed,
          }),
        );
        if (resumed.result.coverage === "complete") break;
      }
      if (scenario.stage === "put-503")
        assert.ok(
          blobPuts > putsBefore + candidates.length,
          "admitted journal livelocked: restart never retried PUT",
        );
      assert.equal(resumed.result.coverage, "complete");
      const total = scenario.records * scopes.length;
      assert.equal(resumed.result.total, total);
      assert.deepEqual(
        resumed.result.through,
        Object.fromEntries(scopes.map((scope) => [scope, "1"])),
      );
      assert.deepEqual(resumed.result.days, [
        { date: "2026-09-28", added: 0 },
        { date: "2026-09-29", added: 0 },
        { date: "2026-09-30", added: 0 },
        { date: "2026-10-01", added: total },
        { date: "2026-10-02", added: 0 },
        { date: "2026-10-03", added: 0 },
        { date: "2026-10-04", added: 0 },
      ]);
      for (const candidate of candidates) {
        const writes = blobPutHistory.filter(
          (write) =>
            write.scope === candidate.scope &&
            write.version === candidate.version,
        );
        assert.ok(
          writes.every(
            (write) =>
              write.version === candidate.version &&
              write.hash === candidate.hash,
          ),
          "retry changed original candidate bytes/version",
        );
        const registered = lastRegistered.get(candidate.scope);
        const rows = await db
          .select()
          .from(schema.dataPointVersions)
          .where(eq(schema.dataPointVersions.id, idFor(candidate.scope)));
        const original = rows.find(
          (row) => row.expectedVersion === candidate.version,
        );
        assert.ok(original, "retry lost original candidate version");
        assert.equal(original.signature.length, 132);
        const ciphertext = await readFile(
          blobPath(`${candidate.scope}/${candidate.version}`),
        );
        assert.equal(keccak256(ciphertext), candidate.hash);
        const plain = await decryptWithPassword(
          ciphertext,
          keyPassword(candidate.scope),
        );
        const envelope = JSON.parse(new TextDecoder().decode(plain));
        assert.equal(original.dataHash, keccak256(plain));
        assert.equal(
          original.metadataHash,
          keccak256(
            stringToHex(
              JSON.stringify({
                scope: candidate.scope,
                collectedAt: envelope.collectedAt,
                sizeBytes: ciphertext.byteLength,
              }),
            ),
          ),
        );
        if (envelope.data.through === "1") {
          assert.equal(
            rows.length,
            1,
            "retry blindly advanced completed candidate version",
          );
          assert.equal(original.dataHash, registered.dataHash);
          assert.equal(original.metadataHash, registered.metadataHash);
        } else {
          assert.equal(envelope.data.through, "0");
          assert.deepEqual(rows.map((row) => row.expectedVersion).sort(), [
            "1",
            "2",
          ]);
          const headPlain = await decryptWithPassword(
            await readFile(blobPath(`${candidate.scope}/2`)),
            keyPassword(candidate.scope),
          );
          assert.equal(
            JSON.parse(new TextDecoder().decode(headPlain)).data.through,
            "1",
          );
        }
        assert.equal((await journal(candidate.scope)).exists, false);
      }
      await assertFullEquality(resumed.result);
    }
    assert.ok(fixturePost > 0);
    console.log(
      JSON.stringify({
        result: "PASS",
        journalRegression: true,
        browserRestarts,
        fixturePost,
        blobPuts,
        fullRuntimeEquality,
        gatewayHead: "d8ed3c09952a4151ab94df30aa905423eca6a29d",
      }),
    );
  } else {
    const attempts = [];
    for (let i = 0; i < 8; i++) {
      const priorBytes = servedBlobBytes;
      const output = await command([
        "eval",
        "--json",
        "(async () => await window.proof())()",
      ]);

      const parsed = JSON.parse(output);
      const value = parsed.data?.result ?? parsed.result ?? parsed;
      const outcome = typeof value === "string" ? JSON.parse(value) : value;
      assert.ok(
        outcome.elapsedMs < 10250,
        "worker session exceeded ten-second bound",
      );
      assert.ok(
        outcome.hostBytesCharged <= 8 * 1024 * 1024,
        "host work exceeded aggregate byte bound",
      );
      attempts.push(outcome);
      console.log(
        JSON.stringify({
          invocation: i + 1,
          ciphertextReadBytes: servedBlobBytes - priorBytes,
          ...outcome,
          result: {
            coverage: outcome.result?.coverage,
            total: outcome.result?.total,
            through: outcome.result?.through,
          },
        }),
      );
      assert.equal(outcome.active, 0);
      if (outcome.result?.coverage === "complete") break;
    }
    const last = attempts.at(-1);
    assert.equal(last.result.coverage, "complete");
    assert.equal(last.result.total, 2);
    await command(["close"]);
    browserSession = `vana12-proof-${process.pid}-${++browserRestarts}`;
    await command(["open", origin]);
    await command(["wait", "--fn", "window.ready === true"]);
    const restarted = await command([
      "eval",
      "--json",
      "(async () => await window.proof())()",
    ]);
    const initialReload = JSON.parse(restarted).data.result;
    assert.equal(initialReload.result.coverage, "complete");
    assert.equal(initialReload.result.total, 2);
    assert.equal(initialReload.active, 0);
    const decode = (output) => {
      const p = JSON.parse(output);
      const result = p.data.result;
      if (result.elapsedMs !== undefined)
        assert.ok(
          result.elapsedMs < 10250,
          "worker session exceeded ten-second bound",
        );
      if (result.hostBytesCharged !== undefined)
        assert.ok(
          result.hostBytesCharged <= 8 * 1024 * 1024,
          "host work exceeded aggregate byte bound",
        );
      return result;
    };
    const interrupted = [];
    for (const [index, stage] of [
      "sign",
      "put",
      "register",
      "verify",
      "stall",
    ].entries()) {
      const version = count + index + 1;
      const collectedAt = new Date(
        Date.UTC(2026, 9, 1, 13, 0, version),
      ).toISOString();
      const data = {
        conversations: [
          { id: "old" },
          { id: "new" },
          ...Array.from({ length: index + 1 }, (_, j) => ({ id: `case-${j}` })),
        ],
      };
      const envelope = createDataFileEnvelope(source, collectedAt, data);
      const plain = new TextEncoder().encode(JSON.stringify(envelope));
      const encrypted = await encryptWithPassword(plain, keyPassword(source));
      await writeFile(blobPath(`${source}/${version}`), encrypted);
      await register({
        scope: source,
        expectedVersion: String(version),
        dataHash: keccak256(plain),
        metadataHash: keccak256(
          stringToHex(
            JSON.stringify({
              scope: source,
              collectedAt,
              sizeBytes: encrypted.byteLength,
            }),
          ),
        ),
        signature: "local-settled-fixture",
      });
      if (stage === "stall") {
        const nextVersion = version + 1;
        const nextCollectedAt = new Date(
          Date.UTC(2026, 9, 1, 13, 0, nextVersion),
        ).toISOString();
        const nextData = {
          padding: randomBytes(256 * 1024).toString("base64"),
          conversations: [...data.conversations, { id: "case-5" }],
        };
        const nextPlain = new TextEncoder().encode(
          JSON.stringify(
            createDataFileEnvelope(source, nextCollectedAt, nextData),
          ),
        );
        const nextEncrypted = await encryptWithPassword(
          nextPlain,
          keyPassword(source),
        );
        await writeFile(blobPath(`${source}/${nextVersion}`), nextEncrypted);
        await register({
          scope: source,
          expectedVersion: String(nextVersion),
          dataHash: keccak256(nextPlain),
          metadataHash: keccak256(
            stringToHex(
              JSON.stringify({
                scope: source,
                collectedAt: nextCollectedAt,
                sizeBytes: nextEncrypted.byteLength,
              }),
            ),
          ),
          signature: "local-settled-fixture",
        });
        faultVersion = String(nextVersion);
      }
      fault = stage === "sign" ? "" : stage;
      const failed = decode(
        await command([
          "eval",
          "--json",
          `(async()=>await window.proof(${stage === "sign"}))()`,
        ]),
      );
      assert.notEqual(
        failed.result.coverage,
        "complete",
        `${stage} claimed complete`,
      );
      assert.equal(failed.active, 0);
      if (stage === "stall") {
        assert.equal(
          failed.result.coverage,
          "behind",
          "budget exhaustion must not be classified as missing history",
        );
        assert.equal(failed.result.through[source], String(version));
        const checkpoint = lastRegistered.get(
          `vana.system.additions.${source}`,
        );
        const bytes = await readFile(
          blobPath(`${checkpoint.scope}/${checkpoint.expectedVersion}`),
        );
        const plain = await decryptWithPassword(
          bytes,
          keyPassword(checkpoint.scope),
        );
        assert.equal(
          JSON.parse(new TextDecoder().decode(plain)).data.through,
          String(version),
          "slow unit lost durable prefix",
        );
      }
      fault = "";
      await command(["close"]);
      browserSession = `vana12-proof-${process.pid}-${++browserRestarts}`;
      await command(["open", origin]);
      await command(["wait", "--fn", "window.ready === true"]);
      let resumed;
      for (let retry = 0; retry < 4; retry++) {
        resumed = decode(
          await command([
            "eval",
            "--json",
            "(async()=>await window.proof())()",
          ]),
        );
        if (resumed.result.coverage === "complete") break;
      }
      assert.equal(
        resumed.result.coverage,
        "complete",
        `${stage} did not resume`,
      );
      assert.equal(
        resumed.result.total,
        3 + index + (stage === "stall" ? 1 : 0),
      );
      assert.equal(resumed.active, 0);
      interrupted.push({
        stage,
        interruptedCoverage: failed.result.coverage,
        hostBytesCharged: failed.hostBytesCharged,
        elapsedMs: failed.elapsedMs,
        restartedTotal: resumed.result.total,
        activeWorkers: resumed.active,
      });
    }
    const noClone = decode(
      await command([
        "eval",
        "--json",
        "(async()=>await window.uploadNoClone())()",
      ]),
    );
    assert.equal(noClone.touched, 0);
    assert.equal(noClone.active, 0);
    const transportCases = [];
    for (const [index, stage] of [
      "declared-length",
      "lying-length",
      "stream-overflow",
      "missing-length",
      "compressed",
    ].entries()) {
      const version = count + 7 + index;
      const collectedAt = new Date(
        Date.UTC(2026, 9, 1, 14, 0, version),
      ).toISOString();
      const data = {
        conversations: [
          { id: "old" },
          { id: "new" },
          ...Array.from({ length: 7 + index }, (_, j) => ({ id: `case-${j}` })),
        ],
        padding: "z".repeat(stage === "compressed" ? 1024 * 1024 : 0),
      };
      const envelope = createDataFileEnvelope(source, collectedAt, data);
      const plain = new TextEncoder().encode(JSON.stringify(envelope));
      const encrypted =
        stage === "compressed"
          ? await encrypt({
              message: await createMessage({ binary: plain }),
              passwords: [keyPassword(source)],
              format: "binary",
              config: { preferredCompressionAlgorithm: enums.compression.zlib },
            })
          : await encryptWithPassword(plain, keyPassword(source));
      await writeFile(blobPath(`${source}/${version}`), encrypted);
      await register({
        scope: source,
        expectedVersion: String(version),
        dataHash: keccak256(plain),
        metadataHash: keccak256(
          stringToHex(
            JSON.stringify({
              scope: source,
              collectedAt,
              sizeBytes: encrypted.byteLength,
            }),
          ),
        ),
        signature: "local-settled-fixture",
      });
      faultVersion = String(version);
      fault = stage;
      const outcome = decode(
        await command(["eval", "--json", "(async()=>await window.proof())()"]),
      );
      assert.equal(outcome.active, 0);
      if (stage === "missing-length") {
        assert.equal(outcome.result.coverage, "complete");
        assert.equal(outcome.result.total, 9 + index);
      } else assert.notEqual(outcome.result.coverage, "complete");
      fault = "";
      if (stage !== "compressed") {
        const resumed = decode(
          await command([
            "eval",
            "--json",
            "(async()=>await window.proof())()",
          ]),
        );
        assert.equal(resumed.result.coverage, "complete");
        assert.equal(resumed.result.total, 9 + index);
      }
      if (stage === "missing-length") {
        await assertFullEquality(outcome.result);
      }
      transportCases.push({
        stage,
        coverage: outcome.result.coverage,
        elapsedMs: outcome.elapsedMs,
        activeWorkers: outcome.active,
      });
    }
    console.log(JSON.stringify({ transportCases, noClone }));
    assert.equal(stalledActive, 0);
    assert.equal(stalledClosed, 1);
    console.log(JSON.stringify({ interrupted, stalledActive, stalledClosed }));
    assert.ok(fixturePost > 0);
    assert.ok(blobPuts > 0);
    console.log(
      JSON.stringify({
        result: "PASS",
        actualBrowser: true,
        actualWorkerArtifact: true,
        browserRestarts,
        fullRuntimeEquality,
        gatewayHead: "d8ed3c09952a4151ab94df30aa905423eca6a29d",
        versions: count,
        attempts: attempts.length,
        fixturePost,
        blobPuts,
        inventoryCalls,
        ciphertextBytes: blobBytes,
        limitations:
          "Actual Gateway POST with real owner signatures and SQL; local simulated settlement; no production or chain transaction",
      }),
    );
  }
  await command(["close"]);
} finally {
  await command(["close"]).catch(() => {});
  await new Promise((resolve) => {
    server.closeAllConnections();
    server.close(resolve);
  });
  if (db) await db.$client.end();
  await pg.stop();
  await rm(root, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}
