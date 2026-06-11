/**
 * End-to-end test of the storage + sync round-trip between two personal
 * servers, against a live gateway + Vana storage.
 *
 * Scenario:
 *   1. A user signs the master-key message (shared identity for both servers).
 *   2. Personal Server A registers itself as a trusted server of the user.
 *   3. A schema for SCOPE is registered on the gateway.
 *   4. The user ingests data into Server A's local store (unsynced).
 *   5. Server A's UPLOAD worker runs: encrypt → upload the version-keyed blob
 *      `{scope}/{version}` to Vana storage → register the DPv2 data point on
 *      the gateway (server-delegated AddData) → stamp the dataPointId.
 *   6. Personal Server B (a *different* server account, but the SAME owner +
 *      master key, with a fresh local store) runs its DOWNLOAD worker:
 *      list the owner's data points from the gateway → reconstruct each blob
 *      URL from (scope, expectedVersion) → download (blob reads are public) →
 *      decrypt with the shared scope key → write + index locally.
 *   7. Assert Server B reconstructed the exact envelope Server A uploaded.
 *
 * This proves the migrated sync workers (upload.ts / download.ts) round-trip
 * real ciphertext through Vana storage, addressed purely by the on-chain
 * DataPointRecord's (scope, expectedVersion) — no URL is stored anywhere.
 *
 * Drives the workers directly (no HTTP server / sync-manager registration
 * gate / tunnel) so the test surface is exactly the two worker functions.
 *
 * Usage:
 *   cd ~/repo/personal-server-ts
 *   npm run e2e:sync
 *
 * Env (read from .env.local if present):
 *   GATEWAY_URL          default: bundled Moksha dev gateway
 *   STORAGE_API_URL      default: https://storage-dev.vana.org
 *   CHAIN_ID             default: 14800
 *   SCOPE                default: instagram.profile
 *
 * Notes / dependencies on the live deployment:
 *   - Server A's blob PUT requires the gateway to confirm A is a trusted
 *     server of the owner (storage middleware → verifyServerDelegation).
 *   - registerDataPoint is signed by Server A's *server* key on behalf of the
 *     owner; the gateway must honor server-delegated AddData. If it doesn't,
 *     step 5 fails with a clear signer/owner error.
 */

import { readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  createGatewayClient,
  deriveMasterKey,
  recoverServerOwner,
  createDataFileEnvelope,
  serverRegistrationDomain,
  SERVER_REGISTRATION_TYPES,
  MASTER_KEY_MESSAGE,
  type DataPortabilityGatewayConfig,
} from "@opendatalabs/vana-sdk/node";

import { initializeDatabase } from "../packages/server/src/storage/index-schema.js";
import { createIndexManager } from "../packages/server/src/storage/index-manager.js";
import { createNodeDataStorage } from "../packages/server/src/storage/node-data-storage.js";
import { readDataFile } from "../packages/server/src/storage/hierarchy.js";
import { loadOrCreateServerAccount } from "../packages/server/src/keys/server-account.js";
import { createVanaSyncStorageAdapter } from "../packages/core/src/storage/adapters/index.js";
import { createServerSigner } from "../packages/core/src/signing/signer.js";
import { uploadAll } from "../packages/core/src/sync/workers/upload.js";
import { downloadAll } from "../packages/core/src/sync/workers/download.js";
import type { SyncCursor } from "../packages/core/src/sync/cursor.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import type { ServerConfig } from "../packages/core/src/schemas/server-config.js";
import type { ServerAccount } from "../packages/core/src/keys/server-account.js";
import type { GatewayConfig } from "../packages/core/src/schemas/server-config.js";
import type { Hex } from "viem";

// ─── .env.local loader ──────────────────────────────────────────────────

loadEnvFile(resolve(process.cwd(), ".env.local"));

function loadEnvFile(path: string): void {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return;
  }
  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] ??= value;
  }
}

// ─── Configuration ───────────────────────────────────────────────────────

const GATEWAY_URL = (
  process.env["GATEWAY_URL"] ??
  "https://data-gateway-env-dev-opendatalabs.vercel.app"
).replace(/\/$/, "");
const STORAGE_API_URL = (
  process.env["STORAGE_API_URL"] ?? "https://storage-dev.vana.org"
).replace(/\/$/, "");
const CHAIN_ID = Number(process.env["CHAIN_ID"] ?? 14800);
const SCOPE = process.env["SCOPE"] ?? "instagram.profile";

const DATA_REFINER_REGISTRY_CONTRACT = (process.env[
  "DATA_REFINER_REGISTRY_CONTRACT"
] ?? "0x93c3EF89369fDcf08Be159D9DeF0F18AB6Be008c") as `0x${string}`;
const SCHEMA_DEFINITION_URL =
  process.env["SCHEMA_DEFINITION_URL"] ??
  "https://example.com/schemas/instagram.profile.json";
const SCHEMA_DIALECT = process.env["SCHEMA_DIALECT"] ?? "json-schema";

const GATEWAY_CONFIG: DataPortabilityGatewayConfig = {
  chainId: CHAIN_ID,
  contracts: {
    dataRegistry:
      process.env["DATA_REGISTRY_CONTRACT"] ??
      "0x8f1eFCdff3d0d5BB535e32620721c7EBed151867",
    dataPortabilityPermissions:
      process.env["DATA_PORTABILITY_PERMISSIONS_CONTRACT"] ??
      "0x4d3FA76064D88e0454cFc4CaD7e5FeC3e3124011",
    dataPortabilityServer:
      process.env["DATA_PORTABILITY_SERVER_CONTRACT"] ??
      "0xCae2CE0e9caa6643ed28186cF57bd40Bd9E17Eab",
    dataPortabilityGrantees:
      process.env["DATA_PORTABILITY_GRANTEES_CONTRACT"] ??
      "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
  },
};

const SCHEMA_REGISTRATION_TYPES = {
  SchemaRegistration: [
    { name: "ownerAddress", type: "address" },
    { name: "name", type: "string" },
    { name: "definitionUrl", type: "string" },
    { name: "scope", type: "string" },
    { name: "dialect", type: "string" },
  ],
} as const;

// ─── Helpers ─────────────────────────────────────────────────────────────

let stepNumber = 0;
function step(msg: string): void {
  stepNumber += 1;
  console.log(`\n[${stepNumber}] ${msg}`);
}

const fmt = (addr: string) => `${addr.slice(0, 6)}…${addr.slice(-4)}`;

async function pollUntil<T>(
  label: string,
  fn: () => Promise<T | null>,
  { timeoutMs = 60_000, intervalMs = 2_000 } = {},
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt += 1;
    try {
      const result = await fn();
      if (result !== null) {
        console.log(`    ✓ ${label} (attempt ${attempt})`);
        return result;
      }
    } catch (err) {
      console.log(`    (attempt ${attempt} failed: ${(err as Error).message})`);
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

function assertEq<T>(actual: T, expected: T, label: string): void {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    throw new Error(`Assertion failed (${label}): expected ${e}, got ${a}`);
  }
  console.log(`    ✓ ${label}`);
}

const logger = {
  info: (obj: unknown, msg?: string) =>
    console.log(`    · ${msg ?? ""} ${summarize(obj)}`),
  error: (obj: unknown, msg?: string) =>
    console.log(`    ✗ ${msg ?? ""} ${summarize(obj)}`),
  warn: (obj: unknown, msg?: string) =>
    console.log(`    ! ${msg ?? ""} ${summarize(obj)}`),
  debug: () => {},
} as unknown as import("../packages/core/src/logger/index.js").Logger;

function summarize(obj: unknown): string {
  if (obj && typeof obj === "object") {
    const o = obj as Record<string, unknown>;
    const keep = ["scope", "version", "dataPointId", "path", "url", "error"];
    const picked = Object.fromEntries(
      keep.filter((k) => k in o).map((k) => [k, o[k]]),
    );
    return Object.keys(picked).length ? JSON.stringify(picked) : "";
  }
  return String(obj ?? "");
}

// A personal server's local-side handle: its own server account + index +
// data-storage port + vana storage adapter + signer, all sharing the owner.
interface ServerSide {
  label: string;
  serverAccount: ServerAccount;
  storage: ReturnType<typeof createNodeDataStorage>;
  storageAdapter: ReturnType<typeof createVanaSyncStorageAdapter>;
  signer: ReturnType<typeof createServerSigner>;
  dataDir: string;
  rootDir: string;
  cleanup(): Promise<void>;
}

async function makeServerSide(
  label: string,
  config: ServerConfig,
  signerGatewayConfig: GatewayConfig,
  serverOwner: `0x${string}`,
): Promise<ServerSide> {
  const rootDir = await mkdtemp(join(tmpdir(), `e2e-sync-${label}-`));
  const dataDir = join(rootDir, "data");
  const db = initializeDatabase(join(rootDir, "index.db"));
  const indexManager = createIndexManager(db);
  const storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
  const serverAccount = loadOrCreateServerAccount(join(rootDir, "key.json"));
  const storageAdapter = createVanaSyncStorageAdapter({
    config,
    serverOwner,
    serverAccount,
  });
  const signer = createServerSigner(serverAccount, signerGatewayConfig);
  return {
    label,
    serverAccount,
    storage,
    storageAdapter,
    signer,
    dataDir,
    rootDir,
    async cleanup() {
      db.close();
      await rm(rootDir, { recursive: true, force: true });
    },
  };
}

// ─── Main ────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  Personal server storage + sync end-to-end (Moksha)");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Gateway:   ${GATEWAY_URL}`);
  console.log(`  Storage:   ${STORAGE_API_URL}`);
  console.log(`  Chain ID:  ${CHAIN_ID}`);
  console.log(`  Scope:     ${SCOPE}`);

  const gateway = createGatewayClient(GATEWAY_URL);

  const config = ServerConfigSchema.parse({
    storage: { backend: "vana", config: { vana: { apiUrl: STORAGE_API_URL } } },
    gateway: {
      url: GATEWAY_URL,
      chainId: CHAIN_ID,
      contracts: GATEWAY_CONFIG.contracts,
    },
  });

  // ─── 1. User identity (shared by both servers) ──────────────────────
  step("Generating user wallet + master-key signature");
  const userAccount = privateKeyToAccount(generatePrivateKey());
  const ownerSignature = (await userAccount.signMessage({
    message: MASTER_KEY_MESSAGE,
  })) as Hex;
  const masterKey = deriveMasterKey(ownerSignature);
  const serverOwner = (await recoverServerOwner(
    ownerSignature,
  )) as `0x${string}`;
  console.log(`    user/owner: ${fmt(userAccount.address)}  (testnet only)`);
  assertEq(
    serverOwner.toLowerCase(),
    userAccount.address.toLowerCase(),
    "serverOwner recovered from signature == user",
  );

  const serverA = await makeServerSide(
    "A",
    config,
    config.gateway,
    serverOwner,
  );
  const serverB = await makeServerSide(
    "B",
    config,
    config.gateway,
    serverOwner,
  );
  console.log(`    server A:   ${fmt(serverA.serverAccount.address)}`);
  console.log(`    server B:   ${fmt(serverB.serverAccount.address)}`);

  try {
    // ─── 2. Server A registers as a trusted server of the owner ───────
    // Required so the storage backend's delegation check lets A's server
    // key PUT into the owner's blob namespace.
    step("Registering Server A as a trusted server on the gateway");
    const serverSig = await userAccount.signTypedData({
      domain: serverRegistrationDomain(GATEWAY_CONFIG),
      types: SERVER_REGISTRATION_TYPES,
      primaryType: "ServerRegistration",
      message: {
        ownerAddress: userAccount.address,
        serverAddress: serverA.serverAccount.address,
        publicKey: serverA.serverAccount.publicKey,
        serverUrl: "https://server-a.e2e.test",
      },
    });
    const serverRes = await gateway.registerServer({
      ownerAddress: userAccount.address,
      serverAddress: serverA.serverAccount.address,
      publicKey: serverA.serverAccount.publicKey,
      serverUrl: "https://server-a.e2e.test",
      signature: serverSig,
    });
    console.log(`    serverId:   ${serverRes.serverId ?? "(none returned)"}`);

    // Wait until the gateway confirms the delegation (storage reads this).
    await pollUntil(
      "gateway reports Server A registered for owner",
      async () =>
        (await gateway.getServer(serverA.serverAccount.address)) ? true : null,
    );

    // ─── 3. Register the schema for SCOPE ─────────────────────────────
    step(`Registering schema for scope=${SCOPE} on the gateway`);
    const schemaId = await registerSchema(userAccount);
    console.log(`    schemaId:   ${schemaId}`);

    // ─── 4. User ingests data into Server A's local store ─────────────
    step("Ingesting data into Server A (unsynced)");
    const collectedAt = new Date().toISOString();
    const payload = { username: "vana_e2e", followers: 42, run: collectedAt };
    const envelope = createDataFileEnvelope(
      SCOPE,
      collectedAt,
      payload,
      SCHEMA_DEFINITION_URL,
      schemaId,
    );
    const write = await serverA.storage.writeEnvelope(envelope);
    serverA.storage.insertEntry({
      fileId: null,
      schemaId,
      path: write.relativePath,
      scope: SCOPE,
      collectedAt,
      sizeBytes: write.sizeBytes,
    });
    const unsynced = serverA.storage.findUnsynced();
    assertEq(unsynced.length, 1, "Server A has 1 unsynced entry");

    // ─── 5. Server A UPLOAD worker → Vana storage + DataPoint ─────────
    step(
      "Running Server A's upload worker (encrypt → store → registerDataPoint)",
    );
    const uploads = await uploadAll({
      storage: serverA.storage,
      storageAdapter: serverA.storageAdapter,
      gateway,
      signer: serverA.signer,
      masterKey,
      serverOwner,
      logger,
    });
    if (uploads.length !== 1) {
      throw new Error(
        `Upload worker produced ${uploads.length} results (expected 1) — check the logs above for the failing step`,
      );
    }
    const uploaded = uploads[0]!;
    console.log(`    dataPointId: ${uploaded.dataPointId}`);
    console.log(`    blob url:    ${uploaded.url}`);
    assertEq(
      serverA.storage.findUnsynced().length,
      0,
      "Server A entry is now synced (dataPointId stamped)",
    );

    // Confirm the encrypted blob is retrievable at the *reconstructed*
    // key URL — i.e. the exact address the download worker derives from
    // (scope, version), not the storage-returned url (which we never
    // persist). This is the real contract the sync round-trip depends on.
    const reconstructedUrl = serverA.storageAdapter.urlForKey(`${SCOPE}/1`);
    await pollUntil("blob is readable at urlForKey(scope/version)", async () =>
      (await serverA.storageAdapter.exists(reconstructedUrl)) ? true : null,
    );

    // ─── 6. Server B DOWNLOAD worker → syncs A's data point ───────────
    step(
      "Running Server B's download worker (list → download → decrypt → index)",
    );
    let cursorValue: string | null = null;
    const cursor: SyncCursor = {
      read: async () => cursorValue,
      write: async (v: string) => {
        cursorValue = v;
      },
    };

    const downloaded = await pollUntil(
      "Server B downloaded the data point",
      async () => {
        const results = await downloadAll({
          storage: serverB.storage,
          storageAdapter: serverB.storageAdapter,
          gateway,
          cursor,
          masterKey,
          serverOwner,
          logger,
        });
        const hit = results.find((r) => r.dataPointId === uploaded.dataPointId);
        return hit ?? null;
      },
    );
    console.log(`    indexed at:  ${downloaded.path}`);

    // ─── 7. Assert Server B reconstructed the exact envelope ──────────
    step("Verifying Server B's synced copy matches Server A's original");
    const bEntry = serverB.storage.findByDataPointId(uploaded.dataPointId);
    if (!bEntry) {
      throw new Error("Server B has no index entry for the data point");
    }
    assertEq(bEntry.scope, SCOPE, "Server B entry scope matches");
    assertEq(
      bEntry.collectedAt,
      collectedAt,
      "Server B entry collectedAt matches",
    );
    assertEq(
      bEntry.dataPointId,
      uploaded.dataPointId,
      "Server B entry dataPointId matches",
    );

    const bEnvelope = await readDataFile(
      { dataDir: serverB.dataDir },
      SCOPE,
      collectedAt,
    );
    assertEq(
      bEnvelope.data,
      payload,
      "Server B decrypted payload matches original",
    );

    // Sanity: the two servers really used different signing keys, and B
    // never re-uploaded — it discovered A's blob purely from the gateway.
    assertEq(
      serverA.serverAccount.address.toLowerCase() !==
        serverB.serverAccount.address.toLowerCase(),
      true,
      "Servers A and B are distinct server accounts",
    );

    // Idempotency: a second download pass dedups on dataPointId, no dupes.
    const second = await downloadAll({
      storage: serverB.storage,
      storageAdapter: serverB.storageAdapter,
      gateway,
      cursor,
      masterKey,
      serverOwner,
      logger,
    });
    assertEq(
      second.some((r) => r.dataPointId === uploaded.dataPointId),
      false,
      "Second download pass dedups the already-synced data point",
    );

    console.log(
      "\n═══════════════════════════════════════════════════════════",
    );
    console.log("  ✅ Storage + sync round-trip PASSED");
    console.log("═══════════════════════════════════════════════════════════");
  } finally {
    await serverA.cleanup().catch(() => {});
    await serverB.cleanup().catch(() => {});
  }
}

/**
 * Register the SCOPE schema on the gateway (POST /v1/schemas, Web3Signed).
 * Tolerates the 409 already-registered case by falling back to a lookup —
 * the schemaId is deterministic for a (scope, definitionUrl, dialect) tuple.
 */
async function registerSchema(
  owner: ReturnType<typeof privateKeyToAccount>,
): Promise<Hex> {
  const gateway = createGatewayClient(GATEWAY_URL);
  const schemaMsg = {
    ownerAddress: owner.address,
    name: `e2e-${SCOPE}`,
    definitionUrl: SCHEMA_DEFINITION_URL,
    scope: SCOPE,
    dialect: SCHEMA_DIALECT,
  };
  const schemaSig = await owner.signTypedData({
    domain: {
      name: "Vana Data Portability",
      version: "1",
      chainId: CHAIN_ID,
      verifyingContract: DATA_REFINER_REGISTRY_CONTRACT,
    },
    types: SCHEMA_REGISTRATION_TYPES,
    primaryType: "SchemaRegistration",
    message: schemaMsg,
  });
  const extractSchemaId = (obj: unknown): Hex | undefined => {
    if (!obj || typeof obj !== "object") return undefined;
    const r = obj as { schemaId?: unknown; id?: unknown };
    const v = r.schemaId ?? r.id;
    return typeof v === "string" ? (v as Hex) : undefined;
  };

  const res = await fetch(`${GATEWAY_URL}/v1/schemas`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Web3Signed ${schemaSig}`,
    },
    body: JSON.stringify(schemaMsg),
  });

  if (res.status === 201 || res.status === 409) {
    const body = await res.json().catch(() => ({}));
    const fromBody = extractSchemaId(body);
    if (fromBody) return fromBody;
    const existing = await gateway.getSchemaForScope(SCOPE);
    const fromLookup = extractSchemaId(existing);
    if (fromLookup) return fromLookup;
    throw new Error(
      `Schema ${res.status} but no schemaId in body or lookup: ${JSON.stringify(body)}`,
    );
  }
  throw new Error(
    `Schema registration failed: ${res.status} ${await res.text()}`,
  );
}

main().catch((err) => {
  console.error("\n✗ e2e-storage-sync failed:", err);
  process.exit(1);
});
