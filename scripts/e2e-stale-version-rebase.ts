/**
 * End-to-end test of the BUI-540 stale-expectedVersion recovery paths in the
 * upload worker, against a live gateway + Vana storage.
 *
 * Scenario (one owner, one registered server account, three local stores —
 * modelling "same machine, rebuilt index" / a second replica whose per-scope
 * version sequence is behind the registry):
 *
 *   1. Store 1 ingests envelope X (local version 1) and uploads — registers
 *      the scope's data point at version 1.
 *   2. Store 2 (fresh index, same content X, local version 1) uploads — the
 *      gateway 409s; the worker sees the registered dataHash matches and
 *      ADOPTS the existing data point. No new version, no error.
 *   3. Store 3 (fresh index, different content Y, local version 1) uploads —
 *      the gateway 409s; the hash differs, so the worker REBASES: re-uploads
 *      the blob under `{scope}/2`, re-signs at version 2, registers, and
 *      persists version 2 on its index row.
 *   4. A fresh Store 4 runs the download worker and must reconstruct envelope
 *      Y purely from the registry record (scope, expectedVersion=2) — proving
 *      the rebased blob key lines up with what replicas derive.
 *
 * Usage:
 *   GATEWAY_URL=https://dp-rpc-dev.vana.org npx tsx scripts/e2e-stale-version-rebase.ts
 *
 * Env (read from .env.local if present): GATEWAY_URL, STORAGE_API_URL,
 * CHAIN_ID, SCOPE — same defaults as e2e-storage-sync.ts.
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
import {
  uploadAll,
  computeDataPointId,
} from "../packages/core/src/sync/workers/upload.js";
import { downloadAll } from "../packages/core/src/sync/workers/download.js";
import type { SyncCursor } from "../packages/core/src/sync/cursor.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import type { ServerConfig } from "../packages/core/src/schemas/server-config.js";
import type { ServerAccount } from "../packages/core/src/keys/server-account.js";
import type { Hex } from "viem";

// ─── .env.local loader (same as e2e-storage-sync) ───────────────────────

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
  process.env["GATEWAY_URL"] ?? "https://dp-rpc-dev.vana.org"
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

// A local store side. Unlike e2e-storage-sync's makeServerSide, the server
// account is INJECTED so several stores can share one registered server —
// modelling a rebuilt index / replica whose local versions restarted at 1.
interface StoreSide {
  label: string;
  storage: ReturnType<typeof createNodeDataStorage>;
  storageAdapter: ReturnType<typeof createVanaSyncStorageAdapter>;
  signer: ReturnType<typeof createServerSigner>;
  dataDir: string;
  cleanup(): Promise<void>;
}

async function makeStoreSide(
  label: string,
  config: ServerConfig,
  serverAccount: ServerAccount,
  serverOwner: `0x${string}`,
): Promise<StoreSide> {
  const rootDir = await mkdtemp(join(tmpdir(), `e2e-rebase-${label}-`));
  const dataDir = join(rootDir, "data");
  const db = initializeDatabase(join(rootDir, "index.db"));
  const indexManager = createIndexManager(db);
  const storage = createNodeDataStorage({
    indexManager,
    hierarchyOptions: { dataDir },
  });
  const storageAdapter = createVanaSyncStorageAdapter({
    config,
    serverOwner,
    serverAccount,
  });
  const signer = createServerSigner(serverAccount, config.gateway);
  return {
    label,
    storage,
    storageAdapter,
    signer,
    dataDir,
    async cleanup() {
      db.close();
      await rm(rootDir, { recursive: true, force: true });
    },
  };
}

function uploadDeps(side: StoreSide, shared: SharedDeps) {
  return {
    storage: side.storage,
    storageAdapter: side.storageAdapter,
    gateway: shared.gateway,
    signer: side.signer,
    masterKey: shared.masterKey,
    serverOwner: shared.serverOwner,
    logger,
  };
}

interface SharedDeps {
  gateway: ReturnType<typeof createGatewayClient>;
  masterKey: Uint8Array;
  serverOwner: `0x${string}`;
}

function ingest(
  side: StoreSide,
  envelope: ReturnType<typeof createDataFileEnvelope>,
  schemaId: Hex,
): Promise<void> {
  return Promise.resolve(side.storage.writeEnvelope(envelope)).then((write) => {
    side.storage.insertEntry({
      fileId: null,
      schemaId,
      path: write.relativePath,
      scope: envelope.scope,
      collectedAt: envelope.collectedAt,
      sizeBytes: write.sizeBytes,
    });
  });
}

// ─── Main ────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  BUI-540: stale-expectedVersion adopt/rebase end-to-end");
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

  const shared: SharedDeps = { gateway, masterKey, serverOwner };
  const keyDir = await mkdtemp(join(tmpdir(), "e2e-rebase-key-"));
  const serverAccount = loadOrCreateServerAccount(join(keyDir, "key.json"));
  console.log(`    server:     ${fmt(serverAccount.address)}`);

  const store1 = await makeStoreSide("s1", config, serverAccount, serverOwner);
  const store2 = await makeStoreSide("s2", config, serverAccount, serverOwner);
  const store3 = await makeStoreSide("s3", config, serverAccount, serverOwner);
  const store4 = await makeStoreSide("s4", config, serverAccount, serverOwner);

  try {
    step("Registering the server as a trusted server on the gateway");
    const serverSig = await userAccount.signTypedData({
      domain: serverRegistrationDomain(GATEWAY_CONFIG),
      types: SERVER_REGISTRATION_TYPES,
      primaryType: "ServerRegistration",
      message: {
        ownerAddress: userAccount.address,
        serverAddress: serverAccount.address,
        publicKey: serverAccount.publicKey,
        serverUrl: "https://rebase.e2e.test",
      },
    });
    await gateway.registerServer({
      ownerAddress: userAccount.address,
      serverAddress: serverAccount.address,
      publicKey: serverAccount.publicKey,
      serverUrl: "https://rebase.e2e.test",
      signature: serverSig,
    });
    await pollUntil("gateway reports the server registered", async () =>
      (await gateway.getServer(serverAccount.address)) ? true : null,
    );

    step(`Registering schema for scope=${SCOPE}`);
    const schemaId = await registerSchema(userAccount);
    console.log(`    schemaId:   ${schemaId}`);

    // ─── Baseline: store 1 registers version 1 ────────────────────────
    step("Store 1: ingest envelope X and upload (registers version 1)");
    const collectedAtX = new Date().toISOString();
    const envelopeX = createDataFileEnvelope(
      SCOPE,
      collectedAtX,
      { who: "store1", payload: "X" },
      SCHEMA_DEFINITION_URL,
      schemaId,
    );
    await ingest(store1, envelopeX, schemaId);
    const up1 = await uploadAll(uploadDeps(store1, shared), {
      onError: (_e, err) => console.log(`    ✗ store1 upload: ${err.message}`),
    });
    assertEq(up1.length, 1, "store 1 uploaded");
    const registryId = computeDataPointId(serverOwner, SCOPE);
    const recordV1 = await gateway.getDataPoint(registryId);
    assertEq(recordV1?.expectedVersion, "1", "registry at version 1");

    // ─── Adopt: same content, colliding local version 1 ───────────────
    step("Store 2: same envelope X at local version 1 → expect ADOPT");
    await ingest(store2, envelopeX, schemaId);
    const up2 = await uploadAll(uploadDeps(store2, shared), {
      onError: (_e, err) => console.log(`    ✗ store2 upload: ${err.message}`),
    });
    assertEq(up2.length, 1, "store 2 upload succeeded (no head-block)");
    assertEq(
      up2[0]!.dataPointId,
      registryId,
      "store 2 adopted the registered data point",
    );
    const recordAfterAdopt = await gateway.getDataPoint(registryId);
    assertEq(
      recordAfterAdopt?.expectedVersion,
      "1",
      "adopt minted no new version",
    );
    assertEq(
      store2.storage.findUnsynced().length,
      0,
      "store 2 entry stamped synced",
    );

    // ─── Rebase: different content, colliding local version 1 ─────────
    step("Store 3: new envelope Y at local version 1 → expect REBASE to 2");
    const collectedAtY = new Date(Date.now() + 1000).toISOString();
    const envelopeY = createDataFileEnvelope(
      SCOPE,
      collectedAtY,
      { who: "store3", payload: "Y" },
      SCHEMA_DEFINITION_URL,
      schemaId,
    );
    await ingest(store3, envelopeY, schemaId);
    const up3 = await uploadAll(uploadDeps(store3, shared), {
      onError: (_e, err) => console.log(`    ✗ store3 upload: ${err.message}`),
    });
    assertEq(up3.length, 1, "store 3 upload succeeded (no head-block)");
    const recordAfterRebase = await gateway.getDataPoint(registryId);
    assertEq(
      recordAfterRebase?.expectedVersion,
      "2",
      "registry advanced to version 2",
    );
    const store3Entry = store3.storage.findEntry({
      scope: SCOPE,
      collectedAt: collectedAtY,
    });
    assertEq(store3Entry?.version, 2, "store 3 index row rebased to version 2");
    assertEq(
      store3.storage.findUnsynced().length,
      0,
      "store 3 entry stamped synced",
    );

    // ─── Round-trip: a fresh replica reconstructs Y from the registry ──
    step("Store 4: download worker reconstructs envelope Y from (scope, v2)");
    let cursorValue: string | null = null;
    const cursor: SyncCursor = {
      read: async () => cursorValue,
      write: async (v: string) => {
        cursorValue = v;
      },
    };
    await pollUntil("store 4 downloaded the rebased data point", async () => {
      const results = await downloadAll({
        storage: store4.storage,
        storageAdapter: store4.storageAdapter,
        gateway,
        cursor,
        masterKey,
        serverOwner,
        logger,
      });
      return results.find((r) => r.dataPointId === registryId) ?? null;
    });
    const downloaded = await readDataFile(
      { dataDir: store4.dataDir },
      SCOPE,
      collectedAtY,
    );
    assertEq(
      downloaded.data,
      envelopeY.data,
      "store 4 decrypted the rebased version's content (Y)",
    );

    console.log("\n═══════════════════════════════════════════════════════");
    console.log("  ✓ BUI-540 adopt + rebase + round-trip all passed");
    console.log("═══════════════════════════════════════════════════════");
  } finally {
    await store1.cleanup();
    await store2.cleanup();
    await store3.cleanup();
    await store4.cleanup();
    await rm(keyDir, { recursive: true, force: true });
  }
}

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
  console.error("\n✗ e2e-stale-version-rebase failed:", err);
  process.exitCode = 1;
});
