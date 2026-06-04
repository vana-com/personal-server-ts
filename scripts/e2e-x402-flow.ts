/**
 * End-to-end test of the personal server's full canary flow against a
 * live gateway + Moksha L1.
 *
 * Scenario:
 *   1. A user spins up their own personal server.
 *   2. The user registers it on the gateway as a trusted server of their wallet.
 *   3. An app registers itself as a builder.
 *   4. The app pre-funds its escrow with VANA so it can pay for reads.
 *   5. The user POSTs personal data to the server (instagram.profile).
 *   6. The user grants the app permission to read that scope via the server.
 *   7. The app does a GET, hits the X402 paywall, signs the payment, retries.
 *   8. The gateway accepts the payment, the server serves the envelope.
 *
 * This script lives outside packages/* so the SDK is resolved as a
 * downstream consumer would resolve it. Runs the personal-server in-process
 * on a random port and drives every endpoint via plain fetch.
 *
 * Usage:
 *   cd ~/repo/personal-server-ts
 *   FUNDER_PRIVATE_KEY=0x... \
 *   GATEWAY_URL=https://data-gateway-... \
 *   npm run e2e:x402
 *
 * Env (read from .env.local if present):
 *   GATEWAY_URL                             default: bundled Moksha dev gateway
 *   RPC_URL                                 default: https://rpc.moksha.vana.org
 *   CHAIN_ID                                default: 14800
 *   DATA_PORTABILITY_ESCROW_CONTRACT        default: config.gateway.contracts.dataPortabilityEscrow
 *   FUNDER_PRIVATE_KEY                      pre-funded wallet that bankrolls the app's escrow
 *   DEPOSIT_AMOUNT                          default: 0.1 (VANA)
 *   SCOPE                                   default: instagram.profile
 *   APP_URL                                 default: https://example-app.test
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  formatEther,
  http,
  keccak256,
  parseEther,
  stringToHex,
  type Hex,
  type PublicClient,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { serve, type ServerType } from "@hono/node-server";
import {
  ADD_DATA_TYPES,
  BUILDER_REGISTRATION_TYPES,
  FILE_REGISTRATION_TYPES,
  GENERIC_PAYMENT_TYPES,
  MASTER_KEY_MESSAGE,
  NATIVE_VANA_ASSET,
  SERVER_REGISTRATION_TYPES,
  builderRegistrationDomain,
  buildDepositNativeRequest,
  createGatewayClient,
  dataRegistryDomain,
  escrowPaymentDomain,
  fileRegistrationDomain,
  getFee,
  serverRegistrationDomain,
  type DataPortabilityGatewayConfig,
  type FeeKind,
} from "@opendatalabs/vana-sdk/node";
import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/node";
import type {
  SettleItem,
  SettleReconcileItem,
} from "@opendatalabs/vana-sdk/node";
import {
  encodePaymentHeader,
  nextPaymentNonce,
  type X402Challenge,
} from "../packages/core/src/payment/index.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import { createServer } from "../packages/server/src/bootstrap.js";
import type { IndexManager } from "@opendatalabs/personal-server-ts-core/storage/index";
import type { ServerAccount } from "../packages/core/src/keys/server-account.js";

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
const RPC_URL = process.env["RPC_URL"] ?? "https://rpc.moksha.vana.org";
const CHAIN_ID = Number(process.env["CHAIN_ID"] ?? 14800);

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
    dataPortabilityEscrow:
      process.env["DATA_PORTABILITY_ESCROW_CONTRACT"] ??
      "0x07d7769081adc3a3DBe91f5E4B98E9A5a6B292e3",
    feeRegistry:
      process.env["FEE_REGISTRY_CONTRACT"] ??
      "0xb4FA18443E0FA6cdC0280D20b8cCDB2377D13Bf2",
  },
};

const FUNDER_PRIVATE_KEY = (process.env["FUNDER_PRIVATE_KEY"] ??
  "0x1cd2368879e231202c7dd07932622ab903ce061d470101bb7a53a897047b2aa8") as Hex;
const DEPOSIT_AMOUNT = parseEther(process.env["DEPOSIT_AMOUNT"] ?? "0.1");
const SCOPE = process.env["SCOPE"] ?? "instagram.profile";
const APP_URL = process.env["APP_URL"] ?? "https://example-app.test";
const POLL_INTERVAL_MS = 2_000;
const POLL_TIMEOUT_MS = 120_000;

// DataRefinerRegistry — verifyingContract for the gateway's POST /v1/schemas
// EIP-712 domain. Same on Moksha + mainnet per the canonical Vana SDK
// address book. The SDK does NOT export a schema-registration helper; we
// hand-build the typed data below.
const DATA_REFINER_REGISTRY_CONTRACT = (process.env[
  "DATA_REFINER_REGISTRY_CONTRACT"
] ?? "0x93c3EF89369fDcf08Be159D9DeF0F18AB6Be008c") as `0x${string}`;
const SCHEMA_DEFINITION_URL =
  process.env["SCHEMA_DEFINITION_URL"] ??
  "https://example.com/schemas/instagram.profile.json";
const SCHEMA_DIALECT = process.env["SCHEMA_DIALECT"] ?? "json-schema";

// EIP-712 type for gateway's POST /v1/schemas. Mirrors data-gateway's
// SCHEMA_REGISTRATION_TYPES exactly — kept in-script because the SDK
// doesn't currently export these for schema registration.
const SCHEMA_REGISTRATION_TYPES = {
  SchemaRegistration: [
    { name: "ownerAddress", type: "address" },
    { name: "name", type: "string" },
    { name: "definitionUrl", type: "string" },
    { name: "scope", type: "string" },
    { name: "dialect", type: "string" },
  ],
} as const;

const moksha = defineChain({
  id: CHAIN_ID,
  name: "Vana Moksha",
  nativeCurrency: { name: "VANA", symbol: "VANA", decimals: 18 },
  rpcUrls: { default: { http: [RPC_URL] } },
});

// ─── Helpers ─────────────────────────────────────────────────────────────

let stepNumber = 0;
function step(msg: string): void {
  stepNumber += 1;
  console.log(`\n[${stepNumber}] ${msg}`);
}

async function pollUntil<T>(
  label: string,
  fn: () => Promise<T | null>,
  timeoutMs = POLL_TIMEOUT_MS,
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
    await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
  }
  throw new Error(`Timed out waiting for: ${label}`);
}

function uncompressedPublicKey(privateKey: Hex): Hex {
  // viem's privateKeyToAccount().publicKey is the 65-byte uncompressed form
  // (0x04 || X || Y) — matches what the gateway stores for builders.
  return privateKeyToAccount(privateKey).publicKey as Hex;
}

function assertEq<T>(actual: T, expected: T, label: string): void {
  if (actual !== expected) {
    throw new Error(
      `Assertion failed (${label}): expected ${JSON.stringify(
        expected,
      )}, got ${JSON.stringify(actual)}`,
    );
  }
}

// On-chain escrow balance probe. The SDK doesn't export a read ABI for
// DataPortabilityEscrow, so we try a few common function names and cache
// the first one that succeeds.
type EscrowProbeAbi = readonly {
  type: "function";
  name: string;
  stateMutability: "view";
  inputs: readonly { type: "address" }[];
  outputs: readonly { type: "uint256" }[];
}[];
type EscrowBalanceProbe = { fn: string; abi: EscrowProbeAbi } | { fn: null };
let escrowProbeCache: EscrowBalanceProbe | undefined;
async function readOnChainAccountEscrow(
  client: PublicClient,
  escrowAddr: `0x${string}`,
  account: `0x${string}`,
  asset: `0x${string}`,
): Promise<{ amount: bigint; via: string } | null> {
  const candidates = ["balances", "getBalance", "balanceOf", "accountBalance"];
  const mkAbi = (fn: string) =>
    [
      {
        type: "function",
        name: fn,
        stateMutability: "view",
        inputs: [{ type: "address" }, { type: "address" }],
        outputs: [{ type: "uint256" }],
      },
    ] as const;
  if (escrowProbeCache?.fn === null) return null;
  if (escrowProbeCache && escrowProbeCache.fn) {
    try {
      const v = (await client.readContract({
        address: escrowAddr,
        abi: escrowProbeCache.abi,
        functionName: escrowProbeCache.fn,
        args: [account, asset],
      })) as unknown as bigint;
      return { amount: v, via: escrowProbeCache.fn };
    } catch {
      // Cached function suddenly stopped working — fall through to re-probe.
    }
  }
  for (const fn of candidates) {
    try {
      const abi = mkAbi(fn);
      const v = (await client.readContract({
        address: escrowAddr,
        abi,
        functionName: fn,
        args: [account, asset],
      })) as unknown as bigint;
      escrowProbeCache = { fn, abi };
      return { amount: v, via: fn };
    } catch {
      // try next
    }
  }
  escrowProbeCache = { fn: null };
  return null;
}

// Address-label registry. Populated as each actor is created, then used by
// fmt() to render any address as "0x... (label)" wherever we know it.
const addressLabels = new Map<string, string>();
function labelAddress(addr: string, label: string): void {
  addressLabels.set(addr.toLowerCase(), label);
}
function fmt(addr: string | null | undefined): string {
  if (!addr) return "(none)";
  const label = addressLabels.get(addr.toLowerCase());
  return label ? `${addr} (${label})` : addr;
}

// ─── Personal server bootstrap ───────────────────────────────────────────

interface PersonalServerHandle {
  url: string;
  // Exposed so the e2e can hand-craft the on-chain registrations that the
  // disabled sync/upload worker would normally perform — AddData (data
  // point) and FileRegistration. The server account signs FileRegistration
  // because the URL is only known to the server in production.
  indexManager: IndexManager;
  serverAccount: ServerAccount;
  dataDir: string;
  cleanup(): Promise<void>;
}

async function startPersonalServer(params: {
  ownerSignature: Hex;
  serverDir: string;
}): Promise<PersonalServerHandle> {
  // Reserve a port by binding ephemeral, then closing.
  const ephemeral: ServerType = serve({
    fetch: () => new Response(),
    port: 0,
  });
  const addr = ephemeral.address();
  if (!addr || typeof addr === "string") {
    throw new Error("Failed to allocate a port");
  }
  const port = (addr as AddressInfo).port;
  await new Promise<void>((resolve, reject) => {
    ephemeral.close((err) => (err ? reject(err) : resolve()));
  });

  const config = ServerConfigSchema.parse({
    server: { port, origin: `http://localhost:${port}` },
    logging: { level: "info", pretty: false },
    // X402 enforcement on every builder read.
    payment: { enabled: true },
    // Local-only run — no tunnel, no sync.
    tunnel: { enabled: false },
    sync: { enabled: false },
    gateway: {
      url: GATEWAY_URL,
      chainId: CHAIN_ID,
      contracts: GATEWAY_CONFIG.contracts,
    },
  });

  process.env.VANA_MASTER_KEY_SIGNATURE = params.ownerSignature;

  const dataDir = join(params.serverDir, "data");
  const context = await createServer(config, {
    serverDir: params.serverDir,
    dataDir,
  });
  if (!context.serverAccount) {
    throw new Error(
      "Personal server didn't provision a serverAccount — master-key signature missing?",
    );
  }

  const httpServer: ServerType = serve({
    fetch: context.app.fetch,
    port,
  });

  return {
    url: `http://localhost:${port}`,
    indexManager: context.indexManager,
    serverAccount: context.serverAccount,
    dataDir,
    async cleanup() {
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
      await context.cleanup();
    },
  };
}

// ─── Main ────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  Personal server X402 end-to-end (Moksha)");
  console.log("═══════════════════════════════════════════════════════════");
  console.log(`  Gateway:        ${GATEWAY_URL}`);
  console.log(`  RPC:            ${RPC_URL}`);
  console.log(`  Chain ID:       ${CHAIN_ID}`);
  console.log(
    `  Escrow:         ${GATEWAY_CONFIG.contracts.dataPortabilityEscrow}`,
  );
  console.log(`  Scope:          ${SCOPE}`);

  const publicClient = createPublicClient({
    chain: moksha,
    transport: http(RPC_URL),
  });
  const gateway = createGatewayClient(GATEWAY_URL);

  // ─── 1. Generate fresh wallets ─────────────────────────────────────
  step("Generating fresh user + app wallets");
  const userPrivateKey = generatePrivateKey();
  const userAccount = privateKeyToAccount(userPrivateKey);
  const appPrivateKey = generatePrivateKey();
  const appAccount = privateKeyToAccount(appPrivateKey);
  const appPublicKey = uncompressedPublicKey(appPrivateKey);
  labelAddress(userAccount.address, "user");
  labelAddress(appAccount.address, "app/builder");
  console.log(`    user:    ${fmt(userAccount.address)}  (testnet only)`);
  console.log(`    app:     ${fmt(appAccount.address)}  (testnet only)`);

  // ─── 2. User signs the master-key message, boots personal-server ───
  step("User signs MASTER_KEY_MESSAGE and starts the personal server");
  const ownerSignature = (await userAccount.signMessage({
    message: MASTER_KEY_MESSAGE,
  })) as Hex;
  console.log(`    signature: ${ownerSignature.slice(0, 18)}…`);

  const serverDir = await mkdtemp(join(tmpdir(), "e2e-ps-x402-"));
  const ps = await startPersonalServer({ ownerSignature, serverDir });
  labelAddress(ps.serverAccount.address, "personal-server");
  console.log(`    server URL: ${ps.url}`);
  console.log(`    server acc: ${fmt(ps.serverAccount.address)}`);
  console.log(`    dataDir:    ${serverDir}`);

  try {
    // ─── 3. Read the server identity health endpoint ──────────────────
    step("Reading personal-server /health for the derived server address");
    const healthRes = await fetch(`${ps.url}/health`);
    const health = (await healthRes.json()) as {
      identity?: {
        address: `0x${string}`;
        publicKey: `0x${string}`;
        serverId: string | null;
      };
      owner?: `0x${string}`;
    };
    if (!health.identity) {
      throw new Error("Personal server didn't report identity");
    }
    const serverAddress = health.identity.address;
    const serverPublicKey = health.identity.publicKey;
    const ownerFromHealth = health.owner;
    if (ownerFromHealth?.toLowerCase() !== userAccount.address.toLowerCase()) {
      throw new Error(
        `serverOwner mismatch: health=${ownerFromHealth} expected=${userAccount.address}`,
      );
    }
    console.log(`    serverAddr: ${serverAddress}`);

    // ─── 4. User registers the personal server on the gateway ─────────
    step(
      "User registering the personal server on-chain via gateway.registerServer",
    );
    // `serverUrl` is stored opaquely; gateway doesn't probe it.
    const localServerUrl = `${ps.url}`;
    const serverSig = await userAccount.signTypedData({
      domain: serverRegistrationDomain(GATEWAY_CONFIG),
      types: SERVER_REGISTRATION_TYPES,
      primaryType: "ServerRegistration",
      message: {
        ownerAddress: userAccount.address,
        serverAddress,
        publicKey: serverPublicKey,
        serverUrl: localServerUrl,
      },
    });
    const serverRes = await gateway.registerServer({
      ownerAddress: userAccount.address,
      serverAddress,
      publicKey: serverPublicKey,
      serverUrl: localServerUrl,
      signature: serverSig,
    });
    if (!serverRes.serverId) {
      throw new Error("registerServer didn't return a serverId");
    }
    const serverId = serverRes.serverId as Hex;
    console.log(`    serverId:   ${serverId}`);

    // ─── 5. App wallet registers itself as a builder ───────────────────
    step("App registering itself as a builder");
    const builderSig = await appAccount.signTypedData({
      domain: builderRegistrationDomain(GATEWAY_CONFIG),
      types: BUILDER_REGISTRATION_TYPES,
      primaryType: "BuilderRegistration",
      message: {
        ownerAddress: appAccount.address,
        granteeAddress: appAccount.address,
        publicKey: appPublicKey,
        appUrl: APP_URL,
      },
    });
    const builderRes = await gateway.registerBuilder({
      ownerAddress: appAccount.address,
      granteeAddress: appAccount.address,
      publicKey: appPublicKey,
      appUrl: APP_URL,
      signature: builderSig,
    });
    if (!builderRes.builderId) {
      throw new Error("registerBuilder didn't return a builderId");
    }
    const builderId = builderRes.builderId as Hex;
    console.log(`    builderId:  ${builderId}`);

    // (The funder deposit is deferred until AFTER grant creation so we can
    // size it from the grant's actual fee — gateway FeeRegistry values
    // change deployment-to-deployment, and a fixed default tends to under-
    // or over-provision.)

    // ─── 6. Builder registers the schema for SCOPE on the gateway ────
    // Schemas live in DataRefinerRegistry — they describe a data type the
    // builder/refiner intends to consume. The builder (the app here) is
    // the natural registrant: the gateway records `ownerAddress` as the
    // schema owner, and the app is the entity that defined the shape.
    step(`Builder registering schema for scope=${SCOPE} on the gateway`);
    const schemaMsg = {
      ownerAddress: appAccount.address,
      name: `e2e-${SCOPE}`,
      definitionUrl: SCHEMA_DEFINITION_URL,
      scope: SCOPE,
      dialect: SCHEMA_DIALECT,
    };
    const schemaSig = await appAccount.signTypedData({
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
    const schemaRes = await fetch(`${GATEWAY_URL}/v1/schemas`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Web3Signed ${schemaSig}`,
      },
      body: JSON.stringify(schemaMsg),
    });
    let registeredSchemaId: Hex | undefined;
    // The gateway uses `id` as the canonical bytes32 field on schema records;
    // create responses often surface `schemaId` as an alias. Read both.
    const extractSchemaId = (obj: unknown): Hex | undefined => {
      if (!obj || typeof obj !== "object") return undefined;
      const r = obj as { schemaId?: unknown; id?: unknown };
      const v = r.schemaId ?? r.id;
      return typeof v === "string" ? (v as Hex) : undefined;
    };
    if (schemaRes.status === 201) {
      const schemaBody = await schemaRes.json().catch(() => ({}));
      registeredSchemaId = extractSchemaId(schemaBody);
      if (!registeredSchemaId) {
        console.log(`    create body: ${JSON.stringify(schemaBody)}`);
      }
      console.log(
        `    schemaId:   ${registeredSchemaId ?? "(missing in 201 body)"}`,
      );
    } else if (schemaRes.status === 409) {
      // Deterministic schemaId — re-running the e2e with the same SCOPE
      // (+ same definitionUrl + dialect) lands on an already-registered
      // row. 409 body shape isn't consistent, so we fall back to a lookup.
      const schemaBody = await schemaRes.json().catch(() => ({}));
      registeredSchemaId = extractSchemaId(schemaBody);
      if (!registeredSchemaId) {
        const existing = await gateway.getSchemaForScope(SCOPE);
        registeredSchemaId = extractSchemaId(existing);
        if (!registeredSchemaId) {
          console.log(`    409 body:   ${JSON.stringify(schemaBody)}`);
          console.log(`    lookup body: ${JSON.stringify(existing)}`);
        }
      }
      console.log(
        `    schemaId:   ${registeredSchemaId ?? "(already registered, lookup failed)"} — 409 conflict, continuing`,
      );
    } else {
      throw new Error(
        `Schema registration failed: ${schemaRes.status} ${await schemaRes.text()}`,
      );
    }

    // ─── 7. User POSTs personal data to the personal server ─────────
    step(`User posting data to personal server at scope=${SCOPE}`);
    const body = { username: "vana_e2e", followers: 42 };
    const bodyStr = JSON.stringify(body);
    const bodyBytes = new TextEncoder().encode(bodyStr);
    const postAuth = await buildWeb3SignedHeader({
      signMessage: async (m: string) =>
        (await userAccount.signMessage({ message: m })) as Hex,
      aud: ps.url,
      method: "POST",
      uri: `/v1/data/${SCOPE}`,
      body: bodyBytes,
    });
    const ingestRes = await fetch(`${ps.url}/v1/data/${SCOPE}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: postAuth },
      body: bodyStr,
    });
    if (ingestRes.status !== 201) {
      throw new Error(
        `Ingest failed: ${ingestRes.status} ${await ingestRes.text()}`,
      );
    }
    const ingestBody = (await ingestRes.json()) as {
      scope: string;
      collectedAt: string;
    };
    console.log(
      `    stored:     scope=${ingestBody.scope} collectedAt=${ingestBody.collectedAt}`,
    );

    // ─── 7.5 Register the ingested envelope as a DPv2 data point ──────
    //
    // The personal server's upload worker would normally do this (sync
    // worker → gateway.registerDataPoint → indexManager.updateDataPointId).
    // We've disabled sync to keep the e2e storage-backend-free, so we
    // perform the on-chain registration here using:
    //   • the personal server's IndexEntry for hash inputs
    //   • the USER wallet for AddData EIP-712 signing — unlike grants,
    //     the gateway enforces `recovered(signature) == ownerAddress` for
    //     AddData with no trusted-server delegation path (off-chain), so
    //     the owner has to sign directly here
    //   • a direct gateway.registerDataPoint call
    // After it lands we patch IndexEntry.dataPointId so the next X402
    // challenge embeds an `accessRecord` → `access` settle op gets queued
    // alongside grant/server/data.
    step("Registering ingested data on-chain via gateway.registerDataPoint");
    const ingestedEntry = ps.indexManager.findLatestByScope(SCOPE);
    if (!ingestedEntry) {
      throw new Error(`personal server has no IndexEntry for scope=${SCOPE}`);
    }
    if (ingestedEntry.dataPointId) {
      throw new Error(
        `expected dataPointId to be null pre-registration, got ${ingestedEntry.dataPointId}`,
      );
    }
    // Mirror the upload worker's commitment recipe (see
    // packages/core/src/sync/workers/upload.ts ~L84-L110). We hash the
    // in-memory canonical JSON of the envelope, NOT the pretty-printed
    // on-disk bytes — readEnvelope deserializes, then we re-stringify
    // compactly so the hash matches the worker's path exactly.
    const envelopeJsonOnDisk = readFileSync(
      join(ps.dataDir, ingestedEntry.path),
      "utf-8",
    );
    const ingestedEnvelope = JSON.parse(envelopeJsonOnDisk);
    const ingestedPlaintext = new TextEncoder().encode(
      JSON.stringify(ingestedEnvelope),
    );
    const dataHash = keccak256(ingestedPlaintext);
    const metadataHash = keccak256(
      stringToHex(
        JSON.stringify({
          scope: ingestedEntry.scope,
          collectedAt: ingestedEntry.collectedAt,
          schemaId: ingestedEntry.schemaId,
          // The upload worker uses encrypted.byteLength here. We've skipped
          // encryption, so plaintext byteLength stands in. On-chain this is
          // just an opaque bytes32 — the contract doesn't reinterpret it.
          sizeBytes: ingestedPlaintext.byteLength,
        }),
      ),
    );
    const addDataMessage = {
      ownerAddress: userAccount.address,
      scope: ingestedEntry.scope,
      dataHash,
      metadataHash,
      expectedVersion: BigInt(ingestedEntry.version),
    };
    const addDataSignature = await userAccount.signTypedData({
      domain: dataRegistryDomain(GATEWAY_CONFIG),
      types: ADD_DATA_TYPES,
      primaryType: "AddData",
      message: addDataMessage,
    });
    const dataPointResult = await gateway.registerDataPoint({
      ownerAddress: userAccount.address,
      scope: ingestedEntry.scope,
      dataHash,
      metadataHash,
      expectedVersion: String(ingestedEntry.version),
      signature: addDataSignature,
    });
    const dataPointId = dataPointResult.dataPointId as Hex | undefined;
    if (!dataPointId) {
      throw new Error("gateway.registerDataPoint returned no dataPointId");
    }
    ps.indexManager.updateDataPointId(ingestedEntry.path, dataPointId);
    console.log(`    dataPointId: ${dataPointId}`);
    console.log(`    version:     ${ingestedEntry.version}`);

    // ─── 7.6 Register the encrypted file location on-chain ──────────
    //
    // Mirrors the upload worker's FileRegistration step (see
    // packages/core/src/sync/workers/upload.ts ~L151-L178). Because we
    // skip the real storage adapter, we hand the gateway a stub URL —
    // a real downloader couldn't fetch it, but on-chain FileRegistration
    // just records the URL as a string.
    //
    // Signing: server-delegated (server key + ownerAddress=user). In
    // production only the server knows the storage URL it picked, so the
    // owner can't pre-sign — the upload worker relies on the gateway +
    // V2 contract honoring trusted-server delegation for FileRegistration.
    // If this 401s with "signer does not match ownerAddress", we have the
    // same gateway gap we saw on AddData (no delegated signing path),
    // and the upload worker can't work against this deployment as-is.
    step("Registering file URL on-chain via gateway.registerFile");
    if (!registeredSchemaId) {
      throw new Error(
        "FileRegistration needs a schemaId — schema step didn't produce one",
      );
    }
    const stubFileUrl =
      `https://example-storage.test/encrypted/${ingestedEntry.scope}/` +
      `${encodeURIComponent(ingestedEntry.collectedAt)}.pgp`;
    const fileRegistrationMessage = {
      ownerAddress: userAccount.address,
      url: stubFileUrl,
      schemaId: registeredSchemaId,
    };
    const fileRegistrationSignature = await ps.serverAccount.signTypedData({
      domain: fileRegistrationDomain(GATEWAY_CONFIG),
      types: FILE_REGISTRATION_TYPES,
      primaryType: "FileRegistration",
      message: fileRegistrationMessage as unknown as Record<string, unknown>,
    });
    const fileRegistration = await gateway.registerFile({
      ownerAddress: userAccount.address,
      url: stubFileUrl,
      schemaId: registeredSchemaId,
      signature: fileRegistrationSignature,
    });
    const fileId = fileRegistration.fileId as Hex | undefined;
    if (!fileId) {
      throw new Error("gateway.registerFile returned no fileId");
    }
    ps.indexManager.updateFileId(ingestedEntry.path, fileId);
    console.log(`    fileId:     ${fileId}`);
    console.log(`    url:        ${stubFileUrl}`);
    console.log(`    signer:     server (${ps.serverAccount.address})`);

    // ─── 8. User creates a grant via the personal server (delegated) ──
    //
    // The personal server signs the GrantRegistration EIP-712 with its own
    // server key on behalf of the owner; the message carries
    // `grantorAddress: serverOwner`. Both the gateway (off-chain) and the
    // V2 PermissionsV2 contract (on-chain) accept this via a trusted-
    // server delegation check: the recovered signer is allowed to act
    // for `grantorAddress` if it's a registered trusted server. This
    // exercises the delegation path end-to-end including on-chain settle.
    step(`User granting scope="${SCOPE}" to app via POST /v1/grants`);
    const grantBodyObj = {
      granteeAddress: appAccount.address,
      scopes: [SCOPE],
    };
    const grantBodyStr = JSON.stringify(grantBodyObj);
    const grantBodyBytes = new TextEncoder().encode(grantBodyStr);
    const grantAuth = await buildWeb3SignedHeader({
      signMessage: async (m: string) =>
        (await userAccount.signMessage({ message: m })) as Hex,
      aud: ps.url,
      method: "POST",
      uri: `/v1/grants`,
      body: grantBodyBytes,
    });
    const grantRes = await fetch(`${ps.url}/v1/grants`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: grantAuth },
      body: grantBodyStr,
    });
    if (grantRes.status !== 201) {
      throw new Error(
        `Grant create failed: ${grantRes.status} ${await grantRes.text()}`,
      );
    }
    const grantBody = (await grantRes.json()) as { grantId: Hex };
    const grantId = grantBody.grantId;
    console.log(`    grantId:    ${grantId}`);

    const grantBeforePay = await gateway.getGrant(grantId);
    if (!grantBeforePay) throw new Error("Created grant not found on gateway");
    assertEq(
      grantBeforePay.paymentStatus,
      "pending",
      "grant.paymentStatus before pay",
    );

    // ─── 9. Funder pre-funds the app's escrow ─────────────────────────
    // Sized from grant.fee.totalDue (the gateway-canonical first-payment
    // amount: registrationFee + dataAccessFee). The FeeRegistry config
    // varies deployment-to-deployment, so a fixed default would under-
    // provision; reading from the grant self-tunes. We add a small
    // headroom for replay tests + future per-read fees.
    const totalDue = BigInt(grantBeforePay.fee.totalDue);
    const baseRequired = (totalDue * 110n) / 100n; // 10% safety
    const required =
      baseRequired > DEPOSIT_AMOUNT ? baseRequired : DEPOSIT_AMOUNT;
    step(
      `Funder depositing ${formatEther(required)} VANA into app's escrow` +
        ` (grant.fee.totalDue=${formatEther(totalDue)} VANA + 10% headroom)`,
    );
    const funderAccount = privateKeyToAccount(FUNDER_PRIVATE_KEY);
    labelAddress(funderAccount.address, "funder");
    const funderBalance = await publicClient.getBalance({
      address: funderAccount.address,
    });
    console.log(`    funder:     ${fmt(funderAccount.address)}`);
    console.log(`    funder bal: ${formatEther(funderBalance)} VANA`);
    if (funderBalance < required) {
      throw new Error(
        `Funder has ${formatEther(funderBalance)} VANA, needs ${formatEther(required)}.` +
          ` Top up ${funderAccount.address} on Moksha.`,
      );
    }
    const funderWallet = createWalletClient({
      account: funderAccount,
      chain: moksha,
      transport: http(RPC_URL),
    });
    const depositReq = buildDepositNativeRequest(GATEWAY_CONFIG, {
      account: appAccount.address,
      amount: required,
    });
    const depositTxHash = await funderWallet.sendTransaction({
      account: funderAccount,
      chain: moksha,
      to: depositReq.to,
      data: depositReq.data,
      value: depositReq.value,
    });
    console.log(`    deposit tx: ${depositTxHash}`);
    const depositReceipt = await publicClient.waitForTransactionReceipt({
      hash: depositTxHash,
    });
    if (depositReceipt.status !== "success") {
      throw new Error(`Deposit tx reverted: ${depositTxHash}`);
    }
    await gateway.submitEscrowDeposit({ txHash: depositTxHash });
    await pollUntil("escrow credited", async () => {
      const r = await gateway.getEscrowBalance(appAccount.address);
      const native = r.balances.find(
        (b: { asset: string }) =>
          b.asset.toLowerCase() === NATIVE_VANA_ASSET.toLowerCase(),
      );
      if (!native || BigInt(native.balance) < required) return null;
      return native;
    });

    // ─── 10. App tries to read without X-PAYMENT → 402 ────────────────
    step(`App reading ${SCOPE} without X-PAYMENT — expecting 402 challenge`);
    const readAuthFn = (uri: string) =>
      buildWeb3SignedHeader({
        signMessage: async (m: string) =>
          (await appAccount.signMessage({ message: m })) as Hex,
        aud: ps.url,
        method: "GET",
        uri,
        grantId,
      });
    const readUri = `/v1/data/${SCOPE}`;
    const noPayRes = await fetch(`${ps.url}${readUri}`, {
      headers: { Authorization: await readAuthFn(readUri) },
    });
    if (noPayRes.status !== 402) {
      throw new Error(
        `Expected 402, got ${noPayRes.status}: ${await noPayRes.text()}`,
      );
    }
    const challenge = (await noPayRes.json()) as X402Challenge;
    assertEq(challenge.x402Version, 1, "challenge.x402Version");
    assertEq(challenge.error, "PAYMENT_REQUIRED", "challenge.error");
    if (challenge.accepts.length !== 1) {
      throw new Error("challenge.accepts should have exactly one option");
    }
    const accept = challenge.accepts[0];
    console.log(
      `    amount:     ${accept.amount} (${formatEther(BigInt(accept.amount))} VANA)`,
    );
    console.log(
      `    breakdown:  reg=${accept.breakdown.registrationFee} access=${accept.breakdown.dataAccessFee} regOwed=${accept.breakdown.registrationOwed}`,
    );
    if (accept.accessRecord) {
      console.log(
        `    accessRec:  dataPointId=${accept.accessRecord.dataPointId.slice(0, 14)}…`,
      );
      console.log(
        `    recordId:   ${accept.accessRecord.recordId.slice(0, 14)}…`,
      );
    } else {
      console.log(`    accessRec:  (none — entry has no dataPointId)`);
    }
    // recordId is opId for the `access` settle op we watch in step 16.
    const accessRecordId: Hex | undefined = accept.accessRecord?.recordId;

    // ─── 10. App signs the GenericPayment + retries with X-PAYMENT ───
    step("App signing GenericPayment and retrying with X-PAYMENT");
    const paymentNonce = nextPaymentNonce();
    const paymentMessage = {
      payerAddress: appAccount.address,
      opType: "grant" as const,
      opId: accept.message.opId,
      asset: accept.message.asset as `0x${string}`,
      amount: BigInt(accept.message.amount),
      paymentNonce,
    };
    const paymentSig = await appAccount.signTypedData({
      domain: escrowPaymentDomain(GATEWAY_CONFIG),
      types: GENERIC_PAYMENT_TYPES,
      primaryType: "GenericPayment",
      message: paymentMessage,
    });
    const xPaymentHeader = encodePaymentHeader({
      x402Version: 1,
      scheme: "vana-escrow-grant",
      network: accept.network,
      payload: {
        message: {
          payerAddress: appAccount.address,
          opType: "grant",
          opId: accept.message.opId,
          asset: accept.message.asset as `0x${string}`,
          amount: accept.message.amount,
          paymentNonce: paymentNonce.toString(),
        },
        signature: paymentSig as `0x${string}`,
        ...(accept.accessRecord ? { accessRecord: accept.accessRecord } : {}),
      },
    });
    console.log(`    paymentNonce: ${paymentNonce.toString().slice(0, 10)}…`);

    const payRes = await fetch(`${ps.url}${readUri}`, {
      headers: {
        Authorization: await readAuthFn(readUri),
        "X-PAYMENT": xPaymentHeader,
      },
    });
    if (payRes.status !== 200) {
      throw new Error(
        `Expected 200 after X-PAYMENT, got ${payRes.status}: ${await payRes.text()}`,
      );
    }
    // The personal server echoes the gateway's payForOperation response
    // body via X-PAYMENT-RESPONSE (base64-encoded JSON, X402 spec).
    const xPaymentResponseHeader = payRes.headers.get("x-payment-response");
    let gatewayPayResponse: unknown = null;
    if (xPaymentResponseHeader) {
      try {
        gatewayPayResponse = JSON.parse(
          Buffer.from(xPaymentResponseHeader, "base64").toString("utf-8"),
        );
      } catch (err) {
        console.log(
          `    (failed to decode X-PAYMENT-RESPONSE: ${(err as Error).message})`,
        );
      }
    }
    const envelope = (await payRes.json()) as {
      version: string;
      scope: string;
      collectedAt: string;
      data: Record<string, unknown>;
    };
    assertEq(envelope.scope, SCOPE, "envelope.scope");
    assertEq(envelope.data.username, "vana_e2e", "envelope.data.username");
    assertEq(envelope.data.followers, 42, "envelope.data.followers");
    console.log(
      `    served:     scope=${envelope.scope} collectedAt=${envelope.collectedAt}`,
    );
    console.log(`    payload:    ${JSON.stringify(envelope.data)}`);
    console.log(`    gateway response (X-PAYMENT-RESPONSE):`);
    if (gatewayPayResponse) {
      const pretty = JSON.stringify(gatewayPayResponse, null, 2)
        .split("\n")
        .map((line) => `      ${line}`)
        .join("\n");
      console.log(pretty);
    } else {
      console.log("      (none — personal server didn't forward gateway body)");
    }

    // ─── 11. Verify post-payment state on the gateway ────────────────
    step("Verifying grant.paymentStatus flipped to 'paid'");
    const grantAfterPay = await gateway.getGrant(grantId);
    if (!grantAfterPay) throw new Error("grant disappeared after pay");
    console.log(`    paymentStatus:   ${grantAfterPay.paymentStatus}`);
    console.log(`    paidBy:          ${fmt(grantAfterPay.paidBy ?? null)}`);
    console.log(`    paidAt:          ${grantAfterPay.paidAt}`);
    assertEq(grantAfterPay.paymentStatus, "paid", "grant.paymentStatus after");
    assertEq(
      grantAfterPay.paidBy?.toLowerCase(),
      appAccount.address.toLowerCase(),
      "grant.paidBy",
    );

    // Pre-settle escrow snapshot. The gateway tracks four amounts per asset:
    //
    //   balance          — total funds in escrow (on-chain finalized)
    //   pendingAmount    — reserved for in-flight ops, not yet on-chain
    //   authorizedAmount — authorized for spend (incl. pending settles)
    //   availableAmount  — net free balance for new ops
    //
    // After off-chain `paymentStatus=paid` we expect `balance` to be
    // unchanged and the X402 payment to show up in `pendingAmount` (or
    // `authorizedAmount`, depending on the gateway). The on-chain debit
    // — visible as a `balance` drop — only lands after settle finalizes.
    step("Snapshotting escrow balance after off-chain payment (pre-settle)");
    const balancePreSettle = await gateway.getEscrowBalance(appAccount.address);
    const nativePreSettle = balancePreSettle.balances.find(
      (b: { asset: string }) =>
        b.asset.toLowerCase() === NATIVE_VANA_ASSET.toLowerCase(),
    );
    if (!nativePreSettle) throw new Error("app has no native balance row");
    const balBeforeSettle = BigInt(nativePreSettle.balance);
    const pendingBefore = BigInt(nativePreSettle.pendingAmount);
    const authorizedBefore = BigInt(nativePreSettle.authorizedAmount);
    const availableBefore = BigInt(nativePreSettle.availableAmount);
    // On-chain reading: (1) probe the escrow contract for a per-account
    // balance getter (the SDK doesn't export this; we try common names),
    // and (2) read the escrow contract's own native VANA balance — the
    // sum of all users' funds in escrow.
    const escrowContractAddr = GATEWAY_CONFIG.contracts
      .dataPortabilityEscrow as `0x${string}`;
    const [onChainProbeBefore, escrowContractBalBefore] = await Promise.all([
      readOnChainAccountEscrow(
        publicClient,
        escrowContractAddr,
        appAccount.address,
        NATIVE_VANA_ASSET as `0x${string}`,
      ),
      publicClient.getBalance({ address: escrowContractAddr }),
    ]);
    console.log(`    account:           ${fmt(appAccount.address)}`);
    console.log(`    deposited:         ${formatEther(required)} VANA`);
    console.log(`    gateway view (per-account):`);
    console.log(`      balance:         ${formatEther(balBeforeSettle)} VANA`);
    console.log(`      pendingAmount:   ${formatEther(pendingBefore)} VANA`);
    console.log(`      authorizedAmount:${formatEther(authorizedBefore)} VANA`);
    console.log(`      availableAmount: ${formatEther(availableBefore)} VANA`);
    console.log(`    on-chain view:`);
    if (onChainProbeBefore) {
      console.log(
        `      per-account:     ${formatEther(onChainProbeBefore.amount)} VANA` +
          `  via=${onChainProbeBefore.via}(account, NATIVE_VANA_ASSET)`,
      );
    } else {
      console.log(
        `      per-account:     (no getter found — tried balances/getBalance/balanceOf/accountBalance)`,
      );
    }
    console.log(
      `      contract total:  ${formatEther(escrowContractBalBefore)} VANA` +
        `  (escrow ${escrowContractAddr})`,
    );
    console.log(
      `    (debit lands in 'balance' at on-chain settle — see post-finalization check)`,
    );

    // ─── 12. Replay the same X-PAYMENT → should be rejected ──────────
    step(
      "Replaying the same X-PAYMENT — gateway should reject 409 → fresh 402",
    );
    const replayRes = await fetch(`${ps.url}${readUri}`, {
      headers: {
        Authorization: await readAuthFn(readUri),
        "X-PAYMENT": xPaymentHeader,
      },
    });
    if (replayRes.status !== 402) {
      throw new Error(
        `Expected fresh 402 on replay, got ${replayRes.status}: ${await replayRes.text()}`,
      );
    }
    const replayBody = (await replayRes.json()) as X402Challenge;
    assertEq(
      replayBody.x402Version,
      1,
      "replay re-challenges with x402Version",
    );
    console.log(
      `    replay rejected (nonce already used by gateway); a fresh challenge was reissued`,
    );

    // ─── 15. Drain pending ops to chain via gateway.settle ───────────
    // settle() submits pending off-chain ledger entries to L1: grant
    // registration, server registration, the just-settled payment, etc.
    // The gateway batches scans; ops can be in {pending|submitting|
    // confirmed|finalized|failed|reorged}.
    //
    // `failed` is OFTEN TRANSIENT here — e.g., the grant's settle tx
    // depends on the server's on-chain registration tx having mined
    // first, but they may be sent in the same batch and race. The
    // gateway's own scheduler retries failed items on subsequent passes;
    // our poll in step 16 lets that play out. We log the diagnostic so
    // the operator can see what happened but don't bail.
    // ─── Resolve fee recipients from the FeeRegistry contract ───────
    //
    // FeeRegistry has up to 5 configurable ops, each with its own payee
    // and contracted amount. We resolve them here so the post-settle
    // step can attribute per-tx fee credits to the right wallets.
    //
    // Native VANA only; if any fee is configured against an ERC20 asset,
    // we skip it with a warning rather than fail.
    const FEE_KINDS: FeeKind[] = [
      "grant_registration",
      "data_access",
      "server_registration",
      "builder_registration",
      "data_registration",
    ];
    const feeEntries = await Promise.all(
      FEE_KINDS.map(async (k) => ({
        kind: k,
        entry: await getFee(publicClient, GATEWAY_CONFIG, k),
      })),
    );
    interface FeeRecipientState {
      kinds: FeeKind[];
      contractedAmount: bigint;
    }
    const recipientMap = new Map<string, FeeRecipientState>();
    for (const { kind, entry } of feeEntries) {
      if (!entry.enabled) continue;
      if (entry.asset.toLowerCase() !== NATIVE_VANA_ASSET.toLowerCase()) {
        console.log(
          `    ⚠ fee[${kind}] uses ERC20 ${entry.asset} — tracker only handles native VANA, skipping`,
        );
        continue;
      }
      const payee = entry.payee.toLowerCase();
      let rec = recipientMap.get(payee);
      if (!rec) {
        rec = { kinds: [], contractedAmount: 0n };
        recipientMap.set(payee, rec);
      }
      rec.kinds.push(kind);
      rec.contractedAmount += entry.amount;
    }
    step(
      `Resolving fee recipients from FeeRegistry (${recipientMap.size} payee(s))`,
    );
    for (const [payee, rec] of recipientMap) {
      // Label this payee so later logs (per-tx fee credits) render
      // "0x... (fee-recipient)" instead of bare addresses.
      if (!addressLabels.has(payee)) {
        labelAddress(payee, "fee-recipient");
      }
      console.log(
        `    ${fmt(payee)}` +
          `  contracted=${formatEther(rec.contractedAmount)} VANA` +
          `  fees=[${rec.kinds.join(", ")}]`,
      );
    }

    step("Draining pending ops via gateway.settle()");
    const settleResult = await gateway.settle();
    console.log(`    scanned:   ${settleResult.scanned}`);
    console.log(`    confirmed: ${settleResult.confirmed}`);
    console.log(`    submitted: ${settleResult.submitted}`);
    console.log(`    skipped:   ${settleResult.skipped}`);
    console.log(`    failed:    ${settleResult.failed}`);

    function logInitial(opType: string, opId: Hex, label: string): void {
      const item = settleResult.items.find(
        (i: SettleItem) =>
          i.opType === opType && i.opId.toLowerCase() === opId.toLowerCase(),
      );
      if (!item) {
        console.log(
          `    ${label}: (not in this scan — already settled, or queued for a later batch)`,
        );
        return;
      }
      const tx =
        "settleTxHash" in item && item.settleTxHash
          ? ` tx=${item.settleTxHash}`
          : "";
      const err =
        "error" in item && item.error
          ? `\n      error: ${String(item.error).slice(0, 180).replace(/\s+/g, " ")}`
          : "";
      console.log(`    ${label}: status=${item.status}${tx}${err}`);
    }
    logInitial("grant", grantId, "grant ");
    logInitial("server", serverId, "server");
    logInitial("data", dataPointId, "data  ");
    if (accessRecordId) {
      logInitial("access", accessRecordId, "access");
    }

    // ─── 16. Poll gateway.settle until ALL watched ops finalize ─────
    // Loop until every watched op reaches status="finalized". `reorged`
    // is fatal (chain rewound past a settle tx; the gateway will resubmit
    // but the assertion target moved). On each poll we capture the settle
    // tx hash and chain block height for the final summary.
    //
    // Timeout is generous (default 10 min); override with
    // FINALIZE_TIMEOUT_MS env if your chain is slow. Polls every 10s by
    // default to limit gateway load while still picking up state changes
    // promptly on Moksha's ~6s block time.
    step("Polling gateway.settle for reconcile → finalized");
    const FINALIZE_TIMEOUT_MS = Number(
      process.env["FINALIZE_TIMEOUT_MS"] ?? 600_000,
    );
    const FINALIZE_POLL_MS = Number(process.env["FINALIZE_POLL_MS"] ?? 10_000);
    const watched: Array<{ label: string; opId: Hex }> = [
      { label: "grant ", opId: grantId },
      { label: "server", opId: serverId },
      { label: "data  ", opId: dataPointId },
    ];
    if (accessRecordId) {
      watched.push({ label: "access", opId: accessRecordId });
    } else {
      console.log(
        "    (skipping `access` op — X402 challenge had no accessRecord)",
      );
    }
    interface WatchedState {
      status: string;
      settleTxHash: string | null;
      chainBlockHeight: string | null;
      reason: string | null;
    }
    const finalStatus: Record<string, WatchedState> = {};
    const finalizeStart = Date.now();
    let finalized = false;
    while (Date.now() - finalizeStart < FINALIZE_TIMEOUT_MS) {
      const r = await gateway.settle();
      const elapsed = Math.round((Date.now() - finalizeStart) / 1000);
      let allFinalized = true;
      let line = `    [${elapsed}s]`;
      for (const w of watched) {
        const item = r.reconciled.items.find(
          (i: SettleReconcileItem) =>
            i.opId.toLowerCase() === w.opId.toLowerCase(),
        );
        const prev = finalStatus[w.opId];
        const cur: WatchedState = item
          ? {
              status: item.status,
              settleTxHash: item.settleTxHash,
              chainBlockHeight: item.chainBlockHeight,
              reason: item.reason ?? null,
            }
          : (prev ?? {
              status: "pending",
              settleTxHash: null,
              chainBlockHeight: null,
              reason: null,
            });
        finalStatus[w.opId] = cur;

        const txSuffix = cur.settleTxHash
          ? ` tx=${cur.settleTxHash.slice(0, 12)}…`
          : "";
        line += ` ${w.label}=${cur.status}${txSuffix}`;
        if (cur.status !== "finalized") allFinalized = false;
        if (cur.status === "reorged") {
          throw new Error(
            `reconcile flagged ${w.label.trim()} ${w.opId} as reorged${cur.reason ? `: ${cur.reason}` : ""}`,
          );
        }
      }
      console.log(line);
      if (allFinalized) {
        finalized = true;
        console.log(`    ✓ all ${watched.length} ops finalized in ${elapsed}s`);
        break;
      }
      await new Promise((r) => setTimeout(r, FINALIZE_POLL_MS));
    }
    if (!finalized) {
      const summary = watched
        .map(
          (w) =>
            `${w.label.trim()}=${finalStatus[w.opId]?.status ?? "pending"}`,
        )
        .join(", ");
      throw new Error(
        `Timed out after ${FINALIZE_TIMEOUT_MS / 1000}s waiting for finalization. Last: ${summary}`,
      );
    }

    // Per-op tx hash + block height summary, now that we know everything
    // landed on-chain finalized.
    console.log("");
    console.log("    Finalized on-chain:");
    for (const w of watched) {
      const s = finalStatus[w.opId];
      console.log(
        `      ${w.label.trim()}:` +
          ` tx=${s.settleTxHash ?? "(none)"}` +
          ` block=${s.chainBlockHeight ?? "(unknown)"}`,
      );
    }

    // ─── Verify app's escrow was debited by the paid amount ────────
    step("Verifying app's escrow debited after on-chain settle");
    const balancePostSettle = await gateway.getEscrowBalance(
      appAccount.address,
    );
    const nativePostSettle = balancePostSettle.balances.find(
      (b: { asset: string }) =>
        b.asset.toLowerCase() === NATIVE_VANA_ASSET.toLowerCase(),
    );
    if (!nativePostSettle) throw new Error("app has no native balance row");
    const balAfterSettle = BigInt(nativePostSettle.balance);
    const pendingAfter = BigInt(nativePostSettle.pendingAmount);
    const authorizedAfter = BigInt(nativePostSettle.authorizedAmount);
    const availableAfter = BigInt(nativePostSettle.availableAmount);
    const actualDebit = balBeforeSettle - balAfterSettle;
    const [onChainProbeAfter, escrowContractBalAfter] = await Promise.all([
      readOnChainAccountEscrow(
        publicClient,
        escrowContractAddr,
        appAccount.address,
        NATIVE_VANA_ASSET as `0x${string}`,
      ),
      publicClient.getBalance({ address: escrowContractAddr }),
    ]);
    const escrowContractDelta =
      escrowContractBalBefore - escrowContractBalAfter;
    console.log(`    account:           ${fmt(appAccount.address)}`);
    console.log(`    gateway view (per-account):`);
    console.log(
      `      balance:         ${formatEther(balBeforeSettle)} → ${formatEther(balAfterSettle)} VANA` +
        ` (Δ -${formatEther(actualDebit)})`,
    );
    console.log(
      `      pendingAmount:   ${formatEther(pendingBefore)} → ${formatEther(pendingAfter)} VANA`,
    );
    console.log(
      `      authorizedAmount:${formatEther(authorizedBefore)} → ${formatEther(authorizedAfter)} VANA`,
    );
    console.log(
      `      availableAmount: ${formatEther(availableBefore)} → ${formatEther(availableAfter)} VANA`,
    );
    console.log(`    on-chain view:`);
    if (onChainProbeBefore && onChainProbeAfter) {
      const onChainDelta = onChainProbeBefore.amount - onChainProbeAfter.amount;
      const sign = onChainDelta >= 0n ? "-" : "+";
      const absDelta = onChainDelta >= 0n ? onChainDelta : -onChainDelta;
      console.log(
        `      per-account:     ${formatEther(onChainProbeBefore.amount)} → ${formatEther(onChainProbeAfter.amount)} VANA` +
          ` (Δ ${sign}${formatEther(absDelta)})  via=${onChainProbeAfter.via}`,
      );
    } else {
      console.log(`      per-account:     (no getter found)`);
    }
    {
      const sign = escrowContractDelta >= 0n ? "-" : "+";
      const absDelta =
        escrowContractDelta >= 0n ? escrowContractDelta : -escrowContractDelta;
      console.log(
        `      contract total:  ${formatEther(escrowContractBalBefore)} → ${formatEther(escrowContractBalAfter)} VANA` +
          ` (Δ ${sign}${formatEther(absDelta)})  (escrow ${escrowContractAddr})`,
      );
    }
    console.log(
      `    expected debit:    ${formatEther(totalDue)} VANA (grant.fee.totalDue)`,
    );
    if (actualDebit !== totalDue) {
      console.log(
        `    ⚠ debit ${formatEther(actualDebit)} VANA != totalDue ${formatEther(totalDue)} VANA` +
          ` — the gateway may have rolled fees from concurrent ops into this account.`,
      );
    }

    // ─── Per-tx fee credit attribution via call trace ───────────────
    //
    // Walks each settle tx's internal call tree (via debug_traceTransaction
    // with callTracer) and sums the native VANA value transfers landing at
    // each known fee recipient. This isolates exactly what THIS tx paid to
    // each recipient — immune to unrelated traffic touching the same wallet
    // in the same block, which the prior balance-diff approach conflated.
    //
    // Requires the RPC to support debug_traceTransaction. If it doesn't,
    // we fall back to a clear warning instead of producing misleading data.
    step("Computing per-tx fee credits via call trace");
    interface CallFrame {
      from?: string;
      to?: string;
      value?: string;
      type?: string;
      calls?: CallFrame[];
    }
    function* walkCalls(call: CallFrame): IterableIterator<CallFrame> {
      yield call;
      if (Array.isArray(call.calls)) {
        for (const child of call.calls) yield* walkCalls(child);
      }
    }
    const totalReceived = new Map<string, bigint>();
    let traceFailed = false;
    for (const w of watched) {
      const s = finalStatus[w.opId];
      if (!s.settleTxHash) continue;
      let trace: CallFrame;
      try {
        trace = (await publicClient.request({
          method: "debug_traceTransaction",
          params: [s.settleTxHash, { tracer: "callTracer" }],
        } as unknown as {
          method: "eth_chainId";
          params?: undefined;
        })) as unknown as CallFrame;
      } catch (err) {
        const msg = (err as Error).message ?? String(err);
        console.log(
          `    ⚠ debug_traceTransaction not supported by RPC (${msg.slice(0, 80)}).` +
            ` Falling back; per-tx attribution unavailable.`,
        );
        traceFailed = true;
        break;
      }
      // Sum native value transfers per `to` address inside this tx.
      const perTxCredits = new Map<string, bigint>();
      for (const c of walkCalls(trace)) {
        if (!c.to || !c.value) continue;
        if (c.value === "0x" || c.value === "0x0") continue;
        const v = BigInt(c.value);
        if (v === 0n) continue;
        const to = c.to.toLowerCase();
        perTxCredits.set(to, (perTxCredits.get(to) ?? 0n) + v);
      }
      const creditedRecipients: Array<{ payee: string; amount: bigint }> = [];
      for (const payee of recipientMap.keys()) {
        const amt = perTxCredits.get(payee);
        if (amt && amt > 0n) {
          creditedRecipients.push({ payee, amount: amt });
          totalReceived.set(payee, (totalReceived.get(payee) ?? 0n) + amt);
        }
      }
      console.log(
        `    [${w.label.trim()}] tx=${s.settleTxHash}` +
          ` block=${s.chainBlockHeight ?? "?"}`,
      );
      if (creditedRecipients.length === 0) {
        console.log(`      (no value transfers to known fee recipients)`);
      } else {
        for (const { payee, amount } of creditedRecipients) {
          const rec = recipientMap.get(payee)!;
          console.log(
            `      ${fmt(payee)}  +${formatEther(amount)} VANA` +
              `  fees=[${rec.kinds.join(", ")}]`,
          );
        }
      }
    }
    if (!traceFailed) {
      console.log("");
      console.log(
        "    Total fees received per recipient (across all settle txs):",
      );
      for (const [payee, rec] of recipientMap) {
        const total = totalReceived.get(payee) ?? 0n;
        console.log(
          `      ${fmt(payee)}  total=+${formatEther(total)} VANA` +
            `  fees=[${rec.kinds.join(", ")}]`,
        );
      }
    }

    // ─── 17. Final cross-check via gateway.getGrant + escrow ──────────
    step("Cross-checking grant chain state after settle");
    const settledGrant = await gateway.getGrant(grantId);
    if (!settledGrant) throw new Error("grant disappeared after settle");
    console.log(`    status:           ${settledGrant.status}`);
    console.log(`    settleTxHash:     ${settledGrant.settleTxHash}`);
    console.log(`    settleSubmittedAt:${settledGrant.settleSubmittedAt}`);
    if (
      settledGrant.status !== "confirmed" &&
      settledGrant.status !== "finalized" &&
      settledGrant.status !== "submitting"
    ) {
      throw new Error(
        `unexpected grant.status after settle: ${settledGrant.status}`,
      );
    }

    // ─── Done ─────────────────────────────────────────────────────────
    console.log(
      "\n═══════════════════════════════════════════════════════════",
    );
    console.log("  ✓ Personal server X402 E2E PASSED");
    console.log("═══════════════════════════════════════════════════════════");
    console.log(`  user:    ${userAccount.address}`);
    console.log(`  app:     ${appAccount.address}`);
    console.log(`  server:  ${serverAddress}`);
    console.log(`  scope:   ${SCOPE}`);
    console.log(`  grant:   ${grantId}`);
  } finally {
    await ps.cleanup().catch((err) => {
      console.error("cleanup failed:", err);
    });
    await rm(serverDir, { recursive: true, force: true }).catch(
      () => undefined,
    );
  }
}

main().catch((err) => {
  console.error("\n✗ Personal server X402 E2E failed:");
  console.error(err);
  process.exit(1);
});
