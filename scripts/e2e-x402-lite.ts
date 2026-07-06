/**
 * End-to-end test of the PERSONAL SERVER LITE runtime's full x402 lifecycle
 * against a live gateway + Moksha L1.
 *
 * This is the PS-Lite analogue of scripts/e2e-x402-flow.ts. Instead of booting
 * the Node server (`createServer` from the server package), it boots the Lite
 * runtime — `createPsLiteRuntime` from packages/lite/src/runtime.ts, the same
 * code app-dev.vana.org runs in the browser — wraps its `.fetch` in
 * @hono/node-server's `serve({ fetch, port })` to expose a real URL, and drives
 * the identical x402 lifecycle against the live gateway:
 *
 *   1. A user generates a fresh server keypair and boots the Lite runtime.
 *   2. The user registers it on the gateway as a trusted server of their wallet.
 *   3. An app registers itself as a builder.
 *   4. The user POSTs personal data to the Lite runtime (instagram.profile).
 *   5. The ingested envelope is registered on-chain as a DPv2 data point.
 *   6. The user grants the app permission to read that scope (delegated, the
 *      server signer signs GrantRegistration on behalf of the owner).
 *   7. The app does a GET, hits the X402 paywall. Without payment the data is
 *      withheld (the 402 body is a challenge, never the envelope).
 *   8. The app signs the payment and retries; the gateway accepts it and the
 *      Lite runtime serves the envelope.
 *   9. gateway.settle() drains pending ops on-chain; we poll to finalization.
 *  10. We assert the builder settled on-chain via the GranteeRegistered event.
 *
 * The gateway/chain-side logic (EIP-712 signing, escrow deposit, the 402 parse
 * + X-PAYMENT encode, the settle/finalize poll loop, the GranteeRegistered
 * assertion) is IDENTICAL to the Node script and is reused verbatim. What
 * differs is purely how the server is booted and how its identity/signer/
 * storage are provided — see the "LITE-SPECIFIC" comments below.
 *
 * Lite storage note (full data-point path): unlike the Node server, the Lite
 * runtime has no IndexManager/dataDir; it uses an in-memory DataStoragePort
 * (createMemoryPsLiteStorage). That port DOES expose everything we need to do
 * the full on-chain data-point registration:
 *   • findEntry({ scope })        → the ingested IndexEntry (version, path, …)
 *   • readEnvelope(scope, at)     → the stored envelope object (for hashing)
 *   • updateDataPointId(path, id) → stamps the dataPointId back onto the entry
 * So this script does NOT fall back to the no-accessRecord path — it performs
 * the full registerDataPoint + accessRecord + `access` settle op, matching the
 * Node template's behaviour exactly.
 *
 * This script lives outside packages/* so the SDK is resolved as a downstream
 * consumer would resolve it. Runs the Lite runtime in-process on a random port
 * and drives every endpoint via plain fetch.
 *
 * Usage:
 *   cd ~/repo/personal-server-ts
 *   FUNDER_PRIVATE_KEY=0x... \
 *   GATEWAY_URL=https://data-gateway-... \
 *   npm run e2e:x402-lite
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
 *   FINALIZE_TIMEOUT_MS                     default: 600000
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { AddressInfo } from "node:net";
import {
  createPublicClient,
  createWalletClient,
  defineChain,
  formatEther,
  http,
  keccak256,
  parseAbiItem,
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
  GENERIC_PAYMENT_TYPES,
  NATIVE_VANA_ASSET,
  SERVER_REGISTRATION_TYPES,
  builderRegistrationDomain,
  buildDepositNativeRequest,
  createGatewayClient,
  dataRegistryDomain,
  escrowPaymentDomain,
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
import type { GatewayConfig } from "../packages/core/src/schemas/server-config.js";
import { createServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import type { ServerAccount } from "../packages/core/src/keys/server-account.js";
// ─── LITE-SPECIFIC imports ────────────────────────────────────────────────
// Boot the same Lite runtime + auth wiring the browser uses, backed by the
// in-memory stores (the Node-equivalent of SQLite + the data dir). Import
// specifiers mirror scripts/e2e-read-scope-lite.ts verbatim.
import {
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
  type PsLiteRuntime,
} from "../packages/lite/src/runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
  createMemoryPsLiteAccessLogStore,
} from "../packages/lite/src/test-support/memory.js";
import { createInMemoryMcpConnectionStore } from "@opendatalabs/personal-server-ts-core/mcp";
import type { DataStoragePort } from "@opendatalabs/personal-server-ts-core/ports";
import type { DataReadPolicyPorts } from "@opendatalabs/personal-server-ts-core/policy";

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

// ─── Personal server LITE bootstrap ────────────────────────────────────────
//
// This is the heart of the Node-vs-Lite difference. The Node script calls
// `createServer(...)` and lets the server derive a serverAccount from the
// master-key signature. The Lite runtime takes its identity + signer + storage
// as explicit options, so we build them here and hand them in.

interface PersonalServerHandle {
  url: string;
  // The in-memory DataStoragePort backing the Lite runtime. Exposed so the
  // e2e can do the on-chain data-point registration the (disabled) sync/upload
  // worker would normally perform — read the ingested entry/envelope for
  // hashing, then patch its dataPointId. Node's equivalent was indexManager +
  // dataDir; Lite's is this single port.
  storage: DataStoragePort;
  serverAccount: ServerAccount;
  cleanup(): Promise<void>;
}

async function startPersonalServerLite(params: {
  ownerAddress: `0x${string}`;
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
  const origin = `http://localhost:${port}`;

  // ─── LITE-SPECIFIC: server identity + signer ─────────────────────────
  // The Node server derives a serverAccount from the master-key signature and
  // signs accessRecords with it. Lite has no master key, so we generate a
  // fresh server private key and build a ServerAccount over it (viem
  // privateKeyToAccount → {address, publicKey, signTypedData, signMessage}),
  // then wrap it with createServerSigner so the runtime can sign
  // GrantRegistration (delegated grants) AND RecordDataAccess (the x402
  // accessRecord on paid reads).
  const serverPrivateKey = generatePrivateKey();
  const viemServerAccount = privateKeyToAccount(serverPrivateKey);
  const serverAccount: ServerAccount = {
    address: viemServerAccount.address,
    publicKey: viemServerAccount.publicKey as `0x${string}`,
    async signTypedData(p) {
      return (await viemServerAccount.signTypedData({
        domain: p.domain,
        types: p.types,
        primaryType: p.primaryType,
        message: p.message,
      } as Parameters<
        typeof viemServerAccount.signTypedData
      >[0])) as `0x${string}`;
    },
    async signMessage(message: string) {
      return (await viemServerAccount.signMessage({
        message,
      })) as `0x${string}`;
    },
  };
  // createServerSigner takes the core GatewayConfig (chainId + contracts).
  // GATEWAY_CONFIG is a DataPortabilityGatewayConfig with the identical shape
  // for these fields, so it satisfies the GatewayConfig contract.
  const serverSigner = createServerSigner(
    serverAccount,
    GATEWAY_CONFIG as GatewayConfig,
  );

  // ─── LITE-SPECIFIC: in-memory stores + auth ───────────────────────────
  // Memory analogues of the Node server's SQLite + data dir. The auth wiring
  // mirrors scripts/e2e-read-scope-lite.ts: web3-signed owner auth, with the
  // gateway client doubling as the read-policy verifier (auth session +
  // grant). We share the access-log store between reader + writer.
  const storage = createMemoryPsLiteStorage();
  const accessLog = createMemoryPsLiteAccessLogStore();
  const gateway = createGatewayClient(GATEWAY_URL);
  // The Lite runtime + auth are typed against the BROWSER GatewayClient; the
  // Node client is structurally compatible for the endpoints they touch
  // (getServer/getBuilder/getGrant/registerDataPoint/payForOperation/…). One
  // cast at the boundary keeps the call sites clean — mirrors the `as never`
  // the browser e2e (e2e-read-scope-lite.ts) uses for the same reason.
  const browserGateway = gateway as unknown as Parameters<
    typeof createPsLiteRuntime
  >[0]["gateway"];
  // For the read-policy ports, the gateway doubles as both verifiers
  // (authSessionVerifier.getBuilder + grantVerifier.getGrant).
  const policyGateway =
    gateway as unknown as DataReadPolicyPorts["grantVerifier"] &
      DataReadPolicyPorts["authSessionVerifier"];

  // createPsLiteRuntime computes paymentEnabled = config.payment?.enabled and
  // THROWS if payment is enabled with an incomplete gateway config (it
  // requires url + chainId + contracts.dataPortabilityEscrow + dataRegistry).
  // GATEWAY_CONFIG is fully populated, so the full x402 path engages.
  const runtime: PsLiteRuntime = createPsLiteRuntime({
    active: true,
    storage,
    config: {
      server: { origin },
      gateway: {
        url: GATEWAY_URL,
        chainId: CHAIN_ID,
        contracts: GATEWAY_CONFIG.contracts,
      },
      payment: { enabled: true },
    },
    gateway: browserGateway,
    serverOwner: params.ownerAddress,
    // Full ServerSigner — the runtime narrows it internally to
    // signRecordDataAccess (x402 data path) and signGrantRegistration (grants).
    serverSigner,
    identity: {
      address: serverAccount.address,
      publicKey: serverAccount.publicKey,
    },
    accessLogReader: accessLog,
    accessLogWriter: accessLog,
    tokenStore: createMemoryPsLiteTokenStore(),
    mcpConnectionStore: createInMemoryMcpConnectionStore(),
    // In-memory config persistence — without this the runtime defaults to
    // IndexedDB (browser-only) and throws under Node. Mirrors e2e-read-scope-lite.
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createWeb3SignedPsLiteAuth({
      origin,
      ownerAddress: params.ownerAddress,
      dataReadPolicyPorts: {
        authSessionVerifier: policyGateway,
        grantVerifier: policyGateway,
      },
    }),
  });

  const httpServer: ServerType = serve({
    fetch: (request: Request) => runtime.fetch(request),
    port,
  });

  return {
    url: origin,
    storage,
    serverAccount,
    async cleanup() {
      await new Promise<void>((resolve, reject) => {
        httpServer.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}

// ─── Main ────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("═══════════════════════════════════════════════════════════");
  console.log("  Personal server LITE X402 end-to-end (Moksha)");
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

  // Some gateways (e.g. moksha) gate POST /v1/settle behind a shared secret;
  // the SDK's gateway.settle() sends no Authorization, so it 401s there. When
  // SETTLE_SECRET is set we drive settle via a direct fetch carrying
  // `Authorization: Bearer <secret>`; otherwise fall back to the SDK client
  // (open settle endpoints, e.g. dev). Same response shape either way.
  const SETTLE_SECRET = process.env["SETTLE_SECRET"];
  const drainSettle = async (): Promise<
    Awaited<ReturnType<typeof gateway.settle>>
  > => {
    if (!SETTLE_SECRET) return gateway.settle();
    const res = await fetch(`${GATEWAY_URL}/v1/settle`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${SETTLE_SECRET}`,
      },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      throw new Error(`Gateway error: ${res.status} ${res.statusText}`);
    }
    return res.json() as Promise<Awaited<ReturnType<typeof gateway.settle>>>;
  };
  console.log(
    `  Settle auth:    ${SETTLE_SECRET ? "Bearer SETTLE_SECRET" : "(none — SDK client)"}`,
  );

  // ─── 1. Generate fresh wallets ─────────────────────────────────────
  step("Generating fresh user + app wallets");
  const userPrivateKey = generatePrivateKey();
  const userAccount = privateKeyToAccount(userPrivateKey);
  const appPrivateKey = generatePrivateKey();
  const appAccount = privateKeyToAccount(appPrivateKey);
  const appPublicKey = uncompressedPublicKey(appPrivateKey);
  // The builder OWNER is a separate identity from the grantee. registerGrantee
  // takes (owner, granteeAddress, publicKey): the owner authorizes (and signs)
  // the registration, the grantee is the app wallet whose key backs publicKey.
  // The owner only signs off-chain (EIP-712) — the gateway relayer submits the
  // tx — so it needs no on-chain balance.
  const builderOwnerPrivateKey = generatePrivateKey();
  const builderOwnerAccount = privateKeyToAccount(builderOwnerPrivateKey);
  labelAddress(userAccount.address, "user");
  labelAddress(appAccount.address, "app/grantee");
  labelAddress(builderOwnerAccount.address, "builder-owner");
  console.log(`    user:        ${fmt(userAccount.address)}  (testnet only)`);
  console.log(`    app/grantee: ${fmt(appAccount.address)}  (testnet only)`);
  console.log(
    `    builder-own: ${fmt(builderOwnerAccount.address)}  (testnet only)`,
  );

  // ─── 2. Boot the personal-server LITE runtime ──────────────────────
  // No master-key signature here: the Lite runtime takes its identity + signer
  // explicitly (we generate a fresh server keypair inside the bootstrap). The
  // owner is just the user's address.
  step("Booting the personal-server LITE runtime (createPsLiteRuntime)");
  const ps = await startPersonalServerLite({
    ownerAddress: userAccount.address,
  });
  labelAddress(ps.serverAccount.address, "personal-server");
  console.log(`    server URL: ${ps.url}`);
  console.log(`    server acc: ${fmt(ps.serverAccount.address)}`);

  try {
    // ─── 3. Read the Lite runtime /health for the server identity ─────
    step("Reading LITE /health for the server identity");
    const healthRes = await fetch(`${ps.url}/health`);
    const health = (await healthRes.json()) as {
      identity?: {
        address: `0x${string}`;
        publicKey: `0x${string}`;
      };
      owner?: `0x${string}`;
    };
    if (!health.identity) {
      throw new Error("Lite runtime didn't report identity");
    }
    const serverAddress = health.identity.address;
    const serverPublicKey = health.identity.publicKey;
    const ownerFromHealth = health.owner;
    if (ownerFromHealth?.toLowerCase() !== userAccount.address.toLowerCase()) {
      throw new Error(
        `serverOwner mismatch: health=${ownerFromHealth} expected=${userAccount.address}`,
      );
    }
    assertEq(
      serverAddress.toLowerCase(),
      ps.serverAccount.address.toLowerCase(),
      "health.identity.address == serverAccount.address",
    );
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
    // Lower bound for the on-chain GranteeRegistered scan in the final step.
    // The gateway relayer submits registerGrantee during a later settle drain,
    // so the event lands after this block — scanning from here keeps the
    // getLogs range tight while still covering the eventual tx.
    const builderProbeFromBlock = await publicClient.getBlockNumber();
    // The gateway recovers the registration signature against ownerAddress
    // (expectedSigner = owner), so the OWNER signs — not the grantee. publicKey
    // must still derive to granteeAddress (the app wallet).
    const builderSig = await builderOwnerAccount.signTypedData({
      domain: builderRegistrationDomain(GATEWAY_CONFIG),
      types: BUILDER_REGISTRATION_TYPES,
      primaryType: "BuilderRegistration",
      message: {
        ownerAddress: builderOwnerAccount.address,
        granteeAddress: appAccount.address,
        publicKey: appPublicKey,
        appUrl: APP_URL,
      },
    });
    const builderRes = await gateway.registerBuilder({
      ownerAddress: builderOwnerAccount.address,
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
    console.log(
      `    owner→grantee: ${fmt(builderOwnerAccount.address)} → ${fmt(appAccount.address)}`,
    );

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

    // ─── 7. User POSTs personal data to the LITE runtime ─────────────
    step(`User posting data to LITE runtime at scope=${SCOPE}`);
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
    // worker → gateway.registerDataPoint → updateDataPointId). We've left
    // sync disabled to keep the e2e storage-backend-free, so we perform the
    // on-chain registration here using:
    //   • the Lite DataStoragePort's IndexEntry for hash inputs (Node used
    //     indexManager + the on-disk envelope; Lite uses findEntry +
    //     readEnvelope on the in-memory port — see the "Lite storage note"
    //     in the file header)
    //   • the USER wallet for AddData EIP-712 signing — unlike grants, the
    //     gateway enforces `recovered(signature) == ownerAddress` for AddData
    //     with no trusted-server delegation path (off-chain), so the owner has
    //     to sign directly here
    //   • a direct gateway.registerDataPoint call
    // After it lands we patch the entry's dataPointId so the next X402
    // challenge embeds an `accessRecord` → `access` settle op gets queued
    // alongside grant/server/data.
    step("Registering ingested data on-chain via gateway.registerDataPoint");
    const ingestedEntry = ps.storage.findEntry({ scope: SCOPE });
    if (!ingestedEntry) {
      throw new Error(`Lite storage has no IndexEntry for scope=${SCOPE}`);
    }
    if (ingestedEntry.dataPointId) {
      throw new Error(
        `expected dataPointId to be null pre-registration, got ${ingestedEntry.dataPointId}`,
      );
    }
    // Mirror the upload worker's commitment recipe (see
    // packages/core/src/sync/workers/upload.ts ~L84-L110). We hash the
    // in-memory canonical JSON of the envelope. The Node script read the
    // pretty-printed on-disk bytes then re-stringified compactly; the Lite
    // port hands back the deserialized envelope directly, which we stringify
    // compactly for the identical hash input.
    const ingestedEnvelope = await ps.storage.readEnvelope(
      ingestedEntry.scope,
      ingestedEntry.collectedAt,
    );
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
    await ps.storage.updateDataPointId(ingestedEntry.path, dataPointId);
    console.log(`    dataPointId: ${dataPointId}`);
    console.log(`    version:     ${ingestedEntry.version}`);

    // ─── 8. User creates a grant via the LITE runtime (delegated) ─────
    //
    // The Lite runtime signs the GrantRegistration EIP-712 with its server
    // signer (createServerSigner.signGrantRegistration) on behalf of the
    // owner; the message carries `grantorAddress: serverOwner`. Both the
    // gateway (off-chain) and the V2 PermissionsV2 contract (on-chain) accept
    // this via a trusted-server delegation check: the recovered signer is
    // allowed to act for `grantorAddress` if it's a registered trusted server.
    // This exercises the delegation path end-to-end including on-chain settle.
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
    // First read: the grant is unpaid, so the challenge bundles the one-time
    // grant-registration fee WITH the per-read data-access fee. Capture the
    // pieces so we can contrast them against the second read below.
    const firstReadAmount = accept.amount;
    const firstRegFee = accept.breakdown.registrationFee;
    const firstAccessFee = accept.breakdown.dataAccessFee;
    console.log(`    first read fee (registration + data access):`);
    console.log(
      `      amount:     ${firstReadAmount} (${formatEther(BigInt(firstReadAmount))} VANA)`,
    );
    console.log(
      `      breakdown:  reg=${firstRegFee} access=${firstAccessFee} regOwed=${accept.breakdown.registrationOwed}`,
    );
    assertEq(
      accept.breakdown.registrationOwed,
      true,
      "first read: registrationOwed",
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

    // ─── Negative case: no payment ⇒ no data ──────────────────────────
    // The app made an authorized, grant-valid read but did NOT pay the fee.
    // The server withholds the data: the 402 body is a payment challenge, not
    // the protected envelope. Prove the ingested secret ("vana_e2e") did not
    // leak in the unpaid response — i.e. without paying, the app cannot get
    // the data.
    if (JSON.stringify(challenge).includes("vana_e2e")) {
      throw new Error(
        "Unpaid 402 response leaked the protected data — paywall not enforced",
      );
    }
    const challengeKeys = Object.keys(
      challenge as unknown as Record<string, unknown>,
    );
    if (challengeKeys.includes("data")) {
      throw new Error("Unpaid 402 body unexpectedly carried a `data` field");
    }
    console.log(
      `    ✓ no payment ⇒ data withheld: 402 body is a challenge {${challengeKeys.join(", ")}}, not the envelope`,
    );

    // recordId is opId for the `access` settle op we watch in the poll loop.
    const accessRecordId: Hex | undefined = accept.accessRecord?.recordId;

    // ─── 11. App signs the GenericPayment + retries with X-PAYMENT ───
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

    // ─── 12. Verify post-payment state on the gateway ────────────────
    // The envelope was already served, which means /v1/escrow/pay returned
    // 2xx (the core handler only serves on a 2xx pay response). The grant's
    // paymentStatus is flipped by that same call, but the read-back can lag
    // the write by a beat on a loaded gateway — so poll rather than assert on
    // the first read (mirrors the escrow-credit poll above).
    step("Verifying grant.paymentStatus flipped to 'paid'");
    const grantAfterPay = await pollUntil(
      "grant paymentStatus=paid",
      async () => {
        const g = await gateway.getGrant(grantId);
        if (!g) throw new Error("grant disappeared after pay");
        return g.paymentStatus === "paid" ? g : null;
      },
    );
    console.log(`    paymentStatus:   ${grantAfterPay.paymentStatus}`);
    console.log(`    paidBy:          ${fmt(grantAfterPay.paidBy ?? null)}`);
    console.log(`    paidAt:          ${grantAfterPay.paidAt}`);
    assertEq(grantAfterPay.paymentStatus, "paid", "grant.paymentStatus after");
    assertEq(
      grantAfterPay.paidBy?.toLowerCase(),
      appAccount.address.toLowerCase(),
      "grant.paidBy",
    );

    // ─── Second read: registration paid ⇒ data-access fee only ────────
    // Now that the grant's registration fee is paid, a fresh unpaid read
    // re-issues a 402 whose challenge drops the registration component:
    // buildChallenge sets registrationOwed=false (paymentStatus==="paid"),
    // so registrationFee shows "0" and amount === the per-read dataAccessFee.
    step(
      `Second read of ${SCOPE} without X-PAYMENT — registration already paid`,
    );
    const secondPayRes = await fetch(`${ps.url}${readUri}`, {
      headers: { Authorization: await readAuthFn(readUri) },
    });
    if (secondPayRes.status !== 402) {
      throw new Error(
        `Expected 402 on second read, got ${secondPayRes.status}: ${await secondPayRes.text()}`,
      );
    }
    const secondChallenge = (await secondPayRes.json()) as X402Challenge;
    const secondAccept = secondChallenge.accepts[0];
    console.log(`    second read fee (data access only):`);
    console.log(
      `      amount:     ${secondAccept.amount} (${formatEther(BigInt(secondAccept.amount))} VANA)`,
    );
    console.log(
      `      breakdown:  reg=${secondAccept.breakdown.registrationFee} access=${secondAccept.breakdown.dataAccessFee} regOwed=${secondAccept.breakdown.registrationOwed}`,
    );
    console.log(
      `    first → second: ${firstReadAmount} (reg ${firstRegFee} + access ${firstAccessFee})` +
        ` → ${secondAccept.amount} (access ${secondAccept.breakdown.dataAccessFee})`,
    );
    assertEq(
      secondAccept.breakdown.registrationOwed,
      false,
      "second read: registrationOwed",
    );
    assertEq(
      secondAccept.breakdown.registrationFee,
      "0",
      "second read: registrationFee dropped to 0",
    );
    assertEq(
      secondAccept.amount,
      secondAccept.breakdown.dataAccessFee,
      "second read: amount == dataAccessFee only",
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

    // ─── 13. Replay the same X-PAYMENT → should be rejected ──────────
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

    // ─── 14. Drain pending ops to chain via gateway.settle ───────────
    // settle() submits pending off-chain ledger entries to L1: grant
    // registration, server registration, the just-settled payment, etc.
    // The gateway batches scans; ops can be in {pending|submitting|
    // confirmed|finalized|failed|reorged}.
    //
    // `failed` is OFTEN TRANSIENT here — e.g., the grant's settle tx
    // depends on the server's on-chain registration tx having mined
    // first, but they may be sent in the same batch and race. The
    // gateway's own scheduler retries failed items on subsequent passes;
    // our poll lets that play out. We log the diagnostic so the operator
    // can see what happened but don't bail.
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
    const settleResult = await drainSettle();
    console.log(`    scanned:   ${settleResult.scanned}`);
    console.log(`    confirmed: ${settleResult.confirmed}`);
    console.log(`    submitted: ${settleResult.submitted}`);
    console.log(`    skipped:   ${settleResult.skipped}`);
    console.log(`    failed:    ${settleResult.failed}`);

    function logInitial(opType: string, opId: Hex, label: string): void {
      const item = (settleResult.items ?? []).find(
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
    // Builder registration settles on-chain like server/data registration
    // (registerGrantee, no fee): the gateway drains it once the builder row is
    // status='pending' + payment_status='paid' (paid-on-insert when no builder
    // fee is configured).
    logInitial("builder", builderId, "builder");
    if (accessRecordId) {
      logInitial("access", accessRecordId, "access");
    }

    // Builder settles on-chain via the gateway's drainBuilders → registerGrantee.
    // We do NOT hard-assert on this single drain batch: drainBuilders gates on
    // (status='pending' AND payment_status='paid') with FOR UPDATE SKIP LOCKED,
    // so the builder row may be picked up by THIS settle(), a later poll, or a
    // concurrent gateway drain that already moved it past 'pending' — in which
    // case it's legitimately absent from items[]. We capture the drain item
    // opportunistically (for its settle tx hash) and defer the real assertion
    // to the final step, which checks the on-chain GranteeRegistered event
    // directly (ground truth, batch-independent).
    //
    // NB: older vana-sdk builds typed SettleOpType as
    // "grant"|"server"|"data"|"access" (no "builder"); the gateway always
    // emitted builder items at runtime, so this find() works regardless — the
    // SDK type widening just makes `i.opType === "builder"` type-check.
    let builderDrainItem: SettleItem | undefined = (
      settleResult.items ?? []
    ).find(
      (i: SettleItem) =>
        i.opType === "builder" &&
        i.opId.toLowerCase() === builderId.toLowerCase(),
    );
    if (builderDrainItem) {
      const tx =
        "settleTxHash" in builderDrainItem
          ? builderDrainItem.settleTxHash
          : null;
      console.log(
        `    builder: drained this pass status=${builderDrainItem.status}${tx ? ` tx=${tx}` : ""}`,
      );
    } else {
      console.log(
        `    builder: not in this drain batch (already drained, or queued for a later pass — verified on-chain below)`,
      );
    }

    // ─── 15. Poll gateway.settle until ALL watched ops finalize ─────
    // Loop until every watched op reaches status="finalized". `reorged`
    // is fatal (chain rewound past a settle tx; the gateway will resubmit
    // but the assertion target moved). On each poll we capture the settle
    // tx hash and chain block height for the final summary.
    //
    // Timeout is generous (default 10 min); override with
    // FINALIZE_TIMEOUT_MS env if your chain is slow. Polls every 10s by
    // default to limit gateway load while still picking up state changes
    // promptly on Moksha's ~6s block time.
    step("Polling gateway.settle until every op's settle tx is mined on-chain");
    const FINALIZE_TIMEOUT_MS = Number(
      process.env["FINALIZE_TIMEOUT_MS"] ?? 600_000,
    );
    const FINALIZE_POLL_MS = Number(process.env["FINALIZE_POLL_MS"] ?? 10_000);
    // NOTE: builder is intentionally NOT in the finalize-watched set. The
    // gateway settle DRAIN submits the registerGrantee tx on-chain (asserted
    // below from the drain result), but its RECONCILE phase does not track
    // builder finalization — `reconciled.items` never carries a builder entry,
    // so it would hang at builder=pending forever. We assert builder settled
    // (confirmed + tx) at drain time instead.
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
      // Gateway reconcile verdict: finalized | unchanged | reorged | pending.
      // NOTE this is NOT the op's DB lifecycle status — an op only appears in
      // reconciled.items once it's already 'confirmed', and "unchanged" means
      // "still confirmed, block not past the chain's finalized tip yet".
      reconcileStatus: string;
      settleTxHash: `0x${string}` | null;
      chainBlockHeight: string | null;
      // Ground truth: the settle tx receipt is mined AND status === "success".
      minedOk: boolean;
      reason: string | null;
    }
    const finalStatus: Record<string, WatchedState> = {};
    const finalizeStart = Date.now();
    let allSettled = false;
    // Success condition = every watched op's settle tx is mined + successful
    // on-chain. We do NOT block on the gateway's reconcile promoting
    // 'confirmed' → 'finalized': that gates on the chain's `finalized` tip,
    // which can lag minutes on Moksha (the op sits at reconcile-status
    // "unchanged" — i.e. confirmed-but-not-yet-finalized). A mined+successful
    // settle tx is the real "it landed on-chain" signal; `finalized` is a
    // stricter bonus we surface when it happens.
    while (Date.now() - finalizeStart < FINALIZE_TIMEOUT_MS) {
      const r = await drainSettle();
      // Each poll is also a fresh drain — grab the builder item the first time
      // any pass surfaces it, so the final step can report the settle-drain tx
      // hash alongside the on-chain event.
      // A settle response may omit items/reconciled when a pass has nothing to
      // report (empty/partial body); default to empty arrays so a quiet poll
      // doesn't crash the loop.
      if (!builderDrainItem) {
        builderDrainItem = (r.items ?? []).find(
          (i: SettleItem) =>
            i.opType === "builder" &&
            i.opId.toLowerCase() === builderId.toLowerCase(),
        );
      }
      const elapsed = Math.round((Date.now() - finalizeStart) / 1000);
      let allOk = true;
      let line = `    [${elapsed}s]`;
      for (const w of watched) {
        const item = (r.reconciled?.items ?? []).find(
          (i: SettleReconcileItem) =>
            i.opId.toLowerCase() === w.opId.toLowerCase(),
        );
        const prev = finalStatus[w.opId];
        const reconcileStatus =
          item?.status ?? prev?.reconcileStatus ?? "pending";
        if (reconcileStatus === "reorged") {
          throw new Error(
            `reconcile flagged ${w.label.trim()} ${w.opId} as reorged${item?.reason ? `: ${item.reason}` : ""}`,
          );
        }
        const settleTxHash =
          (item?.settleTxHash as `0x${string}` | null) ??
          prev?.settleTxHash ??
          null;
        let minedOk = prev?.minedOk ?? false;
        let chainBlockHeight =
          item?.chainBlockHeight ?? prev?.chainBlockHeight ?? null;
        // Verify the settle tx directly on-chain (the SDK reconcile item only
        // tells us the gateway's finality view; the receipt tells us the tx
        // actually landed). getTransactionReceipt throws until the tx is mined.
        if (!minedOk && settleTxHash) {
          try {
            const receipt = await publicClient.getTransactionReceipt({
              hash: settleTxHash,
            });
            if (receipt.status === "success") {
              minedOk = true;
              chainBlockHeight = receipt.blockNumber.toString();
            }
          } catch {
            // Receipt not available yet — tx not mined; retry next poll.
          }
        }
        finalStatus[w.opId] = {
          reconcileStatus,
          settleTxHash,
          chainBlockHeight,
          minedOk,
          reason: item?.reason ?? prev?.reason ?? null,
        };

        // Display the TRUE state: finalized (reconcile promoted) > confirmed
        // (settle tx mined) > the raw reconcile verdict (pending/unchanged).
        const state = minedOk
          ? reconcileStatus === "finalized"
            ? "finalized"
            : "confirmed"
          : reconcileStatus;
        const txSuffix = settleTxHash
          ? ` tx=${settleTxHash.slice(0, 12)}…`
          : "";
        line += ` ${w.label}=${state}${txSuffix}`;
        if (!minedOk) allOk = false;
      }
      console.log(line);
      if (allOk) {
        allSettled = true;
        const finalizedCount = watched.filter(
          (w) => finalStatus[w.opId]?.reconcileStatus === "finalized",
        ).length;
        console.log(
          `    ✓ all ${watched.length} ops settled on-chain (settle tx mined) in ${elapsed}s` +
            ` — ${finalizedCount}/${watched.length} also past finality tip`,
        );
        break;
      }
      await new Promise((r) => setTimeout(r, FINALIZE_POLL_MS));
    }
    if (!allSettled) {
      const summary = watched
        .map((w) => {
          const s = finalStatus[w.opId];
          return `${w.label.trim()}=${s?.minedOk ? "confirmed" : (s?.reconcileStatus ?? "pending")}`;
        })
        .join(", ");
      throw new Error(
        `Timed out after ${FINALIZE_TIMEOUT_MS / 1000}s waiting for on-chain settlement (settle tx mined). Last: ${summary}`,
      );
    }

    // Per-op settle-tx + block summary. "confirmed" = settle tx mined;
    // "finalized" = the gateway's reconcile also promoted it past the chain's
    // finality tip (may still be catching up on slow-finality chains).
    console.log("");
    console.log(
      "    Settled on-chain (confirmed = mined; finalized = past finality tip):",
    );
    for (const w of watched) {
      const s = finalStatus[w.opId];
      console.log(
        `      ${w.label.trim()}:` +
          ` ${s.reconcileStatus === "finalized" ? "finalized" : "confirmed"}` +
          ` tx=${s.settleTxHash ?? "(none)"}` +
          ` block=${s.chainBlockHeight ?? "(unknown)"}`,
      );
    }

    // ─── 16. Assert builder registration landed on-chain ────────────
    // Ground truth for builder settlement: the DataPortabilityGrantees
    // contract emits GranteeRegistered when the gateway relayer submits
    // registerGrantee for the builder row. We assert against the event (not a
    // single settle batch) because the builder is not reconcile-tracked and
    // its drain pass is non-deterministic (see the step-14 note). By the time
    // the watched ops above have settled on-chain, the builder's registerGrantee
    // — submitted in the same drain wave — has been mined; a short poll covers
    // any lag.
    step("Verifying builder registration landed on-chain (GranteeRegistered)");
    const GRANTEE_REGISTERED_EVENT = parseAbiItem(
      "event GranteeRegistered(uint256 indexed granteeId, address indexed owner, address indexed granteeAddress, string publicKey)",
    );
    const granteesContract = GATEWAY_CONFIG.contracts
      .dataPortabilityGrantees as `0x${string}`;
    let granteeId: bigint | undefined;
    let granteeTxHash: `0x${string}` | null = null;
    let granteeBlock: bigint | null = null;
    for (let attempt = 1; attempt <= 5 && granteeId === undefined; attempt++) {
      // getLogs is typed off the `event` arg, so `log.args` is fully inferred.
      const logs = await publicClient.getLogs({
        address: granteesContract,
        event: GRANTEE_REGISTERED_EVENT,
        args: { granteeAddress: appAccount.address },
        fromBlock: builderProbeFromBlock,
        toBlock: "latest",
      });
      const last = logs.at(-1);
      if (last) {
        granteeId = last.args.granteeId;
        granteeTxHash = last.transactionHash;
        granteeBlock = last.blockNumber;
      } else {
        await new Promise((r) => setTimeout(r, FINALIZE_POLL_MS));
      }
    }
    if (granteeId === undefined) {
      throw new Error(
        `builder registration did not land on-chain: no GranteeRegistered ` +
          `event for granteeAddress=${appAccount.address} on ${granteesContract} ` +
          `(scanned from block ${builderProbeFromBlock})`,
      );
    }
    const drainTx =
      builderDrainItem && "settleTxHash" in builderDrainItem
        ? builderDrainItem.settleTxHash
        : null;
    console.log(
      `    ✓ builder registered on-chain (registerGrantee)` +
        ` granteeId=${granteeId}` +
        ` tx=${granteeTxHash}` +
        ` block=${granteeBlock}`,
    );
    if (drainTx) {
      console.log(`      (settle drain reported tx=${drainTx})`);
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
    console.log("  ✓ Personal server LITE X402 E2E PASSED");
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
  }
}

main().catch((err) => {
  console.error("\n✗ Personal server LITE X402 E2E failed:");
  console.error(err);
  process.exit(1);
});
