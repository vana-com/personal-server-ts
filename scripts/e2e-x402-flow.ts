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
  parseEther,
  type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { serve, type ServerType } from "@hono/node-server";
import {
  BUILDER_REGISTRATION_TYPES,
  GENERIC_PAYMENT_TYPES,
  MASTER_KEY_MESSAGE,
  NATIVE_VANA_ASSET,
  SERVER_REGISTRATION_TYPES,
  builderRegistrationDomain,
  buildDepositNativeRequest,
  createGatewayClient,
  escrowPaymentDomain,
  serverRegistrationDomain,
  type DataPortabilityGatewayConfig,
} from "@opendatalabs/vana-sdk/node";
import { buildWeb3SignedHeader } from "@opendatalabs/vana-sdk/node";
import {
  encodePaymentHeader,
  nextPaymentNonce,
  type X402Challenge,
} from "../packages/core/src/payment/index.js";
import { ServerConfigSchema } from "../packages/core/src/schemas/server-config.js";
import { createServer } from "../packages/server/src/bootstrap.js";

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

// ─── Personal server bootstrap ───────────────────────────────────────────

interface PersonalServerHandle {
  url: string;
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

  const context = await createServer(config, {
    serverDir: params.serverDir,
    dataDir: join(params.serverDir, "data"),
  });

  const httpServer: ServerType = serve({
    fetch: context.app.fetch,
    port,
  });

  return {
    url: `http://localhost:${port}`,
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
  console.log(`    user:    ${userAccount.address}  (testnet only)`);
  console.log(`    app:     ${appAccount.address}  (testnet only)`);

  // ─── 2. User signs the master-key message, boots personal-server ───
  step("User signs MASTER_KEY_MESSAGE and starts the personal server");
  const ownerSignature = (await userAccount.signMessage({
    message: MASTER_KEY_MESSAGE,
  })) as Hex;
  console.log(`    signature: ${ownerSignature.slice(0, 18)}…`);

  const serverDir = await mkdtemp(join(tmpdir(), "e2e-ps-x402-"));
  const ps = await startPersonalServer({ ownerSignature, serverDir });
  console.log(`    server URL: ${ps.url}`);
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
    console.log(`    serverId:   ${serverRes.serverId}`);

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

    // ─── 6. Funder pre-funds the app's escrow ─────────────────────────
    step(
      `Funder depositing ${formatEther(DEPOSIT_AMOUNT)} VANA into app's escrow`,
    );
    const funderAccount = privateKeyToAccount(FUNDER_PRIVATE_KEY);
    const funderBalance = await publicClient.getBalance({
      address: funderAccount.address,
    });
    console.log(`    funder:     ${funderAccount.address}`);
    console.log(`    funder bal: ${formatEther(funderBalance)} VANA`);
    if (funderBalance < DEPOSIT_AMOUNT) {
      throw new Error(
        `Funder has ${formatEther(funderBalance)} VANA, needs ${formatEther(DEPOSIT_AMOUNT)}. Top up ${funderAccount.address} on Moksha.`,
      );
    }
    const funderWallet = createWalletClient({
      account: funderAccount,
      chain: moksha,
      transport: http(RPC_URL),
    });
    const depositReq = buildDepositNativeRequest(GATEWAY_CONFIG, {
      account: appAccount.address,
      amount: DEPOSIT_AMOUNT,
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
      if (!native || BigInt(native.balance) < DEPOSIT_AMOUNT) return null;
      return native;
    });

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

    // ─── 8. User creates a grant via the personal server ─────────────
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

    // ─── 9. App tries to read without X-PAYMENT → 402 ────────────────
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
    } else {
      console.log(
        `    accessRec:  (none — sync worker hasn't registered the data point)`,
      );
    }

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

    // ─── 11. Verify post-payment state on the gateway ────────────────
    step("Verifying grant.paymentStatus flipped to 'paid'");
    const grantAfterPay = await gateway.getGrant(grantId);
    if (!grantAfterPay) throw new Error("grant disappeared after pay");
    console.log(`    paymentStatus:   ${grantAfterPay.paymentStatus}`);
    console.log(`    paidBy:          ${grantAfterPay.paidBy}`);
    console.log(`    paidAt:          ${grantAfterPay.paidAt}`);
    assertEq(grantAfterPay.paymentStatus, "paid", "grant.paymentStatus after");
    assertEq(
      grantAfterPay.paidBy?.toLowerCase(),
      appAccount.address.toLowerCase(),
      "grant.paidBy",
    );

    step("Verifying app's escrow balance decreased by the paid amount");
    const balanceAfter = await gateway.getEscrowBalance(appAccount.address);
    const nativeAfter = balanceAfter.balances.find(
      (b: { asset: string }) =>
        b.asset.toLowerCase() === NATIVE_VANA_ASSET.toLowerCase(),
    );
    if (!nativeAfter) throw new Error("app has no native balance row");
    const delta = DEPOSIT_AMOUNT - BigInt(nativeAfter.balance);
    console.log(
      `    bal after:  ${formatEther(BigInt(nativeAfter.balance))} VANA`,
    );
    console.log(`    delta:      ${formatEther(delta)} VANA (paid for grant)`);

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
