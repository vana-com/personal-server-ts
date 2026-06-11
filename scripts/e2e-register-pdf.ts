/**
 * End-to-end: register a binary PDF (a DEXA scan) to the Vana network.
 *
 * Flow:
 *   1. Load the owner wallet (VANA_WEB_PRIVATE_KEY from .env.local, else
 *      ephemeral) + derive its master-key signature. The key is never logged.
 *   2. Register a server account with the gateway, then boot a personal server
 *      (sync enabled). Registering before boot avoids a transient "unregistered"
 *      sync warning.
 *   3. Download the sample DEXA PDF and POST it to /v1/data/{scope} as binary.
 *      Unstructured data is ingested schemaless — DPv2 data points are
 *      scope-addressed and carry no schemaId.
 *   4. Trigger sync → the file is encrypted, uploaded to storage (version-keyed),
 *      and registered on-chain (registerDataPoint). Poll until it gets a
 *      dataPointId.
 *   5. Discover the owner's scopes from the gateway via listDataPointsByOwner
 *      (DataPointRecords carry scope directly). Confirm the scope shows up.
 *   6. Boot a SECOND registered server for the same owner; its sync downloads +
 *      decrypts the data point, then serves the raw bytes back — verify match.
 *
 * Run (needs a gateway + storage that point at each other — see e2e:sync notes;
 * the public storage-dev is wired to a stale gateway, so run vana-storage
 * locally against the same GATEWAY_URL and point STORAGE_API_URL at it):
 *   GATEWAY_URL=… STORAGE_API_URL=http://localhost:8787 npm run e2e:register-pdf
 *
 * Optional env overrides (also read from .env.local):
 *   VANA_WEB_PRIVATE_KEY            (owner private key; else a fresh one is made)
 *   GATEWAY_URL                     (default https://dev.data-gateway.vana.org)
 *   STORAGE_API_URL                 (blob storage endpoint that validates the
 *                                    server↔owner link against THIS gateway's
 *                                    environment; defaults to the SDK's prod
 *                                    storage, which rejects a dev-registered
 *                                    server — set this to the dev storage host)
 *   PDF_URL                         (default the DEXA Body sample report)
 *   DATA_SCOPE                      (default dexa.scan)
 *   SERVER_URL                      (URL registered with the gateway)
 *
 *   EIP-712 domain (must match the gateway's chain; defaults = Moksha/14800):
 *   GATEWAY_CHAIN_ID                (e.g. 1480 for mainnet)
 *   GATEWAY_DATA_REGISTRY           (file registration verifying contract)
 *   GATEWAY_DP_SERVER               (server registration verifying contract)
 *   GATEWAY_DP_PERMISSIONS          (grant registration verifying contract)
 *   GATEWAY_DP_GRANTEES             (builder registration verifying contract)
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  type DataPointRecord,
  MASTER_KEY_MESSAGE,
  serverRegistrationDomain,
  SERVER_REGISTRATION_TYPES,
  type ServerRegistrationMessage,
} from "@opendatalabs/vana-sdk/node";
import {
  ServerConfigSchema,
  type ServerConfig,
} from "../packages/core/src/schemas/server-config.js";
import { createServer } from "../packages/server/src/bootstrap.js";
import { loadOrCreateServerAccount } from "../packages/server/src/keys/server-account.js";

// Load .env.local (e.g. VANA_WEB_PRIVATE_KEY) without overriding already-set env
// vars. Secrets are read at runtime only — never logged or committed.
try {
  process.loadEnvFile(".env.local");
} catch {
  // .env.local is optional.
}

const GATEWAY_URL = (
  process.env.GATEWAY_URL ?? "https://dev.data-gateway.vana.org"
).replace(/\/+$/, "");
const STORAGE_API_URL = process.env.STORAGE_API_URL;
const PDF_URL =
  process.env.PDF_URL ??
  "https://dexabody.com/wp-content/uploads/2021/09/Dexa-Body-Sample-Report-1.pdf";
const SCOPE = process.env.DATA_SCOPE ?? "dexa.scan";
const PORT = 8788;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function log(step: string, msg: string) {
  console.log(`\n[${step}] ${msg}`);
}

function sha256hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/** Pretty-print a DataFileEnvelope, truncating the base64 `content` blob. */
function previewEnvelope(envelope: Record<string, unknown>): void {
  const data = { ...((envelope.data as Record<string, unknown>) ?? {}) };
  let contentNote: string | undefined;
  if (typeof data.content === "string") {
    contentNote = `${data.content.slice(0, 24)}… (${data.content.length} base64 chars)`;
    delete data.content;
  }
  console.log("  envelope:");
  console.log(`    version:     ${envelope.version}`);
  console.log(`    scope:       ${envelope.scope}`);
  console.log(`    collectedAt: ${envelope.collectedAt}`);
  console.log("    data:");
  for (const [k, v] of Object.entries(data)) {
    console.log(`      ${k}: ${typeof v === "string" ? v : JSON.stringify(v)}`);
  }
  if (contentNote) console.log(`      content: ${contentNote}`);
}

/**
 * Build a server config. The EIP-712 signing domain (chainId + contract
 * addresses) MUST match the gateway's environment — defaults are Moksha (which
 * matches the dev gateway); for mainnet supply chainId + contracts via env.
 */
function makeConfig(port: number): ServerConfig {
  const contractEnv = {
    dataRegistry: process.env.GATEWAY_DATA_REGISTRY,
    dataPortabilityPermissions: process.env.GATEWAY_DP_PERMISSIONS,
    dataPortabilityServer: process.env.GATEWAY_DP_SERVER,
    dataPortabilityGrantees: process.env.GATEWAY_DP_GRANTEES,
  };
  const contracts = Object.fromEntries(
    Object.entries(contractEnv).filter(([, v]) => v),
  );
  return ServerConfigSchema.parse({
    server: { port, origin: `http://localhost:${port}` },
    gateway: {
      url: GATEWAY_URL,
      ...(process.env.GATEWAY_CHAIN_ID
        ? { chainId: Number(process.env.GATEWAY_CHAIN_ID) }
        : {}),
      ...(Object.keys(contracts).length ? { contracts } : {}),
    },
    sync: { enabled: true },
    tunnel: { enabled: false },
    devUi: { enabled: true },
    logging: { level: "warn" },
    ...(STORAGE_API_URL
      ? {
          storage: {
            backend: "vana",
            config: { vana: { apiUrl: STORAGE_API_URL } },
          },
        }
      : {}),
  });
}

async function registerServer(params: {
  gatewayUrl: string;
  gatewayConfig: ServerConfig["gateway"];
  ownerAccount: ReturnType<typeof privateKeyToAccount>;
  serverAddress: `0x${string}`;
  serverPublicKey: `0x${string}`;
  serverUrl: string;
}): Promise<void> {
  const message: ServerRegistrationMessage = {
    ownerAddress: params.ownerAccount.address,
    serverAddress: params.serverAddress,
    publicKey: params.serverPublicKey,
    serverUrl: params.serverUrl,
  };
  const domain = serverRegistrationDomain(params.gatewayConfig);
  const signature = await params.ownerAccount.signTypedData({
    domain: domain as Parameters<
      typeof params.ownerAccount.signTypedData
    >[0]["domain"],
    types: SERVER_REGISTRATION_TYPES,
    primaryType: "ServerRegistration",
    message: message as unknown as Record<string, unknown>,
  });

  const res = await fetch(`${params.gatewayUrl}/v1/servers`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Web3Signed ${signature}`,
    },
    body: JSON.stringify(message),
  });

  if (res.status === 409) {
    console.log("  server already registered (409)");
    return;
  }
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`server registration failed: ${res.status} ${body}`);
  }
  console.log("  server registered");
}

type ServerCtx = Awaited<ReturnType<typeof createServer>>;
type ReadyServer = ServerCtx & {
  serverAccount: NonNullable<ServerCtx["serverAccount"]>;
  syncManager: NonNullable<ServerCtx["syncManager"]>;
  devToken: string;
};

/**
 * Generate the server signing account, register it with the gateway, THEN boot
 * the server. Registering before boot means the background sync loop is already
 * authorized on its first cycle (no transient "unregistered" warning).
 */
async function bootRegisteredServer(params: {
  rootPath: string;
  port: number;
  ownerAccount: ReturnType<typeof privateKeyToAccount>;
  masterKeySignature: `0x${string}`;
  label: string;
}): Promise<ReadyServer> {
  const config = makeConfig(params.port);
  const serverAccount = loadOrCreateServerAccount(
    join(params.rootPath, "key.json"),
  );
  console.log(`  ${params.label} address: ${serverAccount.address}`);
  await registerServer({
    gatewayUrl: GATEWAY_URL,
    gatewayConfig: config.gateway,
    ownerAccount: params.ownerAccount,
    serverAddress: serverAccount.address,
    serverPublicKey: serverAccount.publicKey,
    serverUrl: `http://localhost:${params.port}`,
  });
  const ctx = await createServer(config, {
    rootPath: params.rootPath,
    ownerSignature: params.masterKeySignature,
  });
  if (!ctx.serverAccount || !ctx.syncManager || !ctx.devToken) {
    throw new Error(
      `${params.label} did not start with sync + signing account`,
    );
  }
  return ctx as ReadyServer;
}

/**
 * Discover the scopes a user has data in, from their on-chain data points:
 *   listDataPointsByOwner(<addr>) → each record's scope   (paginated via cursor)
 * DataPointRecords carry `scope` directly, so no schemaId→scope resolution is
 * needed. Returns a map of scope → data-point count.
 */
async function gatewayScopesForUser(
  gateway: ServerCtx["gatewayClient"],
  userAddress: string,
): Promise<Map<string, number>> {
  const dataPoints: DataPointRecord[] = [];
  let cursor: string | null = null;
  for (let page = 0; page < 100; page++) {
    const result: { dataPoints: DataPointRecord[]; cursor: string | null } =
      await gateway.listDataPointsByOwner(userAddress, cursor);
    dataPoints.push(...result.dataPoints);
    cursor = result.cursor;
    if (!cursor) break;
  }
  console.log(`  ${dataPoints.length} data point(s) on the gateway`);

  const byScope = new Map<string, number>();
  for (const dp of dataPoints) {
    byScope.set(dp.scope, (byScope.get(dp.scope) ?? 0) + 1);
  }
  return byScope;
}

async function main() {
  const rootPath = await mkdtemp(join(tmpdir(), "vana-e2e-"));

  // 1. Owner wallet + master-key signature. Prefer the user's key from
  // .env.local (VANA_WEB_PRIVATE_KEY); otherwise generate an ephemeral one.
  // The private key is read at runtime only and is never logged.
  const envKey = process.env.VANA_WEB_PRIVATE_KEY;
  const ownerPrivateKey = envKey
    ? ((envKey.startsWith("0x") ? envKey : `0x${envKey}`) as `0x${string}`)
    : generatePrivateKey();
  const ownerAccount = privateKeyToAccount(ownerPrivateKey);
  const masterKeySignature = await ownerAccount.signMessage({
    message: MASTER_KEY_MESSAGE,
  });
  log("1/6", "Loaded owner wallet");
  console.log(
    `  owner source:  ${envKey ? "VANA_WEB_PRIVATE_KEY (.env.local)" : "ephemeral (generated)"}`,
  );
  console.log(`  owner address: ${ownerAccount.address}`);
  console.log(`  gateway:       ${GATEWAY_URL}`);
  console.log(`  chainId:       ${makeConfig(PORT).gateway.chainId}`);

  let ctx2: ReadyServer | undefined;
  let rootPath2: string | undefined;
  let ctx: ReadyServer | undefined;
  try {
    // 2. Register the server account, then boot the personal server.
    log("2/6", "Registering + starting personal server");
    ctx = await bootRegisteredServer({
      rootPath,
      port: PORT,
      ownerAccount,
      masterKeySignature,
      label: "server",
    });

    // 3. Download the PDF and POST it as binary (ingested schemaless).
    log("3/6", `Downloading + posting PDF to scope "${SCOPE}"`);
    const pdfRes = await fetch(PDF_URL);
    if (!pdfRes.ok) {
      throw new Error(`failed to download PDF: ${pdfRes.status}`);
    }
    const pdfBytes = new Uint8Array(await pdfRes.arrayBuffer());
    console.log(`  downloaded ${pdfBytes.length} bytes`);

    const postRes = await ctx.app.request(`/v1/data/${SCOPE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/pdf",
        "X-Filename": "dexa-body-sample-report.pdf",
        "X-Vana-Metadata": "DEXA Body sample scan report",
        Authorization: `Bearer ${ctx.devToken}`,
      },
      body: pdfBytes,
    });
    if (postRes.status !== 201) {
      throw new Error(
        `ingest failed: ${postRes.status} ${await postRes.text()}`,
      );
    }
    const ingestResponse = (await postRes.json()) as Record<string, unknown>;
    console.log(
      `  ingested: scope=${ingestResponse.scope} collectedAt=${ingestResponse.collectedAt} status=${ingestResponse.status}`,
    );

    // Fetch the stored envelope to show exactly what was persisted on disk.
    const envRes = await ctx.app.request(`/v1/data/${SCOPE}`, {
      headers: { Authorization: `Bearer ${ctx.devToken}` },
    });
    const envelope = (await envRes.json()) as Record<string, unknown>;
    previewEnvelope(envelope);

    // 4. Sync: encrypt → upload to storage → register the DPv2 data point.
    // Poll for the gateway-assigned dataPointId.
    log("4/6", "Syncing (upload + on-chain registerDataPoint)");
    let dataPointId: string | null = null;
    for (let attempt = 1; attempt <= 12 && !dataPointId; attempt++) {
      await ctx.syncManager.trigger();
      const entry = ctx.indexManager.findLatestByScope(SCOPE);
      dataPointId = entry?.dataPointId ?? null;
      const status = ctx.syncManager.getStatus();
      console.log(
        `  attempt ${attempt}: pending=${status.pendingFiles} blocked=${status.blocked ?? "-"} dataPointId=${dataPointId ?? "…"}`,
      );
      if (status.errors.length) {
        console.log(`    errors: ${JSON.stringify(status.errors.slice(-2))}`);
      }
      if (!dataPointId) await sleep(2500);
    }

    if (!dataPointId) {
      throw new Error(
        "data point was not registered on-chain (no dataPointId after sync). " +
          "Check that the server registration was accepted and storage/gateway are reachable.",
      );
    }

    const record = await ctx.gatewayClient
      .getDataPoint(dataPointId)
      .catch(() => null);
    console.log("  registered:");
    console.log(`    dataPointId: ${dataPointId}`);
    if (record) console.log(`    version:     ${record.expectedVersion}`);

    // 5. Discover the owner's scopes from the gateway by listing data points by
    // owner. Confirms the freshly registered data point is discoverable on the
    // network by user address.
    log("5/6", "Listing owner scopes from the gateway (data points)");
    const scopes = await gatewayScopesForUser(
      ctx.gatewayClient,
      ownerAccount.address,
    );
    console.log(`  scopes (${scopes.size}):`);
    for (const [scope, count] of [...scopes.entries()].sort()) {
      console.log(`    ${scope} — ${count} file${count === 1 ? "" : "s"}`);
    }
    if (!scopes.has(SCOPE)) {
      throw new Error(
        `expected scope "${SCOPE}" not found in the gateway file listing`,
      );
    }

    // 6. Download + decryption: a SECOND personal server for the same owner
    // (registered before boot) pulls the file off the network, decrypts it with
    // the owner's master key, and serves it back — full cross-server round-trip.
    log("6/6", "Verifying download + decryption on a second server");
    rootPath2 = await mkdtemp(join(tmpdir(), "vana-e2e-2-"));
    ctx2 = await bootRegisteredServer({
      rootPath: rootPath2,
      port: PORT + 1,
      ownerAccount,
      masterKeySignature,
      label: "server2",
    });

    // Trigger sync → the download worker fetches + decrypts the file.
    let downloaded = false;
    for (let attempt = 1; attempt <= 12 && !downloaded; attempt++) {
      await ctx2.syncManager.trigger();
      downloaded = Boolean(ctx2.indexManager.findByDataPointId(dataPointId));
      console.log(`  download attempt ${attempt}: found=${downloaded}`);
      if (!downloaded) await sleep(2500);
    }
    if (!downloaded) {
      throw new Error("second server did not download/decrypt the file");
    }

    // Show server 2's decrypted envelope (should be byte-identical to server 1's).
    const env2Res = await ctx2.app.request(`/v1/data/${SCOPE}`, {
      headers: { Authorization: `Bearer ${ctx2.devToken}` },
    });
    const envelope2 = (await env2Res.json()) as Record<string, unknown>;
    console.log("  server2 decrypted envelope:");
    previewEnvelope(envelope2);

    // Read the decrypted bytes back through server 2's raw endpoint.
    const rawRes = await ctx2.app.request(`/v1/data/${SCOPE}?content=raw`, {
      headers: { Authorization: `Bearer ${ctx2.devToken}` },
    });
    if (rawRes.status !== 200) {
      throw new Error(`raw read failed: ${rawRes.status}`);
    }
    const roundTripped = new Uint8Array(await rawRes.arrayBuffer());
    const origHash = sha256hex(pdfBytes);
    const rtHash = sha256hex(roundTripped);
    const matches = origHash === rtHash;
    console.log(
      `  bytes: original=${pdfBytes.length} downloaded=${roundTripped.length}`,
    );
    console.log(`  sha256 original:   ${origHash}`);
    console.log(`  sha256 downloaded: ${rtHash}`);
    console.log(`  content-type: ${rawRes.headers.get("content-type")}`);
    console.log(`  metadata: ${rawRes.headers.get("x-vana-metadata")}`);
    if (!matches) {
      throw new Error("decrypted bytes do not match the original PDF");
    }

    console.log("\n✅ DEXA scan registered AND round-tripped");
    console.log(`   owner:    ${ownerAccount.address}`);
    console.log(`   server:   ${ctx.serverAccount.address}`);
    console.log(`   scope:    ${SCOPE}`);
    console.log(`   dataPointId: ${dataPointId}`);
    if (record) console.log(`   version:     ${record.expectedVersion}`);
    console.log(`   download+decrypt verified: bytes match (sha256 ${rtHash})`);
  } finally {
    if (ctx2) await ctx2.cleanup();
    if (rootPath2) await rm(rootPath2, { recursive: true, force: true });
    if (ctx) await ctx.cleanup();
    await rm(rootPath, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error("\n❌ E2E failed:", err);
  process.exit(1);
});
