/**
 * End-to-end (REAL gateway + storage): a fresh personal server registers,
 * SYNCS the owner's files down from Vana storage (real download + decrypt +
 * block sidecars), then an MCP client reads a synced scope over OAuth.
 *
 * Mirrors e2e-register-pdf.ts's "real" setup (VANA_WEB_PRIVATE_KEY owner, real
 * dev gateway, storage-dev) and adds the full MCP OAuth flow: register client →
 * PKCE authorize → owner approves with scopes (registers the connection's
 * grantee as a builder + creates a grant ON THE GATEWAY) → token → read_scope.
 *
 * The file is NEVER ingested locally — it arrives only via sync/decrypt.
 *
 * Run (needs VANA_WEB_PRIVATE_KEY in .env.local):
 *   GATEWAY_URL=https://data-gateway-env-dev-opendatalabs.vercel.app \
 *   STORAGE_API_URL=https://storage-dev.vana.org \
 *   npx tsx scripts/e2e-sync-mcp.ts
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { privateKeyToAccount } from "viem/accounts";
import {
  MASTER_KEY_MESSAGE,
  deriveMasterKey,
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
import { createNodeDataStorage } from "../packages/server/src/storage/node-data-storage.js";
import { createVanaSyncStorageAdapter } from "@opendatalabs/personal-server-ts-core/storage/adapters";
import { downloadAll } from "../packages/core/src/sync/workers/download.js";
import { buildWeb3SignedHeader } from "@opendatalabs/personal-server-ts-core/test-utils";

try {
  process.loadEnvFile(".env.local");
} catch {
  // optional
}

const GATEWAY_URL = (
  process.env.GATEWAY_URL ??
  "https://data-gateway-env-dev-opendatalabs.vercel.app"
).replace(/\/+$/, "");
const STORAGE_API_URL =
  process.env.STORAGE_API_URL ?? "https://storage-dev.vana.org";
const SCOPES = (process.env.DATA_SCOPES ?? "dexa.scan,chatgpt.conversations")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
// Grant the source wildcard for each scope (e.g. dexa.* , chatgpt.*).
const GRANT_SCOPES = [...new Set(SCOPES.map((s) => `${s.split(".")[0]}.*`))];
const PORT = 8802;
const ORIGIN = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9876/callback";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sha256hex = (b: Uint8Array) =>
  createHash("sha256").update(b).digest("hex");
const b64url = (b: Buffer) => b.toString("base64url");
// Decode the opaque read_scope cursor purely to SHOW pagination progress.
const cursorIndex = (c?: string): number | "—" => {
  if (!c) return "—";
  try {
    return JSON.parse(Buffer.from(c, "base64url").toString()).blockIndex;
  } catch {
    return -1;
  }
};

const failures: string[] = [];
function check(ok: boolean, label: string, detail: unknown = "") {
  console.log(
    `${ok ? "PASS" : "FAIL"} ${label}${detail ? ` — ${String(detail)}` : ""}`,
  );
  if (!ok) failures.push(label);
}

// ── Server registration (same EIP-712 path as e2e-register-pdf) ─────────────
async function registerServer(params: {
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
  const res = await fetch(`${GATEWAY_URL}/v1/servers`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Web3Signed ${signature}`,
    },
    body: JSON.stringify(message),
  });
  if (res.status !== 409 && !res.ok) {
    throw new Error(
      `server registration failed: ${res.status} ${await res.text()}`,
    );
  }
}

// ── MCP / HTTP helpers ──────────────────────────────────────────────────────
type App = { request: (path: string, init?: RequestInit) => Promise<Response> };
type Owner = ReturnType<typeof privateKeyToAccount>;

/** Adapt a viem account to the (address, signMessage(string)) shape the
 * Web3Signed header builder expects. */
function ownerWallet(owner: Owner) {
  return {
    address: owner.address,
    signMessage: (message: string) => owner.signMessage({ message }),
  } as unknown as Parameters<typeof buildWeb3SignedHeader>[0]["wallet"];
}

async function ownerPost(app: App, owner: Owner, path: string, body: unknown) {
  const raw = JSON.stringify(body);
  const auth = await buildWeb3SignedHeader({
    wallet: ownerWallet(owner),
    aud: ORIGIN,
    method: "POST",
    uri: path,
    body: new TextEncoder().encode(raw),
  });
  return app.request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: auth },
    body: raw,
  });
}

async function ownerGet(app: App, owner: Owner, path: string) {
  const auth = await buildWeb3SignedHeader({
    wallet: ownerWallet(owner),
    aud: ORIGIN,
    method: "GET",
    uri: path,
  });
  return app.request(`${ORIGIN}${path}`, {
    headers: { Authorization: auth },
  });
}

interface RpcBody {
  error?: { message?: string };
  result?: {
    content?: Array<{ text?: string }>;
    contents?: Array<Record<string, unknown>>;
    tools?: Array<{ name: string }>;
    isError?: boolean;
  };
  raw?: string;
}

let rpcId = 1;
function parseRpcBody(text: string, contentType: string | null): RpcBody {
  const isSse =
    (contentType ?? "").includes("text/event-stream") ||
    /^(event|data):/m.test(text);
  if (isSse) {
    const line = text
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .filter((l) => l && l !== "[DONE]")
      .pop();
    if (line) {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    }
  }
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function mcpRpc(
  app: App,
  accessToken: string,
  method: string,
  params: Record<string, unknown> = {},
) {
  const res = await app.request(`${ORIGIN}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${accessToken}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }),
  });
  const text = await res.text();
  const body = parseRpcBody(text, res.headers.get("content-type"));
  return { ok: res.ok && !body?.error, status: res.status, body };
}

function toolJson(body: RpcBody): Record<string, unknown> | null {
  const text = body?.result?.content?.[0]?.text;
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

interface ScopeBlock {
  path: string;
  value: unknown;
}
function reassembleBinary(blocks: ScopeBlock[]) {
  const meta: Record<string, unknown> = {};
  let inline: string | undefined;
  const chunks: Array<{ start: number; text: string }> = [];
  for (const b of blocks) {
    const v = b.value as Record<string, unknown> | string | undefined;
    const chunk = /\.content\[chars (\d+):(\d+)\]$/.exec(b.path);
    if (chunk) {
      if (typeof v === "string")
        chunks.push({ start: Number(chunk[1]), text: v });
      continue;
    }
    if (v && typeof v === "object" && b.path.startsWith("$.data")) {
      Object.assign(meta, v);
      if (typeof (v as Record<string, unknown>).content === "string") {
        inline = (v as Record<string, unknown>).content as string;
      }
    }
  }
  let base64 = inline ?? "";
  if (chunks.length > 0) {
    chunks.sort((a, b) => a.start - b.start);
    base64 = chunks.map((c) => c.text).join("");
  }
  return { bytes: new Uint8Array(Buffer.from(base64, "base64")), meta };
}

function makeConfig(): ServerConfig {
  return ServerConfigSchema.parse({
    server: { port: PORT, origin: ORIGIN },
    gateway: { url: GATEWAY_URL },
    sync: { enabled: true },
    tunnel: { enabled: false },
    devUi: { enabled: true },
    logging: { level: "warn" },
    storage: { backend: "vana", config: { vana: { apiUrl: STORAGE_API_URL } } },
  });
}

// ── Main ────────────────────────────────────────────────────────────────────
async function main() {
  const envKey = process.env.VANA_WEB_PRIVATE_KEY;
  if (!envKey) throw new Error("VANA_WEB_PRIVATE_KEY not set (.env.local)");
  const ownerPrivateKey = (
    envKey.startsWith("0x") ? envKey : `0x${envKey}`
  ) as `0x${string}`;
  const owner = privateKeyToAccount(ownerPrivateKey);
  const ownerSignature = await owner.signMessage({
    message: MASTER_KEY_MESSAGE,
  });

  const rootPath = await mkdtemp(join(tmpdir(), "vana-sync-mcp-"));
  const config = makeConfig();

  // Register the server account BEFORE boot so sync is authorized immediately.
  const serverAccount = loadOrCreateServerAccount(join(rootPath, "key.json"));
  console.log(`[1/5] owner=${owner.address} server=${serverAccount.address}`);
  console.log(`  gateway=${GATEWAY_URL} storage=${STORAGE_API_URL}`);
  await registerServer({
    gatewayConfig: config.gateway,
    ownerAccount: owner,
    serverAddress: serverAccount.address,
    serverPublicKey: serverAccount.publicKey,
    serverUrl: ORIGIN,
  });

  const ctx = await createServer(config, {
    rootPath,
    ownerSignature,
    mcpOAuthApprovalUrl: `${ORIGIN}/__approve`,
  });
  const app = ctx.app as unknown as App;
  if (!ctx.syncManager) throw new Error("sync manager not started");

  try {
    // 2. SYNC ALL: pull EVERY file the owner has from storage-dev (real
    //    download → decrypt → write envelope + block sidecars). Trigger the
    //    download worker until its cursor stops advancing (whole dataset pulled).
    console.log("[2/5] Syncing ALL of the owner's files from storage-dev…");
    const have = (s: string) =>
      Boolean(ctx.indexManager.findLatestByScope(s)?.fileId);
    const distinctScopes = () =>
      ctx.indexManager.listDistinctScopes({ limit: 1000, offset: 0 });
    let lastTs: string | null = null;
    let stable = 0;
    for (let i = 1; i <= 60; i++) {
      await ctx.syncManager.trigger();
      const st = ctx.syncManager.getStatus();
      const ts = st.lastProcessedTimestamp ?? null;
      const { scopes, total } = distinctScopes();
      const files = scopes.reduce((n, s) => n + s.versionCount, 0);
      console.log(
        `  cycle ${i}: scopes=${total} files=${files} cursor=${ts ?? "-"}`,
      );
      stable = ts === lastTs ? stable + 1 : 0;
      lastTs = ts;
      // Cursor unchanged for 2 cycles ⇒ download exhausted (all files pulled).
      if (stable >= 2 && SCOPES.every(have)) break;
      await sleep(1500);
    }

    const { scopes: allScopes, total: scopeCount } = distinctScopes();
    const fileCount = allScopes.reduce((n, s) => n + s.versionCount, 0);
    console.log(`  synced ${scopeCount} scope(s) / ${fileCount} file(s):`);
    for (const s of [...allScopes].sort((a, b) =>
      a.scope.localeCompare(b.scope),
    )) {
      console.log(`    ${s.scope} — ${s.versionCount} version(s)`);
    }
    check(
      scopeCount > 0,
      "synced at least one scope from storage",
      `${scopeCount} scopes`,
    );
    for (const s of SCOPES) check(have(s), `synced target scope`, s);

    // 2b. Surface quarantines: corrupt/empty blobs are skipped by the download
    //     worker with a logger.warn (no persistent state, not in getStatus()),
    //     so re-run downloadAll with a capturing logger. Already-synced files
    //     dedup-skip; only empty/corrupt blobs get (re-)quarantined + captured.
    const quarantines: Array<{
      fileId?: string;
      schemaId?: string;
      stage?: string;
    }> = [];
    const capturingLogger = {
      debug() {},
      info() {},
      error() {},
      warn(payload: unknown, message?: string) {
        if (message === "Quarantined corrupt synced file") {
          quarantines.push(
            payload as { fileId?: string; schemaId?: string; stage?: string },
          );
        }
      },
    };
    const storageAdapter = createVanaSyncStorageAdapter({
      config,
      serverOwner: owner.address,
      serverAccount,
    });
    await downloadAll({
      storage: createNodeDataStorage({
        indexManager: ctx.indexManager,
        hierarchyOptions: { dataDir: join(rootPath, "data") },
      }),
      storageAdapter,
      gateway: ctx.gatewayClient,
      cursor: { read: async () => null, write: async () => {} },
      masterKey: deriveMasterKey(ownerSignature),
      serverOwner: owner.address,
      logger: capturingLogger,
    });
    // Resolve target scope schemaIds so we can assert none were quarantined.
    const targetSchemaIds = new Set<string>();
    for (const s of SCOPES) {
      const sc = await ctx.gatewayClient.getSchemaForScope(s);
      if (sc?.id) targetSchemaIds.add(sc.id.toLowerCase());
    }
    console.log(`  quarantined ${quarantines.length} corrupt/empty blob(s):`);
    for (const q of quarantines.slice(0, 10)) {
      console.log(
        `    fileId=${q.fileId} schemaId=${q.schemaId} stage=${q.stage}`,
      );
    }
    const targetQuarantined = quarantines.filter(
      (q) => q.schemaId && targetSchemaIds.has(q.schemaId.toLowerCase()),
    );
    check(
      targetQuarantined.length === 0,
      "no target scope was quarantined",
      targetQuarantined.map((q) => q.schemaId).join(", "),
    );

    // 3. OAuth: register client + PKCE authorize → authorizationId.
    console.log("[3/5] MCP OAuth: register client + authorize");
    const reg = await app.request(`${ORIGIN}/mcp/oauth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client_name: "e2e",
        redirect_uris: [REDIRECT_URI],
      }),
    });
    const client = (await reg.json()) as { client_id: string };
    check(reg.status === 201 && !!client.client_id, "register OAuth client");

    const codeVerifier = b64url(randomBytes(32));
    const codeChallenge = b64url(
      createHash("sha256").update(codeVerifier).digest(),
    );
    const authUrl =
      `${ORIGIN}/mcp/oauth/authorize?response_type=code` +
      `&client_id=${encodeURIComponent(client.client_id)}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
      `&code_challenge=${codeChallenge}&code_challenge_method=S256` +
      `&state=xyz&scope=vana:read`;
    const authRes = await app.request(authUrl, { redirect: "manual" });
    const approvalLoc = authRes.headers.get("location") ?? "";
    const authorizationId = new URL(approvalLoc).searchParams.get(
      "mcp_authorization",
    );
    check(
      Boolean(authorizationId),
      "authorize → authorizationId",
      `status=${authRes.status}`,
    );

    // 4. Owner approves with scopes → registers grantee builder + creates grant
    //    ON THE GATEWAY, then returns the client redirect carrying the code.
    console.log(
      "[4/5] Owner approves scopes (registers grantee builder + creates grant)",
    );
    const approveRes = await ownerPost(
      app,
      owner,
      `/v1/mcp/oauth/authorizations/${authorizationId}/approve`,
      { scopes: GRANT_SCOPES },
    );
    const approveBody = (await approveRes.json()) as {
      redirectTo?: string;
      error?: unknown;
    };
    check(
      approveRes.status === 200 && !!approveBody.redirectTo,
      "approve with scopes",
      approveRes.status === 200 ? "" : JSON.stringify(approveBody),
    );
    if (approveRes.status !== 200) throw new Error("approve failed");
    const code = new URL(approveBody.redirectTo!).searchParams.get("code");
    check(Boolean(code), "approval returned auth code");

    // Redeem the code for an access token.
    const tokenRes = await app.request(`${ORIGIN}/mcp/oauth/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code ?? "",
        code_verifier: codeVerifier,
        client_id: client.client_id,
        redirect_uri: REDIRECT_URI,
      }).toString(),
    });
    const tokenBody = (await tokenRes.json()) as { access_token?: string };
    check(
      Boolean(tokenBody.access_token),
      "token exchange",
      `status=${tokenRes.status}`,
    );
    const accessToken = tokenBody.access_token!;

    // 4b. Confirm the connection's grantee really is a registered builder on
    //     the gateway, and the grant is bound to that builder id.
    const connsRes = await ownerGet(app, owner, "/v1/mcp/connections");
    const conns = (await connsRes.json()) as {
      connections: Array<{
        status: string;
        granteeAddress: `0x${string}`;
        grants: Array<{ grantId: string; scopes: string[] }>;
      }>;
    };
    const approvedConn = conns.connections.find(
      (c) => c.status === "approved" && c.grants.length > 0,
    );
    check(Boolean(approvedConn), "found approved connection");
    if (approvedConn) {
      const builder = await ctx.gatewayClient.getBuilder(
        approvedConn.granteeAddress,
      );
      const grantId = approvedConn.grants[0]!.grantId;
      const grant = await ctx.gatewayClient.getGrant(grantId);
      console.log(`  grantee:    ${approvedConn.granteeAddress}`);
      console.log(`  builder.id: ${builder?.id ?? "(NOT REGISTERED)"}`);
      console.log(`  grantId:    ${grantId}`);
      console.log(`  grant.granteeId: ${grant?.granteeId ?? "(none)"}`);
      check(Boolean(builder), "grantee registered as builder on gateway");
      check(
        !!builder &&
          !!grant &&
          builder.id.toLowerCase() === grant.granteeId.toLowerCase(),
        "grant.granteeId === builder.id",
      );
    }

    // 5. read_scope over MCP (bearer) for each scope, paginating all blocks.
    console.log("[5/5] read_scope over MCP (OAuth bearer)");
    const init = await mcpRpc(app, accessToken, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "sync-mcp-e2e", version: "0.1.0" },
    });
    check(init.ok, "initialize", `status=${init.status}`);

    for (const scope of SCOPES) {
      const allBlocks: ScopeBlock[] = [];
      let cursor: string | undefined;
      let pages = 0;
      let contentKind: string | undefined;
      let failed = false;
      console.log(`  ${scope} pagination (maxBytes=65536/page):`);
      for (; pages < 400; pages++) {
        const args: Record<string, unknown> = { scope, maxBytes: 65536 };
        if (cursor) args.cursor = cursor;
        const fromIndex = cursorIndex(cursor);
        const read = await mcpRpc(app, accessToken, "tools/call", {
          name: "read_scope",
          arguments: args,
        });
        const payload = toolJson(read.body);
        const isError = read.body?.result?.isError === true;
        if (!read.ok || isError || payload?.error) {
          check(
            false,
            `read_scope(${scope}) page`,
            payload?.error ?? payload?.raw ?? read.status,
          );
          failed = true;
          break;
        }
        contentKind = payload?.contentKind as string | undefined;
        const pageBlocks = (payload?.blocks ?? []) as ScopeBlock[];
        allBlocks.push(...pageBlocks);
        cursor = (payload?.nextCursor as string | undefined) ?? undefined;
        console.log(
          `    page ${String(pages + 1).padStart(2)}: blockIndex ${fromIndex} → ` +
            `+${pageBlocks.length} (total ${allBlocks.length}) → ` +
            `next ${cursorIndex(cursor)}${cursor ? "" : " (end)"}`,
        );
        if (!cursor) break;
      }
      if (failed) continue;
      check(allBlocks.length > 0, `read_scope(${scope}) returned blocks`);

      // Size of the encrypted blob actually downloaded from storage for this
      // scope's latest version, vs. the local plaintext size and read bytes.
      const entry = ctx.indexManager.findLatestByScope(scope);
      let encryptedBytes = 0;
      if (entry?.fileId) {
        const rec = await ctx.gatewayClient.getFile(entry.fileId);
        if (rec?.url) {
          try {
            encryptedBytes = (await storageAdapter.download(rec.url)).length;
          } catch {
            encryptedBytes = -1; // download failed
          }
        }
      }
      const readBytes = allBlocks.reduce(
        (n, b) =>
          n +
          (typeof b.value === "string"
            ? b.value.length
            : JSON.stringify(b.value).length),
        0,
      );
      console.log(
        `  ${scope}: contentKind=${contentKind} pages=${pages + 1} blocks=${allBlocks.length}`,
      );
      console.log(
        `    sizes: encrypted blob=${encryptedBytes} B | local plaintext=${entry?.sizeBytes ?? "?"} B | read_scope content=${readBytes} B`,
      );

      const { bytes, meta } = reassembleBinary(allBlocks);
      if (meta.$binary === true) {
        // Binary scope (e.g. dexa.scan PDF): reassemble + verify integrity.
        console.log(
          `    $binary: mime=${meta.mimeType} sizeBytes=${meta.sizeBytes}`,
        );
        if (typeof meta.contentHash === "string") {
          check(
            sha256hex(bytes) ===
              meta.contentHash.replace(/^0x/, "").toLowerCase(),
            `${scope}: bytes match envelope contentHash (sha256)`,
          );
        } else {
          check(
            bytes.length > 0,
            `${scope}: produced bytes`,
            `${bytes.length} B`,
          );
        }
      } else {
        // JSON scope (e.g. chatgpt.conversations): show a preview of the data.
        const sample = allBlocks.find((b) => b.path.startsWith("$.data"));
        const preview = JSON.stringify(sample?.value ?? {}).slice(0, 160);
        console.log(
          `    json preview: ${preview}${preview.length >= 160 ? "…" : ""}`,
        );
        check(allBlocks.length > 0, `${scope}: JSON blocks readable`);
      }
    }
  } finally {
    await ctx.cleanup();
    await rm(rootPath, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error(
      `\n${failures.length} check(s) failed: ${failures.join(", ")}`,
    );
    process.exit(1);
  }
  console.log("\nAll sync→MCP (real) e2e checks passed.");
}

main().catch((err) => {
  console.error("\n❌ E2E failed:", err);
  process.exit(1);
});
