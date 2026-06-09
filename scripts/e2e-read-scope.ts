/**
 * Self-contained end-to-end test for the MCP `read_scope` tool.
 *
 * Boots a real personal server in-process (no external gateway, no network:
 * an injected mock GatewayClient supplies the grant), seeds a JSON scope and a
 * binary scope, opens + approves an MCP connection, then over the real
 * `/mcp/:token` Streamable-HTTP transport: calls `read_scope` for JSON, and
 * fetches the binary file via `resources/read` (vana://scope/<scope>/raw),
 * validating binary integrity (the bytes that come back must match the bytes
 * that went in, byte-for-byte).
 *
 * This exercises the same wire path Claude uses, so it catches transport-level
 * binary corruption (e.g. a relay that UTF-8-mangles binary → the file fails
 * to read). No token or running server required — everything is in-process.
 *
 * Run:
 *   npx tsx scripts/e2e-read-scope.ts
 *
 * Exits non-zero if any check fails.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { MASTER_KEY_MESSAGE } from "@opendatalabs/vana-sdk/node";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/node";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import {
  ServerConfigSchema,
  type ServerConfig,
} from "../packages/core/src/schemas/server-config.js";
import { createServer } from "../packages/server/src/bootstrap.js";

const PORT = 8799;
const ORIGIN = `http://localhost:${PORT}`;
const JSON_SCOPE = "instagram.profile";
const BINARY_SCOPE = "dexa.scan";
const GRANT_SCOPES = ["instagram.*", "dexa.*"];
const PDF_URL =
  process.env.PDF_URL ??
  "https://dexabody.com/wp-content/uploads/2021/09/Dexa-Body-Sample-Report-1.pdf";

const owner = createTestWallet(0);

const failures: string[] = [];
function check(condition: boolean, label: string, detail: unknown = "") {
  const note = detail ? ` — ${String(detail)}` : "";
  console.log(`${condition ? "PASS" : "FAIL"} ${label}${note}`);
  if (!condition) failures.push(label);
}

function sha256hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

async function fetchPdf(): Promise<Uint8Array> {
  const res = await fetch(PDF_URL);
  if (!res.ok) throw new Error(`failed to download PDF: ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * Mock gateway: read_scope's policy check requires
 * getBuilder(signer).id === getGrant(grantId).granteeId. The server signs the
 * read as the connection's generated grantee, so we capture that signer in
 * getBuilder and echo it back as the grant's granteeId — the policy passes
 * without us needing to know the grantee address up front.
 */
function makeMockGateway(): GatewayClient {
  let lastSigner = owner.address as `0x${string}`;
  const grantFor = (grantId: string): GatewayGrantResponse => ({
    id: grantId,
    grantorAddress: owner.address,
    granteeId: lastSigner,
    grant: JSON.stringify({
      user: owner.address,
      builder: lastSigner,
      scopes: GRANT_SCOPES,
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    }),
    fileIds: [],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    revokedAt: null,
    revocationSignature: null,
  });
  const builderFor = (address: string): Builder => ({
    id: address,
    ownerAddress: owner.address,
    granteeAddress: address as `0x${string}`,
    publicKey: "0x04",
    appUrl: "https://e2e.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  });
  return {
    isRegisteredBuilder: async () => true,
    getBuilder: async (address: string) => {
      lastSigner = address as `0x${string}`;
      return builderFor(address);
    },
    getGrant: async (grantId: string) => grantFor(grantId),
    listGrantsByUser: async () => [],
    getSchemaForScope: async (scope: string) => ({
      id: `0xschema-${scope}`,
      ownerAddress: owner.address,
      name: scope,
      definitionUrl: "https://schemas.vana.org/no-schema/v1.json",
      scope,
      addedAt: "2026-01-21T10:00:00.000Z",
    }),
    getSchema: async () => null,
    getServer: async () => null,
    getFile: async () => null,
    listFilesSince: async () => ({ files: [], cursor: null }),
    registerServer: async () => ({ alreadyRegistered: true }),
    registerFile: async () => ({}),
    createGrant: async () => ({ grantId: "grant-e2e" }),
    revokeGrant: async () => undefined,
  } as unknown as GatewayClient;
}

function makeConfig(): ServerConfig {
  return ServerConfigSchema.parse({
    server: { port: PORT, origin: ORIGIN },
    gateway: { url: "http://localhost:9999" },
    sync: { enabled: false },
    tunnel: { enabled: false },
    devUi: { enabled: true },
    logging: { level: "error" },
  });
}

// ── HTTP helpers (call the Hono app directly, no listener) ────────────────

type App = { request: (path: string, init?: RequestInit) => Promise<Response> };

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

async function ownerPost(app: App, path: string, body: unknown) {
  const raw = JSON.stringify(body);
  const auth = await buildWeb3SignedHeader({
    wallet: owner,
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

let rpcId = 1;
function parseRpcBody(text: string, contentType: string | null): unknown {
  const isSse =
    (contentType ?? "").includes("text/event-stream") ||
    /^(event|data):/m.test(text);
  if (isSse) {
    const dataLine = text
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trim())
      .filter((l) => l && l !== "[DONE]")
      .pop();
    if (dataLine) {
      try {
        return JSON.parse(dataLine);
      } catch {
        return { raw: dataLine };
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
  token: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<{ ok: boolean; status: number; body: RpcBody }> {
  const res = await app.request(`${ORIGIN}/mcp/${encodeURIComponent(token)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }),
  });
  const text = await res.text();
  const body = parseRpcBody(text, res.headers.get("content-type")) as RpcBody;
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

// ── Main ──────────────────────────────────────────────────────────────────

async function main() {
  const rootPath = await mkdtemp(join(tmpdir(), "vana-read-scope-e2e-"));
  const ownerSignature = await owner.signMessage(MASTER_KEY_MESSAGE);

  const ctx = await createServer(makeConfig(), {
    rootPath,
    ownerSignature,
    gatewayClient: makeMockGateway(),
  });
  const app = ctx.app as unknown as App;
  const devToken = ctx.devToken;
  if (!devToken) throw new Error("dev token not available (devUi disabled?)");

  try {
    // 1. Seed a JSON scope.
    const jsonRes = await app.request(`${ORIGIN}/v1/data/${JSON_SCOPE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${devToken}`,
      },
      body: JSON.stringify({ username: "e2e_user", followers: 42 }),
    });
    check(
      jsonRes.status === 201,
      "seed JSON scope",
      `status=${jsonRes.status}`,
    );

    // 2. Seed the binary scope with the REAL dexa PDF (~1.5 MB) — large enough
    //    that its base64 content is chunked across many blocks, exercising the
    //    paginate-and-reassemble path (not just a single inline block).
    const binaryBytes = await fetchPdf();
    const wantHash = sha256hex(binaryBytes);
    console.log(`  seeding real PDF: ${binaryBytes.length} bytes`);
    const binRes = await app.request(`${ORIGIN}/v1/data/${BINARY_SCOPE}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/pdf",
        "X-Filename": "dexa-body-sample-report.pdf",
        "X-Vana-Metadata": "DEXA Body sample scan report",
        Authorization: `Bearer ${devToken}`,
      },
      body: binaryBytes as unknown as BodyInit,
    });
    check(
      binRes.status === 201,
      "seed binary scope",
      `status=${binRes.status}`,
    );

    // 3. Open an MCP connection.
    const createRes = await ownerPost(app, "/v1/mcp/connections", {
      displayName: "e2e read_scope",
    });
    check(
      createRes.status === 201,
      "create MCP connection",
      `status=${createRes.status}`,
    );
    const created = (await createRes.json()) as {
      connectionId: string;
      connectionToken: string;
    };

    // 4. Approve it with grants covering both scopes.
    const approveRes = await ownerPost(
      app,
      `/v1/mcp/connections/${created.connectionId}/approve`,
      { grants: [{ grantId: "grant-e2e", scopes: GRANT_SCOPES }] },
    );
    check(
      approveRes.status === 200,
      "approve MCP connection",
      `status=${approveRes.status}`,
    );

    const token = created.connectionToken;

    // 5. initialize + tools/list over the real transport.
    const init = await mcpRpc(app, token, "initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "read-scope-e2e", version: "0.1.0" },
    });
    check(init.ok, "initialize", `status=${init.status}`);

    const tools = await mcpRpc(app, token, "tools/list");
    const toolNames: string[] =
      tools.body?.result?.tools?.map((t: { name: string }) => t.name) ?? [];
    check(toolNames.includes("read_scope"), "tools/list includes read_scope");

    // 6. read_scope on the JSON scope.
    const jsonRead = await mcpRpc(app, token, "tools/call", {
      name: "read_scope",
      arguments: { scope: JSON_SCOPE, maxBytes: 8192 },
    });
    const jsonPayload = toolJson(jsonRead.body);
    check(
      jsonRead.ok && Array.isArray(jsonPayload?.blocks) && !jsonPayload?.error,
      "read_scope(JSON) returns blocks",
      jsonPayload?.error ?? `contentKind=${jsonPayload?.contentKind}`,
    );

    // 7. read_scope on the binary scope returns metadata blocks. On main the
    //    raw bytes are NOT inlined here — they're served via resources/read
    //    (step 8); read_scope just surfaces the binary's shape/metadata.
    const binMeta = toolJson(
      (
        await mcpRpc(app, token, "tools/call", {
          name: "read_scope",
          arguments: { scope: BINARY_SCOPE, maxBytes: 65536 },
        })
      ).body,
    );
    check(
      Array.isArray(binMeta?.blocks) && !binMeta?.error,
      "read_scope(binary) returns metadata blocks",
      binMeta?.error ?? `contentKind=${binMeta?.contentKind}`,
    );

    // 8. Fetch the raw binary via resources/read (vana://scope/<scope>/raw) and
    //    verify the bytes match the original PDF byte-for-byte. This is the
    //    transport path that would surface relay binary corruption.
    const rawRead = await mcpRpc(app, token, "resources/read", {
      uri: `vana://scope/${BINARY_SCOPE}/raw`,
    });
    const content = rawRead.body?.result?.contents?.[0] as
      | {
          blob?: string;
          mimeType?: string;
          _meta?: { sizeBytes?: number };
        }
      | undefined;
    check(
      rawRead.ok && typeof content?.blob === "string",
      "resources/read returns raw binary",
      rawRead.body?.error?.message ?? `status=${rawRead.status}`,
    );
    const decoded = new Uint8Array(Buffer.from(content?.blob ?? "", "base64"));
    console.log(
      `  resources/read: mime=${content?.mimeType} sizeBytes=${content?._meta?.sizeBytes} decoded=${decoded.length}`,
    );
    check(
      decoded.length === binaryBytes.length,
      "binary length round-trips",
      `${decoded.length}/${binaryBytes.length}`,
    );
    const gotHash = sha256hex(decoded);
    check(
      gotHash === wantHash,
      "binary content matches original PDF (sha256)",
      gotHash === wantHash ? "" : `${gotHash} != ${wantHash}`,
    );
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
  console.log("\nAll read_scope e2e checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
