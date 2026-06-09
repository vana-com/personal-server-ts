/**
 * Self-contained end-to-end test for the MCP `read_scope` tool.
 *
 * Boots a real personal server in-process (no external gateway, no network:
 * an injected mock GatewayClient supplies the grant), seeds a JSON scope and a
 * binary scope, opens + approves an MCP connection, then calls `read_scope`
 * over the real `/mcp/:token` Streamable-HTTP transport and validates the
 * returned blocks — including binary integrity (the bytes that come back must
 * match the bytes that went in, byte-for-byte).
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
  console.log(
    `${condition ? "PASS" : "FAIL"} ${label}${detail ? ` — ${String(detail)}` : ""}`,
  );
  if (!condition) failures.push(label);
}

function sha256hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

interface ScopeBlock {
  path: string;
  value: unknown;
}

/**
 * Reassemble a binary file from read_scope blocks. Small files arrive as a
 * single block whose value is the whole `data` object (with `content` inline).
 * Large files are split: a metadata group block ($binary/mimeType/…) plus the
 * base64 `content` chopped into ordered `$.data.content[chars a:b]` chunks.
 */
function reassembleBinary(blocks: ScopeBlock[]): {
  bytes: Uint8Array;
  meta?: Record<string, unknown>;
} {
  const meta: Record<string, unknown> = {};
  let inline: string | undefined;
  const chunks: Array<{ start: number; text: string }> = [];

  for (const b of blocks) {
    const v = b.value as Record<string, unknown> | string | undefined;
    const isChunk = /\.content\[chars (\d+):(\d+)\]$/.exec(b.path);
    if (isChunk) {
      if (typeof v === "string") {
        chunks.push({ start: Number(isChunk[1]), text: v });
      }
      continue;
    }
    // Merge metadata from the data object / its grouped sub-blocks
    // ($.data, $.data.{$binary:…}, $.data.{contentHash:…}, …).
    if (v && typeof v === "object" && b.path.startsWith("$.data")) {
      Object.assign(meta, v);
      if (typeof (v as Record<string, unknown>).content === "string") {
        inline = (v as Record<string, unknown>).content as string; // small/inline case
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

    // 7. read_scope on the binary scope — paginate through ALL blocks (the
    //    1.5 MB PDF's base64 is chunked well past one page), collect them, then
    //    reassemble + verify the bytes match the original PDF.
    // Decode the opaque cursor purely to SHOW pagination progress.
    const cursorIndex = (c?: string): number | "—" => {
      if (!c) return "—";
      try {
        return JSON.parse(Buffer.from(c, "base64url").toString()).blockIndex;
      } catch {
        return -1;
      }
    };
    console.log("  read_scope pagination (maxBytes=65536/page):");
    const allBlocks: ScopeBlock[] = [];
    let cursor: string | undefined;
    let pages = 0;
    let lastContentKind: string | undefined;
    for (; pages < 200; pages++) {
      // 65536 is read_scope's MAX_READ_SCOPE_MAX_BYTES; larger values are
      // rejected by the tool schema. The PDF spans many pages at this budget.
      const args: Record<string, unknown> = {
        scope: BINARY_SCOPE,
        maxBytes: 65536,
      };
      if (cursor) args.cursor = cursor;
      const fromIndex = cursorIndex(cursor);
      const read = await mcpRpc(app, token, "tools/call", {
        name: "read_scope",
        arguments: args,
      });
      const payload = toolJson(read.body);
      const isError = read.body?.result?.isError === true;
      if (!read.ok || isError || payload?.error) {
        check(
          false,
          "read_scope(binary) page",
          payload?.error ??
            (isError ? (payload?.raw ?? "isError") : read.status),
        );
        break;
      }
      lastContentKind = payload?.contentKind as string | undefined;
      const pageBlocks = (payload?.blocks ?? []) as ScopeBlock[];
      allBlocks.push(...pageBlocks);
      cursor = (payload?.nextCursor as string | undefined) ?? undefined;
      console.log(
        `    page ${String(pages + 1).padStart(2)}: cursor blockIndex ${fromIndex} → ` +
          `+${pageBlocks.length} blocks (total ${allBlocks.length}) → ` +
          `nextCursor blockIndex ${cursorIndex(cursor)}${cursor ? "" : " (end)"}`,
      );
      if (!cursor) break;
    }
    check(allBlocks.length > 0, "read_scope(binary) returned blocks");
    check(
      pages >= 1,
      "read_scope(binary) paginated across multiple pages",
      `pages=${pages + 1}`,
    );
    console.log(
      `  binary read: contentKind=${lastContentKind} pages=${pages + 1} blocks=${allBlocks.length}`,
    );

    const { bytes: decoded, meta } = reassembleBinary(allBlocks);
    if (meta) {
      console.log(
        `  $binary: mime=${meta.mimeType} sizeBytes=${meta.sizeBytes} encoding=${meta.encoding}`,
      );
    }
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
    if (typeof meta?.contentHash === "string") {
      check(
        meta.contentHash.replace(/^0x/, "").toLowerCase() === wantHash,
        "block contentHash matches original",
      );
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
  console.log("\nAll read_scope e2e checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
