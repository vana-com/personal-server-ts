/**
 * Browser-runtime e2e for MCP `read_scope`.
 *
 * Exercises the SAME code that runs in the browser (Personal Server Lite —
 * `createPsLiteRuntime`, what app-dev.vana.org boots) rather than the Node
 * server. It ingests a binary PDF + a JSON scope through the Lite runtime,
 * opens + approves an MCP connection, and drives `read_scope` over the Lite
 * runtime's own `/mcp/:token` transport — reassembling the binary and checking
 * byte integrity.
 *
 * "Browser environment" here means the Lite runtime + browser storage contract
 * (block sidecars via the DataStoragePort). It runs in Node with the in-memory
 * storage shim (no real IndexedDB/OPFS); for a true-browser run you'd drive
 * this through @vitest/browser or Playwright (not wired in this repo).
 *
 * Run:  npx tsx scripts/e2e-read-scope-lite.ts
 */

import { createHash } from "node:crypto";
import {
  createPsLiteRuntime,
  createWeb3SignedPsLiteAuth,
} from "../packages/lite/src/runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
  createMemoryPsLiteAccessLogStore,
} from "../packages/lite/src/test-support/memory.js";
import { createInMemoryMcpConnectionStore } from "@opendatalabs/personal-server-ts-core/mcp";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type {
  Builder,
  GatewayClient,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";

const ORIGIN = "https://ps-lite.local";
const BINARY_SCOPE = "dexa.scan";
const JSON_SCOPE = "instagram.profile";
const GRANT_SCOPES = ["dexa.*", "instagram.*"];
const PDF_URL =
  process.env.PDF_URL ??
  "https://dexabody.com/wp-content/uploads/2021/09/Dexa-Body-Sample-Report-1.pdf";

const owner = createTestWallet(0);

const failures: string[] = [];
function check(ok: boolean, label: string, detail: unknown = "") {
  console.log(
    `${ok ? "PASS" : "FAIL"} ${label}${detail ? ` — ${String(detail)}` : ""}`,
  );
  if (!ok) failures.push(label);
}
const sha256hex = (b: Uint8Array) =>
  createHash("sha256").update(b).digest("hex");
// Decode the opaque read_scope cursor purely to SHOW pagination progress.
const cursorIndex = (c?: string): number | "—" => {
  if (!c) return "—";
  try {
    return JSON.parse(Buffer.from(c, "base64url").toString()).blockIndex;
  } catch {
    return -1;
  }
};

// Mock gateway: capture the read signer (the connection's grantee) in
// getBuilder and echo it as the grant's granteeId so read_scope's policy
// (builder.id === grant.granteeId + scope coverage) passes.
function makeMockGateway(): GatewayClient {
  let lastSigner = owner.address as `0x${string}`;
  const grant = (id: string): GatewayGrantResponse =>
    ({
      id,
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
    }) as unknown as GatewayGrantResponse;
  const builder = (address: string): Builder => ({
    id: address,
    ownerAddress: owner.address,
    granteeAddress: address as `0x${string}`,
    publicKey: "0x04",
    appUrl: "https://claude.test",
    addedAt: "2026-01-21T10:00:00.000Z",
  });
  return {
    isRegisteredBuilder: async () => true,
    getBuilder: async (address: string) => {
      lastSigner = address as `0x${string}`;
      return builder(address);
    },
    getGrant: async (id: string) => grant(id),
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
    createGrant: async () => ({ grantId: "grant-lite-1" }),
    revokeGrant: async () => undefined,
  } as unknown as GatewayClient;
}

type Runtime = { fetch: (req: Request) => Promise<Response> };

async function ownerReq(
  method: "GET" | "POST",
  path: string,
  opts: { json?: unknown; bytes?: Uint8Array; contentType?: string } = {},
): Promise<Request> {
  const bodyBytes =
    opts.bytes ??
    (opts.json !== undefined
      ? new TextEncoder().encode(JSON.stringify(opts.json))
      : undefined);
  const auth = await buildWeb3SignedHeader({
    wallet: owner,
    aud: ORIGIN,
    method,
    uri: path,
    ...(bodyBytes ? { body: bodyBytes } : {}),
  });
  const headers: Record<string, string> = { Authorization: auth };
  if (opts.json !== undefined) headers["Content-Type"] = "application/json";
  if (opts.contentType) headers["Content-Type"] = opts.contentType;
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers,
    body: bodyBytes as BodyInit | undefined,
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
function parseRpc(text: string, ct: string | null): RpcBody {
  if (
    (ct ?? "").includes("text/event-stream") ||
    /^(event|data):/m.test(text)
  ) {
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
  runtime: Runtime,
  token: string,
  method: string,
  params: Record<string, unknown> = {},
) {
  const res = await runtime.fetch(
    new Request(`${ORIGIN}/mcp/${encodeURIComponent(token)}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: rpcId++, method, params }),
    }),
  );
  const text = await res.text();
  const body = parseRpc(text, res.headers.get("content-type"));
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

async function main() {
  const gateway = makeMockGateway();
  const accessLog = createMemoryPsLiteAccessLogStore();
  const runtime: Runtime = createPsLiteRuntime({
    active: true,
    storage: createMemoryPsLiteStorage(),
    config: { gateway: { url: "https://gateway.test", chainId: 14800 } },
    gateway,
    serverSigner: {
      signGrantRegistration: async () => "0xsig" as `0x${string}`,
    },
    accessLogReader: accessLog,
    accessLogWriter: accessLog,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    mcpConnectionStore: createInMemoryMcpConnectionStore(),
    auth: createWeb3SignedPsLiteAuth({
      origin: ORIGIN,
      ownerAddress: owner.address,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
    }),
  } as never);

  console.log("[1/4] Lite (browser) runtime up; ingesting data");
  const pdf = new Uint8Array(await (await fetch(PDF_URL)).arrayBuffer());
  const wantHash = sha256hex(pdf);
  const binRes = await runtime.fetch(
    await ownerReq("POST", `/v1/data/${BINARY_SCOPE}`, {
      bytes: pdf,
      contentType: "application/pdf",
    }),
  );
  check(
    [200, 201].includes(binRes.status),
    "ingest binary scope",
    `status=${binRes.status}`,
  );
  const jsonRes = await runtime.fetch(
    await ownerReq("POST", `/v1/data/${JSON_SCOPE}`, {
      json: { handle: "browser_user", followers: 3 },
    }),
  );
  check(
    [200, 201].includes(jsonRes.status),
    "ingest JSON scope",
    `status=${jsonRes.status}`,
  );

  console.log("[2/4] Open + approve MCP connection (browser runtime)");
  const createRes = await runtime.fetch(
    await ownerReq("POST", "/v1/mcp/connections", {
      json: { displayName: "Claude" },
    }),
  );
  check(
    createRes.status === 201,
    "create MCP connection",
    `status=${createRes.status}`,
  );
  const created = (await createRes.json()) as {
    connectionId: string;
    connectionToken: string;
  };
  const approveRes = await runtime.fetch(
    await ownerReq(
      "POST",
      `/v1/mcp/connections/${created.connectionId}/approve`,
      {
        json: { grants: [{ grantId: "grant-lite-1", scopes: GRANT_SCOPES }] },
      },
    ),
  );
  check(
    approveRes.status === 200,
    "approve MCP connection",
    `status=${approveRes.status}`,
  );
  const token = created.connectionToken;

  console.log("[3/4] read_scope over the Lite /mcp transport");
  const init = await mcpRpc(runtime, token, "initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "lite-read-scope-e2e", version: "0.1.0" },
  });
  check(init.ok, "initialize", `status=${init.status}`);
  const tools = await mcpRpc(runtime, token, "tools/list");
  const toolNames: string[] =
    tools.body?.result?.tools?.map((t: { name: string }) => t.name) ?? [];
  check(toolNames.includes("read_scope"), "tools/list includes read_scope");

  console.log("[4/4] Verify scopes");
  for (const scope of [BINARY_SCOPE, JSON_SCOPE]) {
    const all: ScopeBlock[] = [];
    let cursor: string | undefined;
    let pages = 0;
    let kind: string | undefined;
    let failed = false;
    console.log(`  ${scope} pagination (maxBytes=65536/page):`);
    for (; pages < 400; pages++) {
      const args: Record<string, unknown> = { scope, maxBytes: 65536 };
      if (cursor) args.cursor = cursor;
      const fromIndex = cursorIndex(cursor);
      const read = await mcpRpc(runtime, token, "tools/call", {
        name: "read_scope",
        arguments: args,
      });
      const payload = toolJson(read.body);
      if (!read.ok || read.body?.result?.isError || payload?.error) {
        check(
          false,
          `read_scope(${scope})`,
          payload?.error ?? payload?.raw ?? read.status,
        );
        failed = true;
        break;
      }
      kind = payload?.contentKind as string | undefined;
      const pageBlocks = (payload?.blocks ?? []) as ScopeBlock[];
      all.push(...pageBlocks);
      cursor = (payload?.nextCursor as string | undefined) ?? undefined;
      console.log(
        `    page ${String(pages + 1).padStart(2)}: blockIndex ${fromIndex} → ` +
          `+${pageBlocks.length} (total ${all.length}) → ` +
          `next ${cursorIndex(cursor)}${cursor ? "" : " (end)"}`,
      );
      if (!cursor) break;
    }
    if (failed) continue;
    console.log(
      `  ${scope}: contentKind=${kind} pages=${pages + 1} blocks=${all.length}`,
    );
    const { bytes, meta } = reassembleBinary(all);
    if (meta.$binary === true) {
      check(
        sha256hex(bytes) === wantHash,
        `${scope}: bytes match original PDF (sha256)`,
      );
    } else {
      check(all.length > 0, `${scope}: JSON blocks readable`);
    }
  }

  if (failures.length > 0) {
    console.error(
      `\n${failures.length} check(s) failed: ${failures.join(", ")}`,
    );
    process.exit(1);
  }
  console.log("\nAll Lite (browser) read_scope e2e checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
