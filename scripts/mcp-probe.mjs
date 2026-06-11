#!/usr/bin/env node

const DEFAULT_RPC_TIMEOUT_MS = 10_000;
const DEFAULT_SEARCH_TIMEOUT_MS = 5_000;
const DEFAULT_READ_TIMEOUT_MS = 8_000;
const DEFAULT_TOOLS_LIST_MAX_BYTES = 64_000;

const endpoint = process.env.MCP_ENDPOINT ?? process.argv[2];
const token = process.env.MCP_TOKEN ?? process.argv[3];

if (!endpoint || !token || process.argv.includes("--help")) {
  console.error(
    [
      "Usage:",
      "  MCP_ENDPOINT=https://.../mcp MCP_TOKEN=... node scripts/mcp-probe.mjs",
      "  node scripts/mcp-probe.mjs https://.../mcp <token>",
      "",
      "Optional env:",
      `  MCP_RPC_TIMEOUT_MS=${DEFAULT_RPC_TIMEOUT_MS}`,
      `  MCP_SEARCH_TIMEOUT_MS=${DEFAULT_SEARCH_TIMEOUT_MS}`,
      `  MCP_READ_TIMEOUT_MS=${DEFAULT_READ_TIMEOUT_MS}`,
      `  MCP_TOOLS_LIST_MAX_BYTES=${DEFAULT_TOOLS_LIST_MAX_BYTES}`,
      "  MCP_READ_SCOPES=github.profile,chatgpt.conversations,instagram.profile",
    ].join("\n"),
  );
  process.exit(process.argv.includes("--help") ? 0 : 2);
}

let nextId = 1;
const failures = [];

function numberEnv(name, fallback) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

const rpcTimeoutMs = numberEnv("MCP_RPC_TIMEOUT_MS", DEFAULT_RPC_TIMEOUT_MS);
const searchTimeoutMs = numberEnv(
  "MCP_SEARCH_TIMEOUT_MS",
  DEFAULT_SEARCH_TIMEOUT_MS,
);
const readTimeoutMs = numberEnv("MCP_READ_TIMEOUT_MS", DEFAULT_READ_TIMEOUT_MS);
const toolsListMaxBytes = numberEnv(
  "MCP_TOOLS_LIST_MAX_BYTES",
  DEFAULT_TOOLS_LIST_MAX_BYTES,
);
const readScopes = (
  process.env.MCP_READ_SCOPES ??
  "github.profile,chatgpt.conversations,instagram.profile"
)
  .split(",")
  .map((scope) => scope.trim())
  .filter(Boolean);

async function rpc(method, params = {}, options = {}) {
  const id = nextId++;
  const timeoutMs = options.timeoutMs ?? rpcTimeoutMs;
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: controller.signal,
    });
    const text = await response.text();
    const elapsedMs = Date.now() - started;
    let body;
    try {
      body = text ? JSON.parse(text) : null;
    } catch {
      body = { raw: text };
    }
    return {
      ok: response.ok && !body?.error,
      elapsedMs,
      status: response.status,
      body,
      bytes: text.length,
    };
  } catch (error) {
    const elapsedMs = Date.now() - started;
    const timedOut = error?.name === "AbortError";
    return {
      ok: false,
      elapsedMs,
      status: 0,
      body: {
        error: {
          code: timedOut ? "probe_timeout" : "probe_fetch_error",
          message: timedOut
            ? `probe timed out after ${timeoutMs}ms`
            : String(error?.message ?? error),
        },
      },
      bytes: 0,
    };
  } finally {
    clearTimeout(timer);
  }
}

function toolCall(name, args = {}, options = {}) {
  return rpc("tools/call", { name, arguments: args }, options);
}

function parseToolJson(result) {
  const text = result?.body?.result?.content?.[0]?.text;
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

function jsonRpcError(result) {
  return result?.body?.error;
}

function toolError(result) {
  return parseToolJson(result)?.error ?? jsonRpcError(result)?.message;
}

function record(condition, label, detail) {
  const line = `${condition ? "PASS" : "FAIL"} ${label}${detail ? ` ${detail}` : ""}`;
  console.log(line);
  if (!condition) failures.push(line);
}

function summarizeTool(name, result) {
  const payload = parseToolJson(result);
  const error = payload?.error ?? jsonRpcError(result)?.message;
  console.log(
    `${result.ok ? "ok" : "fail"} ${name} ${result.elapsedMs}ms status=${result.status}${
      error ? ` error=${error}` : ""
    }`,
  );
  return payload;
}

const initialize = await rpc("initialize", {
  protocolVersion: "2025-06-18",
  capabilities: {},
  clientInfo: { name: "ps-mcp-readiness-probe", version: "0.1.0" },
});
record(
  initialize.ok,
  "initialize returns success",
  `${initialize.elapsedMs}ms`,
);

const tools = await rpc("tools/list");
const toolsBytes = JSON.stringify(tools.body).length;
const toolNames =
  tools.body?.result?.tools?.map((tool) => tool.name).sort() ??
  tools.body?.tools?.map((tool) => tool.name).sort() ??
  [];
console.log(
  `tools/list ${tools.elapsedMs}ms status=${tools.status} bytes=${toolsBytes} tools=${toolNames.join(",")}`,
);
record(tools.ok, "tools/list returns success");
record(
  toolsBytes <= toolsListMaxBytes,
  "tools/list stays under byte budget",
  `${toolsBytes}/${toolsListMaxBytes}`,
);
for (const requiredTool of [
  "list_granted_scopes",
  "read_scope",
  "search_personal_context",
]) {
  record(
    toolNames.includes(requiredTool),
    `tools/list includes ${requiredTool}`,
  );
}

const scopes = summarizeTool(
  "list_granted_scopes",
  await toolCall("list_granted_scopes"),
);
record(
  Array.isArray(scopes?.scopes),
  "list_granted_scopes returns scopes array",
);
if (Array.isArray(scopes?.scopes)) {
  const counts = scopes.scopes.reduce((acc, item) => {
    const key = item.dataStatus ?? "unknown";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  console.log(`scope_status_counts ${JSON.stringify(counts)}`);
  record(
    scopes.scopes.every((scope) => typeof scope.dataStatus === "string"),
    "list_granted_scopes includes structured dataStatus",
  );
}

const search = await toolCall(
  "search_personal_context",
  {
    query: "zzqqxx-readiness-no-match",
    maxResults: 5,
    timeoutMs: Math.max(1, searchTimeoutMs - 1_000),
  },
  { timeoutMs: searchTimeoutMs },
);
const searchPayload = summarizeTool("search_personal_context/no-match", search);
record(
  search.elapsedMs < searchTimeoutMs,
  "search_personal_context respects probe deadline",
  `${search.elapsedMs}/${searchTimeoutMs}ms`,
);
record(
  search.ok || Boolean(searchPayload?.error || jsonRpcError(search)),
  "search_personal_context returns success or structured error",
);

for (const scope of readScopes) {
  const read = await toolCall(
    "read_scope",
    { scope, maxBytes: 8192 },
    { timeoutMs: readTimeoutMs },
  );
  const payload = summarizeTool(`read_scope/${scope}`, read);
  record(
    read.elapsedMs < readTimeoutMs,
    `read_scope/${scope} respects probe deadline`,
    `${read.elapsedMs}/${readTimeoutMs}ms`,
  );
  record(
    read.ok || Boolean(payload?.error || jsonRpcError(read)),
    `read_scope/${scope} returns success or structured error`,
    toolError(read) ? `error=${toolError(read)}` : "",
  );
}

if (failures.length > 0) {
  console.error(`\n${failures.length} readiness check(s) failed.`);
  process.exit(1);
}

console.log("\nAll MCP readiness checks passed.");
