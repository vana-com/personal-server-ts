/**
 * `ask_personal_data` — phase 8's workflow-scoped query tool.
 *
 * The tool itself computes nothing. What it owns, and what is under test
 * here, is the boundary: which scopes reach the engine (never more than the
 * connection's grant), and what happens on a session where a multi-scope
 * sweep cannot be settled.
 */

import { describe, expect, it, vi } from "vitest";

import { MCP_TOOLS, type McpAskPersonalDataPort } from "./tools.js";
import type { McpConnectionRecord } from "./types.js";
import type { McpDataReadClient } from "./read-client.js";
import type { QueryAnswer } from "../query/agent/types.js";

function getTool(name: string) {
  const tool = MCP_TOOLS.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool ${name}`);
  return tool;
}

function createConnection(
  grants: McpConnectionRecord["grants"] = [
    { grantId: "grant-1", scopes: ["oura.sleep", "chatgpt.history"] },
  ],
): McpConnectionRecord {
  return {
    id: "conn-1",
    displayName: "Test client",
    granteeAddress: "0x1111111111111111111111111111111111111111",
    granteePublicKey: "0x04deadbeef",
    encryptedGranteePrivateKey: {
      kind: "plaintext",
      privateKey:
        "0x2222222222222222222222222222222222222222222222222222222222222222",
    },
    tokenHash: "token-hash",
    status: "approved",
    grants,
    createdAt: "2026-06-05T00:00:00Z",
    approvedAt: "2026-06-05T00:00:00Z",
  };
}

function createReadClient(
  overrides: Partial<McpDataReadClient> = {},
): McpDataReadClient {
  return {
    listScopes: vi.fn().mockResolvedValue({
      status: 200,
      scopes: [],
      total: 0,
      limit: 0,
      offset: 0,
    }),
    getScopeMetadata: vi.fn().mockResolvedValue(null),
    readScopeBlocks: vi.fn().mockRejectedValue(new Error("not mocked")),
    readRawScopeFile: vi.fn().mockRejectedValue(new Error("not mocked")),
    ...overrides,
  } as McpDataReadClient;
}

const ANSWER: QueryAnswer = {
  answer: "42",
  citations: [],
  coverage: {
    scopesScanned: ["oura.sleep"],
    recordsScanned: 1100,
    scopesSkipped: [],
    complete: true,
  },
  determinism: "generated",
  cost: { toolCalls: 1, inputTokens: 10, outputTokens: 5 },
};

function recordingPort(): McpAskPersonalDataPort & {
  calls: Parameters<McpAskPersonalDataPort["ask"]>[0][];
} {
  const calls: Parameters<McpAskPersonalDataPort["ask"]>[0][] = [];
  return {
    calls,
    async ask(input) {
      calls.push(input);
      return ANSWER;
    },
  };
}

async function ask(
  args: Record<string, unknown>,
  ctx: {
    connection?: McpConnectionRecord;
    readClient?: McpDataReadClient;
    askPersonalData?: McpAskPersonalDataPort;
  } = {},
) {
  const result = await getTool("ask_personal_data").handler(args, {
    connection: ctx.connection ?? createConnection(),
    readClient: ctx.readClient ?? createReadClient(),
    ...(ctx.askPersonalData ? { askPersonalData: ctx.askPersonalData } : {}),
  });
  return {
    result,
    payload: JSON.parse(result.content[0]!.text as string) as Record<
      string,
      unknown
    >,
  };
}

/* ------------------------------------------------------------------ *
 * Availability
 * ------------------------------------------------------------------ */

describe("ask_personal_data availability", () => {
  it("is registered alongside the primitives, not instead of them", () => {
    const names = MCP_TOOLS.map((t) => t.name);
    expect(names).toContain("ask_personal_data");
    // Phase 8 keeps the primitives for consumers driving their own loop.
    expect(names).toContain("read_scope");
    expect(names).toContain("list_granted_scopes");
    expect(names).toContain("search_personal_context");
  });

  it("reports itself unavailable when no engine is wired", async () => {
    const { result, payload } = await ask({ question: "how much sleep?" });
    expect(result.isError).toBe(true);
    expect(payload.error).toBe("query_unavailable");
    // It points at the tools that still work rather than just failing.
    expect(String(payload.message)).toContain("read_scope");
  });

  it("rejects an empty question before touching the engine", async () => {
    const port = recordingPort();
    const { result } = await ask(
      { question: "   " },
      { askPersonalData: port },
    );
    expect(result.isError).toBe(true);
    expect(port.calls).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ *
 * The grant: narrow, never widen
 * ------------------------------------------------------------------ */

describe("ask_personal_data grant handling", () => {
  it("defaults to the connection's own scopes", async () => {
    const port = recordingPort();
    await ask({ question: "how much sleep?" }, { askPersonalData: port });
    // `uniqueScopes` reports the connection's scopes sorted.
    expect(port.calls[0]!.scopes).toEqual([
      { scope: "chatgpt.history", grantId: "grant-1" },
      { scope: "oura.sleep", grantId: "grant-1" },
    ]);
  });

  it("honours a narrowing request", async () => {
    const port = recordingPort();
    await ask(
      { question: "how much sleep?", scopes: ["oura.sleep"] },
      { askPersonalData: port },
    );
    expect(port.calls[0]!.scopes).toEqual([
      { scope: "oura.sleep", grantId: "grant-1" },
    ]);
  });

  it("never widens to a scope no grant covers", async () => {
    const port = recordingPort();
    const { payload } = await ask(
      { question: "how much sleep?", scopes: ["oura.sleep", "someone.else"] },
      { askPersonalData: port },
    );
    // The ungranted scope does not reach the engine...
    expect(port.calls[0]!.scopes.map((s) => s.scope)).toEqual(["oura.sleep"]);
    // ...and its refusal is reported rather than silently dropped.
    expect(payload.scopeErrors).toContainEqual({
      scope: "someone.else",
      error: "scope_not_granted",
    });
  });

  it("refuses outright when nothing in the request is granted", async () => {
    const port = recordingPort();
    const { result, payload } = await ask(
      { question: "how much sleep?", scopes: ["someone.else"] },
      { askPersonalData: port },
    );
    expect(result.isError).toBe(true);
    expect(payload.error).toBe("no_granted_scope");
    expect(port.calls).toHaveLength(0);
  });

  it("expands a wildcard grant only to scopes the grant still covers", async () => {
    const port = recordingPort();
    const readClient = createReadClient({
      listScopes: vi.fn().mockResolvedValue({
        status: 200,
        scopes: [
          { scope: "oura.sleep" },
          { scope: "oura.activity" },
          // A scope the discovery listing returned but no grant covers.
          { scope: "spotify.streaming" },
        ],
        total: 3,
        limit: 200,
        offset: 0,
      }),
    });
    await ask(
      { question: "how much sleep?" },
      {
        connection: createConnection([
          { grantId: "grant-w", scopes: ["oura.*"] },
        ]),
        readClient,
        askPersonalData: port,
      },
    );
    expect(port.calls[0]!.scopes.map((s) => s.scope)).toEqual([
      "oura.sleep",
      "oura.activity",
    ]);
  });

  it("passes the caller's budget through", async () => {
    const port = recordingPort();
    await ask(
      { question: "how much sleep?", budget: { toolCalls: 5 } },
      { askPersonalData: port },
    );
    expect(port.calls[0]!.budget).toEqual({ toolCalls: 5 });
  });

  it("hands the engine the connection's own read client", async () => {
    const port = recordingPort();
    const readClient = createReadClient();
    await ask(
      { question: "how much sleep?" },
      { readClient, askPersonalData: port },
    );
    // The engine must read through this client and no other: it is what
    // performs the grant check, the access-log write and the settlement.
    expect(port.calls[0]!.readClient).toBe(readClient);
  });
});

/* ------------------------------------------------------------------ *
 * Payment: a sweep cannot settle N proofs from one call
 * ------------------------------------------------------------------ */

describe("ask_personal_data on a paying session", () => {
  it("declines rather than sweeping unmetered, and names the chargeable scopes", async () => {
    const port = recordingPort();
    const { result, payload } = await ask(
      { question: "how much sleep?" },
      {
        readClient: createReadClient({ enforcesPayment: true }),
        askPersonalData: port,
      },
    );

    expect(result.isError).toBe(true);
    expect(payload.error).toBe("payment_required_for_sweep");
    // An x402 proof binds to one (grant, dataPointId, version, recordId,
    // nonce); N scopes need N signed proofs and one tool call carries one.
    // Reading anyway would be an unmetered read, so it does not read.
    expect(port.calls).toHaveLength(0);
    expect(payload.paymentRequiredScopes).toEqual([
      "chatgpt.history",
      "oura.sleep",
    ]);
    // It routes the caller to the tool that CAN settle one scope at a time.
    expect(String(payload.message)).toContain("read_scope");
  });

  it("sweeps normally on a free session", async () => {
    const port = recordingPort();
    const { result } = await ask(
      { question: "how much sleep?" },
      {
        readClient: createReadClient({ enforcesPayment: false }),
        askPersonalData: port,
      },
    );
    expect(result.isError).toBeUndefined();
    expect(port.calls).toHaveLength(1);
  });
});

/* ------------------------------------------------------------------ *
 * The answer
 * ------------------------------------------------------------------ */

describe("ask_personal_data result", () => {
  it("returns the QueryAnswer with its coverage intact", async () => {
    const { payload } = await ask(
      { question: "how much sleep?" },
      { askPersonalData: recordingPort() },
    );
    expect(payload.answer).toBe("42");
    // Coverage is the property that distinguishes this from a naive LLM
    // call; the tool must not reshape it on the way out.
    expect(payload.coverage).toEqual(ANSWER.coverage);
    expect(payload.determinism).toBe("generated");
    expect(payload.cost).toEqual(ANSWER.cost);
  });

  it("surfaces an engine failure as a tool error, not a thrown handler", async () => {
    const { result, payload } = await ask(
      { question: "how much sleep?" },
      {
        askPersonalData: {
          async ask() {
            throw new Error("sandbox unavailable");
          },
        },
      },
    );
    expect(result.isError).toBe(true);
    expect(payload.error).toBe("query_failed");
    expect(String(payload.message)).toContain("sandbox unavailable");
  });
});
