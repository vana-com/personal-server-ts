/**
 * The MCP engine's read path — where phase 8's metering requirement is met.
 *
 * The whole reason `ask_personal_data` can claim "settle and log per scope
 * touched" is that every scope reaches the sandbox through
 * `McpDataReadClient.readScopeEnvelope`, which is `GET /v1/data/:scope` run
 * in-process: the same grant check, the same access-log row, the same x402
 * cycle. If this ever stopped going through the read client, the sweep would
 * become an unmetered, unlogged bulk read of the caller's grant.
 */

import { describe, expect, it, vi } from "vitest";

import type { McpDataReadClient } from "@opendatalabs/personal-server-ts-core/mcp";
import { createFakeInferenceProvider } from "@opendatalabs/personal-server-ts-core/derivatives";

import { createMcpAskPersonalDataPort } from "./mcp-ask-port.js";
import { createQueryConcurrency } from "./query-service.js";

function readClientOver(scopes: Record<string, unknown[]>): McpDataReadClient {
  return {
    listScopes: vi.fn(),
    getScopeMetadata: vi.fn(),
    readScopeBlocks: vi.fn().mockRejectedValue(new Error("bounded read")),
    readRawScopeFile: vi.fn().mockRejectedValue(new Error("binary only")),
    readScopeEnvelope: vi.fn(async ({ scope }: { scope: string }) => {
      const items = scopes[scope];
      if (!items) throw new Error(`no data for ${scope}`);
      return {
        status: 200,
        scope,
        collectedAt: "2026-01-01T00:00:00Z",
        version: "1",
        envelope: {
          version: 1,
          scope,
          collectedAt: "2026-01-01T00:00:00Z",
          data: { items },
        },
      };
    }),
  } as unknown as McpDataReadClient;
}

/** A provider that sweeps the named scopes in one script, then answers. */
function sweepingProvider(scopes: string[]) {
  const body = scopes
    .map((s) => `total += (await vana.readAll(${JSON.stringify(s)})).length;`)
    .join("\n");
  return createFakeInferenceProvider({
    respond: (_input, n) =>
      n === 0
        ? {
            content:
              "```vana:run\nlet total = 0;\n" +
              body +
              '\nvana.result({ answer: "" + total, citations: [] });\n```',
          }
        : {
            content:
              "```vana:answer\n" +
              JSON.stringify({ answer: "swept", citations: [] }) +
              "\n```",
          },
  });
}

describe("createMcpAskPersonalDataPort", () => {
  it("reads every scope through the metered read client, once each", async () => {
    const readClient = readClientOver({
      "oura.sleep": [{ d: 1 }, { d: 2 }],
      "chatgpt.history": [{ m: 1 }],
    });
    const port = createMcpAskPersonalDataPort({
      provider: sweepingProvider(["oura.sleep", "chatgpt.history"]),
    });

    const answer = await port.ask({
      question: "how many records?",
      scopes: [
        { scope: "oura.sleep", grantId: "grant-1" },
        { scope: "chatgpt.history", grantId: "grant-2" },
      ],
      readClient,
    });

    const calls = vi.mocked(readClient.readScopeEnvelope!).mock.calls;
    // Two scopes touched is two reads — and therefore two grant checks, two
    // access-log rows and, on a paying session, two settlements.
    expect(calls).toHaveLength(2);
    // Each read carries the grant that covers ITS scope, not a shared one.
    expect(calls.map(([a]) => [a.scope, a.grantId])).toEqual([
      ["oura.sleep", "grant-1"],
      ["chatgpt.history", "grant-2"],
    ]);
    // The bounded path is never used: a `truncated` block would make
    // `recordsScanned` a total over a partial read.
    expect(readClient.readScopeBlocks).not.toHaveBeenCalled();

    expect(answer.coverage.recordsScanned).toBe(3);
    expect(answer.coverage.scopesScanned.sort()).toEqual([
      "chatgpt.history",
      "oura.sleep",
    ]);
  });

  it("never reads a scope the tool did not resolve into the grant", async () => {
    const readClient = readClientOver({ "oura.sleep": [{ d: 1 }] });
    const port = createMcpAskPersonalDataPort({
      provider: sweepingProvider(["oura.sleep"]),
    });

    await port.ask({
      question: "how many?",
      scopes: [{ scope: "oura.sleep", grantId: "grant-1" }],
      readClient,
    });

    const scopesRead = vi
      .mocked(readClient.readScopeEnvelope!)
      .mock.calls.map(([a]) => a.scope);
    expect(scopesRead).toEqual(["oura.sleep"]);
  });

  it("degrades honestly when the client cannot serve whole scopes", async () => {
    // An older or partial read client with no `readScopeEnvelope`. Reading
    // through the bounded path instead would risk a short corpus reported as
    // a complete scan, so the scope is skipped and coverage says so.
    const readClient = {
      listScopes: vi.fn(),
      getScopeMetadata: vi.fn(),
      readScopeBlocks: vi.fn(),
      readRawScopeFile: vi.fn(),
    } as unknown as McpDataReadClient;

    const answer = await createMcpAskPersonalDataPort({
      provider: createFakeInferenceProvider(),
    }).ask({
      question: "how many?",
      scopes: [{ scope: "oura.sleep", grantId: "grant-1" }],
      readClient,
    });

    expect(answer.coverage.scopesScanned).toEqual([]);
    expect(answer.coverage.scopesSkipped[0]?.scope).toBe("oura.sleep");
    expect(readClient.readScopeBlocks).not.toHaveBeenCalled();
  });

  it("shares the process-wide concurrency ceiling when given one", async () => {
    const gate = createQueryConcurrency(1);
    gate.acquire();
    await expect(
      createMcpAskPersonalDataPort({
        provider: createFakeInferenceProvider(),
        concurrency: gate,
      }).ask({
        question: "how many?",
        scopes: [{ scope: "oura.sleep", grantId: "grant-1" }],
        readClient: readClientOver({ "oura.sleep": [{ d: 1 }] }),
      }),
    ).rejects.toThrow(/Too many questions/);
  });
});
