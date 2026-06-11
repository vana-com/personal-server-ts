import { describe, expect, it, vi } from "vitest";
import { McpActivityRecorder } from "./activity.js";
import { MCP_TOOLS } from "./tools.js";
import type { McpConnectionRecord } from "./types.js";

function createConnection(): McpConnectionRecord {
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
    grants: [
      { grantId: "grant-1", scopes: ["instagram.*"] },
      { grantId: "grant-2", scopes: ["chatgpt.history"], sourceId: "" },
    ],
    createdAt: "2026-06-05T00:00:00Z",
    approvedAt: "2026-06-05T00:00:00Z",
  };
}

describe("McpActivityRecorder", () => {
  it("starts an event in running state", () => {
    const r = new McpActivityRecorder();
    const id = r.start({ tool: "list_granted_scopes" });
    const { events } = r.snapshot();
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ id, status: "running" });
    expect(events[0].finishedAt).toBeUndefined();
  });

  it("finishes with succeeded", () => {
    const r = new McpActivityRecorder();
    const id = r.start({ tool: "read_scope", scopes: ["instagram.profile"] });
    r.update(id, {
      phase: "response_preparing",
      handlerDurationMs: 12,
      payloadBytes: 2048,
      textBytes: 1024,
      structuredContentBytes: 1024,
    });
    expect(r.snapshot().events[0]).toMatchObject({
      status: "running",
      phase: "response_preparing",
      handlerDurationMs: 12,
      payloadBytes: 2048,
    });
    r.finish(id, { status: "succeeded", resultCount: 3 });
    const ev = r.snapshot().events[0];
    expect(ev).toMatchObject({
      id,
      status: "succeeded",
      phase: "response_ready",
      resultCount: 3,
      handlerDurationMs: 12,
      payloadBytes: 2048,
      textBytes: 1024,
      structuredContentBytes: 1024,
    });
    expect(ev.finishedAt).toBeDefined();
    expect(typeof ev.durationMs).toBe("number");
  });

  it("records failure with errorCode", () => {
    const r = new McpActivityRecorder();
    const id = r.start({
      tool: "search_personal_context",
      queryPreview: "hello",
    });
    r.finish(id, { status: "failed", errorCode: "scope_not_granted" });
    const { events, running } = r.snapshot();
    expect(events[0]).toMatchObject({
      status: "failed",
      errorCode: "scope_not_granted",
    });
    expect(running).toBe(0);
  });

  it("counts running events", () => {
    const r = new McpActivityRecorder();
    const id1 = r.start({ tool: "t1" });
    const id2 = r.start({ tool: "t2" });
    expect(r.snapshot().running).toBe(2);
    r.finish(id1, { status: "succeeded" });
    expect(r.snapshot().running).toBe(1);
    r.finish(id2, { status: "timed_out" });
    expect(r.snapshot().running).toBe(0);
  });

  it("caps ring buffer and evicts oldest finished event", () => {
    const r = new McpActivityRecorder(3);
    const id1 = r.start({ tool: "t1" });
    r.finish(id1, { status: "succeeded" });
    const id2 = r.start({ tool: "t2" });
    r.finish(id2, { status: "succeeded" });
    const id3 = r.start({ tool: "t3" });
    r.finish(id3, { status: "succeeded" });
    const id4 = r.start({ tool: "t4" });
    const ids = r.snapshot().events.map((e) => e.id);
    expect(ids).not.toContain(id1);
    expect(ids).toContain(id4);
    expect(ids).toHaveLength(3);
  });

  it("returns snapshot newest-first", () => {
    const r = new McpActivityRecorder();
    const id1 = r.start({ tool: "t1" });
    r.finish(id1, { status: "succeeded" });
    const id2 = r.start({ tool: "t2" });
    r.finish(id2, { status: "succeeded" });
    const { events } = r.snapshot();
    expect(events[0].id).toBe(id2);
    expect(events[1].id).toBe(id1);
  });

  it("clips queryPreview to 120 chars", () => {
    const r = new McpActivityRecorder();
    const id = r.start({ tool: "search", queryPreview: "a".repeat(200) });
    expect(r.snapshot().events[0].queryPreview).toHaveLength(120);
    r.finish(id, { status: "succeeded" });
  });

  it("ignores finish for unknown id", () => {
    const r = new McpActivityRecorder();
    expect(() => r.finish("nope", { status: "succeeded" })).not.toThrow();
  });

  it("does not record raw data payloads", () => {
    const r = new McpActivityRecorder();
    const id = r.start({ tool: "read_scope", scopes: ["instagram.profile"] });
    r.finish(id, { status: "succeeded", resultCount: 5 });
    const ev = r.snapshot().events[0];
    expect(ev).not.toHaveProperty("blocks");
    expect(ev).not.toHaveProperty("data");
    expect(ev).not.toHaveProperty("content");
    expect(ev).not.toHaveProperty("matches");
  });

  it("records running state visible while tool is in flight", async () => {
    const r = new McpActivityRecorder();
    const connection = createConnection();
    let resolveRead!: () => void;
    const slowReadClient = {
      readScopeBlocks: vi.fn(
        () =>
          new Promise<{
            scope: string;
            blocks: never[];
            warnings: never[];
            collectedAt: string;
            contentKind: string;
          }>((resolve) => {
            resolveRead = () =>
              resolve({
                scope: "instagram.profile",
                blocks: [],
                warnings: [],
                collectedAt: "2026-06-05T00:00:00Z",
                contentKind: "json",
              });
          }),
      ),
    };

    const id = r.start({ tool: "read_scope", scopes: ["instagram.profile"] });
    const tool = MCP_TOOLS.find((t) => t.name === "read_scope")!;
    const callPromise = tool.handler(
      { scope: "instagram.profile" },
      { connection, readClient: slowReadClient as never },
    );

    expect(r.snapshot().running).toBe(1);
    expect(r.snapshot().events.find((e) => e.id === id)?.status).toBe(
      "running",
    );

    resolveRead();
    await callPromise;
    r.finish(id, { status: "succeeded" });
    expect(r.snapshot().running).toBe(0);
  });

  it("records timed_out status", () => {
    const r = new McpActivityRecorder();
    const id = r.start({
      tool: "search_personal_context",
      queryPreview: "test",
    });
    r.finish(id, { status: "timed_out", errorCode: "scope_search_timeout" });
    expect(r.snapshot().events[0]).toMatchObject({
      status: "timed_out",
      errorCode: "scope_search_timeout",
    });
  });

  it("records aborted status", () => {
    const r = new McpActivityRecorder();
    const id = r.start({ tool: "search_personal_context" });
    r.finish(id, { status: "aborted" });
    expect(r.snapshot().events[0].status).toBe("aborted");
  });
});
