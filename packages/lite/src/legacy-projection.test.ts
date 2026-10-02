/**
 * PS-Lite serves legacy scope bodies projected from stored PDPP records,
 * through every read path an app or builder uses: the data route, the
 * owner-only stored view, and the bounded block reads MCP tools use.
 */

import { describe, expect, it } from "vitest";
import { buildDataBlocksAsync } from "@opendatalabs/personal-server-ts-core/storage/blocks";
import { withLegacyProjection } from "@opendatalabs/personal-server-ts-core/storage/legacy-projection";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";

const conversations = {
  records: [
    {
      id: "conv-1",
      title: "Trip plan",
      create_time: "2026-09-01T10:00:00Z",
      update_time: "2026-09-01T10:05:00Z",
      current_node: "m1",
      message_count_on_current_branch: 1,
    },
  ],
};
const messages = {
  records: [
    {
      id: "m1",
      conversation_id: "conv-1",
      parent_id: null,
      role: "user",
      content: "How do I get to Lyon?",
      content_type: "text",
      model_slug: null,
      create_time: "2026-09-01T10:01:00Z",
      on_current_branch: true,
    },
  ],
};

function createRuntime() {
  const storage = createMemoryPsLiteStorage();
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const runtime = createPsLiteRuntime({
    storage,
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    auth: createBearerTokenPsLiteAuth({
      ownerToken: "owner-token",
      builderToken: "builder-token",
    }),
    active: true,
  });
  return { runtime, storage };
}

async function post(
  runtime: ReturnType<typeof createRuntime>["runtime"],
  scope: string,
  body: unknown,
) {
  const res = await runtime.fetch(
    new Request(`https://ps.local/v1/data/${scope}`, {
      method: "POST",
      headers: {
        Authorization: "Bearer owner-token",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
    }),
  );
  expect(res.status).toBe(201);
}

function get(
  runtime: ReturnType<typeof createRuntime>["runtime"],
  path: string,
  token = "owner-token",
) {
  return runtime.fetch(
    new Request(`https://ps.local${path}`, {
      headers: { Authorization: `Bearer ${token}` },
    }),
  );
}

describe("PS-Lite legacy projection", () => {
  it("serves the projected legacy body to the owner and keeps the stored records", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);

    const res = await get(runtime, "/v1/data/chatgpt.conversations");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: unknown };
    expect(body.data).toMatchObject({
      conversations: [
        {
          id: "conv-1",
          title: "Trip plan",
          message_count: 1,
          messages: [{ id: "m1", role: "user" }],
        },
      ],
      total: 1,
    });

    // Sync is built on the raw port: it still sees the canonical records.
    const entry = storage.findEntry({ scope: "chatgpt.conversations" })!;
    const stored = await storage.readEnvelope(
      "chatgpt.conversations",
      entry.collectedAt,
    );
    expect(stored.data).toEqual(conversations);
  });

  it("returns the stored body to the owner with ?view=stored", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "chatgpt.conversations", conversations);

    const res = await get(
      runtime,
      "/v1/data/chatgpt.conversations?view=stored",
    );

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toEqual(
      conversations,
    );
  });

  it("refuses ?view=stored to a grantee and an unknown view to anyone", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "chatgpt.conversations", conversations);

    const grantee = await get(
      runtime,
      "/v1/data/chatgpt.conversations?view=stored&grantId=grant-1",
      "builder-token",
    );
    expect(grantee.status).toBe(403);

    const unknown = await get(
      runtime,
      "/v1/data/chatgpt.conversations?view=raw",
    );
    expect(unknown.status).toBe(400);
    expect(await unknown.json()).toMatchObject({
      error: { errorCode: "INVALID_VIEW" },
    });
  });

  it("serves a grantee the projected body", async () => {
    const { runtime } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);

    const res = await get(
      runtime,
      "/v1/data/chatgpt.conversations?grantId=grant-1",
      "builder-token",
    );

    expect(res.status).toBe(200);
    expect(((await res.json()) as { data: unknown }).data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 1 }],
      total: 1,
    });
  });

  it("builds MCP blocks and the manifest from the projected envelope, not the stored sidecar", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);
    const { collectedAt } = storage.findEntry({
      scope: "chatgpt.conversations",
    })!;
    // Ingest wrote a sidecar for the stored {records} body.
    expect(
      await storage.readBlockManifest!("chatgpt.conversations", collectedAt),
    ).not.toBeNull();
    const served = withLegacyProjection(storage);
    const projected = await served.readEnvelope(
      "chatgpt.conversations",
      collectedAt,
    );
    const expected = await buildDataBlocksAsync({
      scope: "chatgpt.conversations",
      collectedAt,
      content: projected,
    });

    expect(
      await served.readBlockManifest!("chatgpt.conversations", collectedAt),
    ).toEqual(expected.manifest);
    expect(
      await served.hasScopeBlocks!("chatgpt.conversations", collectedAt),
    ).toBe(true);

    const read = await served.readScopeBlocks!(
      "chatgpt.conversations",
      collectedAt,
      { maxBytes: 1_000_000 },
    );
    expect(read.blocks).toEqual(expected.blocks);
    expect(read.nextCursor).toBeUndefined();
    expect(JSON.stringify(read.blocks)).toContain("How do I get to Lyon?");
    expect(JSON.stringify(read.blocks)).not.toContain(
      "message_count_on_current_branch",
    );
  });

  it("pages projected blocks with a cursor", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);
    const { collectedAt } = storage.findEntry({
      scope: "chatgpt.conversations",
    })!;
    const served = withLegacyProjection(storage);
    const all = await served.readScopeBlocks!(
      "chatgpt.conversations",
      collectedAt,
      { maxBytes: 1_000_000 },
    );

    const paged: string[] = [];
    let cursor: string | undefined;
    do {
      const page = await served.readScopeBlocks!(
        "chatgpt.conversations",
        collectedAt,
        { maxBytes: 40, ...(cursor ? { cursor } : {}) },
      );
      for (const block of page.blocks) {
        paged.push(
          typeof block.value === "string"
            ? block.value
            : JSON.stringify(block.value),
        );
      }
      cursor = page.nextCursor;
    } while (cursor);

    expect(paged.join("")).toBe(
      all.blocks
        .map((block) =>
          typeof block.value === "string"
            ? block.value
            : JSON.stringify(block.value),
        )
        .join(""),
    );
  });
  it("rejects a block cursor after a sibling stream changes", async () => {
    const { runtime, storage } = createRuntime();
    await post(runtime, "chatgpt.messages", messages);
    await post(runtime, "chatgpt.conversations", conversations);
    const { collectedAt } = storage.findEntry({
      scope: "chatgpt.conversations",
    })!;
    const served = withLegacyProjection(storage);
    const first = await served.readScopeBlocks!(
      "chatgpt.conversations",
      collectedAt,
      { maxBytes: 40 },
    );
    expect(first.nextCursor).toBeDefined();

    await post(runtime, "chatgpt.messages", {
      records: [{ ...messages.records[0], content: "Changed" }],
    });

    await expect(
      served.readScopeBlocks!("chatgpt.conversations", collectedAt, {
        maxBytes: 40,
        cursor: first.nextCursor,
      }),
    ).rejects.toMatchObject({ code: "cursor_invalid" });
  });
});
