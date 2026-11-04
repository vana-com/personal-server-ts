/**
 * O22's real-server companion: a retained message tombstone and one broken
 * ChatGPT conversation must refuse the whole canonical scope without making
 * the earlier legacy body a way to reach the deleted message.
 */

import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { recoverServerOwner } from "@opendatalabs/vana-sdk/node";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { createServer, type ServerContext } from "./bootstrap.js";
import { registerTestConnection } from "./pdpp/test-connections.js";

const KNOWN_SIG =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";
const OWNER_TOKEN = "oracle-1904-control-plane";
const SCRATCH_ROOT = join(homedir(), ".tmp", "personal-server-tests");
const CHATGPT = "https://registry.pdpp.dev/sources/chatgpt";
const SCOPE = "chatgpt.conversations";
const INSTANCE_PREFIX = "chatgpt:";
const T0 = "2026-11-03T00:00:00.000Z";
const T1 = "2026-11-04T00:00:00.000Z";
const T2 = "2026-11-05T00:00:00.000Z";
const DELETED_MESSAGE_ID = "A:x";
const LEGACY_DELETED_MESSAGE_ID = "x";
const LEGACY_FILE_ID = "oracle-1904-synthetic-legacy-file";
const DELETED_CONTENT = "synthetic deleted ChatGPT message body O22";
const DELETED_CONTENT_SHA256 = createHash("sha256")
  .update(DELETED_CONTENT, "utf8")
  .digest("hex");

const conversationFields = {
  id: "A",
  title: "Synthetic conversation",
  create_time: T0,
  update_time: T0,
  current_node: "x",
  message_count_on_current_branch: 1,
};
const messageFields = {
  id: DELETED_MESSAGE_ID,
  conversation_id: "A",
  parent_id: "root",
  role: "user",
  content_type: "text",
  content: DELETED_CONTENT,
  create_time: T0,
  model_slug: "synthetic",
  on_current_branch: true,
};

const declaration = JSON.stringify({
  source_id: CHATGPT,
  source_kind: "connector",
  version: "1",
  streams: [
    {
      name: "conversations",
      fields: Object.keys(conversationFields),
      required_fields: ["id"],
      primary_key: ["id"],
    },
    {
      name: "messages",
      fields: Object.keys(messageFields),
      required_fields: ["id"],
      primary_key: ["id"],
      schema: {
        type: "object",
        required: ["id", "content"],
        properties: {
          id: { type: "string" },
          content: {
            type: ["string", "null"],
            x_pdpp_text_encoding: "pdpp-safe-escape-v1",
          },
          blob_ref: {
            x_pdpp_blob_projects_field: "content",
            x_pdpp_blob_codec: "json-string-v1",
          },
        },
      },
    },
  ],
});

type MessageEvidence = { ids: string[]; contentHashes: string[] };

let tempDir: string;
let ctx: ServerContext | undefined;
let owner: string;
let pdppOwnerToken: string;

type ReadResult = { status: number; text: string; dataSource?: string | null };

function conversation(
  id: string,
  currentNode: string,
  count: number,
  updateTime: string,
) {
  return {
    id,
    title: id === "H" ? "Healthy synthetic H" : `Synthetic ${id}`,
    create_time: T0,
    update_time: updateTime,
    current_node: currentNode,
    message_count_on_current_branch: count,
  };
}

function message(
  conversationId: string,
  node: string,
  parentId: string | null,
  content: string,
  role = "user",
) {
  return {
    id: `${conversationId}:${node}`,
    conversation_id: conversationId,
    parent_id: parentId,
    role,
    content_type: "text",
    content,
    create_time: T0,
    model_slug: "synthetic",
    on_current_branch: true,
  };
}

function messageEvidence(
  value: unknown,
  found: MessageEvidence = { ids: [], contentHashes: [] },
): MessageEvidence {
  if (Array.isArray(value)) {
    for (const entry of value) messageEvidence(entry, found);
    return found;
  }
  if (value === null || typeof value !== "object") return found;

  const row = value as Record<string, unknown>;
  if (typeof row.role === "string" && typeof row.id === "string") {
    found.ids.push(row.id);
    if (typeof row.content === "string") {
      found.contentHashes.push(
        createHash("sha256").update(row.content, "utf8").digest("hex"),
      );
    }
  }
  for (const nested of Object.values(row)) messageEvidence(nested, found);
  return found;
}

function exposure(path: string, response: { status: number; text: string }) {
  const evidence = messageEvidence(JSON.parse(response.text) as unknown);
  return {
    path,
    status: response.status,
    deletedIdPresent: evidence.ids.some(
      (id) => id === DELETED_MESSAGE_ID || id === LEGACY_DELETED_MESSAGE_ID,
    ),
    deletedContentHashPresent: evidence.contentHashes.includes(
      DELETED_CONTENT_SHA256,
    ),
  };
}

async function bootServer() {
  const declarationsDir = join(tempDir, "declarations");
  await mkdir(declarationsDir, { recursive: true });
  const declarationPath = join(declarationsDir, "chatgpt.json");
  await writeFile(declarationPath, declaration, "utf8");

  const gateway = {
    getBuilder: vi.fn().mockResolvedValue(null),
    getGrant: vi.fn().mockResolvedValue(null),
  } as unknown as GatewayClient;

  return createServer(
    ServerConfigSchema.parse({
      tunnel: { enabled: false },
      payment: { enabled: false },
      pdpp: {
        enabled: true,
        declarationPaths: [declarationPath],
        methods: [{ method_id: "chatgpt", declaration_path: declarationPath }],
      },
    }),
    {
      serverDir: tempDir,
      dataDir: join(tempDir, "data"),
      gatewayClient: gateway,
    },
  );
}

async function legacyWrite(data: Record<string, unknown>) {
  vi.useFakeTimers({ toFake: ["Date"] });
  try {
    vi.setSystemTime(new Date(T0));
    const response = await ctx!.app.request(`/v1/data/${SCOPE}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${ctx!.devToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(data),
    });
    expect(response.status).toBe(201);
  } finally {
    vi.useRealTimers();
  }
}

async function ownerGet(path: string) {
  const response = await ctx!.app.request(path, {
    headers: { authorization: `Bearer ${OWNER_TOKEN}` },
  });
  return {
    status: response.status,
    text: await response.text(),
    dataSource: response.headers.get("X-Vana-Data-Source"),
  };
}

async function pdppRequest(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${pdppOwnerToken}`);
  const response = await ctx!.app.request(path, {
    ...init,
    headers,
  });
  return { status: response.status, text: await response.text() };
}

async function ingest(
  stream: "conversations" | "messages",
  data: Record<string, unknown>,
  emittedAt: string,
) {
  const response = await pdppRequest(
    `/v1/streams/${stream}/records/ingest?method=chatgpt&binding_generation=1`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        instance: `${INSTANCE_PREFIX}${owner}`,
        key: String(data.id),
        data,
        emitted_at: emittedAt,
      }),
    },
  );
  expect(response.status, response.text).toBe(200);
  expect(JSON.parse(response.text)).toMatchObject({
    accepted: 1,
    rejected: [],
  });
}

async function replaceStream(
  stream: "conversations" | "messages",
  rows: Record<string, unknown>[],
  collectedAt: string,
) {
  const response = await pdppRequest(
    `/v1/streams/${stream}/records/replace?method=chatgpt&binding_generation=1`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        instance: `${INSTANCE_PREFIX}${owner}`,
        emitted_at: collectedAt,
        source_collected_at: collectedAt,
        records: rows.map((data) => ({
          key: String(data.id),
          data,
          emitted_at: collectedAt,
        })),
      }),
    },
  );
  expect(response.status, response.text).toBe(200);
}

async function setupCoveredLegacyScope(establishTakeover = true) {
  const legacyData = {
    conversations: [
      {
        id: "A",
        title: "Synthetic A",
        create_time: T0,
        update_time: T0,
        message_count: 1,
        messages: [
          {
            id: LEGACY_DELETED_MESSAGE_ID,
            role: "user",
            content: DELETED_CONTENT,
            content_type: "text",
            create_time: T0,
            model: "synthetic",
          },
        ],
      },
      {
        id: "H",
        title: "Healthy synthetic H",
        create_time: T0,
        update_time: T0,
        message_count: 1,
        messages: [
          {
            id: "h0",
            role: "user",
            content: "healthy synthetic H body",
            content_type: "text",
            create_time: T0,
            model: "synthetic",
          },
        ],
      },
    ],
    total: 2,
  };
  await legacyWrite(legacyData);
  const unlinkedLegacyEntry = ctx!.indexManager.findLatestByScope(SCOPE);
  expect(unlinkedLegacyEntry?.fileId).toBeNull();
  expect(
    ctx!.indexManager.updateFileId(unlinkedLegacyEntry!.path, LEGACY_FILE_ID),
  ).toBe(true);

  // ruled by lead 11-03: oracle precondition used an Oura-only flag
  const beforeTakeover = await ownerGet(`/v1/data/${SCOPE}`);
  expect(beforeTakeover.status).toBe(200);
  expect(beforeTakeover.dataSource).toBe("legacy");
  const beforeEvidence = messageEvidence(
    JSON.parse(beforeTakeover.text) as unknown,
  );
  expect(beforeEvidence.ids).toContain(LEGACY_DELETED_MESSAGE_ID);
  expect(beforeEvidence.contentHashes).toContain(DELETED_CONTENT_SHA256);

  pdppOwnerToken = await registerTestConnection(
    ctx!.app,
    ctx!.devToken!,
    owner,
    CHATGPT,
    "chatgpt",
  );
  await ingest("conversations", conversation("A", "x", 1, T0), T0);
  await ingest("conversations", conversation("H", "h0", 1, T0), T0);
  await ingest("messages", message("A", "x", null, DELETED_CONTENT), T0);
  await ingest(
    "messages",
    message("H", "h0", null, "healthy synthetic H body"),
    T0,
  );

  if (establishTakeover) {
    const takeover = await ownerGet(`/v1/data/${SCOPE}`);
    expect(takeover.status).toBe(200);
    expect(takeover.dataSource).toBe("canonical");
    const takeoverEvidence = messageEvidence(
      JSON.parse(takeover.text) as unknown,
    );
    expect(takeoverEvidence.ids).toContain(LEGACY_DELETED_MESSAGE_ID);
    expect(takeoverEvidence.contentHashes).toContain(DELETED_CONTENT_SHA256);
  }

  const legacyEntry = ctx!.indexManager.findLatestByScope(SCOPE);
  expect(legacyEntry).toBeDefined();
  return { legacyEntry: legacyEntry! };
}

function expectRetainedMessageTombstone() {
  const db = new Database(join(tempDir, "index.db"), {
    readonly: true,
    fileMustExist: true,
  });
  try {
    const row = db
      .prepare(
        "SELECT record_key, data, deleted FROM pdpp_records WHERE instance = ? AND stream = 'messages' AND record_key = ?",
      )
      .get(`${INSTANCE_PREFIX}${owner}`, DELETED_MESSAGE_ID) as
      { record_key: string; data: string | null; deleted: number } | undefined;
    expect(row).toEqual({
      record_key: DELETED_MESSAGE_ID,
      data: null,
      deleted: 1,
    });
  } finally {
    db.close();
  }
}

function expectNoLegacyTakeover() {
  const db = new Database(join(tempDir, "index.db"), {
    readonly: true,
    fileMustExist: true,
  });
  try {
    const row = db
      .prepare(
        "SELECT COUNT(*) AS count FROM legacy_scope_takeovers WHERE scope = ?",
      )
      .get(SCOPE) as { count: number };
    expect(row.count).toBe(0);
  } finally {
    db.close();
  }
}

async function readLegacyAndRecordSurfaces(legacyEntry: {
  collectedAt: string;
  fileId: string | null;
}) {
  const at = encodeURIComponent(legacyEntry.collectedAt);
  const fileId = legacyEntry.fileId;
  const reads: { path: string; response: ReadResult }[] = [
    { path: "latest", response: await ownerGet(`/v1/data/${SCOPE}`) },
    {
      path: "stored",
      response: await ownerGet(`/v1/data/${SCOPE}?view=stored`),
    },
    {
      path: "history-at",
      response: await ownerGet(`/v1/data/${SCOPE}?at=${at}`),
    },
    {
      path: "stored-at",
      response: await ownerGet(`/v1/data/${SCOPE}?view=stored&at=${at}`),
    },
    {
      path: "version-list",
      response: await ownerGet(`/v1/data/${SCOPE}/versions`),
    },
    { path: "scope-list", response: await ownerGet("/v1/data") },
    {
      path: "record-list",
      response: await pdppRequest("/v1/streams/messages/records?limit=100"),
    },
    {
      path: "record-get-deleted-id",
      response: await pdppRequest(
        `/v1/streams/messages/records/${encodeURIComponent(DELETED_MESSAGE_ID)}`,
      ),
    },
  ];
  if (fileId !== null) {
    const id = encodeURIComponent(fileId);
    reads.push(
      {
        path: "history-file-id",
        response: await ownerGet(`/v1/data/${SCOPE}?fileId=${id}`),
      },
      {
        path: "stored-file-id",
        response: await ownerGet(`/v1/data/${SCOPE}?view=stored&fileId=${id}`),
      },
    );
  }
  return reads;
}

function exposuresOf(reads: { path: string; response: ReadResult }[]) {
  return reads
    .map(({ path, response }) => exposure(path, response))
    .filter(
      (result) => result.deletedIdPresent || result.deletedContentHashPresent,
    );
}

async function damageConversationWithDeletedParent() {
  const deleted = await pdppRequest(
    `/v1/streams/messages/records/${encodeURIComponent(DELETED_MESSAGE_ID)}`,
    { method: "DELETE" },
  );
  expect(deleted.status).toBe(204);
  expectRetainedMessageTombstone();

  await ingest(
    "messages",
    message(
      "A",
      "y",
      DELETED_MESSAGE_ID,
      "replacement synthetic answer",
      "assistant",
    ),
    T1,
  );
  await ingest("conversations", conversation("A", "y", 2, T1), T1);
}

function expectCanonicalRefusal(response: { status: number; text: string }) {
  expect(response.status).toBe(503);
  expect(JSON.parse(response.text)).toMatchObject({
    error: "CANONICAL_VIEW_UNAVAILABLE",
    reason: "canonical_view_incomplete",
  });
}

function expectDeletedBodyAbsent(response: { status: number; text: string }) {
  const evidence = messageEvidence(JSON.parse(response.text) as unknown);
  expect(
    evidence.ids.some(
      (id) => id === DELETED_MESSAGE_ID || id === LEGACY_DELETED_MESSAGE_ID,
    ),
  ).toBe(false);
  expect(evidence.contentHashes).not.toContain(DELETED_CONTENT_SHA256);
}

beforeEach(async () => {
  await mkdir(SCRATCH_ROOT, { recursive: true });
  tempDir = await mkdtemp(join(SCRATCH_ROOT, "oracle-1904-http-"));
  vi.stubEnv("VANA_MASTER_KEY_SIGNATURE", KNOWN_SIG);
  vi.stubEnv("PS_ACCESS_TOKEN", OWNER_TOKEN);
  owner = (await recoverServerOwner(KNOWN_SIG)).toLowerCase();
  ctx = await bootServer();
});

afterEach(async () => {
  await ctx?.cleanup();
  ctx = undefined;
  await rm(tempDir, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe("ChatGPT retained-message deletion through the real server", () => {
  it("refuses an incomplete latest view and does not expose the deleted message through legacy reads", async () => {
    const { legacyEntry } = await setupCoveredLegacyScope();
    await damageConversationWithDeletedParent();

    const latest = await ownerGet(`/v1/data/${SCOPE}`);
    expectCanonicalRefusal(latest);
    expectDeletedBodyAbsent(latest);
    const reads = await readLegacyAndRecordSurfaces(legacyEntry);
    const list = reads.find(({ path }) => path === "scope-list")!.response;
    expect(list.status).toBe(200);
    const listedScopes = (
      JSON.parse(list.text) as { scopes: { scope: string }[] }
    ).scopes.map((entry) => entry.scope);
    expect(listedScopes).not.toContain(SCOPE);

    const exposures = exposuresOf(reads);
    expect(exposures).toEqual([]);
  });

  it("serves a repaired branch without the deleted ID or body after reopen", async () => {
    const { legacyEntry: oldLegacyEntry } = await setupCoveredLegacyScope();
    await damageConversationWithDeletedParent();

    await replaceStream(
      "messages",
      [
        message("A", "repair", null, "repaired synthetic answer", "assistant"),
        message("H", "h0", null, "healthy synthetic H body"),
      ],
      T2,
    );
    await replaceStream(
      "conversations",
      [conversation("A", "repair", 1, T2), conversation("H", "h0", 1, T2)],
      T2,
    );
    expectRetainedMessageTombstone();

    const repaired = await ownerGet(`/v1/data/${SCOPE}`);
    expect(repaired.status).toBe(200);
    expect(repaired.dataSource).toBe("canonical");
    expectDeletedBodyAbsent(repaired);
    expect(repaired.text).toContain("repaired synthetic answer");

    const preReopenReads = await readLegacyAndRecordSurfaces(oldLegacyEntry);
    const preReopenLatest = preReopenReads.find(
      ({ path }) => path === "latest",
    )!.response;
    expect(preReopenLatest.status).toBe(200);
    expect(preReopenLatest.dataSource).toBe("canonical");
    expectDeletedBodyAbsent(preReopenLatest);

    await ctx!.cleanup();
    ctx = await bootServer();

    expectRetainedMessageTombstone();
    const reopened = await ownerGet(`/v1/data/${SCOPE}`);
    expect(reopened.status).toBe(200);
    expect(reopened.dataSource).toBe("canonical");
    expectDeletedBodyAbsent(reopened);
    expect(reopened.text).toContain("repaired synthetic answer");

    const postReopenReads = await readLegacyAndRecordSurfaces(oldLegacyEntry);
    const postReopenLatest = postReopenReads.find(
      ({ path }) => path === "latest",
    )!.response;
    expect(postReopenLatest.status).toBe(200);
    expect(postReopenLatest.dataSource).toBe("canonical");
    expectDeletedBodyAbsent(postReopenLatest);
    expect(exposuresOf(preReopenReads)).toEqual([]);
    expect(exposuresOf(postReopenReads)).toEqual([]);
  });

  it("refuses deleted history through every legacy read before canonical takeover", async () => {
    const { legacyEntry } = await setupCoveredLegacyScope(false);
    expectNoLegacyTakeover();

    const at = encodeURIComponent(legacyEntry.collectedAt);
    const fileId = encodeURIComponent(legacyEntry.fileId!);
    const preDeleteHistory = [
      {
        path: "stored",
        response: await ownerGet(`/v1/data/${SCOPE}?view=stored`),
      },
      {
        path: "history-at",
        response: await ownerGet(`/v1/data/${SCOPE}?at=${at}`),
      },
      {
        path: "stored-at",
        response: await ownerGet(`/v1/data/${SCOPE}?view=stored&at=${at}`),
      },
      {
        path: "history-file-id",
        response: await ownerGet(`/v1/data/${SCOPE}?fileId=${fileId}`),
      },
      {
        path: "stored-file-id",
        response: await ownerGet(
          `/v1/data/${SCOPE}?view=stored&fileId=${fileId}`,
        ),
      },
    ];
    expect(preDeleteHistory.map(({ response }) => response.status)).toEqual([
      200, 200, 200, 200, 200,
    ]);
    expectNoLegacyTakeover();
    expect(
      exposuresOf(preDeleteHistory)
        .map(({ path }) => path)
        .sort(),
    ).toEqual([
      "history-at",
      "history-file-id",
      "stored",
      "stored-at",
      "stored-file-id",
    ]);

    await damageConversationWithDeletedParent();
    const afterDelete = await readLegacyAndRecordSurfaces(legacyEntry);
    const latest = afterDelete.find(({ path }) => path === "latest")!.response;
    expectCanonicalRefusal(latest);
    expectDeletedBodyAbsent(latest);

    const listing = afterDelete.find(
      ({ path }) => path === "scope-list",
    )!.response;
    expect(listing.status).toBe(200);
    expectDeletedBodyAbsent(listing);

    const messageList = afterDelete.find(
      ({ path }) => path === "record-list",
    )!.response;
    expect(messageList.status).toBe(200);
    const liveMessageRows = (
      JSON.parse(messageList.text) as {
        data: { id: string; data?: { content?: string } }[];
      }
    ).data;
    expect(liveMessageRows.map((row) => row.id)).not.toContain(
      DELETED_MESSAGE_ID,
    );
    expect(liveMessageRows).toContainEqual(
      expect.objectContaining({
        id: "H:h0",
        data: expect.objectContaining({ content: "healthy synthetic H body" }),
      }),
    );

    expect(exposuresOf(afterDelete)).toEqual([]);
    expectNoLegacyTakeover();
    expectRetainedMessageTombstone();
  });
});
