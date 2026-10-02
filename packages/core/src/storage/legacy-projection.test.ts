import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { diffBodies } from "../legacy-projection/__fixtures__/parity/diff.js";
import { ingestDataContract } from "../contracts/data.js";
import type { DataStoragePort } from "../ports/index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import {
  classifyStoredBody,
  legacyScopesProjectedFrom,
  withLegacyProjection,
  type LegacyProjectionIssue,
} from "./legacy-projection.js";

const conversation = {
  id: "conv-1",
  title: "Trip plan",
  create_time: "2026-09-01T10:00:00Z",
  update_time: "2026-09-01T10:05:00Z",
  current_node: "m2",
  message_count_on_current_branch: 2,
};
const messages = [
  {
    id: "m2",
    conversation_id: "conv-1",
    parent_id: "m1",
    role: "assistant",
    content: "Take the train.",
    content_type: "text",
    model_slug: "gpt-5",
    create_time: "2026-09-01T10:02:00Z",
    on_current_branch: true,
  },
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
];

async function store(
  storage: DataStoragePort,
  scope: string,
  collectedAt: string,
  body: Record<string, unknown>,
) {
  const result = await ingestDataContract({
    storage,
    scopeParam: scope,
    body,
    collectedAt,
    status: "stored",
  });
  if (!result.ok) throw new Error(JSON.stringify(result.body));
}

describe("classifyStoredBody", () => {
  it.each([
    ["chatgpt.conversations", { records: [] }, "pdpp-projected"],
    ["claude.projects", { records: [{ id: "p" }] }, "pdpp-projected"],
    ["chatgpt.messages", { records: [] }, "pdpp-unprojected"],
    ["oura.sleep", { records: [] }, "pdpp-unprojected"],
    ["github.repositories", { records: [] }, "pdpp-unprojected"],
    ["chatgpt.conversations", { conversations: [], total: 0 }, "legacy"],
    ["chatgpt.conversations", { records: [], total: 0 }, "legacy"],
    ["chatgpt.conversations", { records: {} }, "legacy"],
    ["chatgpt.conversations", [], "legacy"],
    [
      "chatgpt.conversations",
      { exportSummary: {}, timestamp: "t", version: "1", platform: "web" },
      "legacy",
    ],
    [
      "chatgpt.conversations",
      { records: [], $writtenBy: { builder: "0x1" } },
      "pdpp-projected",
    ],
    [
      "chatgpt.conversations",
      { records: [{ stream: "conversations", data: { id: "c" } }] },
      "pdpp-unprojected",
    ],
  ])("%s %j is %s", (scope, data, form) => {
    expect(classifyStoredBody(scope, data)).toBe(form);
  });
});

describe("legacyScopesProjectedFrom", () => {
  it.each([
    ["chatgpt.messages", ["chatgpt.conversations"]],
    ["chatgpt.conversations", []],
    ["claude.account_profile", ["claude.conversations", "claude.projects"]],
    ["claude.project_documents", ["claude.projects"]],
    ["oura.sleep", []],
    ["notes", []],
  ])("%s → %j", (scope, expected) => {
    expect(legacyScopesProjectedFrom(scope).sort()).toEqual(expected);
  });
});

describe("withLegacyProjection", () => {
  it("serves chatgpt.conversations projected from the stored conversations and messages streams", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:02.000Z", {
      records: messages,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const served = withLegacyProjection(raw);

    const envelope = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(envelope.scope).toBe("chatgpt.conversations");
    expect(envelope.collectedAt).toBe("2026-10-01T00:00:01.000Z");
    expect(envelope.data).toEqual({
      conversations: [
        {
          id: "conv-1",
          title: "Trip plan",
          create_time: "2026-09-01T10:00:00Z",
          update_time: "2026-09-01T10:05:00Z",
          message_count: 2,
          messages: [
            {
              id: "m1",
              role: "user",
              content: "How do I get to Lyon?",
              content_type: "text",
              create_time: "2026-09-01T10:01:00Z",
              model: null,
            },
            {
              id: "m2",
              role: "assistant",
              content: "Take the train.",
              content_type: "text",
              create_time: "2026-09-01T10:02:00Z",
              model: "gpt-5",
            },
          ],
          // The newest input version, not the wall clock.
          fetched_at: "2026-10-01T00:00:02.000Z",
        },
      ],
      total: 1,
    });
  });

  it("leaves the raw port's stored body untouched", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [{ ...conversation, message_count_on_current_branch: 0 }],
    });
    const before = JSON.stringify(
      await raw.readEnvelope(
        "chatgpt.conversations",
        "2026-10-01T00:00:01.000Z",
      ),
    );
    const served = withLegacyProjection(raw);
    await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(
      JSON.stringify(
        await raw.readEnvelope(
          "chatgpt.conversations",
          "2026-10-01T00:00:01.000Z",
        ),
      ),
    ).toBe(before);
    expect(
      (
        await served.readStoredEnvelope!(
          "chatgpt.conversations",
          "2026-10-01T00:00:01.000Z",
        )
      ).data,
    ).toEqual({
      records: [{ ...conversation, message_count_on_current_branch: 0 }],
    });
  });

  it.each([
    ["a legacy body", "chatgpt.conversations", { conversations: [], total: 0 }],
    ["an unbound records stream", "chatgpt.messages", { records: messages }],
    ["records of an unprojected source", "oura.sleep", { records: [{}] }],
    ["an unrelated scope", "notes.entries", { text: "hello" }],
  ])("passes %s through unchanged", async (_label, scope, body) => {
    const raw = createMemoryDataStorage();
    await store(raw, scope, "2026-10-01T00:00:01.000Z", body);
    const served = withLegacyProjection(raw);

    expect(
      await served.readEnvelope(scope, "2026-10-01T00:00:01.000Z"),
    ).toEqual(await raw.readEnvelope(scope, "2026-10-01T00:00:01.000Z"));
  });

  it("serves the other conversations when one stored conversation is malformed", async () => {
    const raw = createMemoryDataStorage();
    const issues: LegacyProjectionIssue[] = [];
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:01.000Z", {
      records: messages,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [
        conversation,
        { id: "conv-2", title: "Broken", current_node: "x" },
      ],
    });
    const served = withLegacyProjection(raw, {
      onIssue: (issue) => issues.push(issue),
    });

    const { data } = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 2 }],
      total: 1,
    });
    expect(issues).toEqual([
      {
        kind: "projection_diagnostics",
        scope: "chatgpt.conversations",
        collectedAt: "2026-10-01T00:00:01.000Z",
        diagnostics: [
          {
            kind: "records_dropped",
            scope: "chatgpt.conversations",
            stream: "conversations",
            count: 1,
            reasons: ["Conversation lacks a current-branch message count"],
          },
        ],
      },
    ]);
  });

  it("projects conversations with empty threads when no messages stream is stored", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const served = withLegacyProjection(raw);

    const { data } = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(data).toMatchObject({
      conversations: [{ id: "conv-1", message_count: 0, messages: [] }],
      total: 1,
    });
  });

  it("serves the stored body and reports the error when projection fails", async () => {
    const raw = createMemoryDataStorage();
    const onIssue = vi.fn();
    // A claude scope with no account_profile stream cannot be projected.
    await store(raw, "claude.projects", "2026-10-01T00:00:01.000Z", {
      records: [{ id: "p1", name: "Research" }],
    });
    const served = withLegacyProjection(raw, { onIssue });

    const envelope = await served.readEnvelope(
      "claude.projects",
      "2026-10-01T00:00:01.000Z",
    );

    expect(envelope.data).toEqual({
      records: [{ id: "p1", name: "Research" }],
    });
    expect(onIssue).toHaveBeenCalledWith(
      expect.objectContaining({
        kind: "projection_failed",
        scope: "claude.projects",
        error: expect.objectContaining({ kind: "missing_stream" }),
      }),
    );
  });

  it("projects the same stored data to the same bytes on every read", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:02.000Z", {
      records: messages,
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const first = JSON.stringify(
      await withLegacyProjection(raw).readEnvelope(
        "chatgpt.conversations",
        "2026-10-01T00:00:01.000Z",
      ),
    );
    await new Promise((resolve) => setTimeout(resolve, 5));
    const second = JSON.stringify(
      await withLegacyProjection(raw).readEnvelope(
        "chatgpt.conversations",
        "2026-10-01T00:00:01.000Z",
      ),
    );

    expect(second).toBe(first);
  });

  it("re-projects when a sibling stream gets a new version", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [conversation],
    });
    const served = withLegacyProjection(raw);
    const before = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:03.000Z", {
      records: messages,
    });
    const after = await served.readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(before.data).toMatchObject({
      conversations: [{ message_count: 0 }],
    });
    expect(after.data).toMatchObject({
      conversations: [{ message_count: 2 }],
    });
  });

  it("serves the new content after a version is deleted and written again at the same collectedAt", async () => {
    const raw = createMemoryDataStorage();
    const at = "2026-10-01T00:00:01.000Z";
    await store(raw, "chatgpt.conversations", at, {
      records: [{ ...conversation, message_count_on_current_branch: 0 }],
    });
    const served = withLegacyProjection(raw);
    await served.readEnvelope("chatgpt.conversations", at);
    await raw.deleteVersion("chatgpt.conversations", at);
    await store(raw, "chatgpt.conversations", at, {
      records: [
        {
          ...conversation,
          title: "Replaced",
          message_count_on_current_branch: 0,
        },
      ],
    });

    const { data } = await served.readEnvelope("chatgpt.conversations", at);

    expect(data).toMatchObject({ conversations: [{ title: "Replaced" }] });
  });

  it("serves chatgpt.conversations newest update first, not in id order", async () => {
    const raw = createMemoryDataStorage();
    const older = {
      ...conversation,
      id: "conv-a",
      update_time: "2026-09-01T10:05:00Z",
      current_node: null,
      message_count_on_current_branch: 0,
    };
    const newer = {
      ...older,
      id: "conv-b",
      update_time: "2026-09-02T10:05:00Z",
    };
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:00.000Z", {
      records: [],
    });
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [older, newer],
    });

    const { data } = await withLegacyProjection(raw).readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(
      (data as { conversations: { id: string }[] }).conversations.map(
        (c) => c.id,
      ),
    ).toEqual(["conv-b", "conv-a"]);
  });

  it("parses each legacy version once to classify it, even when reads alternate between scopes", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      conversations: [],
      total: 0,
    });
    await store(raw, "chatgpt.memories", "2026-10-01T00:00:01.000Z", {
      memories: [],
      total: 0,
    });
    // Raw bytes, as a file-backed port returns them without parsing.
    raw.readEnvelopeBytes = async () => new Uint8Array();
    const readEnvelope = vi.spyOn(raw, "readEnvelope");
    const served = withLegacyProjection(raw);

    for (let round = 0; round < 3; round += 1) {
      for (const scope of ["chatgpt.conversations", "chatgpt.memories"]) {
        await served.readEnvelopeBytes!(scope, "2026-10-01T00:00:01.000Z");
      }
    }

    expect(readEnvelope.mock.calls.map(([scope]) => scope).sort()).toEqual([
      "chatgpt.conversations",
      "chatgpt.memories",
    ]);
  });

  it("reads a legacy envelope once when it serves it", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      conversations: [],
      total: 0,
    });
    const readEnvelope = vi.spyOn(raw, "readEnvelope");

    await withLegacyProjection(raw).readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(readEnvelope).toHaveBeenCalledOnce();
  });

  it("serves a body of tagged {stream, data} rows as stored", async () => {
    const raw = createMemoryDataStorage();
    await store(raw, "chatgpt.messages", "2026-10-01T00:00:00.000Z", {
      records: messages,
    });
    const body = {
      records: [{ stream: "conversations", data: conversation }],
    };
    await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", body);

    const { data } = await withLegacyProjection(raw).readEnvelope(
      "chatgpt.conversations",
      "2026-10-01T00:00:01.000Z",
    );

    expect(data).toEqual(body);
  });

  it.each([
    ["after", "2026-10-01T00:00:02.000Z", "2026-10-02T00:00:02.000Z"],
    ["before", "2026-10-01T00:00:00.000Z", "2026-10-02T00:00:00.000Z"],
  ])(
    "joins a historical version with the messages its run wrote %s it",
    async (_order, run1Messages, run2Messages) => {
      const raw = createMemoryDataStorage();
      await store(raw, "chatgpt.messages", run1Messages, { records: messages });
      await store(raw, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
        records: [conversation],
      });
      await store(raw, "chatgpt.messages", run2Messages, {
        records: [messages[1]],
      });
      await store(raw, "chatgpt.conversations", "2026-10-02T00:00:01.000Z", {
        records: [
          {
            ...conversation,
            current_node: "m1",
            message_count_on_current_branch: 1,
          },
        ],
      });
      const served = withLegacyProjection(raw);
      const thread = async (collectedAt: string) =>
        (
          (await served.readEnvelope("chatgpt.conversations", collectedAt))
            .data as { conversations: { messages: { id: string }[] }[] }
        ).conversations[0].messages.map((m) => m.id);

      expect(await thread("2026-10-01T00:00:01.000Z")).toEqual(["m1", "m2"]);
      expect(await thread("2026-10-02T00:00:01.000Z")).toEqual(["m1"]);
    },
  );

  it("is idempotent", () => {
    const served = withLegacyProjection(createMemoryDataStorage());
    expect(withLegacyProjection(served)).toBe(served);
  });

  it("forwards writes and listings to the raw port", async () => {
    const raw = createMemoryDataStorage();
    const served = withLegacyProjection(raw);
    await store(served, "chatgpt.conversations", "2026-10-01T00:00:01.000Z", {
      records: [],
    });

    expect(raw.entries.map((entry) => entry.scope)).toEqual([
      "chatgpt.conversations",
    ]);
    expect(served.listScopes({}).total).toBe(1);
    expect(served.kind).toBe("custom");
  });
});

describe("withLegacyProjection parity goldens", () => {
  // Same clock the legacy connector ran under (see the goldens' provenance),
  // so the projection time equals legacy's stamped fetched_at.
  const COLLECTED_AT = "2026-10-01T00:00:00.000Z";

  it.each([
    "chatgpt.conversations",
    "chatgpt.memories",
    "claude.conversations",
    "claude.projects",
  ])(
    "serves %s from its stored PDPP streams as the legacy connector's body, except the reviewed differences",
    async (scope) => {
      const golden = JSON.parse(
        readFileSync(
          new URL(
            `../legacy-projection/__fixtures__/parity/${scope}.json`,
            import.meta.url,
          ),
          "utf8",
        ),
      ) as {
        streams: Record<string, Record<string, unknown>[]>;
        legacyBody: Record<string, unknown>;
        reviewedDifferences: { path: string }[];
      };
      const source = scope.split(".")[0];
      const raw = createMemoryDataStorage();
      for (const [stream, rows] of Object.entries(golden.streams)) {
        await store(raw, `${source}.${stream}`, COLLECTED_AT, {
          records: rows,
        });
      }

      const { data } = await withLegacyProjection(raw).readEnvelope(
        scope,
        COLLECTED_AT,
      );

      expect(
        diffBodies(golden.legacyBody, data).map(({ path }) => path),
      ).toEqual(golden.reviewedDifferences.map(({ path }) => path));
    },
  );
});
