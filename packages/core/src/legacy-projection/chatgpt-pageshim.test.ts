// chatgpt.conversations from ChatGPT 0.2.0 and PageShim 0.3.1 records.
// Every value here is synthetic.
import { readdirSync, readFileSync } from "node:fs";
import Ajv from "ajv";
import { describe, expect, it } from "vitest";
import chatgpt031Declaration from "./declarations/chatgpt-0.3.1.collection-profile.json";
import {
  everyItemRowDropped,
  LEGACY_SCOPE_BINDINGS,
  legacyProjectionFor,
  legacyScopesProjectedOnRead,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import { LEGACY_SCHEMA_VERSIONS } from "./legacy-schema-versions.js";
import chatgptConversationsSchema from "./legacy-schemas/chatgpt.conversations.json";
import type { PdppRecord, ProjectionResult } from "./types.js";

const SCOPE = "chatgpt.conversations";
const NOW = "2026-10-21T00:00:00.000Z";

type Version = "0.2.0" | "0.3.1";

/**
 * One message row as each version stores it. 0.2.0 names a message by its
 * bare node id. 0.3.1 names it `<conversation>:<node>`, adds `node_id`, and
 * links `parent_id` to the parent's record id.
 */
function message(
  version: Version,
  conversation: string,
  node: string,
  parent: string | null,
  fields: Record<string, unknown> = {},
): PdppRecord {
  const record = (n: string) =>
    version === "0.3.1" ? `${conversation}:${n}` : n;
  return {
    stream: "messages",
    data: {
      id: record(node),
      ...(version === "0.3.1" ? { node_id: node } : {}),
      conversation_id: conversation,
      parent_id: parent === null ? null : record(parent),
      children_ids: [],
      role: "user",
      content: `Synthetic ${node}`,
      content_type: "text",
      model_slug: null,
      create_time: null,
      on_current_branch: true,
      ...fields,
    },
  };
}

function conversation(
  id: string,
  currentNode: string,
  count: number,
  fields: Record<string, unknown> = {},
): PdppRecord {
  return {
    stream: "conversations",
    data: {
      id,
      title: `Synthetic ${id}`,
      create_time: "2026-01-01T00:00:00.000Z",
      update_time: "2026-01-02T00:00:00.000Z",
      current_node: currentNode,
      message_count_on_current_branch: count,
      ...fields,
    },
  };
}

/**
 * A thread whose current branch is n1 → n2 → n3, under a synthetic root n0
 * that carries no message, plus an abandoned regeneration n2b.
 */
function thread(version: Version, id = "conv-a"): PdppRecord[] {
  return [
    conversation(id, "n3", 3),
    message(version, id, "n1", "n0", {
      content: "Synthetic question",
      create_time: "2026-01-01T00:00:01.000Z",
    }),
    message(version, id, "n2", "n1", {
      role: "assistant",
      content: "Synthetic answer",
      model_slug: "synthetic-model",
    }),
    message(version, id, "n3", "n2", {
      role: "tool",
      content: "synthetic tool output",
      content_type: "code",
    }),
    message(version, id, "n2b", "n1", {
      role: "assistant",
      content: "Synthetic discarded answer",
      on_current_branch: false,
    }),
  ];
}

/** What Desktop writes for `thread()`: legacy message ids are node ids. */
const DESKTOP_THREAD = {
  id: "conv-a",
  title: "Synthetic conv-a",
  create_time: "2026-01-01T00:00:00.000Z",
  update_time: "2026-01-02T00:00:00.000Z",
  message_count: 2,
  messages: [
    {
      id: "n1",
      role: "user",
      content: "Synthetic question",
      content_type: "text",
      create_time: "2026-01-01T00:00:01.000Z",
      model: null,
    },
    {
      id: "n2",
      role: "assistant",
      content: "Synthetic answer",
      content_type: "text",
      create_time: null,
      model: "synthetic-model",
    },
  ],
  fetched_at: NOW,
};

const project = (records: PdppRecord[]): ProjectionResult =>
  projectPdppRecordsToLegacyPayload(SCOPE, records, {
    fetchedStreams: ["conversations", "messages"],
    now: NOW,
  });

const validate = new Ajv({ allErrors: true, strict: false }).compile(
  chatgptConversationsSchema.schema as Record<string, unknown>,
);

/** The source text of every legacy message in a projected payload. */
function contents(result: ProjectionResult): string[] {
  if (!result.ok) return [];
  return (
    result.payload.conversations as { messages: { content: string }[] }[]
  ).flatMap((c) => c.messages.map((m) => m.content));
}

describe("chatgpt.conversations from ChatGPT 0.2.0 and PageShim 0.3.1", () => {
  it.each<Version>(["0.2.0", "0.3.1"])(
    "projects a %s thread into Desktop's body, threaded by node id",
    (version) => {
      const result = project(thread(version));
      expect(result).toEqual({
        ok: true,
        payload: { conversations: [DESKTOP_THREAD], total: 1 },
      });
      if (result.ok) expect(validate(result.payload)).toBe(true);
    },
  );

  it("projects the 0.2.0 parity golden to the same body whether stored as 0.2.0 or 0.3.1", () => {
    const golden = JSON.parse(
      readFileSync(
        new URL(
          "./__fixtures__/parity/chatgpt.conversations.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as { streams: Record<string, Record<string, unknown>[]> };
    const asStored = Object.entries(golden.streams).flatMap(([stream, rows]) =>
      rows.map((data) => ({ stream, data })),
    );
    // The same rows as PageShim 0.3.1 names them.
    const as031 = asStored.map((record) => {
      if (record.stream !== "messages") return record;
      const {
        id,
        conversation_id: c,
        parent_id: parent,
      } = record.data as {
        id: string;
        conversation_id: string;
        parent_id: string | null;
      };
      return {
        ...record,
        data: {
          ...record.data,
          id: `${c}:${id}`,
          node_id: id,
          parent_id: parent === null ? null : `${c}:${parent}`,
        },
      };
    });
    const before = project(asStored);
    expect(before.ok).toBe(true);
    expect(project(as031)).toEqual(before);
  });

  it("takes node_id as the node, whatever the record id holds", () => {
    // node_id is the declared node; the record id is only a storage key.
    const records = thread("0.3.1").map((record) =>
      record.stream === "messages"
        ? {
            ...record,
            data: {
              ...record.data,
              id: `record-${String(record.data.node_id)}`,
              parent_id:
                record.data.parent_id === null
                  ? null
                  : `record-${String(record.data.parent_id).split(":")[1]}`,
            },
          }
        : record,
    );
    // A parent link names a record; it is resolved to that record's node.
    expect(project(records)).toEqual(project(thread("0.3.1")));
  });

  it("counts a node stored by a 0.2.0 run and again by a 0.3.1 run once, preferring 0.3.1", () => {
    const stale = thread("0.2.0").filter((r) => r.stream === "messages");
    const result = project([
      ...stale.map((r) =>
        r.data.id === "n2"
          ? { ...r, data: { ...r.data, content: "Stale answer" } }
          : r,
      ),
      ...thread("0.3.1"),
    ]);
    expect(result).toEqual({
      ok: true,
      payload: { conversations: [DESKTOP_THREAD], total: 1 },
    });
  });

  describe("a thread whose current branch arrived incomplete", () => {
    // Its branch should hold two messages, but only the tip arrived.
    const broken = [
      conversation("conv-broken", "n2", 2),
      message("0.3.1", "conv-broken", "n2", "n1"),
    ];
    // Its count matches, but the tip's parent chain does not reach n1.
    const disconnected = [
      conversation("conv-disconnected", "n2", 2),
      message("0.3.1", "conv-disconnected", "n1", null),
      message("0.3.1", "conv-disconnected", "n2", "missing"),
    ];

    it("costs only that conversation, and is counted", () => {
      const result = project([...thread("0.3.1"), ...broken, ...disconnected]);
      expect(result).toEqual({
        ok: true,
        payload: { conversations: [DESKTOP_THREAD], total: 1 },
        diagnostics: [
          {
            kind: "records_dropped",
            scope: SCOPE,
            stream: "conversations",
            count: 2,
            reasons: [
              "Current branch message count does not match conversation",
              "Current branch message chain is incomplete",
            ],
          },
        ],
      });
    });

    it("accounts for every conversation when none maps, so a reader fails the scope", () => {
      const result = project([...broken, ...disconnected]);
      expect(result).toEqual({
        ok: true,
        payload: { conversations: [], total: 0 },
        diagnostics: [
          {
            kind: "records_dropped",
            scope: SCOPE,
            stream: "conversations",
            count: 2,
            reasons: [
              "Current branch message count does not match conversation",
              "Current branch message chain is incomplete",
            ],
          },
        ],
      });
      // Both Personal Server read paths reject this as unavailable.
      expect(
        everyItemRowDropped(
          "conversations",
          2,
          result.ok ? result.diagnostics : [],
        ),
      ).toEqual({
        dropped: 2,
        reasons: [
          "Current branch message count does not match conversation",
          "Current branch message chain is incomplete",
        ],
      });
      expect(
        everyItemRowDropped(
          "conversations",
          3,
          result.ok ? result.diagnostics : [],
        ),
      ).toBeNull();
    });

    it("still serves an account with no conversations as empty", () => {
      expect(project([])).toEqual({
        ok: true,
        payload: { conversations: [], total: 0 },
      });
    });
  });

  describe("a message whose text PageShim could not collect", () => {
    /** thread() with the answer (n2) replaced by `change`. */
    const withAnswer = (
      change: (data: Record<string, unknown>) => Record<string, unknown>,
    ) =>
      thread("0.3.1").map((r) =>
        r.data.node_id === "n2" ? { ...r, data: change(r.data) } : r,
      );
    const withoutContent = ({
      content: _content,
      ...rest
    }: Record<string, unknown>) => rest;
    const withoutText = withAnswer(withoutContent);
    const inUnreadBlob = withAnswer((data) => ({
      ...data,
      content: null,
      blob_ref: { blob_id: "blob-synthetic", mime_type: "application/json" },
    }));

    it.each([
      {
        case: "no content and no blob_ref",
        records: withoutText,
        reason: "Message text was omitted by the source",
      },
      {
        case: "a blob_ref this read did not resolve",
        records: inUnreadBlob,
        reason: "Message text is in a blob that was not resolved",
      },
    ])(
      "leaves it out of its thread, keeps the thread, and counts it ($case)",
      ({ records, reason }) => {
        const result = project(records);
        expect(result).toEqual({
          ok: true,
          payload: {
            conversations: [
              {
                ...DESKTOP_THREAD,
                message_count: 1,
                messages: [DESKTOP_THREAD.messages[0]],
              },
            ],
            total: 1,
          },
          diagnostics: [
            {
              kind: "records_dropped",
              scope: SCOPE,
              stream: "messages",
              count: 1,
              reasons: [reason],
            },
          ],
        });
        // No placeholder stands in for the text.
        expect(contents(result)).toEqual(["Synthetic question"]);
        if (result.ok) expect(validate(result.payload)).toBe(true);
      },
    );

    it("does not count a message legacy never carried", () => {
      // A tool message is not in Desktop's thread whether or not it has text.
      const result = project(
        thread("0.3.1").map((r) =>
          r.data.node_id === "n3" ? { ...r, data: withoutContent(r.data) } : r,
        ),
      );
      expect(result).toEqual({
        ok: true,
        payload: { conversations: [DESKTOP_THREAD], total: 1 },
      });
    });
  });

  it("pins the ChatGPT versions it reads, and reads only fields 0.3.1 declares", () => {
    const binding = LEGACY_SCOPE_BINDINGS.get(SCOPE)!;
    expect(chatgpt031Declaration.version).toBe("0.3.1");
    expect(binding.provenance.map((p) => p.path.split("#")[0])).toEqual([
      "declarations/chatgpt-0.3.1.collection-profile.json",
      "declarations/chatgpt-0.2.0.collection-profile.json",
    ]);
    const messages = chatgpt031Declaration.streams.find(
      (s) => s.name === "messages",
    )!;
    expect(Object.keys(messages.schema.properties)).toEqual(
      expect.arrayContaining(binding.fieldsRead.messages!),
    );
    expect(binding.fieldsRead.messages).toContain("node_id");
  });
});

describe("which scopes the Personal Server projects on read", () => {
  it("lists every bound legacy scope, ChatGPT conversations among them", () => {
    const scopes = legacyScopesProjectedOnRead();
    expect(scopes).toEqual([...LEGACY_SCOPE_BINDINGS.keys()].sort());
    expect(scopes).toContain(SCOPE);
  });

  it("names the PDPP streams, the vault scopes they are stored under, and the body version", () => {
    expect(legacyProjectionFor(SCOPE)).toEqual({
      scope: SCOPE,
      pdppSource: "https://registry.pdpp.dev/connectors/chatgpt",
      streams: ["conversations", "messages"],
      storedScopes: ["chatgpt.conversations", "chatgpt.messages"],
      legacySchemaVersion: "2.0.0",
    });
  });

  it("follows a reviewed alternate profile", () => {
    expect(
      legacyProjectionFor("github.profile", { profileKey: "github-browser" }),
    ).toMatchObject({
      pdppSource: "https://registry.pdpp.dev/connectors/github-browser",
    });
  });

  it.each([
    { scope: "chatgpt.messages", why: "a PDPP stream with no legacy body" },
    { scope: "unknown.scope", why: "an unbound scope" },
    { scope: "seedbot.contacts", why: "test debris" },
  ])("is null for $why", ({ scope }) => {
    expect(legacyProjectionFor(scope)).toBeNull();
  });

  it("is null for a profile that cannot project the scope", () => {
    expect(
      legacyProjectionFor(SCOPE, { profileKey: "github-browser" }),
    ).toBeNull();
  });

  it("states the version each vendored legacy schema file declares", () => {
    const dir = new URL("./legacy-schemas/", import.meta.url);
    const files = Object.fromEntries(
      readdirSync(dir).map((name) => [
        name,
        (
          JSON.parse(readFileSync(new URL(name, dir), "utf8")) as {
            version: string;
          }
        ).version,
      ]),
    );
    expect(LEGACY_SCHEMA_VERSIONS).toEqual(files);
    for (const [scope, binding] of LEGACY_SCOPE_BINDINGS) {
      expect(legacyProjectionFor(scope)?.legacySchemaVersion, scope).toBe(
        files[binding.legacySchemaPath],
      );
    }
  });
});
