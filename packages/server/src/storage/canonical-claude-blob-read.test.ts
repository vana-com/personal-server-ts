import Database from "better-sqlite3";
import Ajv from "ajv";
import { readFile } from "node:fs/promises";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readCanonicalLegacyScope } from "@opendatalabs/personal-server-ts-core/storage/canonical-legacy-projection";
import { createSqliteRecordStore } from "./pdpp-records-sqlite-store.js";

const selection = {
  instance: "claude-test",
  sourceId: "https://registry.pdpp.dev/sources/anthropic",
  method: "anthropic",
};
const collected = "2026-09-01T12:00:00.000Z";
const profile = {
  id: "org",
  organization_id: "org",
  full_name: "Synthetic reader",
  plan: null,
  name_source: "users_json",
  metadata_status: "valid",
};

describe("canonical Claude source blobs", () => {
  let db: InstanceType<typeof Database>;
  let store: ReturnType<typeof createSqliteRecordStore>;
  beforeEach(() => {
    db = new Database(":memory:");
    store = createSqliteRecordStore(db);
    store.registerConnection({ ...selection, label: "Synthetic Claude" });
  });
  afterEach(() => store.close());

  function replace(stream: string, rows: Record<string, unknown>[]) {
    expect(
      store.replaceStream({
        ...selection,
        generation: 1,
        stream,
        primaryKey: ["id"],
        emittedAt: collected,
        sourceCollectedAt: collected,
        envelopes: rows.map((data) => ({
          instance: selection.instance,
          stream,
          key: String(data.id),
          data,
          emitted_at: collected,
        })),
      }).applied,
    ).toBe(true);
  }
  function blob(stream: string, payload: Record<string, unknown>) {
    const bytes = new TextEncoder().encode(
      JSON.stringify({
        format: "anthropic-source-record-v1",
        stream,
        record_key: payload.uuid,
        payload,
      }),
    );
    const meta = store.storeBlobBytesForInstance({
      ...selection,
      generation: 1,
      bytes,
      mimeType: "application/json",
    });
    return {
      id: payload.uuid,
      blob_ref: {
        blob_id: meta.blobId,
        sha256: meta.sha256,
        size_bytes: meta.sizeBytes,
        mime_type: meta.mimeType,
      },
    };
  }

  it("expands a verified project and documents without writing another stored body", async () => {
    const payload = {
      uuid: "project-1",
      name: "Research",
      description: "Synthetic project",
      created_at: collected,
      updated_at: collected,
      docs: [
        {
          uuid: "doc-1",
          filename: "notes.txt",
          content: "Research notes",
          created_at: collected,
        },
      ],
      ignored_secret_field: "excluded",
    };
    replace("account_profile", [profile]);
    replace("projects", [blob("projects", payload)]);
    // Explicit TEST P7 completion with the same nonempty source documents.
    replace("project_documents", [
      {
        id: "doc-1",
        project_id: "project-1",
        filename: "notes.txt",
        content: "Research notes",
        create_time: collected,
        update_time: null,
      },
    ]);
    const before = db.prepare("SELECT total_changes() AS n").get();
    const result = await readCanonicalLegacyScope({
      store,
      selection,
      scope: "claude.projects",
      profileBy: "method",
    });
    if (!result.ok) throw new Error(JSON.stringify(result));
    expect(result).toMatchObject({
      ok: true,
      complete: true,
      envelope: {
        version: "1.0",
        scope: "claude.projects",
        collectedAt: collected,
        data: {
          profile: { name: "Synthetic reader", plan: null },
          organizationId: "org",
          total: 1,
          source: "official-export",
          projects: [
            {
              id: "project-1",
              title: "Research",
              href: "/project/project-1",
              label: "Project, Research",
              archived: false,
              detail: {
                uuid: "project-1",
                name: "Research",
                docs: [
                  {
                    uuid: "doc-1",
                    filename: "notes.txt",
                    content: "Research notes",
                    created_at: collected,
                    updated_at: null,
                  },
                ],
              },
            },
          ],
        },
      },
    });
    if (result.ok)
      expect(
        (result.envelope.data.projects as { detail: unknown }[])[0]?.detail,
      ).not.toHaveProperty("ignored_secret_field");
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toEqual(result);
    expect(db.prepare("SELECT total_changes() AS n").get()).toEqual(before);
  });
  it("serves ordered nonempty conversation detail and checks matching inline children", async () => {
    const earlier = "2026-09-01T11:00:00.000Z";
    const payload = {
      uuid: "chat-1",
      name: "Export chat",
      created_at: earlier,
      chat_messages: [
        {
          uuid: "later",
          sender: "assistant",
          parent_message_uuid: "earlier",
          created_at: collected,
          content: [{ text: "Reply" }],
          attachments: [],
        },
        {
          uuid: "earlier",
          sender: "human",
          parent_message_uuid: null,
          created_at: earlier,
          text: "Question",
          attachments: [],
        },
      ],
    };
    replace("account_profile", [profile]);
    replace("conversations", [blob("conversations", payload)]);
    // Nonempty append-only inline detail; no empty append-only P7 workaround.
    const put = store.ingestBatch(
      [
        {
          instance: selection.instance,
          stream: "messages",
          key: "earlier",
          emitted_at: collected,
          data: {
            id: "earlier",
            conversation_id: "chat-1",
            role: "human",
            parent_id: null,
            content: "Question",
            create_time: earlier,
            update_time: null,
            attachments: [],
          },
        },
        {
          instance: selection.instance,
          stream: "messages",
          key: "later",
          emitted_at: collected,
          data: {
            id: "later",
            conversation_id: "chat-1",
            role: "assistant",
            parent_id: "earlier",
            content: "Reply",
            create_time: collected,
            update_time: null,
            attachments: [],
          },
        },
      ],
      () => "append_only",
      () => ["id"],
      { method: selection.method, generation: 1 },
    );
    expect(put.rejected).toEqual([]);
    const result = await readCanonicalLegacyScope({
      store,
      selection,
      scope: "claude.conversations",
      profileBy: "method",
    });
    expect(result).toMatchObject({
      ok: true,
      envelope: {
        data: {
          total: 1,
          messageTotal: 2,
          conversations: [
            {
              id: "chat-1",
              title: "Export chat",
              messageCount: 2,
              messages: [
                { id: "earlier", content: "Question" },
                { id: "later", content: "Reply", parentId: "earlier" },
              ],
            },
          ],
        },
      },
    });
    if (!result.ok) throw new Error(JSON.stringify(result));
    const schema = JSON.parse(
      await readFile(
        new URL(
          "../../../core/src/legacy-projection/legacy-schemas/claude.conversations.json",
          import.meta.url,
        ),
        "utf8",
      ),
    );
    expect(
      new Ajv({ allErrors: true }).validate(
        schema.schema,
        result.envelope.data,
      ),
    ).toBe(true);
    expect(
      store.listRecords("messages", {
        instanceIds: [selection.instance],
        limit: 100,
        order: "asc",
      }).data,
    ).toHaveLength(2);
  });

  it("keeps absent stream completion as a refusal even when its parent blob has an empty list", async () => {
    replace("account_profile", [profile]);
    replace("projects", [
      blob("projects", { uuid: "p", name: "Project", docs: [] }),
    ]);
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "stream_completion_unknown",
      streams: ["project_documents"],
    });
  });

  it("refuses physically corrupt stored bytes and never assembles an empty project", async () => {
    replace("account_profile", [profile]);
    const parent = blob("projects", { uuid: "p", name: "Project", docs: [] });
    replace("projects", [parent]);
    replace("project_documents", []);
    db.prepare("UPDATE pdpp_blob_bytes SET bytes=? WHERE blob_id=?").run(
      Buffer.from("corrupt"),
      parent.blob_ref.blob_id,
    );
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "blob_missing_or_corrupt",
    });
  });

  it("checks the selected connection and method before any blob read", async () => {
    replace("account_profile", [profile]);
    replace("projects", [
      blob("projects", { uuid: "p", name: "Project", docs: [] }),
    ]);
    replace("project_documents", []);
    const get = store.getBlobBytes;
    let reads = 0;
    store.getBlobBytes = (id) => {
      reads++;
      return get(id);
    };
    expect(
      await readCanonicalLegacyScope({
        store,
        selection: { ...selection, method: "wrong" },
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({ ok: false, reason: "scope_source_mismatch" });
    expect(
      await readCanonicalLegacyScope({
        store,
        selection: { ...selection, instance: "foreign" },
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({ ok: false, reason: "connection_unavailable" });
    expect(reads).toBe(0);
  });
  it("refuses an explicitly empty child receipt that contradicts embedded documents", async () => {
    replace("account_profile", [profile]);
    replace("projects", [
      blob("projects", {
        uuid: "p",
        name: "Project",
        docs: [{ uuid: "d", filename: "file", content: "body" }],
      }),
    ]);
    replace("project_documents", []);
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "source_child_missing_inline",
    });
  });

  it("uses separately authoritative documents for project metadata that omits a docs list", async () => {
    replace("account_profile", [profile]);
    replace("projects", [
      blob("projects", { uuid: "p", name: "Metadata only" }),
    ]);
    replace("project_documents", [
      {
        id: "d",
        project_id: "p",
        filename: "file",
        content: "Separate document",
        create_time: null,
        update_time: null,
      },
    ]);
    const result = await readCanonicalLegacyScope({
      store,
      selection,
      scope: "claude.projects",
      profileBy: "method",
    });
    expect(result).toMatchObject({
      ok: true,
      envelope: {
        data: {
          projects: [
            {
              title: "Metadata only",
              detail: { docs: [{ uuid: "d", content: "Separate document" }] },
            },
          ],
        },
      },
    });
    if (result.ok)
      expect(
        (result.envelope.data.projects as { detail: unknown }[])[0]?.detail,
      ).not.toHaveProperty("raw_docs");
  });

  it("refuses extra inline documents when the source explicitly says empty", async () => {
    replace("account_profile", [profile]);
    replace("projects", [
      blob("projects", { uuid: "p", name: "Project", docs: [] }),
    ]);
    replace("project_documents", [
      {
        id: "extra",
        project_id: "p",
        filename: "file",
        content: "Unexpected",
        create_time: null,
        update_time: null,
      },
    ]);
    expect(
      await readCanonicalLegacyScope({
        store,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "inline_child_absent_from_blob",
    });
  });
  it("refuses known missing completion before reading any selected source blob bytes", async () => {
    const parents = Array.from({ length: 4 }, (_, index) =>
      blob("projects", {
        uuid: `bulk-${index}`,
        name: "Tiny metadata",
        docs: [],
        ignored_large_raw_field: "x".repeat(1024 * 1024),
      }),
    );
    replace("projects", parents);
    let byteCalls = 0;
    const readStore = {
      ...store,
      getBlobBytes(id: string) {
        byteCalls++;
        return store.getBlobBytes(id);
      },
    };
    expect(
      await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "stream_completion_unknown",
      streams: ["account_profile", "project_documents"],
    });
    expect(byteCalls).toBe(0);
  });

  it("refuses a read above its aggregate blob budget before copying any body", async () => {
    replace("account_profile", [profile]);
    const parents = Array.from({ length: 4 }, (_, index) =>
      blob("projects", {
        uuid: `bulk-${index}`,
        name: "Tiny metadata",
        docs: [],
        ignored_large_raw_field: "x".repeat(1024 * 1024),
      }),
    );
    replace("projects", parents);
    replace("project_documents", []);
    const total = parents.reduce(
      (sum, parent) => sum + parent.blob_ref.size_bytes,
      0,
    );
    let byteCalls = 0;
    const readStore = {
      ...store,
      getBlobBytes(id: string) {
        byteCalls++;
        return store.getBlobBytes(id);
      },
    };
    const input = {
      store: readStore,
      selection,
      scope: "claude.projects",
      profileBy: "method" as const,
      blobByteBudget: 1,
    };
    expect(await readCanonicalLegacyScope(input)).toMatchObject({
      ok: false,
      reason: "blob_read_budget_exceeded",
      requiredBytes: total,
      maxBytes: 1,
    });
    expect(byteCalls).toBe(0);
  });

  it.each([
    [
      "nonempty",
      [
        {
          uuid: "d",
          filename: "file",
          content: "contradictory stored raw document",
        },
      ],
    ],
    ["null", null],
    ["object", {}],
    ["scalar", "malformed"],
    ["malformed array", [null]],
  ])(
    "refuses %s raw_docs summary when source project metadata omitted docs",
    async (_label, raw_docs) => {
      replace("account_profile", [profile]);
      replace("projects", [
        { ...blob("projects", { uuid: "p", name: "Metadata only" }), raw_docs },
      ]);
      replace("project_documents", [
        {
          id: "d",
          project_id: "p",
          filename: "file",
          content: "Separate canonical document",
          create_time: null,
          update_time: null,
        },
      ]);
      expect(
        await readCanonicalLegacyScope({
          store,
          selection,
          scope: "claude.projects",
          profileBy: "method",
        }),
      ).toMatchObject({
        ok: false,
        reason: "blob_backed_record_invalid",
        detail: "parent_blob_conflict",
      });
    },
  );
  it.each([-1, 0, 1])(
    "checks the exact aggregate boundary with budget offset %s",
    async (offset) => {
      replace("account_profile", [profile]);
      const parents = [
        blob("projects", { uuid: "a", name: "A", docs: [] }),
        blob("projects", { uuid: "b", name: "B", docs: [] }),
      ];
      replace("projects", parents);
      replace("project_documents", []);
      const total = parents.reduce(
        (sum, parent) => sum + parent.blob_ref.size_bytes,
        0,
      );
      const before = db.prepare("SELECT total_changes() AS n").get();
      let byteCalls = 0;
      const readStore = {
        ...store,
        getBlobBytes(id: string) {
          byteCalls++;
          return store.getBlobBytes(id);
        },
      };
      const result = await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
        blobByteBudget: total + offset,
      });
      if (offset < 0) {
        expect(result).toEqual({
          ok: false,
          status: "unavailable",
          reason: "blob_read_budget_exceeded",
          requiredBytes: total,
          maxBytes: total - 1,
        });
        expect(byteCalls).toBe(0);
      } else {
        expect(result).toMatchObject({
          ok: true,
          envelope: { data: { total: 2 } },
        });
        expect(byteCalls).toBe(2);
      }
      expect(db.prepare("SELECT total_changes() AS n").get()).toEqual(before);
    },
  );

  it("counts duplicate blob references once without accepting a false parent identity", async () => {
    replace("account_profile", [profile]);
    const parent = blob("projects", { uuid: "p", name: "Project", docs: [] });
    replace("projects", [parent, { ...parent, id: "other-parent" }]);
    replace("project_documents", []);
    let byteCalls = 0,
      metadataCalls = 0;
    const readStore = {
      ...store,
      getBlobBytes(id: string) {
        byteCalls++;
        return store.getBlobBytes(id);
      },
      getBlobMeta(id: string) {
        metadataCalls++;
        return store.getBlobMeta(id);
      },
    };
    expect(
      await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
        blobByteBudget: parent.blob_ref.size_bytes,
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "source_envelope_mismatch",
    });
    expect(metadataCalls).toBe(1);
    expect(byteCalls).toBe(1);
  });

  it("refuses malformed or missing metadata before loading any otherwise-valid peer blob", async () => {
    replace("account_profile", [profile]);
    const good = blob("projects", { uuid: "a", name: "A", docs: [] });
    const bad = blob("projects", { uuid: "b", name: "B", docs: [] });
    replace("projects", [good, bad]);
    replace("project_documents", []);
    db.prepare(
      "UPDATE pdpp_blobs SET mime_type='text/plain' WHERE blob_id=?",
    ).run(bad.blob_ref.blob_id);
    let byteCalls = 0;
    const readStore = {
      ...store,
      getBlobBytes(id: string) {
        byteCalls++;
        return store.getBlobBytes(id);
      },
    };
    expect(
      await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "blob_metadata_mismatch",
    });
    expect(byteCalls).toBe(0);
    db.transaction(() => {
      db.prepare("DELETE FROM pdpp_blob_claims WHERE blob_id=?").run(
        bad.blob_ref.blob_id,
      );
      db.prepare("DELETE FROM pdpp_blob_bytes WHERE blob_id=?").run(
        bad.blob_ref.blob_id,
      );
      db.prepare("DELETE FROM pdpp_blobs WHERE blob_id=?").run(
        bad.blob_ref.blob_id,
      );
    })();
    expect(
      await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "blob_missing_or_corrupt",
    });
    expect(byteCalls).toBe(0);
  });

  it("accepts the legitimate empty omitted-docs summary without adding raw_docs to app data", async () => {
    replace("account_profile", [profile]);
    replace("projects", [
      {
        ...blob("projects", { uuid: "p", name: "Metadata only" }),
        raw_docs: [],
      },
    ]);
    replace("project_documents", [
      {
        id: "d",
        project_id: "p",
        filename: "file",
        content: "Separate document",
        create_time: null,
        update_time: null,
      },
    ]);
    const result = await readCanonicalLegacyScope({
      store,
      selection,
      scope: "claude.projects",
      profileBy: "method",
    });
    expect(result).toMatchObject({
      ok: true,
      envelope: {
        data: {
          projects: [{ detail: { docs: [{ content: "Separate document" }] } }],
        },
      },
    });
    if (result.ok)
      expect(
        (result.envelope.data.projects as { detail: unknown }[])[0]?.detail,
      ).not.toHaveProperty("raw_docs");
  });
  it("refuses invalid peer references and unsupported child blobs without loading a valid parent body", async () => {
    replace("account_profile", [profile]);
    const good = blob("projects", { uuid: "p", name: "P", docs: [] });
    replace("projects", [good, { id: "bad", blob_ref: null }]);
    replace("project_documents", []);
    let byteCalls = 0;
    const readStore = {
      ...store,
      getBlobBytes(id: string) {
        byteCalls++;
        return store.getBlobBytes(id);
      },
    };
    expect(
      await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_record_invalid",
      detail: "invalid_blob_reference",
    });
    expect(byteCalls).toBe(0);
    replace("projects", [good]);
    replace("project_documents", [
      { id: "d", project_id: "p", blob_ref: good.blob_ref },
    ]);
    expect(
      await readCanonicalLegacyScope({
        store: readStore,
        selection,
        scope: "claude.projects",
        profileBy: "method",
      }),
    ).toMatchObject({
      ok: false,
      reason: "blob_backed_records_unsupported",
      stream: "project_documents",
      recordCount: 1,
    });
    expect(byteCalls).toBe(0);
  });
});
