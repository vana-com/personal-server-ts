import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  readCanonicalLegacyScope,
  type CanonicalLegacyReadStore,
  type CanonicalStreamCompletion,
} from "./canonical-legacy-projection.js";
import {
  LEGACY_SCOPE_BINDINGS,
  legacyScopeToPdppSelection,
  type LegacyScopeBinding,
  projectPdppRecordsToLegacyPayload,
} from "../legacy-projection/index.js";
import {
  createLegacyScopeView,
  type LegacyScopeAuthority,
} from "./legacy-scope-view.js";
import { selectForTarget } from "../localdb/read-selection.js";
import type { PdppStoredRecord } from "./pdpp-records/types.js";

vi.mock("../legacy-projection/index.js", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  const project = actual.projectPdppRecordsToLegacyPayload as (
    ...args: unknown[]
  ) => unknown;
  return {
    ...actual,
    projectPdppRecordsToLegacyPayload: vi.fn((...args: unknown[]) =>
      project(...args),
    ),
  };
});

/**
 * What the projector is handed for iCloud Notes (`notes`, `folders` required;
 * `profile` optional), by the receipts the store holds. The real store's side
 * of this is in the server's canonical-legacy-projection tests; here the
 * projector's input is the thing under test.
 */
const NOW = "2026-09-10T07:00:00.000Z";
const selection = {
  instance: "test",
  sourceId: "https://registry.pdpp.dev/sources/icloud-notes",
  method: "icloud-notes",
};
const ROWS: Record<string, Record<string, unknown>[]> = {
  folders: [{ id: "f1", name: "Notes" }],
  notes: [
    {
      id: "n1",
      title: "Grocery list",
      snippet: "milk",
      folder_id: "f1",
      is_pinned: false,
      created_at: "2026-09-01T00:00:00Z",
      modified_at: "2026-09-02T00:00:00Z",
      has_attachments: false,
      text_content: "milk",
    },
  ],
  profile: [{ id: "p1", user_name: "Ada" }],
};

function storeWith(
  profile: Record<string, unknown>[],
  receiptStreams: string[],
): CanonicalLegacyReadStore {
  const rowsOf = (stream: string): PdppStoredRecord[] =>
    (stream === "profile" ? profile : (ROWS[stream] ?? [])).map((data) => ({
      stream,
      data,
      instance: "test",
      recordKey: data.id as string,
      version: 1,
      emittedAt: NOW,
      deleted: false,
    }));
  const binding = {
    ...selection,
    deletedAt: null,
    generation: 1,
    resetClock: 0,
  };
  const receipts: CanonicalStreamCompletion[] = receiptStreams.map(
    (stream) => ({
      instance: "test",
      stream,
      method: "icloud-notes",
      generation: 1,
      sourceCollectedAt: NOW,
      writeSeq: 1,
      liveCount: rowsOf(stream).length,
    }),
  );
  return {
    getInstanceBinding: () => binding,
    listConnections: () => [binding],
    readSnapshot: (read) => read(),
    listArrivalOrder: () => [],
    listStreamCompletions: () => receipts,
    listStreams: () =>
      ["folders", "notes", "profile"].map((stream) => ({
        stream,
        recordCount: rowsOf(stream).length,
        lastUpdated: NOW,
      })),
    listRecords: (stream) => ({
      data: rowsOf(stream),
      hasMore: false,
      nextCursor: null,
      horizon: "1",
    }),
  };
}

const projector = vi.mocked(projectPdppRecordsToLegacyPayload);
const handedToProjector = () => {
  const [, records, options] = projector.mock.calls[0]!;
  return {
    streams: [...new Set(records.map((record) => record.stream))].sort(),
    fetchedStreams: options.fetchedStreams,
  };
};

describe("the stored legacy read hands the projector the streams it serves", () => {
  beforeEach(() => {
    // Braces: a returned mock would be run by vitest as teardown.
    projector.mockClear();
  });

  it("names no optional stream that has rows but no receipt", async () => {
    const read = await readCanonicalLegacyScope({
      store: storeWith(ROWS.profile!, ["folders", "notes"]),
      scope: "icloud_notes.notes",
      selection,
      requireCompletionReceipts: true,
    });
    expect(read).toMatchObject({ ok: true });
    expect(handedToProjector()).toEqual({
      streams: ["folders", "notes"],
      fetchedStreams: ["notes", "folders"],
    });
  });

  it("names an optional stream whose receipt proves rows", async () => {
    await readCanonicalLegacyScope({
      store: storeWith(ROWS.profile!, ["folders", "notes", "profile"]),
      scope: "icloud_notes.notes",
      selection,
      requireCompletionReceipts: true,
    });
    expect(handedToProjector()).toEqual({
      streams: ["folders", "notes", "profile"],
      fetchedStreams: ["notes", "folders", "profile"],
    });
  });

  it("names an optional stream whose receipt proves it empty, with no rows handed over", async () => {
    await readCanonicalLegacyScope({
      store: storeWith([], ["folders", "notes", "profile"]),
      scope: "icloud_notes.notes",
      selection,
      requireCompletionReceipts: true,
    });
    expect(handedToProjector()).toEqual({
      streams: ["folders", "notes"],
      fetchedStreams: ["notes", "folders", "profile"],
    });
  });
});

describe("synthetic optional-stream contract", () => {
  const scope = "synthetic.items";
  const selected = {
    instance: "test",
    sourceId: "https://registry.pdpp.dev/sources/synthetic",
    method: "synthetic",
  };
  const project = vi.fn<LegacyScopeBinding["project"]>(() => ({
    ok: true,
    payload: { items: [] },
  }));
  const binding: LegacyScopeBinding = {
    scope,
    pdppSource: "https://registry.pdpp.dev/connectors/synthetic",
    pdppStreams: ["R", "O"],
    optionalStreams: ["O"],
    project,
    fieldsRead: {},
    primaryKey: {},
    legacySchemaPath: "",
    lossy: [],
    provenance: [],
  };
  function fixture(
    withOptionalReceipt: boolean,
    optionalBlob = true,
  ): CanonicalLegacyReadStore {
    const owner = {
      ...selected,
      deletedAt: null,
      generation: 1,
      resetClock: 0,
    };
    return {
      getInstanceBinding: () => owner,
      listConnections: () => [owner],
      readSnapshot: (read) => read(),
      listArrivalOrder: () => [],
      listStreams: () =>
        ["R", "O"].map((stream) => ({
          stream,
          recordCount: 1,
          lastUpdated: NOW,
        })),
      listStreamCompletions: () =>
        (withOptionalReceipt ? ["R", "O"] : ["R"]).map((stream) => ({
          stream,
          method: "synthetic",
          generation: 1,
          sourceCollectedAt: NOW,
          writeSeq: 1,
          liveCount: 1,
        })),
      listRecords: (stream) => ({
        data: [
          {
            stream,
            instance: "test",
            recordKey: "1",
            version: 1,
            emittedAt: NOW,
            deleted: false,
            data:
              stream === "O" && optionalBlob
                ? { id: "1", blob_ref: "sha256:unsupported" }
                : { id: "1" },
          },
        ],
        hasMore: false,
        nextCursor: null,
        horizon: "1",
      }),
      getBlobBytes: vi.fn(() => {
        throw new Error("optional blob body must not be read");
      }),
    };
  }
  async function withBinding(run: () => Promise<void>) {
    if (!(LEGACY_SCOPE_BINDINGS instanceof Map))
      throw new Error("expected test catalogue Map");
    LEGACY_SCOPE_BINDINGS.set(scope, binding);
    project.mockClear();
    projector.mockClear();
    try {
      await run();
    } finally {
      LEGACY_SCOPE_BINDINGS.delete(scope);
      binding.optionalStreams = ["O"];
      delete binding.rowOrder;
    }
  }
  for (const receipt of [false, true]) {
    it(`omits unsupported optional blobs with optional receipt=${receipt}`, () =>
      withBinding(async () => {
        const store = fixture(receipt);
        const result = await readCanonicalLegacyScope({
          store,
          scope,
          selection: selected,
          requireCompletionReceipts: true,
        });
        expect(result).toMatchObject({ ok: true });
        if (result.ok)
          expect(result.diagnostics.sourceRowCounts).toEqual({ R: 1 });
        expect(handedToProjector()).toEqual({
          streams: ["R"],
          fetchedStreams: ["R"],
        });
        expect(store.getBlobBytes).not.toHaveBeenCalled();
      }));
  }
  it.each([
    ["R", "O"],
    ["O", "R"],
  ])(
    "refuses required unsupported blobs before reading bodies in order %j",
    (first, second) =>
      withBinding(async () => {
        binding.pdppStreams = [first, second];
        binding.optionalStreams = [];
        const store = fixture(true);
        try {
          const result = await readCanonicalLegacyScope({
            store,
            scope,
            selection: selected,
            requireCompletionReceipts: true,
          });
          expect(result).toMatchObject({
            ok: false,
            reason: "blob_backed_records_unsupported",
          });
          expect(store.getBlobBytes).not.toHaveBeenCalled();
          expect(projector).not.toHaveBeenCalled();
        } finally {
          binding.pdppStreams = ["R", "O"];
        }
      }),
  );

  it.each(["absent", "method", "generation", "count", "time"])(
    "does not read an optional stream with %s receipt",
    (variant) =>
      withBinding(async () => {
        binding.rowOrder = "arrival";
        const store = fixture(variant !== "absent");
        const receipts = store.listStreamCompletions;
        store.listStreamCompletions = (...args) =>
          receipts(...args).map((receipt) =>
            receipt.stream !== "O"
              ? receipt
              : {
                  ...receipt,
                  ...(variant === "method" ? { method: "other" } : {}),
                  ...(variant === "generation" ? { generation: 2 } : {}),
                  ...(variant === "count" ? { liveCount: 2 } : {}),
                  ...(variant === "time"
                    ? { sourceCollectedAt: "invalid" }
                    : {}),
                },
          );
        const listRecords = vi.spyOn(store, "listRecords");
        const listArrivalOrder = vi.spyOn(store, "listArrivalOrder");
        const forInstance = vi.fn(() => undefined);
        store.getBlobMeta = vi.fn();
        const result = await readCanonicalLegacyScope({
          store,
          scope,
          selection: selected,
          requireCompletionReceipts: true,
          declarations: { forInstance },
        });
        expect(result).toMatchObject({ ok: true });
        expect(listRecords.mock.calls.map((call) => call[0])).not.toContain(
          "O",
        );
        expect(
          listArrivalOrder.mock.calls.map((call) => call[1]),
        ).not.toContain("O");
        expect(
          forInstance.mock.calls.map((call: unknown[]) => call[1]),
        ).not.toContain("O");
        expect(store.getBlobMeta).not.toHaveBeenCalled();
        expect(store.getBlobBytes).not.toHaveBeenCalled();
      }),
  );

  it.each(["valid", "missing body", "invalid reference"])(
    "handles a supported optional blob: %s",
    (variant) =>
      withBinding(async () => {
        const store = fixture(true);
        const bytes = new TextEncoder().encode('"hello"');
        const digest = [
          ...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
        ]
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        const blobId = `sha256:${digest}`;
        const rows = store.listRecords;
        store.listRecords = (stream, ...args) => {
          const page = rows(stream, ...args);
          if (stream === "O")
            page.data[0]!.data = {
              id: "1",
              blob_ref: {
                blob_id: variant === "invalid reference" ? "bad" : blobId,
                sha256: digest,
                mime_type: "application/json",
                size_bytes: bytes.length,
              },
            };
          return page;
        };
        store.getBlobMeta = vi.fn(() => ({
          blobId,
          sha256: digest,
          mimeType: "application/json",
          sizeBytes: bytes.length,
        }));
        store.getBlobBytes = vi.fn(() =>
          variant === "missing body" ? undefined : bytes,
        );
        const declarations = {
          forInstance: (_instance: string, stream: string) =>
            stream === "O"
              ? {
                  name: "O",
                  semantics: "mutable_state" as const,
                  primaryKey: ["id"],
                  cursorField: "id",
                  requiredFields: [],
                  schema: {
                    properties: {
                      text: {},
                      blob_ref: {
                        x_pdpp_blob_codec: "json-string-v1",
                        x_pdpp_blob_projects_field: "text",
                      },
                    },
                  },
                }
              : undefined,
        };
        const result = await readCanonicalLegacyScope({
          store,
          scope,
          selection: selected,
          requireCompletionReceipts: true,
          includeStreamTimes: true,
          declarations,
        });
        if (variant !== "valid") {
          expect(result).toMatchObject({
            ok: false,
            reason:
              variant === "missing body"
                ? "missing_raw_blob"
                : "blob_backed_record_invalid",
          });
          expect(projector).not.toHaveBeenCalled();
          return;
        }
        expect(result).toMatchObject({
          ok: true,
          diagnostics: { sourceRowCounts: { R: 1, O: 1 } },
          streamCollectionTimes: { O: NOW },
          streamCompletionTimes: { O: NOW },
        });
        expect(projector.mock.calls[0]![1]).toContainEqual(
          expect.objectContaining({
            stream: "O",
            data: { id: "1", text: "hello" },
          }),
        );
      }),
  );

  it("excludes all traces of an unsupported optional stream across refreshes", () =>
    withBinding(async () => {
      binding.rowOrder = "arrival";
      const store = fixture(true);
      let revision = 1;
      const rows = store.listRecords;
      store.listRecords = (stream, ...args) => {
        const page = rows(stream, ...args);
        if (stream !== "O") return page;
        page.data[0]!.version = revision;
        page.data.push({ ...page.data[0]!, recordKey: "2", data: { id: "2" } });
        page.horizon = String(revision);
        return page;
      };
      const streams = store.listStreams;
      store.listStreams = (...args) =>
        streams(...args).map((entry) =>
          entry.stream === "O"
            ? {
                ...entry,
                recordCount: 2,
                lastUpdated: `2026-11-0${revision}T00:00:00.000Z`,
              }
            : entry,
        );
      const receipts = store.listStreamCompletions;
      store.listStreamCompletions = (...args) =>
        receipts(...args).map((receipt) =>
          receipt.stream === "O"
            ? {
                ...receipt,
                liveCount: 2,
                writeSeq: revision,
                sourceCollectedAt: `2026-11-0${revision}T00:00:00.000Z`,
              }
            : receipt,
        );
      const read = () =>
        readCanonicalLegacyScope({
          store,
          scope,
          selection: selected,
          requireCompletionReceipts: true,
          includeStreamTimes: true,
        });
      const first = await read();
      revision = 2;
      const second = await read();
      expect(first.ok && second.ok).toBe(true);
      if (!first.ok || !second.ok) return;
      expect(second.revision).toEqual(first.revision);
      expect(second.envelope.collectedAt).toEqual(first.envelope.collectedAt);
      expect(second.diagnostics).toEqual(first.diagnostics);
      expect(second.diagnostics).toMatchObject({
        sourceRowCounts: { R: 1 },
        omissions: [],
        partialRows: [],
      });
      expect(second.diagnostics.unproven).toBeUndefined();
      expect(second.streamCollectionTimes).toEqual({ R: NOW });
      expect(second.streamCompletionTimes).toEqual({ R: NOW });
      expect(handedToProjector()).toEqual({
        streams: ["R"],
        fetchedStreams: ["R"],
      });
      expect(store.getBlobBytes).not.toHaveBeenCalled();
    }));

  it("refuses an all-optional binding before lookup or projection", () =>
    withBinding(async () => {
      binding.optionalStreams = ["R", "O"];
      expect(legacyScopeToPdppSelection(scope)).toMatchObject({
        ok: false,
        error: { kind: "invalid_binding" },
      });
      expect(
        projectPdppRecordsToLegacyPayload(scope, [], {
          fetchedStreams: ["R", "O"],
        }),
      ).toMatchObject({ ok: false, error: { kind: "invalid_binding" } });
      const result = await readCanonicalLegacyScope({
        store: fixture(true, false),
        scope,
        selection: selected,
        requireCompletionReceipts: true,
      });
      expect(result).toMatchObject({ ok: false, reason: "invalid_binding" });
      expect(project).not.toHaveBeenCalled();
    }));

  function viewFor(store: CanonicalLegacyReadStore) {
    const authority: LegacyScopeAuthority = {
      listMethodConnections: () => [store.getInstanceBinding("test")],
      hasHeldData: () => true,
      hasRetainedTombstones: () => false,
      readSnapshot: (read) => read(),
      writeClock: () => 1,
      arrivalRevision: () => 1,
      hasTakeover: () => false,
      hasMethodTakeover: () => false,
      hasCoveredHead: () => false,
      isReset: () => false,
      cachedVerdict: () => null,
      verdictFor: () => [],
      resetTakeover: () => {},
      eligibleLegacyHead: () => null,
      confirmRead: () => true,
    };
    return createLegacyScopeView({
      authority,
      records: store,
      configuredMethods: () => ["synthetic"],
    });
  }
  it("rejects all-optional listing and alias selection without a projector call", () =>
    withBinding(async () => {
      binding.optionalStreams = ["R", "O"];
      expect(viewFor(fixture(true, false)).listingFor(scope)).toMatchObject({
        kind: "refused",
        refusal: { reason: "invalid_binding" },
      });
      expect(
        selectForTarget(
          {
            connector: "synthetic",
            streams: ["R", "O"],
            alias: {
              connector: "synthetic",
              streams: ["R", "O"],
              requiredStreams: [],
              project: () => project([], { fetchedStreams: [] }),
            },
          },
          [],
        ),
      ).toMatchObject({ kind: "invalid_binding" });
      expect(project).not.toHaveBeenCalled();
    }));
  it("keeps listing and body horizons equal through an optional-only refresh", () =>
    withBinding(async () => {
      const store = fixture(true, false);
      let optionalTime = "2026-11-02T00:00:00.000Z";
      const receipts = store.listStreamCompletions;
      store.listStreamCompletions = (instance) =>
        receipts(instance).map((receipt) => ({
          ...receipt,
          sourceCollectedAt:
            receipt.stream === "O" ? optionalTime : "2026-11-01T00:00:00.000Z",
        }));
      const view = viewFor(store);
      for (const time of [
        "2026-11-02T00:00:00.000Z",
        "2026-11-03T00:00:00.000Z",
      ]) {
        optionalTime = time;
        const result = await readCanonicalLegacyScope({
          store,
          scope,
          selection: selected,
          requireCompletionReceipts: true,
        });
        expect(result).toMatchObject({
          ok: true,
          envelope: { collectedAt: time },
        });
        expect(view.listCanonicalScopes(undefined)).toContainEqual({
          scope,
          collectedAt: time,
        });
      }
    }));
});
