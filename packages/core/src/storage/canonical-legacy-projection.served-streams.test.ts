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
