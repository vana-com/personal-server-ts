import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  readCanonicalLegacyScope,
  type CanonicalLegacyReadStore,
  type CanonicalStreamCompletion,
} from "./canonical-legacy-projection.js";
import { projectPdppRecordsToLegacyPayload } from "../legacy-projection/index.js";
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
