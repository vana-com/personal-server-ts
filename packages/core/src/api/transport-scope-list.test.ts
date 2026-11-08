import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

// Test 2: the owner's scope listing never shows a physical stream-sync row,
// before pagination or totals. The rows stay in storage (raw index is unchanged).
const COLLECTED = "2026-10-20T00:00:00.000Z";
const ORDINARY = ["instagram.profile", "notes.items"];
const PHYSICAL = [
  "pdpp.chatgpt~0123456789abcdef.conversations",
  "pdpp.chatgpt~0123456789abcdef",
  "pdpp.chatgpt~.conversations",
  "pdpp.chatgpt~",
];

async function listing(query: string) {
  const storage = createMemoryDataStorage();
  for (const scope of [...ORDINARY, ...PHYSICAL]) {
    await storage.insertEntry({
      fileId: scope,
      scope,
      collectedAt: COLLECTED,
      path: scope,
      sizeBytes: 1,
      version: 1,
      dataPointId: null,
    });
  }
  const deps: PersonalServerDataApiDeps = {
    storage,
    auth: {
      authorizeOwner: vi.fn(),
      authorizeBuilderList: vi.fn(async () => undefined),
      authorizeBuilderRead: vi.fn(),
    } as never,
    accessLogWriter: { write: vi.fn(async () => undefined) },
    now: () => new Date("2026-10-21T00:00:00.000Z"),
    createLogId: () => "log-1",
  };
  const response = await handlePersonalServerDataRequest(
    new Request(`https://ps.example.com/${query}`),
    deps,
  );
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    scopes: { scope: string }[];
    total?: number;
  };
  return { body, storage };
}

describe("owner scope listing hides physical rows", () => {
  it("lists only ordinary names, with totals over the filtered set", async () => {
    const { body } = await listing("");
    expect(body.scopes.map((row) => row.scope).sort()).toEqual(
      [...ORDINARY].sort(),
    );
    expect(body.total).toBe(ORDINARY.length);
  });

  it("paginates over the filtered set, not the raw index", async () => {
    const first = await listing("?limit=1&offset=0");
    const second = await listing("?limit=1&offset=1");
    const names = [...first.body.scopes, ...second.body.scopes].map(
      (row) => row.scope,
    );
    expect(names.sort()).toEqual([...ORDINARY].sort());
    expect(first.body.total).toBe(ORDINARY.length);
  });

  it("keeps the physical rows in storage", async () => {
    const { storage } = await listing("");
    expect(storage.entries.map((row) => row.scope)).toEqual(
      expect.arrayContaining(PHYSICAL),
    );
  });
});
