import { describe, expect, it, vi } from "vitest";
import type { DataStoragePort } from "../ports/index.js";
import { computeDataPointId } from "../sync/data-point-id.js";
import {
  LINEAGE_KEY,
  LOCAL_SCOPE_SCAN_PAGE,
  MAX_LINEAGE_SOURCES,
  assertDerivedScopeNaming,
  derivedScopeViolatesNaming,
  extractLineageField,
  hasReservedLineageKey,
  parseLineageSources,
  prepareLineage,
  readStoredLineage,
  resolveLineageSources,
  stampLineage,
  type LineageSourceLookup,
} from "./lineage.js";

const OWNER = "0xAbCdEf1234567890AbCdEf1234567890AbCdEf12" as const;
const OTHER_OWNER = "0x1111111111111111111111111111111111111111" as const;
const SOURCE_SCOPE = "chatgpt.conversations";
const OTHER_SOURCE_SCOPE = "oura.sleep";
const DERIVED_SCOPE = "spine.health.summary";
const SOURCE_ID = computeDataPointId(OWNER, SOURCE_SCOPE);
const OTHER_SOURCE_ID = computeDataPointId(OWNER, OTHER_SOURCE_SCOPE);
const UNKNOWN_ID = `0x${"9".repeat(64)}` as const;

function storageWithScopes(
  ...scopes: string[]
): Pick<DataStoragePort, "listScopes"> {
  return {
    listScopes: vi.fn().mockReturnValue({
      scopes: scopes.map((scope) => ({
        scope,
        latestCollectedAt: "2026-01-01T00:00:00Z",
        versionCount: 1,
      })),
      total: scopes.length,
    }),
  };
}

describe("parseLineageSources", () => {
  it("accepts distinct bytes32 ids and lowercases them", () => {
    const upper = SOURCE_ID.toUpperCase().replace("0X", "0x");
    expect(parseLineageSources([upper, OTHER_SOURCE_ID])).toEqual([
      SOURCE_ID,
      OTHER_SOURCE_ID,
    ]);
  });

  it("accepts an empty list (root record)", () => {
    expect(parseLineageSources([])).toEqual([]);
  });

  it("rejects a non-array", () => {
    expect(() => parseLineageSources("0xabc")).toThrow(
      expect.objectContaining({ errorCode: "LINEAGE_INVALID", code: 400 }),
    );
  });

  it("rejects entries that are not bytes32 hex", () => {
    expect(() => parseLineageSources(["0x1234"])).toThrow(
      expect.objectContaining({ errorCode: "LINEAGE_INVALID" }),
    );
    expect(() => parseLineageSources([42])).toThrow(
      expect.objectContaining({ errorCode: "LINEAGE_INVALID" }),
    );
  });

  it("rejects duplicates, case-insensitively", () => {
    expect(() =>
      parseLineageSources([SOURCE_ID, SOURCE_ID.toUpperCase()]),
    ).toThrow(expect.objectContaining({ errorCode: "LINEAGE_INVALID" }));
  });

  it("rejects more than the maximum number of sources", () => {
    const many = Array.from(
      { length: MAX_LINEAGE_SOURCES + 1 },
      (_, i) => `0x${i.toString(16).padStart(64, "0")}`,
    );
    expect(() => parseLineageSources(many)).toThrow(
      expect.objectContaining({ errorCode: "LINEAGE_INVALID" }),
    );
  });
});

describe("naming rule", () => {
  it("flags a derived scope that shares the source's first segment", () => {
    expect(
      derivedScopeViolatesNaming("chatgpt.health.summary", SOURCE_SCOPE),
    ).toBe(true);
    expect(derivedScopeViolatesNaming("chatgpt", SOURCE_SCOPE)).toBe(true);
    expect(derivedScopeViolatesNaming(DERIVED_SCOPE, SOURCE_SCOPE)).toBe(false);
  });

  it("assertDerivedScopeNaming throws 400 naming the offending source", () => {
    expect(() =>
      assertDerivedScopeNaming("chatgpt.summary", [
        OTHER_SOURCE_SCOPE,
        SOURCE_SCOPE,
      ]),
    ).toThrow(
      expect.objectContaining({
        errorCode: "LINEAGE_SCOPE_UNDER_SOURCE_PREFIX",
        code: 400,
        details: { scope: "chatgpt.summary", sourceScope: SOURCE_SCOPE },
      }),
    );
    expect(() =>
      assertDerivedScopeNaming(DERIVED_SCOPE, [
        SOURCE_SCOPE,
        OTHER_SOURCE_SCOPE,
      ]),
    ).not.toThrow();
  });
});

describe("resolveLineageSources", () => {
  it("resolves sources from the local index without touching the gateway", async () => {
    const gateway: LineageSourceLookup = { getDataPoint: vi.fn() };
    const resolved = await resolveLineageSources({
      scope: DERIVED_SCOPE,
      sources: [SOURCE_ID, OTHER_SOURCE_ID],
      serverOwner: OWNER,
      storage: storageWithScopes(SOURCE_SCOPE, OTHER_SOURCE_SCOPE),
      gateway,
    });
    expect(resolved).toEqual([
      {
        dataPointId: SOURCE_ID,
        scope: SOURCE_SCOPE,
        version: null,
        deletedAt: null,
      },
      {
        dataPointId: OTHER_SOURCE_ID,
        scope: OTHER_SOURCE_SCOPE,
        version: null,
        deletedAt: null,
      },
    ]);
    expect(gateway.getDataPoint).not.toHaveBeenCalled();
  });

  it("resolves a non-local source at the gateway, deleted sources included", async () => {
    const gateway: LineageSourceLookup = {
      getDataPoint: vi.fn().mockResolvedValue({
        dataPointId: SOURCE_ID,
        ownerAddress: OWNER.toLowerCase(),
        scope: SOURCE_SCOPE,
        version: "4",
        deletedAt: "2026-08-01T00:00:00.000Z",
      }),
    };
    const resolved = await resolveLineageSources({
      scope: DERIVED_SCOPE,
      sources: [SOURCE_ID],
      serverOwner: OWNER,
      storage: storageWithScopes(),
      gateway,
    });
    expect(resolved).toEqual([
      {
        dataPointId: SOURCE_ID,
        scope: SOURCE_SCOPE,
        version: "4",
        deletedAt: "2026-08-01T00:00:00.000Z",
      },
    ]);
    expect(gateway.getDataPoint).toHaveBeenCalledWith(SOURCE_ID);
  });

  it("fails with 422 listing every id that is unknown or belongs to another owner", async () => {
    const gateway: LineageSourceLookup = {
      getDataPoint: vi.fn(async (id: string) =>
        id === OTHER_SOURCE_ID
          ? {
              dataPointId: OTHER_SOURCE_ID,
              ownerAddress: OTHER_OWNER,
              scope: OTHER_SOURCE_SCOPE,
              version: "1",
              deletedAt: null,
            }
          : null,
      ),
    };
    await expect(
      resolveLineageSources({
        scope: DERIVED_SCOPE,
        sources: [SOURCE_ID, UNKNOWN_ID, OTHER_SOURCE_ID],
        serverOwner: OWNER,
        storage: storageWithScopes(SOURCE_SCOPE),
        gateway,
      }),
    ).rejects.toMatchObject({
      errorCode: "LINEAGE_SOURCE_UNKNOWN",
      code: 422,
      details: { unknown: [UNKNOWN_ID, OTHER_SOURCE_ID] },
    });
  });

  it("treats a non-local source as unknown when no gateway is configured", async () => {
    await expect(
      resolveLineageSources({
        scope: DERIVED_SCOPE,
        sources: [SOURCE_ID],
        serverOwner: OWNER,
        storage: storageWithScopes(),
      }),
    ).rejects.toMatchObject({
      errorCode: "LINEAGE_SOURCE_UNKNOWN",
      details: { unknown: [SOURCE_ID] },
    });
  });

  it("pages through the whole local index so a source past the first page resolves locally", async () => {
    const total = LOCAL_SCOPE_SCAN_PAGE * 2 + 5;
    const listScopes = vi.fn(
      ({ limit, offset }: { limit: number; offset: number }) => ({
        scopes: Array.from(
          { length: Math.max(0, Math.min(limit, total - offset)) },
          (_, i) => {
            const n = offset + i;
            return {
              scope: n === total - 1 ? SOURCE_SCOPE : `filler.scope${n}`,
              latestCollectedAt: "2026-01-01T00:00:00Z",
              versionCount: 1,
            };
          },
        ),
        total,
      }),
    );
    const gateway: LineageSourceLookup = { getDataPoint: vi.fn() };
    const resolved = await resolveLineageSources({
      scope: DERIVED_SCOPE,
      sources: [SOURCE_ID],
      serverOwner: OWNER,
      storage: { listScopes },
      gateway,
    });
    expect(resolved[0].scope).toBe(SOURCE_SCOPE);
    expect(listScopes).toHaveBeenCalledTimes(3);
    expect(gateway.getDataPoint).not.toHaveBeenCalled();
  });

  it("stops scanning once every source is found", async () => {
    const listScopes = vi.fn().mockReturnValue({
      scopes: [
        { scope: SOURCE_SCOPE, latestCollectedAt: "x", versionCount: 1 },
      ],
      total: 50_000,
    });
    await resolveLineageSources({
      scope: DERIVED_SCOPE,
      sources: [SOURCE_ID],
      serverOwner: OWNER,
      storage: { listScopes },
    });
    expect(listScopes).toHaveBeenCalledTimes(1);
  });

  it("fails with 502 when the gateway lookup throws (retryable, not 'unknown')", async () => {
    const gateway: LineageSourceLookup = {
      getDataPoint: vi.fn().mockRejectedValue(new Error("Gateway error: 503")),
    };
    await expect(
      resolveLineageSources({
        scope: DERIVED_SCOPE,
        sources: [SOURCE_ID],
        serverOwner: OWNER,
        storage: storageWithScopes(),
        gateway,
      }),
    ).rejects.toMatchObject({
      errorCode: "LINEAGE_SOURCE_LOOKUP_FAILED",
      code: 502,
    });
  });

  it("rejects a record that cites its own data point", async () => {
    await expect(
      resolveLineageSources({
        scope: DERIVED_SCOPE,
        sources: [computeDataPointId(OWNER, DERIVED_SCOPE)],
        serverOwner: OWNER,
        storage: storageWithScopes(DERIVED_SCOPE),
      }),
    ).rejects.toMatchObject({ errorCode: "LINEAGE_INVALID", code: 400 });
  });
});

describe("prepareLineage", () => {
  const now = () => new Date("2026-08-31T09:12:44.000Z");

  it("produces the $lineage record for valid sources", async () => {
    const lineage = await prepareLineage({
      scope: DERIVED_SCOPE,
      field: [SOURCE_ID.toUpperCase().replace("0X", "0x"), OTHER_SOURCE_ID],
      serverOwner: OWNER,
      storage: storageWithScopes(SOURCE_SCOPE, OTHER_SOURCE_SCOPE),
      now,
    });
    expect(lineage).toEqual({
      sources: [SOURCE_ID, OTHER_SOURCE_ID],
      writtenAt: "2026-08-31T09:12:44.000Z",
    });
  });

  it("returns undefined for an empty list: a root record, nothing to stamp", async () => {
    await expect(
      prepareLineage({
        scope: DERIVED_SCOPE,
        field: [],
        serverOwner: OWNER,
        storage: storageWithScopes(),
        now,
      }),
    ).resolves.toBeUndefined();
  });

  it("applies the naming rule against the resolved source scopes", async () => {
    await expect(
      prepareLineage({
        scope: "chatgpt.summary",
        field: [SOURCE_ID],
        serverOwner: OWNER,
        storage: storageWithScopes(SOURCE_SCOPE),
        now,
      }),
    ).rejects.toMatchObject({
      errorCode: "LINEAGE_SCOPE_UNDER_SOURCE_PREFIX",
    });
  });

  it("fails closed without a server owner", async () => {
    await expect(
      prepareLineage({
        scope: DERIVED_SCOPE,
        field: [SOURCE_ID],
        serverOwner: undefined,
        storage: storageWithScopes(SOURCE_SCOPE),
        now,
      }),
    ).rejects.toMatchObject({ errorCode: "SERVER_NOT_CONFIGURED" });
  });

  it("validates the shape before anything else", async () => {
    await expect(
      prepareLineage({
        scope: DERIVED_SCOPE,
        field: "not-a-list",
        serverOwner: undefined,
        storage: storageWithScopes(),
        now,
      }),
    ).rejects.toMatchObject({ errorCode: "LINEAGE_INVALID" });
  });
});

describe("stored lineage helpers", () => {
  it("stamps and reads back the reserved key", () => {
    const stamped = stampLineage(
      { note: "x" },
      { sources: [SOURCE_ID], writtenAt: "2026-01-01T00:00:00.000Z" },
    );
    expect(hasReservedLineageKey(stamped)).toBe(true);
    expect(hasReservedLineageKey({ note: "x" })).toBe(false);
    expect(readStoredLineage(stamped)).toEqual({
      sources: [SOURCE_ID],
      writtenAt: "2026-01-01T00:00:00.000Z",
    });
    expect(stamped.note).toBe("x");
  });

  it("readStoredLineage tolerates malformed or absent lineage", () => {
    expect(readStoredLineage(undefined)).toBeNull();
    expect(readStoredLineage({ note: "x" })).toBeNull();
    expect(readStoredLineage({ [LINEAGE_KEY]: "nope" })).toBeNull();
    expect(
      readStoredLineage({ [LINEAGE_KEY]: { sources: ["bad"], writtenAt: "" } }),
    ).toBeNull();
  });

  it("extractLineageField reads the caller field from objects only", () => {
    expect(extractLineageField({ lineage: [SOURCE_ID] })).toEqual([SOURCE_ID]);
    expect(extractLineageField({ note: "x" })).toBeUndefined();
    expect(extractLineageField("DEXA scan")).toBeUndefined();
    expect(extractLineageField(null)).toBeUndefined();
    expect(extractLineageField([SOURCE_ID])).toBeUndefined();
  });
});
