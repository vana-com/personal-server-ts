import { describe, expect, it } from "vitest";
import { compareLegacyCoverage } from "./legacy-scope-coverage.js";

const keys = { "$.items": ["id"], "$.items[].children": ["id"] };

describe("legacy scope coverage", () => {
  it("covers legacy entities and fields while allowing canonical extras", () => {
    const verdict = compareLegacyCoverage(
      {
        items: [
          { id: "a", name: "A" },
          { id: "b", name: "B" },
        ],
      },
      {
        items: [
          { id: "extra", name: "E" },
          { id: "a", name: "A", newField: true },
          { id: "b", name: "B" },
        ],
        anotherField: true,
      },
      { entityKeys: keys },
    );
    expect(verdict.covered).toBe(true);
    expect(verdict.reason).toBeNull();
    expect(verdict.missingEntityCount).toBe(0);
    expect(verdict.mismatchedFieldPaths).toEqual([]);
    expect(verdict.byteDelta).toBe(
      verdict.canonicalBytes - verdict.legacyBytes,
    );
  });

  it("records missing entities without disclosing values", () => {
    const verdict = compareLegacyCoverage(
      { items: [{ id: "private-id", name: "A" }] },
      { items: [] },
      { entityKeys: keys },
    );
    expect(verdict.covered).toBe(false);
    expect(verdict.reason).toBe("missing_entity");
    expect(verdict.missingEntityCount).toBe(1);
    expect(JSON.stringify(verdict)).not.toContain("private-id");
  });

  it("records changed and absent fields as paths only", () => {
    const verdict = compareLegacyCoverage(
      { items: [{ id: "private-id", name: "A", nested: { title: "secret" } }] },
      { items: [{ id: "private-id", name: "B", nested: {} }] },
      { entityKeys: keys },
    );
    expect(verdict.covered).toBe(false);
    expect(verdict.reason).toBe("field_mismatch");
    expect(verdict.mismatchedFieldPaths).toEqual([
      "$.items[0].name",
      "$.items[0].nested.title",
    ]);
    expect(verdict.reasonCounts.missing_field).toBe(1);
    expect(verdict.reasonCounts.field_mismatch).toBe(1);
    expect(JSON.stringify(verdict)).not.toContain("private-id");
    expect(JSON.stringify(verdict)).not.toContain("secret");
  });

  it("counts a same-time absent path as missing_field", () => {
    const verdict = compareLegacyCoverage(
      { profile: { name: "A" } },
      { profile: {} },
    );
    expect(verdict.reason).toBe("missing_field");
    expect(verdict.reasonCounts.missing_field).toBe(1);
  });

  it("refuses an entity array with no stable key", () => {
    const verdict = compareLegacyCoverage(
      { items: [{ name: "A" }] },
      { items: [{ name: "A" }] },
      {},
    );
    expect(verdict.covered).toBe(false);
    expect(verdict.reason).toBe("no_stable_key");
    expect(verdict.mismatchedFieldPaths).toEqual(["$.items"]);
  });

  it("refuses a missing or repeated key even when the bodies look equal", () => {
    for (const items of [
      [{ id: null, name: "A" }],
      [{ id: "same" }, { id: "same" }],
    ]) {
      const verdict = compareLegacyCoverage(
        { items },
        { items },
        { entityKeys: keys },
      );
      expect(verdict.reason).toBe("no_stable_key");
    }
  });

  it("keeps the relative order of legacy keys despite interleaved extras", () => {
    const legacy = { items: [{ id: "a" }, { id: "b" }] };
    const reordered = compareLegacyCoverage(
      legacy,
      { items: [{ id: "b" }, { id: "x" }, { id: "a" }] },
      { entityKeys: keys },
    );
    expect(reordered.reason).toBe("array_order");
    expect(reordered.mismatchedFieldPaths).toEqual(["$.items"]);
    const interleaved = compareLegacyCoverage(
      legacy,
      { items: [{ id: "a" }, { id: "x" }, { id: "b" }] },
      { entityKeys: keys },
    );
    expect(interleaved.covered).toBe(true);
  });

  it("recurses through embedded collections and primitive arrays", () => {
    const legacy = {
      items: [{ id: "a", children: [{ id: "child", tags: ["old", "new"] }] }],
    };
    const covered = compareLegacyCoverage(
      legacy,
      {
        items: [
          {
            id: "a",
            children: [
              { id: "child", tags: ["old", "extra", "new"], more: true },
            ],
          },
        ],
      },
      { entityKeys: keys },
    );
    expect(covered.covered).toBe(true);
    const changed = compareLegacyCoverage(
      legacy,
      {
        items: [{ id: "a", children: [{ id: "child", tags: ["new", "old"] }] }],
      },
      { entityKeys: keys },
    );
    expect(changed.reason).toBe("array_order");
    expect(changed.mismatchedFieldPaths).toEqual([
      "$.items[0].children[0].tags",
    ]);
  });

  it("uses schema id fields for arrays when no key map is supplied", () => {
    const verdict = compareLegacyCoverage(
      { items: [{ id: "a", value: 1 }] },
      { items: [{ id: "a", value: 1 }] },
      {
        schema: {
          type: "object",
          properties: {
            items: {
              type: "array",
              items: { type: "object", properties: { id: { type: "string" } } },
            },
          },
        },
      },
    );
    expect(verdict.covered).toBe(true);
  });

  it("records byte growth and applies both configurable growth thresholds", () => {
    const legacy = { text: "a".repeat(16) };
    const canonical = { text: legacy.text, extra: "b".repeat(64) };
    const refused = compareLegacyCoverage(legacy, canonical, {
      maxPayloadRatio: 1.5,
      maxExtraBytes: 32,
    });
    expect(refused.reason).toBe("payload_growth");
    expect(refused.byteDelta).toBeGreaterThan(32);
    expect(
      compareLegacyCoverage(legacy, canonical, { maxExtraBytes: 256 * 1024 })
        .covered,
    ).toBe(true);
    expect(
      compareLegacyCoverage(legacy, canonical, {
        maxPayloadRatio: 100,
        maxExtraBytes: 32,
      }).covered,
    ).toBe(true);
  });

  it("allows newer canonical values to drift while preserving every field", () => {
    const legacy = { items: [{ id: "a", status: "old", score: 1 }] };
    const newer = { items: [{ id: "a", status: "new", score: 2 }] };
    const sameTime = compareLegacyCoverage(legacy, newer, {
      entityKeys: keys,
      canonicalNewer: false,
      allowProvenDeletion: false,
    });
    expect(sameTime.comparisonCase).toBe("same_time");
    expect(sameTime.reason).toBe("field_mismatch");
    const canonicalNewer = compareLegacyCoverage(legacy, newer, {
      entityKeys: keys,
      canonicalNewer: true,
      allowProvenDeletion: false,
    });
    expect(canonicalNewer.comparisonCase).toBe("canonical_newer");
    expect(canonicalNewer.covered).toBe(true);
    expect(canonicalNewer.reasonCounts.field_mismatch).toBe(0);
  });

  it("requires paths, JSON types, and timestamp format class for newer canonical data", () => {
    const legacy = {
      items: [
        {
          id: "a",
          name: "present",
          count: 1,
          updatedAt: "2024-01-01T00:00:00Z",
          date: "2024-01-01",
        },
      ],
    };
    const verdict = compareLegacyCoverage(
      legacy,
      {
        items: [
          {
            id: "a",
            count: "1",
            updatedAt: "2024-01-02",
            date: "2024-01-02T00:00:00Z",
          },
        ],
      },
      { entityKeys: keys, canonicalNewer: true, allowProvenDeletion: false },
    );
    expect(verdict.covered).toBe(false);
    expect(verdict.mismatchedFieldPaths).toEqual([
      "$.items[0].name",
      "$.items[0].count",
      "$.items[0].updatedAt",
      "$.items[0].date",
    ]);
    expect(verdict.reasonCounts.missing_field).toBe(1);
    expect(verdict.reasonCounts.type_mismatch).toBe(1);
    expect(verdict.reasonCounts.timestamp_format).toBe(2);
  });

  it("keeps identity and creation timestamps equal even when canonical is newer", () => {
    const verdict = compareLegacyCoverage(
      {
        id: "owner",
        items: [{ id: "a", createdAt: "2024-01-01", text: "old" }],
      },
      {
        id: "other",
        items: [{ id: "a", createdAt: "2024-01-02", text: "new" }],
      },
      { entityKeys: keys, canonicalNewer: true, allowProvenDeletion: false },
    );
    expect(verdict.covered).toBe(false);
    expect(verdict.reasonCounts.identity_mismatch).toBe(1);
    expect(verdict.reasonCounts.creation_mismatch).toBe(1);
    expect(verdict.mismatchedFieldPaths).toEqual([
      "$.id",
      "$.items[0].createdAt",
    ]);
  });

  it("ignores fetch and collection metadata at every level", () => {
    const verdict = compareLegacyCoverage(
      {
        fetched_at: "2024-01-01",
        items: [
          { id: "a", collectedAt: "2024-01-01", nested: { synced_at: 1 } },
        ],
      },
      { items: [{ id: "a", nested: {} }] },
      { entityKeys: keys, canonicalNewer: false, allowProvenDeletion: false },
    );
    expect(verdict.covered).toBe(true);
    expect(verdict.mismatchedFieldPaths).toEqual([]);
  });

  it("checks array order at same time but allows newer canonical order", () => {
    const legacy = { items: [{ id: "a" }, { id: "b" }] };
    const canonical = { items: [{ id: "b" }, { id: "a" }] };
    expect(
      compareLegacyCoverage(legacy, canonical, {
        entityKeys: keys,
        canonicalNewer: false,
      }).reason,
    ).toBe("array_order");
    expect(
      compareLegacyCoverage(legacy, canonical, {
        entityKeys: keys,
        canonicalNewer: true,
      }).covered,
    ).toBe(true);
  });

  it("allows a newer proven deletion but records it; unproven deletion refuses", () => {
    const legacy = { items: [{ id: "a" }, { id: "b" }] };
    const canonical = { items: [{ id: "a" }] };
    const unproven = compareLegacyCoverage(legacy, canonical, {
      entityKeys: keys,
      canonicalNewer: true,
      allowProvenDeletion: false,
    });
    expect(unproven.covered).toBe(false);
    expect(unproven.reason).toBe("missing_entity");
    const proven = compareLegacyCoverage(legacy, canonical, {
      entityKeys: keys,
      canonicalNewer: true,
      allowProvenDeletion: true,
    });
    expect(proven.covered).toBe(true);
    expect(proven.reason).toBeNull();
    expect(proven.missingEntityCount).toBe(1);
    expect(proven.reasonCounts.missing_entity).toBe(1);
  });

  it("compares ISO timestamp instants at millisecond precision", () => {
    const legacy = { updatedAt: "2024-01-01T00:00:00.123456Z" };
    const sameInstant = compareLegacyCoverage(legacy, {
      updatedAt: "2023-12-31T19:00:00.123999-05:00",
    });
    expect(sameInstant.covered).toBe(true);
    const nextMillisecond = compareLegacyCoverage(legacy, {
      updatedAt: "2024-01-01T00:00:00.124Z",
    });
    expect(nextMillisecond.reason).toBe("field_mismatch");
    const differentFormat = compareLegacyCoverage(legacy, {
      updatedAt: "2024-01-01",
    });
    expect(differentFormat.reason).toBe("timestamp_format");
  });

  it("compares immutable creation timestamps as millisecond instants", () => {
    const legacy = { createdAt: "2024-01-01T00:00:00.123456Z" };
    expect(
      compareLegacyCoverage(
        legacy,
        { createdAt: "2023-12-31T19:00:00.123999-05:00" },
        { canonicalNewer: true },
      ).covered,
    ).toBe(true);
    expect(
      compareLegacyCoverage(
        legacy,
        { createdAt: "2024-01-01T00:00:00.124Z" },
        { canonicalNewer: true },
      ).reason,
    ).toBe("creation_mismatch");
  });

  it("compares ISO instants inside primitive timestamp arrays", () => {
    const verdict = compareLegacyCoverage(
      { timestamps: ["2024-01-01T00:00:00.123456Z"] },
      { timestamps: ["2023-12-31T19:00:00.123999-05:00"] },
    );
    expect(verdict.covered).toBe(true);
  });

  it("keeps *_created* timestamp fields immutable at millisecond precision", () => {
    const legacy = {
      account_created_on: "2024-01-01T00:00:00.123456Z",
      date_created: "2024-01-01T00:00:00.123456Z",
    };
    const sameInstant = compareLegacyCoverage(
      legacy,
      {
        account_created_on: "2023-12-31T19:00:00.123999-05:00",
        date_created: "2023-12-31T19:00:00.123999-05:00",
      },
      { canonicalNewer: true },
    );
    expect(sameInstant.covered).toBe(true);
    const changed = compareLegacyCoverage(
      legacy,
      {
        account_created_on: "2024-01-01T00:00:00.124Z",
        date_created: "2024-01-01T00:00:00.124Z",
      },
      { canonicalNewer: true },
    );
    expect(changed.reasonCounts.creation_mismatch).toBe(2);
  });

  it("checks ISO/date-only format from values under neutral field names", () => {
    const verdict = compareLegacyCoverage(
      { start: "2024-01-01T00:00:00Z", numericId: 123 },
      { start: "2024-01-01", numericId: 123 },
      { canonicalNewer: true },
    );
    expect(verdict.reason).toBe("timestamp_format");
    expect(verdict.reasonCounts.timestamp_format).toBe(1);
    expect(verdict.mismatchedFieldPaths).toEqual(["$.start"]);
    const changedId = compareLegacyCoverage(
      { numericId: 123 },
      { numericId: 456 },
      { canonicalNewer: true },
    );
    expect(changedId.reason).toBe("identity_mismatch");
    expect(changedId.reasonCounts.timestamp_format).toBe(0);
  });

  it("applies only the reviewed ChatGPT memory creation-time exception", () => {
    const legacy = {
      memories: [{ id: "secret-id", created_at: "2024-01-01T00:00:00Z" }],
    };
    const canonical = {
      memories: [{ id: "secret-id", created_at: "2023-01-01T00:00:00Z" }],
    };
    const options = {
      entityKeys: { "$.memories": ["id"] },
      scope: "chatgpt.memories",
    };
    const verdict = compareLegacyCoverage(legacy, canonical, options);
    expect(verdict.covered).toBe(true);
    expect(verdict.appliedExceptions).toEqual([
      {
        path: "$.memories[].created_at",
        reason:
          "legacy collector wrote collection time; canonical carries source creation time",
        authority: "canonical",
      },
    ]);
    expect(JSON.stringify(verdict)).not.toContain("secret-id");
    expect(
      compareLegacyCoverage(legacy, canonical, {
        ...options,
        scope: "other.memories",
      }).reason,
    ).toBe("creation_mismatch");
    expect(
      compareLegacyCoverage(legacy, canonical, {
        ...options,
        scope: undefined,
      }).appliedExceptions,
    ).toEqual([]);
  });

  it("keeps format class mandatory for an allowlisted creation field", () => {
    const verdict = compareLegacyCoverage(
      { memories: [{ id: "a", created_at: "2024-01-01T00:00:00Z" }] },
      { memories: [{ id: "a", created_at: "2024-01-01" }] },
      {
        entityKeys: { "$.memories": ["id"] },
        scope: "chatgpt.memories",
        canonicalNewer: true,
      },
    );
    expect(verdict.reason).toBe("timestamp_format");
    expect(verdict.appliedExceptions).toEqual([]);
  });
});
