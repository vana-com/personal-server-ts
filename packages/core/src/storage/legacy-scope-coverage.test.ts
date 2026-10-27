import { describe, expect, it } from "vitest";
import { compareLegacyCoverage } from "./legacy-scope-coverage.js";
import { LEGACY_SCOPE_ENTITY_KEYS } from "./legacy-scope-entity-keys.js";

const keys = { "$.items": ["id"], "$.items[].children": ["id"] };

describe("legacy scope coverage", () => {
  it.each(["spotify.playlists", "spotify.savedTracks"])(
    "keeps metadata-derived local-file track URIs unkeyed in %s",
    (scope) => {
      const track = {
        uri: "spotify:local:Artist:Album:Title:180",
        name: "Title",
        artists: [],
      };
      const body =
        scope === "spotify.playlists"
          ? {
              playlists: [
                { uri: "spotify:playlist:playlist-a", tracks: [track] },
              ],
            }
          : { savedTracks: [track] };
      const verdict = compareLegacyCoverage(body, body, {
        scope,
        entityKeys: LEGACY_SCOPE_ENTITY_KEYS[scope],
        canonicalNewer: true,
      });
      expect(verdict.covered).toBe(false);
      expect(verdict.reason).toBe("no_stable_key");
    },
  );
  it.each([
    {
      scope: "github.repositories",
      list: "repositories",
      key: "url",
      value: "https://github.com/a/foo",
    },
    {
      scope: "github.starred",
      list: "starred",
      key: "url",
      value: "https://github.com/a/foo",
    },
    {
      scope: "github.profile",
      list: "pinnedRepositories",
      key: "fullName",
      value: "a/foo",
    },
    {
      scope: "github.profile",
      list: "organizations",
      key: "login",
      value: "example",
    },
    {
      scope: "linkedin.connections",
      list: "connections",
      key: "profileUrl",
      value: "https://www.linkedin.com/in/alex",
    },
  ])(
    "does not treat a reused source alias as the same $scope entity",
    ({ scope, list, key, value }) => {
      const verdict = compareLegacyCoverage(
        { [list]: [{ [key]: value, label: "original entity", stars: 99 }] },
        {
          [list]: [{ [key]: value, label: "unrelated replacement", stars: 0 }],
        },
        {
          scope,
          entityKeys: LEGACY_SCOPE_ENTITY_KEYS[scope],
          canonicalNewer: true,
          allowProvenDeletion: false,
        },
      );
      expect(verdict.covered).toBe(false);
    },
  );
  describe.each([false, true])(
    "memory creation coverage (newer=%s)",
    (canonicalNewer) => {
      const options = {
        entityKeys: { "$.memories": ["id"] },
        scope: "chatgpt.memories",
        canonicalNewer,
        allowProvenDeletion: true,
      };
      const body = (created_at: unknown) => ({
        memories: [{ id: "a", created_at }],
      });

      it.each([
        { label: "empty", legacy: ["2024-01-01T00:00:00Z"], canonical: [] },
        {
          label: "shorter",
          legacy: ["2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"],
          canonical: ["2023-01-01T00:00:00Z"],
        },
        {
          label: "duplicate shortage",
          legacy: ["2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"],
          canonical: ["2024-01-01T00:00:00Z"],
        },
      ])("blocks $label canonical creation arrays", ({ legacy, canonical }) => {
        const verdict = compareLegacyCoverage(
          body(legacy),
          body(canonical),
          options,
        );
        expect(verdict.covered).toBe(false);
        expect(verdict.reasonCounts.missing_entity).toBeGreaterThan(0);
        expect(verdict.appliedExceptions).toEqual([]);
      });

      it.each([
        { label: "absent", memory: { id: "a" }, reason: "missing_field" },
        {
          label: "null",
          memory: { id: "a", created_at: null },
          reason: "type_mismatch",
        },
        {
          label: "empty",
          memory: { id: "a", created_at: "" },
          reason: "timestamp_format",
        },
      ])("blocks $label canonical creation scalars", ({ memory, reason }) => {
        const verdict = compareLegacyCoverage(
          body("2024-01-01T00:00:00Z"),
          { memories: [memory] },
          options,
        );
        expect(verdict.covered).toBe(false);
        expect(verdict.reason).toBe(reason);
        expect(verdict.appliedExceptions).toEqual([]);
      });

      it.each([null, "", 123, "2023-01-01"])(
        "keeps array type and timestamp format guards for %s",
        (value) => {
          const verdict = compareLegacyCoverage(
            body(["2024-01-01T00:00:00Z"]),
            body([value]),
            options,
          );
          expect(verdict.covered).toBe(false);
          expect(verdict.appliedExceptions).toEqual([]);
        },
      );

      it("requires same-time cardinality even when a creation value differs", () => {
        const verdict = compareLegacyCoverage(
          body(["2024-01-01T00:00:00Z"]),
          body(["2023-01-01T00:00:00Z", "2023-01-02T00:00:00Z"]),
          options,
        );
        expect(verdict.covered).toBe(canonicalNewer);
        if (!canonicalNewer) expect(verdict.reason).toBe("array_order");
      });

      it.each([false, true])(
        "does not waive empty non-date strings (array=%s)",
        (asArray) => {
          const verdict = compareLegacyCoverage(
            body(asArray ? ["legacy"] : "legacy"),
            body(asArray ? [""] : ""),
            options,
          );
          expect(verdict.covered).toBe(false);
          expect(verdict.appliedExceptions).toEqual([]);
        },
      );
    },
  );
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
      { entityKeys: keys, canonicalNewer: true },
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

  it("covers legacy ChatGPT epoch-second update times with ISO projection timestamps", () => {
    const verdict = compareLegacyCoverage(
      { conversations: [{ id: "a", update_time: 1704067200.123 }] },
      { conversations: [{ id: "a", update_time: "2024-01-01T00:00:00.123Z" }] },
      {
        scope: "chatgpt.conversations",
        entityKeys: LEGACY_SCOPE_ENTITY_KEYS["chatgpt.conversations"],
        canonicalNewer: true,
      },
    );
    expect(verdict.covered).toBe(true);
    expect(verdict.reasonCounts.type_mismatch).toBe(0);
    expect(verdict.appliedExceptions).toEqual([
      expect.objectContaining({ path: "$.conversations[].update_time" }),
    ]);
  });

  it.each([
    {
      label: "same-time changed instant",
      newer: false,
      value: "2024-01-02T00:00:00Z",
    },
    { label: "malformed timestamp", value: "2024-01-01Tinvalid" },
    { label: "date-only timestamp", value: "2024-01-01" },
    { label: "null timestamp", value: null },
    {
      label: "millisecond epoch",
      legacy: 1704067200123,
      value: "2024-01-01T00:00:00.123Z",
    },
    {
      label: "other scope",
      scope: "other.conversations",
      value: "2024-01-01T00:00:00.123Z",
    },
    {
      label: "other field",
      field: "create_time",
      value: "2024-01-01T00:00:00.123Z",
    },
    { label: "nested field", nested: true, value: "2024-01-01T00:00:00.123Z" },
    { label: "changed identity", id: "b", value: "2024-01-01T00:00:00.123Z" },
    {
      label: "missing conversation",
      missing: true,
      value: "2024-01-01T00:00:00.123Z",
    },
  ])(
    "retains coverage protection for ChatGPT epoch timestamps: $label",
    (test) => {
      const field = test.field ?? "update_time";
      const row = (id: string, value: unknown) => ({
        id,
        ...(test.nested
          ? { metadata: { [field]: value } }
          : { [field]: value }),
      });
      const verdict = compareLegacyCoverage(
        { conversations: [row("a", test.legacy ?? 1704067200.123)] },
        {
          conversations: test.missing ? [] : [row(test.id ?? "a", test.value)],
        },
        {
          scope: test.scope ?? "chatgpt.conversations",
          entityKeys: LEGACY_SCOPE_ENTITY_KEYS["chatgpt.conversations"],
          canonicalNewer: test.newer ?? true,
        },
      );
      expect(verdict.covered).toBe(false);
    },
  );

  it.each([false, true])(
    "compares converted ChatGPT timestamps using the existing time policy (newer=%s)",
    (canonicalNewer) => {
      const body = (update_time: unknown) => ({
        conversations: [{ id: "a", update_time }],
      });
      const options = {
        scope: "chatgpt.conversations",
        entityKeys: LEGACY_SCOPE_ENTITY_KEYS["chatgpt.conversations"],
        canonicalNewer,
      };
      expect(
        compareLegacyCoverage(
          body(1704067200.123),
          body("2023-12-31T19:00:00.123-05:00"),
          options,
        ).covered,
      ).toBe(true);
      expect(
        compareLegacyCoverage(
          body(1704067200.123),
          body("2024-01-02T00:00:00Z"),
          options,
        ).covered,
      ).toBe(canonicalNewer);
    },
  );

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

  it("requires scalar arrays to retain their values and same-time sequence", () => {
    expect(
      compareLegacyCoverage(
        { values: ["one", "two"] },
        { values: ["one"] },
        { canonicalNewer: true, allowProvenDeletion: true },
      ).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(
        { values: ["one"] },
        { values: ["changed"] },
        { canonicalNewer: true, allowProvenDeletion: true },
      ).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(
        { values: ["one", "two"] },
        { values: ["two", "one"] },
        { canonicalNewer: false },
      ).reason,
    ).toBe("array_order");
    expect(
      compareLegacyCoverage(
        { values: ["x", "x"] },
        { values: ["x"] },
        { canonicalNewer: true, allowProvenDeletion: true },
      ).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(
        { values: ["one"] },
        { values: ["one", "extra"] },
        { canonicalNewer: false },
      ).reason,
    ).toBe("array_order");
  });

  it("keeps scalar-array type and nullability checks blocking with deletion proof", () => {
    const changedType = compareLegacyCoverage(
      { updatedAt: ["2024-01-01T00:00:00Z"] },
      { updatedAt: [123] },
      { canonicalNewer: true, allowProvenDeletion: true },
    );
    expect(changedType.covered).toBe(false);
    expect(changedType.reason).toBe("type_mismatch");
    const becameNull = compareLegacyCoverage(
      { updatedAt: ["2024-01-01T00:00:00Z"] },
      { updatedAt: [null] },
      { canonicalNewer: true, allowProvenDeletion: true },
    );
    expect(becameNull.covered).toBe(false);
    expect(becameNull.reason).toBe("type_mismatch");
    const changedTimestampFormat = compareLegacyCoverage(
      { updatedAt: ["2024-01-01T00:00:00Z"] },
      { updatedAt: ["2024-01-01"] },
      { canonicalNewer: true, allowProvenDeletion: true },
    );
    expect(changedTimestampFormat.covered).toBe(false);
    expect(changedTimestampFormat.reason).toBe("timestamp_format");
    const extraNull = compareLegacyCoverage(
      { updatedAt: ["2024-01-01T00:00:00Z"] },
      { updatedAt: ["2024-01-01T00:00:00Z", null] },
      { canonicalNewer: true },
    );
    expect(extraNull.covered).toBe(false);
    expect(extraNull.reason).toBe("type_mismatch");
    const extraNumber = compareLegacyCoverage(
      { updatedAt: ["2024-01-01T00:00:00Z"] },
      { updatedAt: ["2024-01-01T00:00:00Z", 123] },
      { canonicalNewer: true },
    );
    expect(extraNumber.covered).toBe(false);
    expect(extraNumber.reason).toBe("type_mismatch");
  });

  it("allows newer object arrays to add entities when the legacy array is empty", () => {
    const verdict = compareLegacyCoverage(
      { items: [] },
      { items: [{ id: "new" }] },
      {
        entityKeys: { "$.items": ["id"] },
        canonicalNewer: true,
      },
    );
    expect(verdict.covered).toBe(true);
  });

  it("keeps creation values immutable through scalar-array comparison", () => {
    const verdict = compareLegacyCoverage(
      { created_at: ["2024-01-01T00:00:00Z"] },
      { created_at: ["2025-01-01T00:00:00Z"] },
      { canonicalNewer: true },
    );
    expect(verdict.covered).toBe(false);
    expect(verdict.reason).toBe("creation_mismatch");
  });

  it.each([false, true])(
    "applies the reviewed memory creation exception to scalar arrays (newer=%s)",
    (canonicalNewer) => {
      const verdict = compareLegacyCoverage(
        {
          memories: [{ id: "a", created_at: ["2024-01-01T00:00:00Z"] }],
        },
        {
          memories: [{ id: "a", created_at: ["2023-01-01T00:00:00Z"] }],
        },
        {
          entityKeys: { "$.memories": ["id"] },
          scope: "chatgpt.memories",
          canonicalNewer,
        },
      );
      expect(verdict.covered).toBe(true);
      expect(verdict.reason).toBeNull();
      expect(verdict.reasonCounts.creation_mismatch).toBe(0);
      expect(verdict.missingEntityCount).toBe(0);
      expect(verdict.mismatchedFieldPaths).toEqual([]);
      expect(verdict.appliedExceptions).toEqual([
        {
          path: "$.memories[].created_at",
          reason:
            "legacy collector wrote collection time; canonical carries source creation time",
          authority: "canonical",
        },
      ]);
    },
  );

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

  it.each([false, true])(
    "trusts canonical ChatGPT memory creation times (newer=%s)",
    (canonicalNewer) => {
      const legacy = {
        memories: [
          { id: "secret-a", created_at: "2024-01-01T00:00:00Z" },
          { id: "secret-b", created_at: "2024-01-02T00:00:00Z" },
        ],
      };
      const canonical = {
        memories: [
          { id: "secret-a", created_at: "2023-01-01T00:00:00Z" },
          { id: "secret-b", created_at: "2023-01-02T00:00:00Z" },
        ],
      };
      const verdict = compareLegacyCoverage(legacy, canonical, {
        entityKeys: { "$.memories": ["id"] },
        scope: "chatgpt.memories",
        canonicalNewer,
      });
      expect(verdict.covered).toBe(true);
      expect(verdict.reason).toBeNull();
      expect(verdict.reasonCounts.creation_mismatch).toBe(0);
      expect(verdict.mismatchedFieldPaths).toEqual([]);
      expect(verdict.appliedExceptions).toEqual([
        {
          path: "$.memories[].created_at",
          reason:
            "legacy collector wrote collection time; canonical carries source creation time",
          authority: "canonical",
        },
      ]);
      expect(JSON.stringify(verdict)).not.toContain("secret-");
      expect(JSON.stringify(verdict)).not.toContain("2024-");
      expect(JSON.stringify(verdict)).not.toContain("2023-");
    },
  );

  it.each(["other.memories", "chatgpt.conversations", undefined])(
    "does not apply the memory creation exception to scope %s",
    (scope) => {
      for (const canonicalNewer of [false, true]) {
        for (const asArray of [false, true]) {
          const legacyTime = "2024-01-01T00:00:00Z";
          const canonicalTime = "2023-01-01T00:00:00Z";
          const verdict = compareLegacyCoverage(
            {
              memories: [
                { id: "a", created_at: asArray ? [legacyTime] : legacyTime },
              ],
            },
            {
              memories: [
                {
                  id: "a",
                  created_at: asArray ? [canonicalTime] : canonicalTime,
                },
              ],
            },
            { entityKeys: { "$.memories": ["id"] }, scope, canonicalNewer },
          );
          expect(verdict.covered).toBe(false);
          expect(verdict.reason).toBe("creation_mismatch");
          expect(verdict.appliedExceptions).toEqual([]);
        }
      }
    },
  );

  it("does not apply the memory creation exception to other paths", () => {
    for (const canonicalNewer of [false, true]) {
      for (const asArray of [false, true]) {
        const legacyTime = "2024-01-01T00:00:00Z";
        const canonicalTime = "2023-01-01T00:00:00Z";
        const body = (time: string) => {
          const created_at = asArray ? [time] : time;
          return {
            created_at,
            other: [{ id: "a", created_at }],
            memories: [
              { id: "a", createdAt: created_at, nested: { created_at } },
            ],
          };
        };
        const verdict = compareLegacyCoverage(
          body(legacyTime),
          body(canonicalTime),
          {
            entityKeys: { "$.memories": ["id"], "$.other": ["id"] },
            scope: "chatgpt.memories",
            canonicalNewer,
          },
        );
        expect(verdict.covered).toBe(false);
        expect(verdict.reason).toBe("creation_mismatch");
        expect(verdict.reasonCounts.creation_mismatch).toBe(4);
        expect(verdict.mismatchedFieldPaths).toEqual([
          "$.created_at",
          "$.other[0].created_at",
          "$.memories[0].createdAt",
          "$.memories[0].nested.created_at",
        ]);
        expect(verdict.appliedExceptions).toEqual([]);
      }
    }
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

describe("Oura frozen integer schema defect", () => {
  const payload = (averageHrv: unknown) => ({
    sleepPeriods: [{ id: "session", averageHrv }],
  });
  const options = {
    scope: "oura.sleep",
    entityKeys: { "$.sleepPeriods": ["id"] },
  };
  it("accepts only the exact schema rounding of a fractional legacy averageHrv", () => {
    const verdict = compareLegacyCoverage(payload(48.6), payload(49), options);
    expect(verdict.covered).toBe(true);
    expect(verdict.appliedExceptions).toHaveLength(1);
    expect(
      compareLegacyCoverage(payload(48.6), payload(48), options).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(payload(48), payload(49), options).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(payload(48.6), payload("49"), options).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(payload(48.6), payload(null), options).covered,
    ).toBe(false);
    expect(
      compareLegacyCoverage(payload(48.6), payload(49), {
        ...options,
        scope: "other.sleep",
      }).covered,
    ).toBe(false);
  });
});
