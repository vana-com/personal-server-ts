import { describe, expect, it } from "vitest";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
} from "./index.js";
import type { LegacyScopeBinding, PdppRecord } from "./types.js";
import { WINDOW_FIXTURES } from "./__fixtures__/window-records.js";

const NOW = "2026-10-26T00:00:00.000Z";

/**
 * Project `records` whole, and again a window of parents at a time with
 * exactly their own children. Returns the whole payload and the windows'
 * joined array and summed keys; every other payload key must equal the whole
 * projection's in each window.
 */
function projectInWindows(
  binding: LegacyScopeBinding,
  records: PdppRecord[],
  options: object,
) {
  const { scope } = binding;
  const window = binding.window!;
  const whole = projectPdppRecordsToLegacyPayload(scope, records, options);
  expect(whole.ok).toBe(true);
  if (!whole.ok) throw new Error("whole projection failed");
  const wholePayload = whole.payload as Record<string, unknown>;

  const parents = records
    .filter((record) => record.stream === window.parentStream)
    .map((record) => record.data)
    .sort(window.parentOrder);
  const total = parents.length;
  const joined: unknown[] = [];
  const sums: Record<string, number> = {};
  for (const size of [2, 1, 3, 1, 5]) {
    const slice = parents.splice(0, size);
    const ids = new Set(slice.map((parent) => parent.id));
    const part = projectPdppRecordsToLegacyPayload(
      scope,
      [
        ...slice.map((data) => ({ stream: window.parentStream, data })),
        ...records.filter(
          (record) =>
            record.stream !== window.parentStream &&
            (record.stream !== window.childStream ||
              ids.has(record.data[window.childKey])),
        ),
      ],
      options,
    );
    expect(part.ok).toBe(true);
    if (!part.ok) throw new Error("window projection failed");
    const payload = part.payload as Record<string, unknown>;
    joined.push(...(payload[window.arrayKey] as unknown[]));
    for (const key of window.sumKeys) {
      sums[key] = (sums[key] ?? 0) + (payload[key] as number);
    }
    for (const key of Object.keys(wholePayload)) {
      if (key === window.arrayKey || window.sumKeys.includes(key)) continue;
      expect(payload[key], `${scope} ${key}`).toEqual(wholePayload[key]);
    }
  }
  expect(parents).toHaveLength(0);
  expect(joined).toHaveLength(total);
  expect(total).toBeGreaterThan(5);
  return { window, wholePayload, joined, sums };
}

/** Every binding of the scope that a caller can select: retained and alternates. */
function variantsOf(scope: string): [string | undefined, LegacyScopeBinding][] {
  return [
    [undefined, LEGACY_SCOPE_BINDINGS.get(scope)!],
    ...alternateLegacyBindingsForScope(scope),
  ];
}

describe("windowed legacy projection", () => {
  it("declares windows only over bound streams with a one-field parent key", () => {
    for (const [scope] of LEGACY_SCOPE_BINDINGS) {
      for (const [, binding] of variantsOf(scope)) {
        const window = binding.window;
        if (!window) continue;
        expect(binding.pdppStreams, scope).toContain(window.parentStream);
        expect(binding.pdppStreams, scope).toContain(window.childStream);
        expect(binding.primaryKey[window.parentStream], scope).toHaveLength(1);
      }
    }
  });

  it("has a join test for every windowed binding", () => {
    const windowed = new Set<string>();
    for (const [scope] of LEGACY_SCOPE_BINDINGS) {
      for (const [, binding] of variantsOf(scope)) {
        if (binding.window) windowed.add(scope);
      }
    }
    expect([...windowed].sort()).toEqual(Object.keys(WINDOW_FIXTURES).sort());
  });

  for (const [scope, fixture] of Object.entries(WINDOW_FIXTURES)) {
    it(`joins ${scope} windows into the whole projection`, () => {
      for (const [profileKey, binding] of variantsOf(scope)) {
        if (!binding.window) continue;
        const { window, wholePayload, joined, sums } = projectInWindows(
          binding,
          fixture(binding),
          {
            fetchedStreams: binding.pdppStreams,
            orderByPrimaryKey: true,
            ...(profileKey ? { profileKey } : {}),
            ...(scope === "chatgpt.conversations"
              ? { profileKey: "chatgpt" }
              : {}),
            now: NOW,
          },
        );
        expect({
          ...wholePayload,
          [window.arrayKey]: joined,
          ...sums,
        }).toEqual(wholePayload);
      }
    });
  }
});

describe("legacy projection memory guard", () => {
  // A binding that joins streams builds all of them in memory at once unless
  // it declares a window. A new multi-stream binding must either window or
  // say in one line why it stays small or cannot be windowed.
  it("requires a window or a one-line reason of every multi-stream binding", () => {
    const failures: string[] = [];
    for (const [scope] of LEGACY_SCOPE_BINDINGS) {
      for (const [profileKey, binding] of variantsOf(scope)) {
        if (binding.pdppStreams.length < 2) continue;
        const label = `${scope}${profileKey ? ` (${profileKey})` : ""}`;
        const reason = binding.memoryBound;
        if (binding.window && reason !== undefined) {
          failures.push(`${label}: has a window and a memoryBound reason`);
        } else if (!binding.window) {
          if (!reason || reason.trim() !== reason || /\n/.test(reason)) {
            failures.push(
              `${label}: declare a window, or memoryBound with a one-line reason`,
            );
          }
        }
      }
    }
    expect(failures).toEqual([]);
  });
});
