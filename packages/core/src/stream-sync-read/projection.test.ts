import { describe, expect, it } from "vitest";
import type {
  JsonObject,
  Line,
} from "@opendatalabs/personal-server-ts-stream-sync";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
  projectPdppRecordsToLegacyPayload,
  type LegacyScopeBinding,
  type PdppRecord,
} from "../legacy-projection/index.js";
import { WINDOW_FIXTURES } from "../legacy-projection/__fixtures__/window-records.js";
import { streamSyncReadHashes } from "./keys.js";
import { createMemoryStreamSyncReadFiles } from "./memory-files.js";
import { planProjection } from "./projection.js";

const NOW = "2026-11-02T00:00:00.000Z";
const COPIES = 40;

/**
 * `COPIES` copies of a window fixture. Each copy prefixes every id the join
 * reads and moves its times by whole hours, so copies interleave in the
 * output order and land in many shards. Streams outside the window stay one
 * copy: they are whole-scope rows such as the account profile.
 */
function replicate(
  binding: LegacyScopeBinding,
  records: PdppRecord[],
): PdppRecord[] {
  const window = binding.window!;
  const ids = new Set(["id", window.childKey, "parent_id", "current_node"]);
  const out: PdppRecord[] = [];
  for (let copy = 0; copy < COPIES; copy++) {
    for (const record of records) {
      if (
        record.stream !== window.parentStream &&
        record.stream !== window.childStream
      ) {
        if (copy === 0) out.push(record);
        continue;
      }
      const data: Record<string, unknown> = { ...record.data };
      for (const [field, value] of Object.entries(data)) {
        if (ids.has(field) && typeof value === "string") {
          data[field] = `k${copy}-${value}`;
        }
        if (
          (field === "update_time" || field === "taken_at") &&
          typeof value === "string" &&
          !Number.isNaN(Date.parse(value))
        ) {
          data[field] = new Date(
            Date.parse(value) + ((copy * 7) % 23) * 3_600_000,
          ).toISOString();
        }
      }
      out.push({ stream: record.stream, data });
    }
  }
  return out;
}

/** A deterministic order unlike both input order and output order. */
function scrambled(rows: Record<string, unknown>[]): Record<string, unknown>[] {
  const key = (row: Record<string, unknown>) => {
    let h = 2166136261;
    for (const ch of JSON.stringify(row)) {
      h = Math.imul(h ^ ch.charCodeAt(0), 16777619) >>> 0;
    }
    return h;
  };
  return [...rows].sort((a, b) => key(a) - key(b));
}

async function streamed(
  binding: LegacyScopeBinding,
  profileKey: string | undefined,
  records: PdppRecord[],
): Promise<string> {
  const byStream = new Map<string, Record<string, unknown>[]>();
  for (const record of records) {
    byStream.set(record.stream, [
      ...(byStream.get(record.stream) ?? []),
      record.data,
    ]);
  }
  const plan = await planProjection({
    scope: binding.scope,
    binding,
    profileKey,
    lines: async function* (stream): AsyncGenerator<Line> {
      for (const v of scrambled(byStream.get(stream) ?? [])) {
        yield { o: 1, r: "run", v: v as JsonObject };
      }
    },
    streamBytes: () => 0,
    sha256: streamSyncReadHashes.sha256,
    spool: createMemoryStreamSyncReadFiles(),
    spoolId: "test",
    budgetBytes: 1,
    now: NOW,
  });
  if (plan.kind !== "ok") throw new Error(`plan ${plan.kind}`);
  let text = "";
  for await (const chunk of plan.payload) text += chunk;
  return text;
}

/**
 * Fraction of adjacent pairs of `want` that keep their order in `got`. Equal
 * items cannot be told apart, so the n-th copy of an item matches the n-th.
 */
function adjacentPairsKept(wantItems: string[], gotItems: string[]): number {
  const label = (items: string[]) => {
    const seen = new Map<string, number>();
    return items.map((item) => {
      const n = seen.get(item) ?? 0;
      seen.set(item, n + 1);
      return `${n}:${item}`;
    });
  };
  const want = label(wantItems);
  const at = new Map(label(gotItems).map((item, i) => [item, i]));
  let kept = 0;
  for (let i = 1; i < want.length; i++) {
    if ((at.get(want[i - 1]!) ?? -1) < (at.get(want[i]!) ?? -1)) kept++;
  }
  return kept / (want.length - 1);
}

describe("streamed legacy projection order", () => {
  for (const [scope, fixture] of Object.entries(WINDOW_FIXTURES)) {
    const variants: [string | undefined, LegacyScopeBinding][] = [
      [undefined, LEGACY_SCOPE_BINDINGS.get(scope)!],
      ...alternateLegacyBindingsForScope(scope),
    ];
    for (const [profileKey, binding] of variants) {
      if (!binding.window) continue;
      const label = `${scope}${profileKey ? ` (${profileKey})` : ""}`;
      it(`writes ${label} byte for byte as the array projector does`, async () => {
        const window = binding.window!;
        const key =
          profileKey ??
          (scope === "chatgpt.conversations" ? "chatgpt" : undefined);
        const records = replicate(binding, fixture(binding));
        const whole = projectPdppRecordsToLegacyPayload(scope, records, {
          fetchedStreams: [...binding.pdppStreams],
          orderByPrimaryKey: true,
          now: NOW,
          ...(key ? { profileKey: key } : {}),
        });
        if (!whole.ok) throw new Error(`array projector: ${whole.error.kind}`);
        const array = whole.payload as Record<string, unknown>;
        const items = array[window.arrayKey] as unknown[];
        expect(items.length).toBeGreaterThan(100);

        const text = await streamed(binding, key, records);
        const got = (JSON.parse(text) as Record<string, unknown>)[
          window.arrayKey
        ] as unknown[];
        expect(
          adjacentPairsKept(
            items.map((item) => JSON.stringify(item)),
            got.map((item) => JSON.stringify(item)),
          ),
        ).toBe(1);
        expect(text).toBe(JSON.stringify(array));
      });
    }
  }
});
