/**
 * Prompt assembly for a question: the source scopes' latest local records,
 * trimmed newest-first to a bounded number of items each, framed by a system
 * prompt that pins the model to the provided data and to a JSON answer.
 *
 * Nothing here leaves the Personal Server except through the inference
 * provider call the compute step makes.
 */

import type { InferenceMessage } from "./inference.js";

export const DEFAULT_MAX_SOURCE_ITEMS = 50;
/** Upper bound on the serialized size of one source's trimmed data. */
export const DEFAULT_MAX_SOURCE_CHARS = 200_000;

/** Keys a record commonly carries its own timestamp under, in priority order. */
const TIMESTAMP_KEYS = [
  "collectedAt",
  "updatedAt",
  "updated_at",
  "update_time",
  "createdAt",
  "created_at",
  "create_time",
  "timestamp",
  "time",
  "date",
  "publishedAt",
  "published_at",
];

/** Server-stamped envelope keys that are not user data. */
const RESERVED_KEYS = new Set(["$lineage", "$writtenBy", "$binary"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function timestampOf(item: unknown): number | null {
  if (!isRecord(item)) return null;
  for (const key of TIMESTAMP_KEYS) {
    const value = item[key];
    if (typeof value === "number" && Number.isFinite(value)) {
      // Seconds vs milliseconds: anything below 1e12 is taken as seconds.
      return value < 1e12 ? value * 1000 : value;
    }
    if (typeof value === "string") {
      const parsed = Date.parse(value);
      if (!Number.isNaN(parsed)) return parsed;
    }
  }
  return null;
}

/**
 * Newest first. Items that carry a timestamp sort by it; items that do not
 * keep their relative order after the timestamped ones, reversed, on the
 * assumption that a connector appends newest last. Stable.
 */
export function sortNewestFirst<T>(items: readonly T[]): T[] {
  const indexed = items.map((item, index) => ({
    item,
    index,
    at: timestampOf(item),
  }));
  const dated = indexed
    .filter((entry) => entry.at !== null)
    .sort((a, b) => b.at! - a.at! || b.index - a.index);
  const undated = indexed.filter((entry) => entry.at === null).reverse();
  return [...dated, ...undated].map((entry) => entry.item);
}

export interface TrimResult {
  data: unknown;
  /** Items kept / items present, summed over every array that was trimmed. */
  kept: number;
  total: number;
  /** True when the char cap cut the serialization. */
  truncated: boolean;
}

/**
 * The trim rule. A record whose `data` is an array is trimmed to the newest
 * `maxItems`; a record object trims every top-level array value the same
 * way and keeps its other keys; reserved server keys are dropped. When the
 * serialized result still exceeds `maxChars`, items are dropped from the
 * old end until it fits (at least one is kept), and as a last resort the
 * serialization itself is cut at `maxChars`.
 */
export function trimSourceData(
  data: unknown,
  options: { maxItems?: number; maxChars?: number } = {},
): TrimResult {
  const maxItems = Math.max(1, options.maxItems ?? DEFAULT_MAX_SOURCE_ITEMS);
  const maxChars = Math.max(1, options.maxChars ?? DEFAULT_MAX_SOURCE_CHARS);

  let kept = 0;
  let total = 0;
  const trimArray = (items: readonly unknown[], limit: number): unknown[] => {
    total += items.length;
    const sorted = sortNewestFirst(items).slice(0, limit);
    kept += sorted.length;
    return sorted;
  };

  const build = (limit: number): unknown => {
    kept = 0;
    total = 0;
    if (Array.isArray(data)) return trimArray(data, limit);
    if (isRecord(data)) {
      const out: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(data)) {
        if (RESERVED_KEYS.has(key)) continue;
        out[key] = Array.isArray(value) ? trimArray(value, limit) : value;
      }
      return out;
    }
    return data;
  };

  let limit = maxItems;
  let result = build(limit);
  let text = JSON.stringify(result) ?? "null";
  // Shrink the item budget while the serialization is over the cap. Each
  // pass at least halves the budget, so this ends in O(log maxItems) steps.
  while (text.length > maxChars && limit > 1) {
    limit = Math.max(1, Math.floor(limit / 2));
    result = build(limit);
    text = JSON.stringify(result) ?? "null";
  }
  if (text.length > maxChars) {
    return {
      data: `${text.slice(0, maxChars)}...[truncated]`,
      kept,
      total,
      truncated: true,
    };
  }
  return { data: result, kept, total, truncated: false };
}

export interface PromptSource {
  scope: string;
  collectedAt: string;
  version: number;
  data: unknown;
  kept: number;
  total: number;
  truncated: boolean;
}

export const SYSTEM_PROMPT = [
  "You answer a question about a person using ONLY the user data provided in the message.",
  "Do not use outside knowledge and do not guess; if the data does not support an answer, say so in the answer.",
  "Respond with a single JSON object and nothing else, with exactly these fields:",
  '  "answer": string, the answer to the question, written for the person the data belongs to;',
  '  "evidence": string, a short summary of which parts of the data support the answer.',
].join("\n");

/** Assemble the chat messages for one compute. */
export function buildQuestionMessages(input: {
  question: string;
  sources: readonly PromptSource[];
}): InferenceMessage[] {
  const sections = input.sources.map((source) => {
    const note =
      source.total > source.kept
        ? ` (newest ${source.kept} of ${source.total} items)`
        : "";
    const cut = source.truncated ? " (truncated)" : "";
    return [
      `### Scope: ${source.scope}${note}${cut}`,
      `Collected at: ${source.collectedAt}`,
      JSON.stringify(source.data),
    ].join("\n");
  });
  const user = [
    "## Question",
    input.question,
    "",
    "## User data",
    ...sections,
    "",
    "Answer the question as a JSON object with the fields answer and evidence.",
  ].join("\n");
  return [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: user },
  ];
}

export interface ParsedAnswer {
  answer: string;
  evidence: string | null;
}

/**
 * Read the model's JSON answer. Tolerates a fenced code block or leading
 * prose around the object; falls back to the whole text as the answer when
 * no object can be parsed (the answer is still the model's, just unframed).
 */
export function parseAnswer(content: string): ParsedAnswer {
  const candidates: string[] = [content.trim()];
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(content);
  if (fenced?.[1]) candidates.unshift(fenced[1].trim());
  const first = content.indexOf("{");
  const last = content.lastIndexOf("}");
  if (first !== -1 && last > first) {
    candidates.push(content.slice(first, last + 1));
  }
  for (const candidate of candidates) {
    try {
      const parsed: unknown = JSON.parse(candidate);
      if (isRecord(parsed) && typeof parsed.answer === "string") {
        return {
          answer: parsed.answer,
          evidence:
            typeof parsed.evidence === "string" ? parsed.evidence : null,
        };
      }
    } catch {
      // try the next framing
    }
  }
  return { answer: content.trim(), evidence: null };
}
