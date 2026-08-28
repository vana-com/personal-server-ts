/**
 * Agentic mode for the derivative compute layer: instead of one completion
 * over newest-first trimmed sources, run a bounded tool loop where the model
 * searches the FULL sources through a per-compute, in-memory keyword index.
 *
 * Everything here executes inside the Personal Server. The model sees the
 * question, the snippets `search_data` returns and the passages it chooses
 * to `read_data` — never the corpus, never the index. The index lives for
 * one compute and is discarded — nothing is stored, synced or granted.
 *
 * See docs/derivative-data-api.md, "Agentic mode".
 */

import MiniSearch from "minisearch";
import type {
  InferenceChatInput,
  InferenceChatResult,
  InferenceMessage,
  InferenceProvider,
  InferenceToolDef,
} from "./inference.js";

export const DEFAULT_MAX_TOOL_CALLS = 6;
/** Passage windows the index scores; long items split into these. */
const PASSAGE_CHARS = 1_600;
/** Snippet length `search_data` returns per hit. */
const SNIPPET_CHARS = 240;
const SEARCH_TOP_K = 8;
/** `read_data` reply bound. */
const READ_CHARS = 6_000;
/** Bound on any single tool result fed back to the model. */
const TOOL_RESULT_CHARS = 8_000;
/** Bound on the total text a corpus indexes; items past it are dropped. */
const MAX_CORPUS_CHARS = 20_000_000;

/** Envelope keys and common metadata keys that are not searchable content. */
const RESERVED_KEYS = new Set(["$lineage", "$writtenBy", "$binary"]);
const METADATA_KEYS = new Set([
  "id",
  "uuid",
  "fetched_at",
  "collectedAt",
  "model",
  "content_type",
  "version",
  "scope",
  "asset_id",
  "type",
]);
/**
 * A string that is ONLY a timestamp ("2026-05-01T09:00:00Z"). A date-prefixed
 * sentence ("2026-05-01 met the cardiologist") is real content and stays.
 */
const PURE_TIMESTAMP = /^\d{4}-\d{2}-\d{2}([T ][0-9:.,+\-Z]*)?$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** String leaves of one item, skipping metadata keys and pure timestamps. */
function harvestText(value: unknown, depth = 0): string {
  if (depth > 12) return "";
  if (typeof value === "string") {
    return PURE_TIMESTAMP.test(value.trim()) ? "" : value;
  }
  if (Array.isArray(value)) {
    return value
      .map((entry) => harvestText(entry, depth + 1))
      .filter(Boolean)
      .join("\n");
  }
  if (isRecord(value)) {
    return Object.entries(value)
      .filter(([key]) => !METADATA_KEYS.has(key) && !RESERVED_KEYS.has(key))
      .map(([, entry]) => harvestText(entry, depth + 1))
      .filter(Boolean)
      .join("\n");
  }
  return "";
}

export interface CorpusPassage {
  /** Stable within one compute: `<scope>#<item>#<window>`. */
  ref: string;
  scope: string;
  /** Key of the source item this window belongs to. */
  itemKey: string;
  text: string;
}

export interface SearchCorpus {
  search(query: string): Array<{
    ref: string;
    scope: string;
    snippet: string;
  }>;
  /** Full text of the ITEM a passage belongs to, bounded to READ_CHARS. */
  read(ref: string): string | null;
  readonly passageCount: number;
  /** True when MAX_CORPUS_CHARS cut indexing short. */
  readonly truncated: boolean;
}

/** `<scope>#<item>` and the window number out of a passage ref. */
function splitRef(ref: string): { itemKey: string; window: number } {
  const parts = ref.split("#");
  return {
    itemKey: parts.slice(0, 2).join("#"),
    window: Number(parts[2] ?? 0) || 0,
  };
}

/**
 * Build the per-compute index. Each source's `data` contributes its
 * top-level array items (a bare array, or every top-level array value of a
 * record — same shape `trimSourceData` understands); a source with no
 * arrays contributes one item. Items are harvested to text and split into
 * bounded windows. Text is held ONCE (the item map); the index stores refs
 * only and passage text is reconstructed by offset.
 */
export function buildSearchCorpus(
  sources: ReadonlyArray<{ scope: string; data: unknown }>,
): SearchCorpus {
  const passages: CorpusPassage[] = [];
  const itemText = new Map<string, string>();
  let indexedChars = 0;
  let truncated = false;

  const addItem = (scope: string, key: string, item: unknown): void => {
    if (truncated) return;
    const text = harvestText(item).trim();
    if (text === "") return;
    if (indexedChars + text.length > MAX_CORPUS_CHARS) {
      truncated = true;
      return;
    }
    indexedChars += text.length;
    const itemKey = `${scope}#${key}`;
    itemText.set(itemKey, text);
    for (let offset = 0; offset < text.length; offset += PASSAGE_CHARS) {
      passages.push({
        ref: `${itemKey}#${offset / PASSAGE_CHARS}`,
        scope,
        itemKey,
        text: text.slice(offset, offset + PASSAGE_CHARS),
      });
    }
  };

  for (const source of sources) {
    const { scope, data } = source;
    if (Array.isArray(data)) {
      data.forEach((item, index) => addItem(scope, String(index), item));
    } else if (isRecord(data)) {
      let hadArray = false;
      for (const [key, value] of Object.entries(data)) {
        if (RESERVED_KEYS.has(key)) continue;
        if (Array.isArray(value)) {
          hadArray = true;
          value.forEach((item, index) =>
            addItem(scope, `${key}[${index}]`, item),
          );
        }
      }
      if (!hadArray) addItem(scope, "record", data);
    } else {
      addItem(scope, "record", data);
    }
  }

  // Text lives once in itemText: the index stores only refs, and the passage
  // objects are released after addAll.
  const index = new MiniSearch<CorpusPassage>({
    idField: "ref",
    fields: ["text"],
    storeFields: ["ref", "scope"],
    searchOptions: { prefix: (term: string) => term.length >= 4 },
  });
  index.addAll(passages);
  passages.length = 0;

  const passageText = (ref: string): string => {
    const { itemKey, window } = splitRef(ref);
    const text = itemText.get(itemKey) ?? "";
    return text.slice(window * PASSAGE_CHARS, (window + 1) * PASSAGE_CHARS);
  };

  return {
    passageCount: index.documentCount,
    truncated,
    search(query) {
      return index
        .search(query)
        .slice(0, SEARCH_TOP_K)
        .map((hit) => {
          const ref = String(hit.id);
          const text = passageText(ref);
          // Center the snippet on the first matched term so the model sees
          // WHY this passage hit, not whatever the window starts with.
          const lower = text.toLowerCase();
          let at = -1;
          for (const term of hit.terms) {
            const found = lower.indexOf(term.toLowerCase());
            if (found >= 0 && (at === -1 || found < at)) at = found;
          }
          const start = at > 60 ? at - 60 : 0;
          return {
            ref,
            scope: (hit as unknown as { scope: string }).scope,
            snippet: text.slice(start, start + SNIPPET_CHARS),
          };
        });
    },
    read(ref) {
      const { itemKey } = splitRef(ref);
      const text = itemText.get(itemKey);
      return text ? text.slice(0, READ_CHARS) : null;
    },
  };
}

const AGENTIC_SYSTEM_PROMPT = [
  "You answer a question about a person using ONLY their data, which you reach through the tools.",
  "search_data is keyword search: it matches literal words only. Vary phrasings, try synonyms, and if the data may be in another language, translate the key terms and search again.",
  "Use read_data when a search hit looks relevant but its snippet does not show the answer.",
  "Do not use outside knowledge and do not guess; if the data does not support an answer, say so in the answer.",
  `You may use at most ${DEFAULT_MAX_TOOL_CALLS} tool calls total. Stop early once you have the answer.`,
  "When you are done, respond with a single JSON object and nothing else, with exactly these fields:",
  '  "answer": string, the answer to the question, written for the person the data belongs to;',
  '  "evidence": string, a short summary of which parts of the data support the answer.',
].join("\n");

const TOOL_DEFS: InferenceToolDef[] = [
  {
    name: "search_data",
    description:
      "Keyword (BM25) search over the person's data. Returns the top matching passages with a ref, their scope and a snippet.",
    parameters: {
      type: "object",
      properties: { query: { type: "string" } },
      required: ["query"],
      additionalProperties: false,
    },
  },
  {
    name: "read_data",
    description:
      "Read the full text of the source item a search ref belongs to (bounded).",
    parameters: {
      type: "object",
      properties: { ref: { type: "string" } },
      required: ["ref"],
      additionalProperties: false,
    },
  },
];

export interface AgenticLoopInput {
  provider: InferenceProvider;
  model: string;
  question: string;
  corpus: SearchCorpus;
  maxToolCalls?: number;
  maxTokens?: number;
  /**
   * Wraps every provider call (retry-with-backoff lives here, so a transient
   * failure retries ONE call, never the whole loop with its tool budget).
   */
  retry?: <T>(attempt: () => Promise<T>) => Promise<T>;
  /** Extra context appended to the question (e.g. withheld binary sources). */
  contextNote?: string;
}

export interface AgenticLoopResult {
  /** The final assistant text, parsed by the caller like completion mode. */
  content: string;
  toolCalls: number;
  receiptId?: string;
  aciIdentity?: string;
}

function executeToolCall(
  corpus: SearchCorpus,
  name: string,
  rawArguments: string,
): string {
  let args: Record<string, unknown> = {};
  try {
    const parsed: unknown = JSON.parse(rawArguments);
    if (isRecord(parsed)) args = parsed;
  } catch {
    return "error: tool arguments were not valid JSON";
  }
  if (name === "search_data") {
    const query = typeof args.query === "string" ? args.query : "";
    if (query.trim() === "") return "error: query must be a non-empty string";
    const hits = corpus.search(query);
    return hits.length === 0
      ? "no results — try different or translated terms"
      : JSON.stringify(hits);
  }
  if (name === "read_data") {
    const ref = typeof args.ref === "string" ? args.ref : "";
    const text = corpus.read(ref);
    return text ?? "error: unknown ref";
  }
  return `error: unknown tool ${name}`;
}

/**
 * The loop. Bounded three ways: `maxToolCalls` tool executions (further
 * requested calls are answered with a refusal), at most budget + 2
 * tool-bearing provider turns plus one final forced answer turn, and every
 * tool result cut to a fixed size. A loop that ends while the model is
 * still requesting tools gets ONE tools-free turn to answer; interim
 * narration is never the answer. Throws what the provider throws; the
 * caller (computeQuestion) owns failure accounting.
 */
export async function runAgenticLoop(
  input: AgenticLoopInput,
): Promise<AgenticLoopResult> {
  const budget = Math.max(1, input.maxToolCalls ?? DEFAULT_MAX_TOOL_CALLS);
  const chat = (args: InferenceChatInput): Promise<InferenceChatResult> =>
    input.retry
      ? input.retry(() => input.provider.chat(args))
      : input.provider.chat(args);
  const question =
    `## Question\n${input.question}` +
    (input.contextNote ? `\n\nNote: ${input.contextNote}` : "");
  const messages: InferenceMessage[] = [
    { role: "system", content: AGENTIC_SYSTEM_PROMPT },
    { role: "user", content: question },
  ];
  let executed = 0;
  let last: InferenceChatResult | null = null;
  let answered = false;
  for (let turn = 0; turn < budget + 2; turn += 1) {
    const reply = await chat({
      model: input.model,
      messages,
      maxTokens: input.maxTokens,
      tools: TOOL_DEFS,
    });
    last = reply;
    const calls = reply.toolCalls ?? [];
    if (calls.length === 0) {
      answered = true;
      break;
    }
    messages.push({
      role: "assistant",
      content: reply.content,
      toolCalls: calls,
    });
    for (const call of calls) {
      const overBudget = executed >= budget;
      if (!overBudget) executed += 1;
      const result = overBudget
        ? "tool budget exhausted — answer now from the information you already have"
        : executeToolCall(input.corpus, call.name, call.arguments);
      messages.push({
        role: "tool",
        content: result.slice(0, TOOL_RESULT_CHARS),
        toolCallId: call.id,
      });
    }
  }
  if (!answered) {
    // Turn cap hit with tools still being requested: one forced answer turn
    // with no tools on offer. Its reply is the answer or the compute fails;
    // the interim narration in `last` is never used.
    messages.push({
      role: "user",
      content:
        "The tool budget is exhausted. Reply now with only the final JSON object.",
    });
    last = await chat({
      model: input.model,
      messages,
      maxTokens: input.maxTokens,
    });
  }
  return {
    content: last?.content ?? "",
    toolCalls: executed,
    ...(last?.receiptId ? { receiptId: last.receiptId } : {}),
    ...(last?.aciIdentity ? { aciIdentity: last.aciIdentity } : {}),
  };
}
