/**
 * The response contract (docs/260828-query-layer-prompt.md §2).
 *
 * Under the code-as-content decision there is no tool-calling wire format, so
 * this parser *is* the interface between the model and the host. It is
 * deliberately strict and deliberately forgiving in exactly the ways the doc
 * specifies:
 *
 * - Every model turn must end with exactly one fenced block tagged `vana:run`
 *   (JavaScript) or `vana:answer` (JSON).
 * - Prose outside the block is ignored — logged, not parsed.
 * - The parser takes the **last** matching block. A model that reasons in
 *   prose, shows a draft, then commits to a final block is behaving correctly.
 *
 * Versioned because the prompt and the parser have to move together.
 */

import type { QueryCitation, QueryConfidence } from "./types.js";

/** Bump whenever the block grammar or the answer payload shape changes. */
export const RESPONSE_CONTRACT_VERSION = "vana-query/2";

export const RUN_TAG = "vana:run";
export const ANSWER_TAG = "vana:answer";

export interface ParsedRun {
  kind: "run";
  /** JavaScript body of the block, verbatim. */
  script: string;
}

export interface ParsedAnswer {
  kind: "answer";
  answer: string;
  citations: QueryCitation[];
  confidence?: QueryConfidence;
  /**
   * The bare number, when the question has a single numeric answer.
   *
   * Without it, grading falls back to pulling the first number out of the
   * prose, which read "30" out of a sentence about a 30-day window while the
   * model had computed the average correctly. An explicit value is the
   * difference between a gradeable answer and a guess about one.
   */
  value?: number;
  /**
   * How the model resolved the set it aggregated over.
   *
   * Measured cause of most remaining failures: the arithmetic is right and the
   * *set* is wrong. Q1 averaged the last full calendar month where the eval
   * means a trailing 31 days; Q14 resolved the trip window correctly and then
   * omitted the pre-trip flight; Q18 computed two defensible denominators and
   * headlined the wrong one. In each case the number was a faithful
   * computation over the wrong rows.
   *
   * Prompt rule 5 already required the model to state its resolution in prose.
   * Prose is not gradeable and it is not comparable across runs, so the
   * resolution is now a field of its own. Free text on purpose: the space of
   * "what set did you pick" is not enumerable, and forcing it into a schema
   * would push the model into inventing keys.
   */
  resolution?: string;
}

export type ContractViolation =
  | "no-block"
  | "unknown-tag"
  | "empty-block"
  | "answer-not-json"
  | "answer-not-object"
  | "answer-missing-answer-field"
  | "answer-bad-citations"
  | "answer-bad-confidence"
  | "answer-bad-value"
  | "answer-bad-resolution";

export interface ParseFailure {
  kind: "violation";
  violation: ContractViolation;
  /** Operator-facing detail. Safe to send back to the model as a repair. */
  detail: string;
}

export type ParsedTurn = ParsedRun | ParsedAnswer | ParseFailure;

interface FencedBlock {
  tag: string;
  body: string;
}

/**
 * Find fenced blocks, supporting both ``` and ~~~ fences and any fence length
 * of three or more. A block closes on the first fence of the *same character*
 * that is at least as long as its opener, which is what lets a `vana:run`
 * body legally contain a nested triple-backtick string.
 */
export function findFencedBlocks(text: string): FencedBlock[] {
  const blocks: FencedBlock[] = [];
  const lines = text.split(/\r?\n/);
  let i = 0;
  while (i < lines.length) {
    const open = /^\s*(`{3,}|~{3,})\s*([^\s`~]*)\s*$/.exec(lines[i] ?? "");
    if (!open) {
      i += 1;
      continue;
    }
    const fence = open[1] ?? "";
    const tag = open[2] ?? "";
    const char = fence[0] ?? "`";
    const minLen = fence.length;
    const body: string[] = [];
    let j = i + 1;
    let closed = false;
    while (j < lines.length) {
      const line = lines[j] ?? "";
      const close = new RegExp(`^\\s*(\\${char}{${minLen},})\\s*$`).exec(line);
      if (close) {
        closed = true;
        break;
      }
      body.push(line);
      j += 1;
    }
    // An unclosed fence still yields its body: a model that ran out of tokens
    // mid-block has still told us what it wanted to do, and the repair path
    // reads better than silently discarding it.
    blocks.push({ tag, body: body.join("\n") });
    i = closed ? j + 1 : j;
  }
  return blocks;
}

function readCitations(value: unknown): QueryCitation[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return null;
  const out: QueryCitation[] = [];
  for (const entry of value) {
    if (typeof entry === "string") {
      out.push({ scope: entry });
      continue;
    }
    if (entry === null || typeof entry !== "object") return null;
    const rec = entry as Record<string, unknown>;
    if (typeof rec.scope !== "string") return null;
    const citation: QueryCitation = { scope: rec.scope };
    if (typeof rec.recordId === "string") citation.recordId = rec.recordId;
    if (typeof rec.blockRef === "string") citation.blockRef = rec.blockRef;
    out.push(citation);
  }
  return out;
}

/**
 * `high`/`medium`/`low`, or a 0–1 number bucketed into them.
 *
 * Gemini answered `"confidence": 1.0` and it was silently dropped. Silently
 * discarding a field the model deliberately set is the wrong failure: either
 * understand it or refuse it. Anything that is neither a known word nor a
 * number in range returns `null`, which the caller turns into a contract
 * violation the repair retry can fix.
 */
function readConfidence(value: unknown): QueryConfidence | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (value === "high" || value === "medium" || value === "low") return value;
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value < 0 || value > 1) return null;
    return value >= 0.75 ? "high" : value >= 0.4 ? "medium" : "low";
  }
  return null;
}

/** A single numeric answer, when the model states one. */
function readValue(value: unknown): number | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  // A numeric string is a near miss worth accepting; anything else is a
  // violation rather than a silent drop.
  if (typeof value === "string" && value.trim() !== "") {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

/** How the model resolved an ambiguous set. Free text; must be non-empty. */
function readResolution(value: unknown): string | undefined | null {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed === "" ? null : trimmed;
}

/**
 * Parse one model turn. Never throws: a malformed turn is a `violation`, which
 * the loop turns into a single repair re-prompt (prompt doc §2).
 */
export function parseTurn(text: string): ParsedTurn {
  const blocks = findFencedBlocks(text);
  const tagged = blocks.filter(
    (b) => b.tag === RUN_TAG || b.tag === ANSWER_TAG,
  );

  if (tagged.length === 0) {
    const seen = blocks.map((b) => b.tag).filter((t) => t !== "");
    if (seen.length > 0) {
      return {
        kind: "violation",
        violation: "unknown-tag",
        detail: `found fenced block(s) tagged ${seen
          .map((t) => `\`${t}\``)
          .join(
            ", ",
          )}, but the only accepted tags are \`${RUN_TAG}\` and \`${ANSWER_TAG}\``,
      };
    }
    return {
      kind: "violation",
      violation: "no-block",
      detail: `no fenced block tagged \`${RUN_TAG}\` or \`${ANSWER_TAG}\` was found`,
    };
  }

  // The contract says the LAST matching block wins.
  const block = tagged[tagged.length - 1] as FencedBlock;

  if (block.body.trim() === "") {
    return {
      kind: "violation",
      violation: "empty-block",
      detail: `the \`${block.tag}\` block was empty`,
    };
  }

  if (block.tag === RUN_TAG) return { kind: "run", script: block.body };

  let parsed: unknown;
  try {
    parsed = JSON.parse(block.body);
  } catch (err) {
    return {
      kind: "violation",
      violation: "answer-not-json",
      detail: `the \`${ANSWER_TAG}\` body was not valid JSON (${
        err instanceof Error ? err.message : "parse error"
      })`,
    };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      kind: "violation",
      violation: "answer-not-object",
      detail: `the \`${ANSWER_TAG}\` body must be a JSON object`,
    };
  }
  const rec = parsed as Record<string, unknown>;
  if (typeof rec.answer !== "string" || rec.answer.trim() === "") {
    return {
      kind: "violation",
      violation: "answer-missing-answer-field",
      detail: `the \`${ANSWER_TAG}\` object needs a non-empty string \`answer\` field`,
    };
  }
  const citations = readCitations(rec.citations);
  if (citations === null) {
    return {
      kind: "violation",
      violation: "answer-bad-citations",
      detail:
        "`citations` must be an array of objects with a string `scope` (or an array of scope strings)",
    };
  }
  const out: ParsedAnswer = { kind: "answer", answer: rec.answer, citations };

  const confidence = readConfidence(rec.confidence);
  if (confidence === null) {
    return {
      kind: "violation",
      violation: "answer-bad-confidence",
      detail:
        '`confidence` must be "high", "medium" or "low" (a number from 0 to 1 is also accepted)',
    };
  }
  if (confidence) out.confidence = confidence;

  const value = readValue(rec.value);
  if (value === null) {
    return {
      kind: "violation",
      violation: "answer-bad-value",
      detail:
        "`value` must be a bare number — no units, no thousands separators, no formatting",
    };
  }
  if (value !== undefined) out.value = value;

  const resolution = readResolution(rec.resolution);
  if (resolution === null) {
    return {
      kind: "violation",
      violation: "answer-bad-resolution",
      detail:
        "`resolution` must be a non-empty string saying which set you aggregated over",
    };
  }
  if (resolution !== undefined) out.resolution = resolution;

  return out;
}

/**
 * The repair message. Names the violation and restates the grammar; sent once
 * (prompt doc §2). Kept short on purpose — it is prepended to a transcript that
 * is already close to the relay's body cap.
 */
export function repairMessage(failure: ParseFailure): string {
  return [
    `Your reply did not follow the response contract: ${failure.detail}.`,
    "",
    "Reply again, ending with exactly ONE fenced block:",
    "",
    "```" + RUN_TAG,
    "// JavaScript to execute",
    "```",
    "",
    "or, when you are done:",
    "",
    "```" + ANSWER_TAG,
    '{"answer": "...", "citations": [{"scope": "..."}], "confidence": "high",',
    ' "value": 1.23, "resolution": "which set you aggregated over"}',
    "```",
    "",
    "Anything outside the block is ignored. Do not explain this message.",
  ].join("\n");
}
