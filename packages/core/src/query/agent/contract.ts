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
export const RESPONSE_CONTRACT_VERSION = "vana-query/1";

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
}

export type ContractViolation =
  | "no-block"
  | "unknown-tag"
  | "empty-block"
  | "answer-not-json"
  | "answer-not-object"
  | "answer-missing-answer-field"
  | "answer-bad-citations";

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

function readConfidence(value: unknown): QueryConfidence | undefined {
  return value === "high" || value === "medium" || value === "low"
    ? value
    : undefined;
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
  if (confidence) out.confidence = confidence;
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
    '{"answer": "...", "citations": [{"scope": "..."}], "confidence": "high"}',
    "```",
    "",
    "Anything outside the block is ignored. Do not explain this message.",
  ].join("\n");
}
