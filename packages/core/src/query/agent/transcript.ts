/**
 * Transcript budgeting for the code-as-content loop.
 *
 * WHY THIS EXISTS, AND WHY IT IS NOT THE SANDBOX'S `maxOutputBytes`:
 *
 * The Vana inference relay (`../data-gateway`) caps a request body at
 * `INFERENCE_MAX_BODY_BYTES` = 2 MiB. Phala's own cap is 32 MiB, so ours is
 * the binding one. A code-as-content loop feeds script output back as the next
 * message's *content*, and the request body carries the whole transcript on
 * every turn — so the cost is cumulative, not per-turn. With `maxToolCalls`
 * defaulting to 50, a naive "8KB per turn" rule still walks into a 413 once
 * assistant scripts are counted.
 *
 * So there are two independent budgets:
 *
 *   sandbox `maxOutputBytes` (1MB default) — how much a script may PRODUCE
 *   this module's budget                   — how much we may SEND BACK
 *
 * A 413 from the relay would fail the whole run, so truncation here is
 * mandatory and must be visible: the model is told its output was cut, and the
 * fact is recorded rather than silently swallowed.
 */

import type { InferenceMessage } from "../../derivatives/inference.js";

/** The relay's body cap. Ours, not Phala's — ours is the binding one. */
export const RELAY_MAX_BODY_BYTES = 2 * 1024 * 1024;

/**
 * Headroom under the relay cap for JSON overhead, the E2EE ciphertext
 * expansion (base64 of AES-GCM output, ~4/3 plus tag and nonce), the model
 * name and routing fields. E2EE is on by default, so the encoded body is
 * meaningfully larger than the plaintext we measure here.
 */
export const TRANSCRIPT_SAFETY_FACTOR = 0.5;

/** Default ceiling on the plaintext transcript we will assemble. */
export const DEFAULT_TRANSCRIPT_BUDGET_BYTES = Math.floor(
  RELAY_MAX_BODY_BYTES * TRANSCRIPT_SAFETY_FACTOR,
);

/**
 * Per-turn cap on script output fed back to the model. Prompt doc §6 suggests
 * starting with the last 8KB plus any `vana.note` output, tuned against the
 * graded set rather than guessed here.
 */
export const DEFAULT_OUTPUT_TAIL_BYTES = 8 * 1024;

const encoder = new TextEncoder();

export function byteLength(text: string): number {
  return encoder.encode(text).length;
}

export function transcriptBytes(messages: InferenceMessage[]): number {
  let total = 0;
  for (const m of messages) total += byteLength(m.content) + m.role.length + 8;
  return total;
}

export interface TruncationNote {
  /** Bytes dropped from the middle of the payload. */
  droppedBytes: number;
}

/**
 * Keep the head and the tail of a script's output, dropping the middle.
 *
 * Head and tail both matter and for different reasons: an exception's stack
 * lands at the end, while a script that logged its record counts first puts the
 * coverage-shaped facts at the beginning. Dropping only the head would hide the
 * denominator the answer is required to state.
 */
export function truncateOutput(
  output: string,
  maxBytes: number = DEFAULT_OUTPUT_TAIL_BYTES,
): { text: string; truncation?: TruncationNote } {
  const size = byteLength(output);
  if (size <= maxBytes) return { text: output };

  // Two thirds tail, one third head: errors and final results are commoner at
  // the end than the setup is at the start.
  const tailBudget = Math.floor((maxBytes * 2) / 3);
  const headBudget = maxBytes - tailBudget;

  const head = sliceBytes(output, headBudget, "head");
  const tail = sliceBytes(output, tailBudget, "tail");
  const dropped = size - byteLength(head) - byteLength(tail);

  return {
    text:
      head +
      `\n\n… [${dropped.toLocaleString("en-US")} bytes of output omitted by the host] …\n\n` +
      tail,
    truncation: { droppedBytes: dropped },
  };
}

/** Slice on a UTF-8 boundary so a multi-byte character is never split. */
function sliceBytes(
  text: string,
  maxBytes: number,
  from: "head" | "tail",
): string {
  if (byteLength(text) <= maxBytes) return text;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const candidate =
      from === "head" ? text.slice(0, mid) : text.slice(text.length - mid);
    if (byteLength(candidate) <= maxBytes) lo = mid;
    else hi = mid - 1;
  }
  return from === "head" ? text.slice(0, lo) : text.slice(text.length - lo);
}

/**
 * Render one script run's result as the user message that goes back to the
 * model. Notes are never truncated away — they are the model's own deliberate
 * signal and are cheap — and the truncation is stated inline so the model knows
 * it is looking at a partial view.
 */
export function renderRunResult(input: {
  stdout: string;
  stderr: string;
  notes: string[];
  termination: string;
  truncatedByHost: boolean;
  maxBytes?: number;
  /**
   * A confinement denial, budget exhaustion or script error, surfaced to the
   * model verbatim. The confined interpreter supports a deliberate subset of
   * JS and fails closed on the rest, so a model that writes a `class` or a
   * generator gets `CONFINEMENT_VIOLATION` — and it can only correct that if
   * it is told which construct was refused. Without this the model burns its
   * one repair attempt on a mystery.
   */
  error?: { code: string; message: string };
}): { content: string; truncation?: TruncationNote } {
  const sections: string[] = [];

  if (input.error) {
    sections.push(
      `Your script did not complete — ${input.error.code}: ${input.error.message}`,
    );
  }

  if (input.notes.length > 0) {
    sections.push("Notes:\n" + input.notes.map((n) => `- ${n}`).join("\n"));
  }

  const combined = [
    input.stdout.trim() === "" ? "" : `stdout:\n${input.stdout}`,
    input.stderr.trim() === "" ? "" : `stderr:\n${input.stderr}`,
  ]
    .filter((s) => s !== "")
    .join("\n\n");

  const { text, truncation } = truncateOutput(
    combined === "" ? "(no output)" : combined,
    input.maxBytes ?? DEFAULT_OUTPUT_TAIL_BYTES,
  );
  sections.push(text);

  if (input.termination !== "completed") {
    sections.push(
      `The run ended early: ${input.termination}. Any figure computed from a partial run must be reported as partial.`,
    );
  }
  if (input.truncatedByHost) {
    sections.push(
      "Your script's output hit the host's output cap and was cut. Print less — aggregate in code and print the result, not the rows.",
    );
  }

  const out: { content: string; truncation?: TruncationNote } = {
    content: sections.join("\n\n"),
  };
  if (truncation) out.truncation = truncation;
  return out;
}

/**
 * Drop the oldest run-result messages when the transcript approaches the relay
 * cap, keeping the system prompt, the question, and the most recent exchanges.
 *
 * A dropped turn is replaced by a marker rather than removed silently: the
 * model must not believe it has the full history when it does not — the same
 * honesty rule the coverage invariant applies to data.
 */
export function fitTranscript(
  messages: InferenceMessage[],
  budgetBytes: number = DEFAULT_TRANSCRIPT_BUDGET_BYTES,
): { messages: InferenceMessage[]; droppedTurns: number } {
  if (transcriptBytes(messages) <= budgetBytes) {
    return { messages, droppedTurns: 0 };
  }
  // Always keep messages[0] (system) and messages[1] (the question).
  const preserved = messages.slice(0, 2);
  const rest = messages.slice(2);
  const kept: InferenceMessage[] = [];
  let used = transcriptBytes(preserved);
  let dropped = 0;

  // Walk backwards: recent turns are the ones the model is reasoning from.
  for (let i = rest.length - 1; i >= 0; i -= 1) {
    const m = rest[i] as InferenceMessage;
    const cost = byteLength(m.content) + m.role.length + 8;
    if (used + cost > budgetBytes && kept.length > 0) {
      dropped = i + 1;
      break;
    }
    used += cost;
    kept.unshift(m);
  }

  if (dropped === 0) return { messages, droppedTurns: 0 };

  const marker: InferenceMessage = {
    role: "user",
    content: `[${dropped} earlier turn(s) were dropped by the host to stay under the relay's request-size limit. You are not seeing the full history. Do not restate conclusions you can no longer verify — re-derive them or say they are unverified.]`,
  };
  return { messages: [...preserved, marker, ...kept], droppedTurns: dropped };
}
