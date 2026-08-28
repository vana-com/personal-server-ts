/**
 * The wire format carrying a confined run's outcome out of the OS sandbox.
 *
 * ## Why a frame at all
 *
 * The capability layer (`runtime.ts`) now executes inside the OS sandbox
 * subprocess, so its host-authored coverage ledger has to cross a process
 * boundary to reach the host. Prompt contract §1 says the model may never
 * assert coverage, so that crossing must be one the model's code cannot
 * forge, suppress or corrupt.
 *
 * ## Why it is safe
 *
 * Model-authored code never touches this format. It runs inside the
 * tree-walking interpreter, which binds no `process`, no `require` and no
 * `globalThis`, and routes `console.log` to a host callback rather than to
 * the process's stdout. The only values it can push outward are the ones it
 * hands to `vana.note` and `vana.result` — and those travel as *fields inside*
 * the document below, base64-encoded along with everything else.
 *
 * Base64 is what makes that structural rather than merely conventional: the
 * base64 alphabet is `A-Za-z0-9+/=`, so an encoded payload can never contain
 * an underscore, and therefore can never reproduce the sentinel. A script that
 * emits the literal text of a sentinel through `vana.note` gets it encoded
 * away into the payload rather than closing or opening a frame.
 *
 * Decoding takes the **last** well-formed frame and **fails closed**: a
 * truncated, absent or unparseable frame yields no coverage at all, never a
 * partial reading that could look complete.
 *
 * Browser-safe: no Node built-ins. `packages/core` is imported by
 * `packages/lite`, and PS-Lite's worker path needs the same framing.
 */

import type { CoverageCounters, ScriptResult } from "./types.js";

export const RESULT_FRAME_BEGIN = "__VANA_RESULT_V1_BEGIN__";
export const RESULT_FRAME_END = "__VANA_RESULT_V1_END__";

/** What one confined run reports back to the host. */
export interface RunDocument {
  v: 1;
  coverage: CoverageCounters;
  result?: ScriptResult;
  notes: string[];
  toolCalls: number;
  classifyUsd: number;
  error?: { code: string; message: string };
}

/** UTF-8 safe base64, using only globals present in Node 18+ and browsers. */
function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  // Chunked: String.fromCharCode(...bytes) blows the argument limit on a
  // large document, and a large document is the normal case here.
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function fromBase64(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new TextDecoder().decode(bytes);
}

/** Serialize a run outcome for transport out of the sandbox. */
export function encodeResultFrame(doc: RunDocument): string {
  return `\n${RESULT_FRAME_BEGIN}${toBase64(JSON.stringify(doc))}${RESULT_FRAME_END}\n`;
}

export type DecodeOutcome =
  | { ok: true; doc: RunDocument }
  | { ok: false; reason: "absent" | "truncated" | "malformed" };

/**
 * Recover the run document from a sandbox's stdout.
 *
 * Takes the LAST complete frame — matching the response contract's
 * last-block-wins rule, and meaning a frame emitted by an earlier phase of the
 * same run cannot shadow the final one. Fails closed on anything unexpected.
 */
export function decodeResultFrame(stdout: string): DecodeOutcome {
  const begin = stdout.lastIndexOf(RESULT_FRAME_BEGIN);
  if (begin === -1) return { ok: false, reason: "absent" };
  const from = begin + RESULT_FRAME_BEGIN.length;
  const end = stdout.indexOf(RESULT_FRAME_END, from);
  // A begin with no end means output was cut mid-frame — almost always the
  // host's own `maxOutputBytes` kill. Never try to salvage a partial payload.
  if (end === -1) return { ok: false, reason: "truncated" };

  try {
    const parsed: unknown = JSON.parse(fromBase64(stdout.slice(from, end)));
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      (parsed as RunDocument).v !== 1 ||
      typeof (parsed as RunDocument).coverage !== "object" ||
      (parsed as RunDocument).coverage === null
    ) {
      return { ok: false, reason: "malformed" };
    }
    return { ok: true, doc: parsed as RunDocument };
  } catch {
    return { ok: false, reason: "malformed" };
  }
}

/**
 * Remove every frame from output destined for the model.
 *
 * The frame is host bookkeeping; showing it to the model wastes context and
 * invites it to imitate the format.
 */
export function stripResultFrames(stdout: string): string {
  let out = "";
  let cursor = 0;
  for (;;) {
    const begin = stdout.indexOf(RESULT_FRAME_BEGIN, cursor);
    if (begin === -1) {
      out += stdout.slice(cursor);
      return out.trim();
    }
    out += stdout.slice(cursor, begin);
    const end = stdout.indexOf(RESULT_FRAME_END, begin);
    // Unterminated frame: drop the remainder, it is a truncated payload.
    if (end === -1) return out.trim();
    cursor = end + RESULT_FRAME_END.length;
  }
}
