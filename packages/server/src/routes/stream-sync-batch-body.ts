/**
 * Read a run-intake batch body, `{"batch": n, "records": [...]}`, as a stream.
 *
 * The body is never held whole. A byte scanner finds the top-level members and
 * the elements of `records` without parsing them, and hands out one element's
 * text at a time. Each element is parsed on its own and released, so the
 * memory for a batch is that of its largest record, not the batch.
 *
 * Member order is free. If `records` comes before `batch`, the raw text of
 * those elements wait (unparsed) until `batch` arrives, which is the cost the
 * old route paid for every batch.
 */

import { RunIntakeError } from "@opendatalabs/personal-server-ts-core/stream-sync";

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COMMA = 0x2c;
const COLON = 0x3a;
const LBRACE = 0x7b;
const RBRACE = 0x7d;
const LBRACKET = 0x5b;
const RBRACKET = 0x5d;

const isSpace = (b: number) =>
  b === 0x20 || b === 0x0a || b === 0x0d || b === 0x09;

function bad(message: string): RunIntakeError {
  return new RunIntakeError("invalid_request", message);
}

type Event =
  | { readonly t: "member"; readonly key: string; readonly text: string }
  | { readonly t: "record"; readonly text: string }
  | { readonly t: "records_end" };

type S =
  | "start"
  | "keyStart"
  | "inKey"
  | "colon"
  | "valueStart"
  | "value"
  | "afterMember"
  | "arrayStart"
  | "elementStart"
  | "element"
  | "done";

/** Top-level members and `records` elements of one JSON object, as text. */
async function* scan(
  chunks: AsyncIterable<Uint8Array>,
  limit: number,
): AsyncGenerator<Event> {
  let state: S = "start";
  let key = "";
  let keyParts: number[] = [];
  let keyEscape = false;
  // The value being collected.
  let parts: string[] = [];
  let valueDecoder = new TextDecoder("utf-8", { fatal: true });
  let depth = 0;
  let inString = false;
  let escape = false;
  let total = 0;
  let arrays = 0;
  const out: Event[] = [];

  // Bytes are decoded as they arrive, so the raw bytes of a large value are
  // released piece by piece and only its text is held.
  const addPiece = (piece: Uint8Array, last: boolean) => {
    try {
      parts.push(valueDecoder.decode(piece, { stream: !last }));
    } catch {
      throw bad("the body is not valid UTF-8");
    }
  };
  const finishValue = (): string => {
    const text = parts.length === 1 ? parts[0]! : parts.join("");
    parts = [];
    valueDecoder = new TextDecoder("utf-8", { fatal: true });
    depth = 0;
    inString = false;
    escape = false;
    return text;
  };

  for await (const chunk of chunks) {
    total += chunk.length;
    if (total > limit) throw bad("the body is over the request limit");
    let segment = -1; // start of the pending slice of this chunk, or -1
    for (let i = 0; i < chunk.length; i += 1) {
      const b = chunk[i]!;
      switch (state) {
        case "start":
          if (isSpace(b)) break;
          if (b !== LBRACE) throw bad("the body is not a JSON object");
          state = "keyStart";
          break;
        case "keyStart":
          if (isSpace(b)) break;
          if (b === RBRACE) {
            state = "done";
            break;
          }
          if (b !== QUOTE) throw bad("the body is not valid JSON");
          keyParts = [];
          keyEscape = false;
          state = "inKey";
          break;
        case "inKey":
          if (keyEscape) {
            keyParts.push(b);
            keyEscape = false;
          } else if (b === BACKSLASH) {
            keyParts.push(b);
            keyEscape = true;
          } else if (b === QUOTE) {
            try {
              key = JSON.parse(
                `"${new TextDecoder().decode(Uint8Array.from(keyParts))}"`,
              ) as string;
            } catch {
              throw bad("the body is not valid JSON");
            }
            state = "colon";
          } else {
            keyParts.push(b);
            if (keyParts.length > 4096) throw bad("a key is too long");
          }
          break;
        case "colon":
          if (isSpace(b)) break;
          if (b !== COLON) throw bad("the body is not valid JSON");
          state = "valueStart";
          break;
        case "valueStart":
          if (isSpace(b)) break;
          if (key === "records" && b === LBRACKET) {
            if (arrays > 0) throw bad("records appear twice");
            arrays += 1;
            state = "arrayStart";
            break;
          }
          state = "value";
          segment = i;
          i -= 1; // reread this byte as the first byte of the value
          break;
        case "arrayStart":
          if (isSpace(b)) break;
          if (b === RBRACKET) {
            out.push({ t: "records_end" });
            state = "afterMember";
            break;
          }
          state = "element";
          segment = i;
          i -= 1;
          break;
        case "elementStart":
          if (isSpace(b)) break;
          state = "element";
          segment = i;
          i -= 1;
          break;
        case "value":
        case "element": {
          if (segment < 0) segment = i;
          let ended = false;
          if (inString) {
            if (escape) escape = false;
            else if (b === BACKSLASH) escape = true;
            else if (b === QUOTE) inString = false;
          } else if (b === QUOTE) inString = true;
          else if (b === LBRACE || b === LBRACKET) depth += 1;
          else if (b === RBRACE || b === RBRACKET) {
            if (depth > 0) depth -= 1;
            else if (state === "value" ? b === RBRACE : true) ended = true;
            else throw bad("the body is not valid JSON");
          } else if (b === COMMA && depth === 0) ended = true;
          if (!ended) break;
          const piece = chunk.subarray(segment, i);
          segment = -1;
          addPiece(piece, true);
          const text = finishValue();
          if (state === "value") {
            out.push({ t: "member", key, text });
            if (b === COMMA) state = "keyStart";
            else state = "done";
          } else if (b === COMMA) {
            out.push({ t: "record", text });
            state = "elementStart";
          } else if (b === RBRACKET) {
            out.push({ t: "record", text });
            out.push({ t: "records_end" });
            state = "afterMember";
          } else {
            throw bad("the body is not valid JSON");
          }
          break;
        }
        case "afterMember":
          if (isSpace(b)) break;
          if (b === COMMA) state = "keyStart";
          else if (b === RBRACE) state = "done";
          else throw bad("the body is not valid JSON");
          break;
        case "done":
          if (!isSpace(b)) throw bad("the body has data after the object");
          break;
      }
    }
    if (segment >= 0) {
      const piece = chunk.subarray(segment);
      addPiece(piece, false);
    }
    while (out.length > 0) yield out.shift()!;
  }
  if (state !== "done") throw bad("the body ended early");
}

function parse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw bad("the body is not JSON");
  }
}

export interface BatchBody {
  readonly batch: unknown;
  /** Each record parsed alone, released when the caller moves on. */
  readonly records: AsyncGenerator<unknown>;
}

/** Read until `batch` is known; the records follow as a stream. */
export async function openBatchBody(
  chunks: AsyncIterable<Uint8Array>,
  limit: number,
): Promise<BatchBody> {
  const events = scan(chunks, limit);
  const early: string[] = [];
  let sawRecords = false;
  let recordsClosed = false;
  let batch: unknown = undefined;
  let haveBatch = false;
  while (!haveBatch) {
    const next = await events.next();
    if (next.done) break;
    const event = next.value;
    if (event.t === "member" && event.key === "batch") {
      batch = parse(event.text);
      haveBatch = true;
    } else if (event.t === "record") {
      sawRecords = true;
      early.push(event.text);
    } else if (event.t === "records_end") {
      sawRecords = true;
      recordsClosed = true;
    } else if (event.t === "member" && event.key === "records") {
      throw bad("records must be an array");
    }
  }
  if (!haveBatch) throw bad("batch and records are required");

  async function* records(): AsyncGenerator<unknown> {
    while (early.length > 0) yield parse(early.shift()!);
    if (!recordsClosed) {
      for await (const event of events) {
        if (event.t === "record") {
          sawRecords = true;
          yield parse(event.text);
        } else if (event.t === "records_end") {
          sawRecords = true;
        } else if (event.t === "member" && event.key === "records") {
          throw bad("records must be an array");
        }
      }
    } else {
      // Drain the rest so trailing members and the end of the object are checked.
      for await (const event of events) {
        if (event.t === "record") throw bad("records appear twice");
      }
    }
    if (!sawRecords) throw bad("batch and records are required");
  }
  return { batch, records: records() };
}
