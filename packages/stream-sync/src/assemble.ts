import { PartIntegrityError } from "./errors.js";
import { sha256Hex, type Sha256 } from "./hash.js";
import { parseHead, type Head } from "./head.js";
import { isPlainObject } from "./json.js";
import type { StampedRecord } from "./records.js";

/**
 * Fetch one part by its content hash. The host returns the bytes it stored, or
 * throws or returns `null`/`undefined` when it has none.
 */
export type FetchPart = (
  hash: string,
) => Promise<Uint8Array | null | undefined>;

const decoder = new TextDecoder("utf-8", { fatal: true });

export interface AssembleExpectation {
  readonly connectionId: string;
  readonly stream: string;
}

/**
 * Read a stream from its head. Parts are fetched one at a time, only the ones
 * the head lists, each checked for length and SHA-256 before it is parsed.
 * Any mismatch throws `PartIntegrityError`; no partial result is returned. An
 * unknown future head format throws `UnsupportedFormatVersionError`.
 *
 * Because parts are fetched by hash from this head's own list, a part that
 * belongs to another head can never be mixed in.
 */
export async function assemble(
  head: Head,
  fetchPart: FetchPart,
  sha256: Sha256,
  expected?: AssembleExpectation,
): Promise<StampedRecord[]> {
  const records: StampedRecord[] = [];
  for await (const batch of readParts(head, fetchPart, sha256, expected)) {
    for (const record of batch) records.push(record);
  }
  return records;
}

/**
 * The same read as `assemble`, one verified part at a time, for readers that
 * must stay inside a memory budget. The record count is checked when the
 * generator finishes, so consume it to the end before trusting the data.
 */
export async function* readParts(
  head: Head,
  fetchPart: FetchPart,
  sha256: Sha256,
  expected?: AssembleExpectation,
): AsyncGenerator<StampedRecord[], void, undefined> {
  const checked = parseHead(head);
  if (
    expected !== undefined &&
    (checked.connectionId !== expected.connectionId ||
      checked.stream !== expected.stream)
  ) {
    throw new PartIntegrityError(
      "identity",
      "head belongs to a different stream or connection",
    );
  }
  let total = 0;
  for (const entry of checked.parts) {
    const bytes = await load(fetchPart, entry.hash);
    if (bytes.length !== entry.bytes) {
      throw new PartIntegrityError(
        "length",
        `part ${entry.hash} has ${bytes.length} bytes, head says ${entry.bytes}`,
        entry.hash,
      );
    }
    const actual = await sha256Hex(sha256, bytes);
    if (actual !== entry.hash) {
      throw new PartIntegrityError(
        "hash",
        `part ${entry.hash} hashes to ${actual}`,
        entry.hash,
      );
    }
    const batch = decodePart(bytes, entry.hash);
    total += batch.length;
    yield batch;
  }
  if (total !== checked.recordCount) {
    throw new PartIntegrityError(
      "record-count",
      `parts hold ${total} records, head says ${checked.recordCount}`,
    );
  }
}

async function load(fetchPart: FetchPart, hash: string): Promise<Uint8Array> {
  let bytes: Uint8Array | null | undefined;
  try {
    bytes = await fetchPart(hash);
  } catch (cause) {
    throw new PartIntegrityError(
      "missing",
      `part ${hash} could not be fetched`,
      hash,
      { cause },
    );
  }
  if (bytes === null || bytes === undefined) {
    throw new PartIntegrityError(
      "missing",
      `part ${hash} is not available`,
      hash,
    );
  }
  return bytes;
}

function decodePart(bytes: Uint8Array, hash: string): StampedRecord[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(decoder.decode(bytes));
  } catch (cause) {
    throw new PartIntegrityError(
      "malformed",
      `part ${hash} is not valid JSON`,
      hash,
      { cause },
    );
  }
  if (
    !isPlainObject(parsed) ||
    Object.keys(parsed).sort().join() !== "observedAt,records"
  ) {
    throw new PartIntegrityError(
      "malformed",
      `part ${hash} is not {"observedAt":[...],"records":[...]}`,
      hash,
    );
  }
  const records = parsed["records"];
  const times = parsed["observedAt"];
  if (!Array.isArray(records) || !records.every(isPlainObject)) {
    throw new PartIntegrityError(
      "malformed",
      `part ${hash} records are not JSON objects`,
      hash,
    );
  }
  if (
    !Array.isArray(times) ||
    times.length !== records.length ||
    !times.every(
      (t) => typeof t === "number" && Number.isSafeInteger(t) && t >= 0,
    )
  ) {
    throw new PartIntegrityError(
      "malformed",
      `part ${hash} observation times do not match its records`,
      hash,
    );
  }
  return records.map((record, i) => ({
    record,
    observedAt: times[i] as number,
  }));
}
