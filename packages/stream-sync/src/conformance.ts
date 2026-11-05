import { assemble } from "./assemble.js";
import { filesOfConnection } from "./connection-files.js";
import { StreamSyncError } from "./errors.js";
import type { Sha256 } from "./hash.js";
import { decodeHead } from "./head.js";
import { canonicalJson } from "./json.js";
import { overlay } from "./overlay.js";
import { split } from "./parts.js";
import { planPublish } from "./publish.js";
import type { Run, StampedRecord } from "./records.js";

/**
 * Shared conformance vectors. The JSON files under `vectors/` hold inputs and
 * expected outputs (exact text, byte counts, SHA-256 hashes); any surface that
 * implements the same behaviour must reproduce them. This runner takes the
 * parsed files, so it does no file or network I/O and runs in any JS runtime.
 *
 * File shape: `{ "vectorVersion": 1, "kind": <kind>, "cases": [...] }`.
 * Kinds and case fields:
 *
 * - `canonical-json`: `name`, `input` (any JSON), `expected` (string).
 * Stamped records are `{ "record": {...}, "observedAt": <ms> }`.
 *
 * - `overlay`: `name`, `primaryKey`, optional `orderField`, `base` and `run`
 *   (stamped records), and either `expected` (stamped records) or
 *   `expectError` (`code` plus optional fields).
 * - `split`: `name`, `records` (stamped), `partSizeBytes`, `expected.parts`
 *   (`text`, `bytes`, `hash`, `recordCount`) and `expected.warnings`.
 * - `plan`: `name`, `input` (connectionId, stream, primaryKey, optional
 *   orderField and partSizeBytes, `latestCopy` stamped, baseVersion, and
 *   `run` = `{records, observedAt}`) and `expected` (`headText`, `headHash`,
 *   `parts` as `{hash, text}`, `warnings`, `expectedBase`) or `expectError`.
 * - `assemble`: `name`, `headText`, `parts` (hash to part text; a missing hash
 *   means the part is not stored), optional `expect` (connectionId, stream),
 *   and either `expectedRecords` (stamped) or `expectError`.
 * - `connection-files`: `name`, `names`, `connectionId`, `expected`.
 *
 * `connection-files` vectors use the placeholder naming grammar, so a surface
 * that pins a different grammar replaces that one file, not the rest.
 */

export interface VectorFile {
  readonly vectorVersion: number;
  readonly kind: string;
  readonly cases: readonly VectorCase[];
}

export type VectorCase = {
  readonly name: string;
  readonly [field: string]: unknown;
};

export interface ConformanceResult {
  readonly kind: string;
  readonly name: string;
  readonly ok: boolean;
  readonly detail?: string;
}

export interface ConformanceDeps {
  readonly sha256: Sha256;
}

const encoder = new TextEncoder();

export async function runConformance(
  files: readonly VectorFile[],
  deps: ConformanceDeps,
): Promise<ConformanceResult[]> {
  const results: ConformanceResult[] = [];
  for (const file of files) {
    for (const vector of file.cases) {
      try {
        const detail = await runCase(file.kind, vector, deps);
        results.push(
          detail === undefined
            ? { kind: file.kind, name: vector.name, ok: true }
            : { kind: file.kind, name: vector.name, ok: false, detail },
        );
      } catch (error) {
        results.push({
          kind: file.kind,
          name: vector.name,
          ok: false,
          detail: `unexpected throw: ${String(error)}`,
        });
      }
    }
  }
  return results;
}

/** Returns `undefined` on success, otherwise a description of the mismatch. */
async function runCase(
  kind: string,
  vector: VectorCase,
  deps: ConformanceDeps,
): Promise<string | undefined> {
  switch (kind) {
    case "canonical-json":
      return expectEqual(canonicalJson(vector["input"]), vector["expected"]);
    case "overlay":
      return withExpectation(vector, () =>
        overlay(
          vector["base"] as StampedRecord[],
          vector["run"] as StampedRecord[],
          vector["primaryKey"] as string[],
          { orderField: vector["orderField"] as string | undefined },
        ),
      ).then((outcome) => outcome ?? undefined);
    case "split":
      return runSplit(vector, deps);
    case "plan":
      return runPlan(vector, deps);
    case "assemble":
      return runAssemble(vector, deps);
    case "connection-files":
      return expectEqual(
        filesOfConnection(
          vector["names"] as string[],
          vector["connectionId"] as string,
        ),
        vector["expected"],
      );
    default:
      return `unknown vector kind: ${kind}`;
  }
}

async function runSplit(
  vector: VectorCase,
  deps: ConformanceDeps,
): Promise<string | undefined> {
  const result = await split(
    vector["records"] as StampedRecord[],
    deps.sha256,
    vector["partSizeBytes"] as number,
  );
  const actual = {
    parts: result.parts.map((part) => ({
      text: new TextDecoder().decode(part.bytes),
      bytes: part.bytes.length,
      hash: part.hash,
      recordCount: part.recordCount,
    })),
    warnings: result.warnings,
  };
  return expectEqual(actual, vector["expected"]);
}

async function runPlan(
  vector: VectorCase,
  deps: ConformanceDeps,
): Promise<string | undefined> {
  const input = vector["input"] as Record<string, unknown>;
  const attempt = () =>
    planPublish({
      connectionId: input["connectionId"] as string,
      stream: input["stream"] as string,
      primaryKey: input["primaryKey"] as string[],
      orderField: input["orderField"] as string | undefined,
      partSizeBytes: input["partSizeBytes"] as number | undefined,
      latestCopy: input["latestCopy"] as StampedRecord[],
      baseVersion: input["baseVersion"] as string | null,
      run: input["run"] as Run,
      sha256: deps.sha256,
    });
  if (vector["expectError"] !== undefined) {
    return withExpectation(vector, attempt).then(
      (outcome) => outcome ?? undefined,
    );
  }
  const plan = await attempt();
  const decoder = new TextDecoder();
  return expectEqual(
    {
      headText: decoder.decode(plan.headBytes),
      headHash: plan.headHash,
      parts: plan.parts.map((part) => ({
        hash: part.hash,
        text: decoder.decode(part.bytes),
      })),
      warnings: plan.warnings,
      expectedBase: plan.expectedBase,
    },
    vector["expected"],
  );
}

async function runAssemble(
  vector: VectorCase,
  deps: ConformanceDeps,
): Promise<string | undefined> {
  const stored = vector["parts"] as Record<string, string>;
  const read = () =>
    assemble(
      decodeHead(vector["headText"] as string),
      async (hash) => {
        const text = Object.prototype.hasOwnProperty.call(stored, hash)
          ? stored[hash]
          : undefined;
        return text === undefined ? undefined : encoder.encode(text);
      },
      deps.sha256,
      vector["expect"] as { connectionId: string; stream: string } | undefined,
    );
  if (vector["expectError"] !== undefined) {
    return withExpectation(vector, read).then(
      (outcome) => outcome ?? undefined,
    );
  }
  return expectEqual(await read(), vector["expectedRecords"]);
}

/**
 * For vectors that expect either a value or a typed error. Returns a mismatch
 * description, or `null` when the vector is satisfied.
 */
async function withExpectation(
  vector: VectorCase,
  run: () => unknown,
): Promise<string | null> {
  const expectError = vector["expectError"] as
    Record<string, unknown> | undefined;
  let value: unknown;
  try {
    value = await run();
  } catch (error) {
    if (expectError === undefined) return `unexpected error: ${String(error)}`;
    if (!(error instanceof StreamSyncError))
      return `non-typed error: ${String(error)}`;
    for (const [field, want] of Object.entries(expectError)) {
      const got = (error as unknown as Record<string, unknown>)[field];
      if (got !== want)
        return `error.${field} is ${String(got)}, expected ${String(want)}`;
    }
    return null;
  }
  if (expectError !== undefined) return "expected an error, got a value";
  return expectEqual(value, vector["expected"]) ?? null;
}

function expectEqual(actual: unknown, expected: unknown): string | undefined {
  return deepEqual(actual, expected)
    ? undefined
    : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (typeof a === "number" && typeof b === "number")
    return Object.is(a, b) || a === b;
  if (
    a === null ||
    b === null ||
    typeof a !== "object" ||
    typeof b !== "object"
  )
    return a === b;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const aKeys = Object.keys(a);
  const bKeys = Object.keys(b);
  if (aKeys.length !== bKeys.length) return false;
  return aKeys.every(
    (key) =>
      Object.prototype.hasOwnProperty.call(b, key) &&
      deepEqual(
        (a as Record<string, unknown>)[key],
        (b as Record<string, unknown>)[key],
      ),
  );
}
