/**
 * The `QueryToolHost` the agent loop consumes, on PS-Lite.
 *
 * This is the browser counterpart of
 * `packages/server/src/query/sandbox-tool-host.ts`. It is a separate file
 * rather than a shared one because the Node host is bound to Node: it reads
 * the runner bundle off disk with `readFileSync` and derives `readPaths`
 * through `node:path`. Neither is reachable from a browser, and the Node arm
 * of the benchmark has to stay byte-for-byte the code it was measured on, so
 * nothing there was refactored to make room for this.
 *
 * What is *not* duplicated is the part that matters: the coverage ledger, the
 * `vana` API and the result-frame protocol all come from `packages/core`, so
 * both runtimes count the same events with the same code. What is duplicated
 * is the cross-run merge, and it is duplicated deliberately and verbatim in
 * behaviour — `lite-tool-host.merge.test.ts` asserts the same properties the
 * Node suite asserts, so a divergence fails a test rather than quietly
 * changing what a counter means on one runtime.
 */

import {
  decodeResultFrame,
  stripResultFrames,
  type CoverageCounters,
} from "@opendatalabs/personal-server-ts-core/query/tools";
import type {
  Sandbox,
  SandboxSpec,
} from "@opendatalabs/personal-server-ts-core/query";

/** One granted scope, with the virtual path backing it. */
export interface LiteGrantedScope {
  scope: string;
  /** Virtual path into the materialized grant. Never a real filesystem path. */
  path: string;
  itemCount?: number;
  collectedAt?: string;
  version?: string;
  contentKind?: string;
  profile?: string;
}

export interface LiteToolHostOptions {
  sandbox: Sandbox;
  scopes: LiteGrantedScope[];
  limits: {
    cpuMs: number;
    memoryMb: number;
    wallClockMs: number;
    maxOutputBytes: number;
  };
}

export interface LiteExecuteOutcome {
  coverage: CoverageCounters;
  notes: string[];
  result?: {
    answer: string;
    citations?: { scope: string; recordId?: string; blockRef?: string }[];
    confidence?: "high" | "medium" | "low";
    value?: number;
  };
  error?: { code: string; message: string };
  termination: string;
  stdout: string;
  stderr: string;
  violations: string[];
  truncated: boolean;
  toolCalls: number;
  classifyUsd: number;
}

/**
 * Coverage for a run whose frame never arrived.
 *
 * Fails closed, identically to the Node host: a truncated frame is
 * indistinguishable from a hostile one, so both mean "we learned nothing",
 * never "a partial reading that might be total".
 */
function failedCoverage(
  reason: "absent" | "truncated" | "malformed",
): CoverageCounters {
  return {
    scopesScanned: [],
    recordsScanned: 0,
    bytesScanned: 0,
    unreadable: 0,
    perScope: {},
    scopesSkipped: [],
    method: "full",
    stoppedBecause: "error",
    enforcementNotes: [`coverage frame ${reason}; no coverage can be trusted`],
  };
}

export function createLiteToolHost(options: LiteToolHostOptions) {
  const { sandbox, scopes, limits } = options;

  /**
   * Merge per-scope, then re-derive the totals.
   *
   * Summing bare totals across runs would reintroduce at the request level the
   * double-count the single-run ledger fixes: a script that reads a scope in
   * turn 1 and re-reads it in turn 3 covered those records once, not twice. So
   * a later run's tally for a scope *replaces* an earlier one when it is
   * larger, and scopes seen in only one run carry through untouched.
   */
  const mergeScopeTotals = (
    prev: CoverageCounters,
    next: CoverageCounters,
  ): Pick<
    CoverageCounters,
    "recordsScanned" | "bytesScanned" | "unreadable" | "perScope"
  > => {
    const perScope: CoverageCounters["perScope"] = { ...prev.perScope };
    for (const [scope, tally] of Object.entries(next.perScope ?? {})) {
      const before = perScope[scope];
      perScope[scope] = before
        ? {
            records: Math.max(before.records, tally.records),
            bytes: Math.max(before.bytes, tally.bytes),
            unreadable: Math.max(before.unreadable, tally.unreadable),
          }
        : tally;
    }
    let records = 0;
    let bytes = 0;
    let unreadable = 0;
    for (const t of Object.values(perScope)) {
      records += t.records;
      bytes += t.bytes;
      unreadable += t.unreadable;
    }
    return {
      recordsScanned: records,
      bytesScanned: bytes,
      unreadable,
      perScope,
    };
  };

  let accumulated: CoverageCounters | undefined;

  const merge = (next: CoverageCounters): CoverageCounters => {
    if (!accumulated) {
      accumulated = next;
      return accumulated;
    }
    const prev = accumulated;
    const skipped = new Map(prev.scopesSkipped.map((s) => [s.scope, s]));
    for (const s of next.scopesSkipped) skipped.set(s.scope, s);
    // A prefiltered pass anywhere taints the request: the answer must say
    // "earliest found", not "earliest" (prompt §5 gap 2).
    const method =
      prev.method === "prefiltered" || next.method === "prefiltered"
        ? "prefiltered"
        : "full";
    accumulated = {
      scopesScanned: [
        ...new Set([...prev.scopesScanned, ...next.scopesScanned]),
      ].sort(),
      ...mergeScopeTotals(prev, next),
      scopesSkipped: [...skipped.values()],
      method,
      ...((prev.stoppedBecause ?? next.stoppedBecause)
        ? { stoppedBecause: prev.stoppedBecause ?? next.stoppedBecause }
        : {}),
      enforcementNotes: [
        ...new Set([...prev.enforcementNotes, ...next.enforcementNotes]),
      ],
    };
    return accumulated;
  };

  const spec: SandboxSpec = {
    // Exactly the materialized grant, and the QuickJS sandbox refuses to run
    // if its own grant map and this list disagree in either direction.
    readPaths: scopes.map((s) => s.path),
    // No write surface exists in the VM; the field is required by the port.
    writePath: "/vana/scratch",
    denyNetwork: true,
    cpuMs: limits.cpuMs,
    memoryMb: limits.memoryMb,
    wallClockMs: limits.wallClockMs,
    maxOutputBytes: limits.maxOutputBytes,
  };

  return {
    readPaths: spec.readPaths,

    coverage(): CoverageCounters {
      return (
        accumulated ?? {
          scopesScanned: [],
          recordsScanned: 0,
          bytesScanned: 0,
          unreadable: 0,
          perScope: {},
          scopesSkipped: [],
          method: "full",
          enforcementNotes: [],
        }
      );
    },

    async listScopes() {
      return scopes.map((s) => {
        const info: {
          scope: string;
          itemCount?: number;
          collectedAt?: string;
          version?: string;
          contentKind?: string;
        } = { scope: s.scope };
        if (s.itemCount !== undefined) info.itemCount = s.itemCount;
        if (s.collectedAt !== undefined) info.collectedAt = s.collectedAt;
        if (s.version !== undefined) info.version = s.version;
        if (s.contentKind !== undefined) info.contentKind = s.contentKind;
        return info;
      });
    },

    async execute(modelCode: string): Promise<LiteExecuteOutcome> {
      /*
       * The model's code is passed as the script itself, not embedded in a
       * host program. On Node it has to be embedded as a string literal
       * because the thing that runs is Node, and Node would execute it; here
       * the thing that runs is a QuickJS VM with no capabilities, so the code
       * *is* the script and the VM is the boundary.
       */
      const run = await sandbox.run(modelCode, spec);
      const decoded = decodeResultFrame(run.stdout);

      const base = {
        termination: run.termination,
        stdout: stripResultFrames(run.stdout),
        stderr: run.stderr,
        violations: run.violations,
        truncated: run.truncated,
      };

      if (!decoded.ok) {
        const failed = failedCoverage(decoded.reason);
        return {
          ...base,
          coverage: merge({
            ...failed,
            enforcementNotes: [
              ...failed.enforcementNotes,
              ...run.enforcement.notes,
            ],
          }),
          notes: [],
          toolCalls: 0,
          classifyUsd: 0,
          error: {
            code: "COVERAGE_FRAME_MISSING",
            message: `the confined run produced no usable coverage frame (${decoded.reason})`,
          },
        };
      }

      const { doc } = decoded;
      return {
        ...base,
        coverage: merge({
          ...doc.coverage,
          enforcementNotes: [
            ...new Set([
              ...doc.coverage.enforcementNotes,
              ...run.enforcement.notes,
            ]),
          ],
        }),
        notes: doc.notes,
        toolCalls: doc.toolCalls,
        classifyUsd: doc.classifyUsd,
        ...(doc.result ? { result: doc.result } : {}),
        ...(doc.error ? { error: doc.error } : {}),
      };
    },
  };
}

export type LiteToolHost = ReturnType<typeof createLiteToolHost>;
