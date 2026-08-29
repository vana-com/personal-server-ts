/**
 * Joins the two sandbox layers into the single `QueryToolHost` the agent loop
 * consumes.
 *
 * Phase 5's loop originally held a `Sandbox` itself and called
 * `sandbox.run(modelCode, spec)` — handing model-authored JavaScript straight
 * to Node, which phase 4b measured to be unsound (it can `require('fs')` past
 * the API and forge a coverage line). The loop no longer holds a sandbox at
 * all: it hands model code to `execute()` and gets back a host-authored
 * outcome. Running model code bare is now not merely discouraged but
 * unreachable from the loop.
 *
 * What this assembles per run:
 *
 * 1. `resolveReadPaths` over the granted scope paths — the OS layer's view.
 * 2. A runner program (`runner-entry.ts`, bundled) with the model's code
 *    embedded as a *string literal*, never as code.
 * 3. `sandbox.run(...)` of that program.
 * 4. `decodeResultFrame` over its stdout, failing closed.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  decodeResultFrame,
  stripResultFrames,
  type CoverageCounters,
  type ScriptHit,
} from "@opendatalabs/personal-server-ts-core/query/tools";
import type {
  Sandbox,
  SandboxSpec,
} from "@opendatalabs/personal-server-ts-core/query";
import { resolveReadPaths } from "./read-paths.js";

/** One granted scope, with the file backing it. */
export interface GrantedScopeFile {
  scope: string;
  path: string;
  itemCount?: number;
  collectedAt?: string;
  version?: string;
  contentKind?: string;
  profile?: string;
}

export interface SandboxToolHostOptions {
  sandbox: Sandbox;
  scopes: GrantedScopeFile[];
  /** Root every granted path must resolve inside. Design §3 risk 1. */
  dataRoot: string;
  scratchDir: string;
  budget: { toolCalls: number; outputBytes: number; classifyUsd?: number };
  callerId?: string;
  limits: {
    cpuMs: number;
    memoryMb: number;
    wallClockMs: number;
    maxOutputBytes: number;
  };
  /** Host-resolved lexical search results, keyed by query. */
  searchResults?: Record<string, ScriptHit[]>;
  maxSteps?: number;
  /** Override the bundled runner path; tests supply a stub. */
  runnerBundlePath?: string;
}

export interface ExecuteOutcome {
  coverage: CoverageCounters;
  notes: string[];
  result?: {
    answer: string;
    citations?: { scope: string; recordId?: string; blockRef?: string }[];
    confidence?: "high" | "medium" | "low";
    value?: number;
  };
  error?: { code: string; message: string };
  /** Sandbox-level facts the loop maps onto `stoppedBecause`. */
  termination: string;
  stdout: string;
  stderr: string;
  violations: string[];
  truncated: boolean;
  toolCalls: number;
  classifyUsd: number;
}

/**
 * Locate the bundled runner.
 *
 * Normally this module runs from `dist/query/`, so the bundle is its sibling.
 * Under `tsx` (the eval script, dev runs) it executes from `src/query/`
 * instead, where no bundle exists — so fall back to the built one. Failing
 * loudly beats falling back to an unbundled path: without the bundle there is
 * no confined interpreter, and silently running without one is the exact
 * unsoundness this whole arrangement exists to remove.
 */
function defaultRunnerPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "runner.js"),
    join(here, "..", "..", "dist", "query", "runner.js"),
  ];
  const found = candidates.find((p) => existsSync(p));
  if (!found) {
    throw new Error(
      `query runner bundle not found (looked in: ${candidates.join(", ")}). ` +
        `Run \`npm run build\` — the bundle is produced by \`bundle-query-runner\`.`,
    );
  }
  return found;
}

/**
 * Coverage for a run whose frame never arrived.
 *
 * Fails closed: no scopes scanned, nothing complete. A truncated frame is
 * indistinguishable from a hostile one, so both are treated as "we learned
 * nothing", never as a partial reading that might look total.
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
    complete: false,
    method: "full",
    stoppedBecause: "error",
    enforcementNotes: [`coverage frame ${reason}; no coverage can be trusted`],
  };
}

export function createSandboxToolHost(options: SandboxToolHostOptions) {
  const {
    sandbox,
    scopes,
    dataRoot,
    scratchDir,
    budget,
    limits,
    callerId,
    searchResults,
    maxSteps,
  } = options;

  /**
   * Coverage accumulated over every run in this request.
   *
   * A question can take several turns, and coverage is a claim about the whole
   * request rather than about its last script. Merging is conservative in
   * every direction: scopes union, counters sum, and `complete` survives only
   * if every run was itself complete.
   */
  /**
   * Merge per-scope, then re-derive the totals.
   *
   * Summing bare totals across runs reintroduces at the request level exactly
   * the double-count the single-run ledger fixes: a script that reads a scope
   * in turn 1 and re-reads it in turn 3 covered those records once, not twice.
   * A later run's tally for a scope therefore *replaces* an earlier one when
   * it is larger, and scopes seen in only one run carry through untouched.
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
    accumulated = {
      scopesScanned: [
        ...new Set([...prev.scopesScanned, ...next.scopesScanned]),
      ].sort(),
      ...mergeScopeTotals(prev, next),
      scopesSkipped: [...skipped.values()],
      complete: prev.complete && next.complete,
      // A prefiltered pass anywhere taints the request: the answer must say
      // "earliest found", not "earliest" (prompt §5 gap 2).
      method:
        prev.method === "prefiltered" || next.method === "prefiltered"
          ? "prefiltered"
          : "full",
      ...((prev.stoppedBecause ?? next.stoppedBecause)
        ? { stoppedBecause: prev.stoppedBecause ?? next.stoppedBecause }
        : {}),
      enforcementNotes: [
        ...new Set([...prev.enforcementNotes, ...next.enforcementNotes]),
      ],
    };
    return accumulated;
  };

  let bundle: string | undefined;
  const loadBundle = (): string => {
    bundle ??= readFileSync(
      options.runnerBundlePath ?? defaultRunnerPath(),
      "utf8",
    );
    return bundle;
  };

  /**
   * The OS layer's read allowlist, derived from the same grant that produced
   * `scopes`. Both layers must agree: a scope the API will not name must not
   * be readable, and a path the OS allows must correspond to a named scope.
   */
  const readPaths = resolveReadPaths(
    scopes.map((s) => s.path),
    dataRoot,
  );

  const spec: SandboxSpec = {
    readPaths,
    writePath: scratchDir,
    denyNetwork: true,
    cpuMs: limits.cpuMs,
    memoryMb: limits.memoryMb,
    wallClockMs: limits.wallClockMs,
    maxOutputBytes: limits.maxOutputBytes,
  };

  return {
    /** The OS-layer allowlist, exposed so the two-layer agreement is testable. */
    readPaths,

    /** Accumulated across the request. Empty-and-incomplete before any run. */
    coverage(): CoverageCounters {
      return (
        accumulated ?? {
          scopesScanned: [],
          recordsScanned: 0,
          bytesScanned: 0,
          unreadable: 0,
          perScope: {},
          scopesSkipped: [],
          complete: false,
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

    /**
     * Build the program the sandbox runs.
     *
     * The model's code is embedded with `JSON.stringify`, so it lands in the
     * program as a string literal. Nothing in the generated file can execute
     * it; only the interpreter reads it.
     */
    buildRunnerProgram(modelCode: string): string {
      const input = {
        modelCode,
        scopes: scopes.map((s) => ({
          scope: s.scope,
          path: s.path,
          ...(s.itemCount === undefined ? {} : { itemCount: s.itemCount }),
          ...(s.collectedAt === undefined
            ? {}
            : { collectedAt: s.collectedAt }),
          ...(s.version === undefined ? {} : { version: s.version }),
          ...(s.contentKind === undefined
            ? {}
            : { contentKind: s.contentKind }),
          ...(s.profile === undefined ? {} : { profile: s.profile }),
        })),
        budget,
        ...(callerId === undefined ? {} : { callerId }),
        // Half the output cap, so the frame always fits with room to spare.
        // A frame cut by `maxOutputBytes` is untrustworthy and costs the run
        // every counter it carried, so the notes inside it yield first.
        frameBudgetBytes: Math.floor(limits.maxOutputBytes / 2),
        enforcementNotes: [] as string[],
        ...(maxSteps === undefined ? {} : { maxSteps }),
        ...(searchResults === undefined ? {} : { searchResults }),
      };
      return `globalThis.__VANA_INPUT__ = ${JSON.stringify(input)};\n${loadBundle()}`;
    },

    async execute(modelCode: string): Promise<ExecuteOutcome> {
      const program = this.buildRunnerProgram(modelCode);
      const run = await sandbox.run(program, spec);
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
          // Enforcement is a host fact about the process, not something the
          // runner inside it can attest to. Plan §4.3: reduced capability
          // must be visible.
          enforcementNotes: [
            ...doc.coverage.enforcementNotes,
            ...run.enforcement.notes,
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

export type SandboxToolHost = ReturnType<typeof createSandboxToolHost>;
