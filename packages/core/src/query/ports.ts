/**
 * Query-layer runtime ports.
 *
 * Types only. This module is imported by `packages/lite` (browser/WebView)
 * as well as `packages/server`, so it must stay browser-safe: no Node
 * built-ins, no `@anthropic-ai/sandbox-runtime`, not even a `import type`
 * that would drag a Node type surface in. Implementations live in
 * `packages/server/src/query/` (Node) and `packages/lite/src/` (browser).
 *
 * See docs/260828-query-layer-implementation-plan.md phase 4a and design
 * §19.7 ("the sandbox is two layers").
 */

/**
 * Why a sandboxed run stopped.
 *
 * The plan's original `SandboxResult` carried a single `timedOut: boolean`.
 * That is too lossy for the prompt contract
 * (docs/260828-query-layer-prompt.md §3), which makes budget exhaustion a
 * first-class outcome carrying `coverage.stoppedBecause` — an answer that
 * ran out of wall clock, one that was killed for allocating 4GB, and one
 * the OS policy denied are three different things to tell a user, and only
 * the first is a "timeout".
 *
 * `timedOut` is retained on {@link SandboxResult} as a derived compatibility
 * field so existing plan-shaped consumers keep working.
 */
export type SandboxTermination =
  /** Script ran to completion. `exitCode` is its own. */
  | "completed"
  /** Script threw or exited non-zero of its own accord. */
  | "error"
  /** `wallClockMs` elapsed. */
  | "wallClock"
  /** `cpuMs` of CPU time consumed (RLIMIT_CPU / SIGXCPU). */
  | "cpu"
  /** `memoryMb` exceeded (RSS watchdog, V8 heap cap, or RLIMIT_AS). */
  | "memory"
  /** `maxOutputBytes` exceeded; output is truncated and the run was killed. */
  | "outputCap"
  /** The OS sandbox denied an operation and the run could not continue. */
  | "policyDenied"
  /** The host could not establish the sandbox at all; nothing was executed. */
  | "sandboxUnavailable";

/**
 * What the host actually managed to enforce for a given run.
 *
 * Enforcement is genuinely platform-dependent — `RLIMIT_AS` is rejected by
 * the macOS kernel, for instance — and a caller that believes a limit is
 * active when it is not will report false confidence to the user. Every
 * implementation must report this honestly, and `false` here is a fact to
 * surface, not to hide.
 */
export interface SandboxEnforcement {
  /** Reads confined to `readPaths`. */
  filesystemRead: boolean;
  /** Writes confined to `writePath`. */
  filesystemWrite: boolean;
  /** Network egress denied. */
  network: boolean;
  /** CPU time bounded. */
  cpu: boolean;
  /** Total process memory bounded (not merely the JS heap). */
  memory: boolean;
  /** Process/thread creation bounded. */
  processCount: boolean;
  /** Wall-clock bounded. */
  wallClock: boolean;
  /**
   * Human-readable notes on anything partial — e.g. "memory bounded by RSS
   * watchdog sampling at 50ms, not by a kernel limit". Surfaced in coverage.
   */
  notes: string[];
}

export interface SandboxSpec {
  /**
   * Absolute, already-resolved paths the script may read: exactly the files
   * under the consumer's grant and nothing else.
   *
   * Implementations must resolve symlinks and reject relative or
   * non-normalized entries before handing these to a policy — design §3
   * risk 1: "data under a grant is one bad `readPaths` computation away
   * from exposure". See `resolveReadPaths` in the Node implementation.
   */
  readPaths: string[];
  /** One scratch directory, the only writable location, discarded after the run. */
  writePath: string;
  /** Non-negotiable. Typed as `true` so it cannot be switched off in a call. */
  denyNetwork: true;
  /** CPU-time budget in milliseconds. */
  cpuMs: number;
  /** Total memory budget in megabytes. */
  memoryMb: number;
  /** Wall-clock budget in milliseconds. */
  wallClockMs: number;
  /** Combined stdout+stderr cap in bytes; the run is killed past it. */
  maxOutputBytes: number;
  /**
   * Maximum concurrent processes/threads. Bounds fork bombs where the
   * platform supports it. Optional: the plan's original spec omitted it.
   */
  maxProcesses?: number;
}

export interface SandboxResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  /**
   * True when the run ended because a *time* budget elapsed. Derived from
   * {@link termination} (`wallClock` or `cpu`); kept for plan-shape
   * compatibility. Prefer `termination`.
   */
  timedOut: boolean;
  /** True when output hit `maxOutputBytes` and was cut. */
  truncated: boolean;
  durationMs: number;
  /** Why the run ended. */
  termination: SandboxTermination;
  /** What the host actually enforced, per limit. */
  enforcement: SandboxEnforcement;
  /**
   * OS-sandbox policy violations observed during the run (denied reads,
   * blocked connects). Present even on a `completed` run: a script that was
   * denied a read and carried on is a coverage fact.
   */
  violations: string[];
}

/**
 * Runs untrusted, model-authored JavaScript under OS-enforced confinement.
 *
 * Implementations: `packages/server/src/query/node-sandbox.ts` (Node,
 * `@anthropic-ai/sandbox-runtime`) and the PS-Lite blob worker.
 */
export interface Sandbox {
  run(script: string, spec: SandboxSpec): Promise<SandboxResult>;
  /**
   * Whether this runtime can sandbox at all, and what it would enforce, so
   * a caller can degrade deliberately and *say* it degraded rather than
   * silently running unconfined. Plan §4.3: "reduced capability must be
   * visible".
   */
  capabilities(): Promise<
    | { available: true; enforcement: SandboxEnforcement }
    | {
        available: false;
        reason: string;
      }
  >;
}

/** The port name used when wiring implementations, matching `ports/index.ts`. */
export type CodeExecutionPort = Sandbox;
