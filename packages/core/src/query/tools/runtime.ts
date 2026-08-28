import { createVanaApi } from "./api.js";
import { QueryToolError, ScriptCompleted } from "./errors.js";
import { ConfinementError, runConfinedScript } from "./interpreter/index.js";
import type {
  CoverageCounters,
  QueryToolContext,
  QueryToolDeps,
  ScriptResult,
  StoppedBecause,
} from "./types.js";

export interface RunQueryScriptOptions {
  /** Verbatim `SandboxEnforcement.notes` from the OS layer, surfaced in coverage. */
  enforcementNotes?: readonly string[];
  maxSteps?: number;
}

export interface QueryScriptOutcome {
  /** What the script produced, if it called `vana.result`. */
  result?: ScriptResult;
  /** Host-authored. Never influenced by anything the script said. */
  coverage: CoverageCounters;
  /** `vana.note` output and `console.log`, in order. */
  notes: string[];
  toolCalls: number;
  classifyUsd: number;
  /** Set when the script failed rather than completing. */
  error?: { code: string; message: string };
}

/**
 * Run one model-authored script under both confinement and accounting.
 *
 * This is the capability layer's entry point. It is deliberately *not* a
 * sandbox: it assumes the OS layer (`Sandbox` in `../ports.js`) already bounds
 * the process. What it adds is the language boundary — the script can name
 * only `vana` and a frozen set of pure globals — and the counters that make
 * `coverage` a host fact rather than a model claim.
 */
export async function runQueryScript(
  source: string,
  ctx: QueryToolContext,
  deps: QueryToolDeps,
  options: RunQueryScriptOptions = {},
): Promise<QueryScriptOutcome> {
  const { api, state } = createVanaApi(ctx, deps);
  const notes: string[] = [];

  let error: { code: string; message: string } | undefined;
  try {
    await runConfinedScript(source, api, {
      maxSteps: options.maxSteps,
      onConsole: (m) => notes.push(m),
    });
  } catch (err) {
    if (err instanceof ScriptCompleted) {
      // Normal termination: `vana.result` unwinds the interpreter.
    } else if (err instanceof QueryToolError) {
      error = { code: err.code, message: err.message };
    } else if (err instanceof ConfinementError) {
      error = { code: "CONFINEMENT_VIOLATION", message: err.message };
    } else {
      error = {
        code: "SCRIPT_ERROR",
        message: err instanceof Error ? err.message : String(err),
      };
    }
  }

  const s = state();
  if (options.enforcementNotes?.length) {
    s.coverage.noteEnforcement(options.enforcementNotes);
  }
  // A run that ended in anything but a clean result did not cover everything,
  // and must say so rather than letting a partial pass look total.
  if (error && error.code !== "BUDGET_EXHAUSTED") {
    s.coverage.stop(mapErrorToStop(error.code));
  }

  return {
    ...(s.result ? { result: s.result } : {}),
    coverage: s.coverage.snapshot(),
    notes: [...notes, ...s.notes],
    toolCalls: s.toolCalls,
    classifyUsd: s.classifyUsd,
    ...(error ? { error } : {}),
  };
}

function mapErrorToStop(code: string): StoppedBecause {
  switch (code) {
    case "BUDGET_EXHAUSTED":
      return "budget";
    case "CONFINEMENT_VIOLATION":
      return "policyDenied";
    default:
      return "error";
  }
}
