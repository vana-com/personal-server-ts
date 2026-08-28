/** Failures the capability layer raises. All are surfaced to the script. */
export type QueryToolErrorCode =
  /** The script named a scope outside the grant. */
  | "SCOPE_NOT_GRANTED"
  /**
   * A per-run budget ceiling was reached. Not an error to the *caller* — the
   * run ends with a partial answer — but it terminates the script.
   */
  | "BUDGET_EXHAUSTED"
  /** `vana.introspect()` called by the party the question is about. */
  | "INTROSPECT_REFUSED"
  /** A capability the host did not register for this request. */
  | "CAPABILITY_UNAVAILABLE"
  /** The script used syntax or a binding the confined realm does not allow. */
  | "CONFINEMENT_VIOLATION"
  /** `vana.result` called more than once, or after the run ended. */
  | "RESULT_ALREADY_SET";

export class QueryToolError extends Error {
  readonly code: QueryToolErrorCode;
  constructor(code: QueryToolErrorCode, message: string) {
    super(message);
    this.name = "QueryToolError";
    this.code = code;
  }
}

/** Thrown to unwind the interpreter when `vana.result` terminates the script. */
export class ScriptCompleted extends Error {
  constructor() {
    super("script called vana.result");
    this.name = "ScriptCompleted";
  }
}
