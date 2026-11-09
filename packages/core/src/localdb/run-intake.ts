import type {
  BatchRequest,
  BatchResponse,
  BeginRequest,
  BeginResponse,
  IntakeDeclarations,
} from "../stream-sync/intake.js";
import type { LocalSyncDeps } from "./deps.js";

/**
 * Run intake, begin and batch, on the database (C.1). `begin` keeps today's
 * checks, adds the dotted-connector 400 (C.5), runs `syncBeforeBegin` (C.0)
 * and writes `runs` + `run_streams` in one batch. `batch` is idempotent by
 * `seq`, checks the fence and typed keys, and writes `run_rows`. Neither goes
 * through the connection queue. Errors are `RunIntakeError`.
 */
export interface RunIntakeStore {
  begin(
    runId: string,
    req: BeginRequest,
    declarations: IntakeDeclarations,
  ): Promise<BeginResponse>;
  batch(runId: string, req: BatchRequest): Promise<BatchResponse>;
}

export function createRunIntakeStore(deps: LocalSyncDeps): RunIntakeStore {
  void deps;
  throw new Error("PS-2: not built");
}
