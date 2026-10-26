import type { PdppRecordRow } from "./types.js";

/** Durable local evidence only. Sequence and record version are not replica revisions. */
export interface CanonicalMutation {
  readonly sequence: number;
  readonly operationId: string;
  readonly writerId: string;
  /** Null only for legacy records whose binding has no retained source/method. */
  readonly sourceId: string | null;
  readonly connectionId: string;
  readonly method: string | null;
  /** Null if no binding row exists for a legacy owner deletion. */
  readonly generation: number | null;
  readonly stream: string;
  readonly recordKey: string;
  readonly operation: "upsert" | "delete";
  /** Full stored value or tombstone, including its original emitted time. */
  readonly value: PdppRecordRow;
  readonly blobIds: readonly string[];
}
