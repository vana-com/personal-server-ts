import type { Hex } from "viem";

// JOB_EXECUTE_WIRE_START
export type JobFailureCode =
  | "AUTH_INVALID"
  | "BUILDER_MISMATCH"
  | "OWNER_MISMATCH"
  | "GRANT_REVOKED"
  | "GRANT_INVALID"
  | "SIGNED_ARTIFACT_MISSING"
  | "SIGNED_ARTIFACT_INVALID"
  | "SERVER_NOT_REGISTERED"
  | "SCOPE_NOT_FOUND"
  | "VERSION_MISMATCH"
  | "DEADLINE_PASSED"
  | "RESULT_SIGNING_REFUSED"
  | "RESULT_UPLOAD_FAILED"
  | "RESULT_TOO_LARGE"
  | "INTERNAL";

export interface JobExecuteResponse {
  /** Object key in vana-storage: `jobresults/{chainId}/{jobId}`. */
  resultObjectKey: string;
  /** SHA-256 of ciphertext bytes. */
  resultHash: Hex;
  resultSize: number;
}

export interface JobExecuteError {
  error: {
    code: JobFailureCode;
    message: string;
    retryable: boolean;
  };
}
// JOB_EXECUTE_WIRE_END
