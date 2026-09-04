import type { Hex } from "viem";
import type { ClaimResponse as SdkClaimResponse } from "@opendatalabs/vana-sdk/protocol/jobs";

export {
  JobEnvelopeError,
  openJobRequest,
} from "@opendatalabs/vana-sdk/crypto/envelope/job";
export {
  CLAIM_POLL_FLOOR_MS,
  DEFAULT_LEASE_SECONDS,
  MAX_LEASE_SECONDS,
  MAX_WAIT_SECONDS,
  type ClaimRequest,
  type CompleteRequest,
  type FailRequest,
  type FencedResponse,
  type HeartbeatRequest,
  type JobRequest,
  type JobRequestEnvelope,
  type TeeNodeHeartbeat,
} from "@opendatalabs/vana-sdk/protocol/jobs";

export type ClaimResponse = Omit<SdkClaimResponse, "job"> & {
  job: SdkClaimResponse["job"] & { chainId: number };
};

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
  | "RESULT_TOO_LARGE"
  | "INTERNAL";

export interface JobExecuteResponse {
  /** Base64 ECIES bytes: iv || ephemeral public key || ciphertext || MAC. */
  resultCiphertext: string;
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
