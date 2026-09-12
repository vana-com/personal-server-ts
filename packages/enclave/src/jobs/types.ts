import type { FleetAssignment } from "../fleet/contracts.js";
import type { Hex } from "viem";
import type {
  ClaimRequest as SdkClaimRequest,
  CompleteRequest as SdkCompleteRequest,
  FailRequest as SdkFailRequest,
  HeartbeatRequest as SdkHeartbeatRequest,
  ClaimResponse as SdkClaimResponse,
} from "@opendatalabs/vana-sdk/protocol/jobs";

export {
  JobEnvelopeError,
  openJobRequest,
} from "@opendatalabs/vana-sdk/crypto/envelope/job";
export {
  CLAIM_POLL_FLOOR_MS,
  DEFAULT_LEASE_SECONDS,
  MAX_LEASE_SECONDS,
  MAX_WAIT_SECONDS,
  type FencedResponse,
  type JobRequest,
  type JobRequestEnvelope,
  type TeeNodeHeartbeat,
} from "@opendatalabs/vana-sdk/protocol/jobs";

export type ClaimRequest = SdkClaimRequest & { assignment?: FleetAssignment };
export type CompleteRequest = SdkCompleteRequest & {
  assignment?: FleetAssignment;
};
export type FailRequest = SdkFailRequest & { assignment?: FleetAssignment };
export type HeartbeatRequest = SdkHeartbeatRequest & {
  assignment?: FleetAssignment;
};
export type ClaimResponse = Omit<SdkClaimResponse, "job"> & {
  job: SdkClaimResponse["job"] & { chainId?: number };
  assignment?: FleetAssignment;
};

const JOB_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function normalizeJobId(value: unknown): string | undefined {
  return typeof value === "string" && JOB_ID_PATTERN.test(value)
    ? value.toLowerCase()
    : undefined;
}

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
