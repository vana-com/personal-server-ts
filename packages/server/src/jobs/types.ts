import type { Address, Hex } from "viem";

// TODO(sdk-jobs): replace with import from "@opendatalabs/vana-sdk/protocol/jobs" once the prerelease is pinned.
export const JOB_PROTOCOL_VERSION = 1;
export const JOB_OPERATIONS = ["raw_read", "inference"] as const;
export type JobOperation = (typeof JOB_OPERATIONS)[number];
export const MAX_INLINE_RESULT_BYTES = 1_048_576;

export interface JobRequest {
  v: 1;
  jobId: string;
  owner: Address;
  builder: Address;
  builderPublicKey: Hex;
  grantId: Hex;
  scope: string;
  operation: JobOperation;
  pinnedVersion: string | null;
  deadline: string;
}

export interface JobRequestEnvelope {
  request: JobRequest;
  auth: string;
}

export interface JobResult {
  v: 1;
  jobId: string;
  scope: string;
  version: string | null;
  contentType: string;
  body: string;
}

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
