import { timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import { isAddress, isHex, type Address, type Hex } from "viem";
import {
  JOB_OPERATIONS,
  JOB_PROTOCOL_VERSION,
  type JobRequestEnvelope,
} from "@opendatalabs/vana-sdk/protocol/jobs";
import { createBodyLimit } from "../middleware/body-limit.js";
import type {
  JobExecuteError,
  JobExecuteResponse,
  JobFailureCode,
} from "../jobs/types.js";
import { JobFailure } from "../jobs/worker.js";

const MAX_JOB_BODY_BYTES = 256 * 1024;
const BEARER_PREFIX = "Bearer ";

export interface EnclaveJobRouteDeps {
  accessToken: string;
  executeJob(envelope: JobRequestEnvelope): Promise<JobExecuteResponse>;
}

export function enclaveJobRoutes(deps: EnclaveJobRouteDeps): Hono {
  const app = new Hono();

  app.use("/execute", createBodyLimit(MAX_JOB_BODY_BYTES));
  app.post("/execute", async (context) => {
    if (
      !hasValidBearer(context.req.header("authorization"), deps.accessToken)
    ) {
      return context.json(
        jobError("AUTH_INVALID", "invalid bearer token"),
        401,
      );
    }

    let body: unknown;
    try {
      body = await context.req.json();
    } catch {
      return context.json({ error: { message: "invalid request body" } }, 400);
    }
    if (!isJobEnvelope(body)) {
      return context.json({ error: { message: "invalid request body" } }, 400);
    }

    try {
      return context.json(await deps.executeJob(body), 200);
    } catch (error) {
      if (error instanceof JobFailure) {
        return context.json(
          jobError(error.code, error.message, error.retryable),
          statusFor(error.code),
        );
      }

      return context.json(
        jobError("INTERNAL", "job execution failed", true),
        500,
      );
    }
  });

  return app;
}

function hasValidBearer(header: string | undefined, expected: string): boolean {
  if (!header?.startsWith(BEARER_PREFIX)) {
    return false;
  }

  const received = Buffer.from(header.slice(BEARER_PREFIX.length));
  const target = Buffer.from(expected);
  if (received.length !== target.length) {
    return false;
  }

  return timingSafeEqual(received, target);
}

function isJobEnvelope(value: unknown): value is JobRequestEnvelope {
  if (!isRecord(value) || !isRecord(value.request)) {
    return false;
  }

  const request = value.request;

  return (
    value.auth !== "" &&
    typeof value.auth === "string" &&
    request.v === JOB_PROTOCOL_VERSION &&
    typeof request.jobId === "string" &&
    isAddressValue(request.owner) &&
    isAddressValue(request.builder) &&
    isHexValue(request.builderPublicKey) &&
    isHexValue(request.grantId) &&
    typeof request.scope === "string" &&
    JOB_OPERATIONS.some((operation) => operation === request.operation) &&
    (request.pinnedVersion === null ||
      typeof request.pinnedVersion === "string") &&
    typeof request.deadline === "string"
  );
}

function isAddressValue(value: unknown): value is Address {
  return typeof value === "string" && isAddress(value);
}

function isHexValue(value: unknown): value is Hex {
  return typeof value === "string" && isHex(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function jobError(
  code: JobFailureCode,
  message: string,
  retryable = false,
): JobExecuteError {
  return { error: { code, message, retryable } };
}

function statusFor(
  code: JobFailureCode,
): 401 | 403 | 404 | 409 | 410 | 413 | 500 {
  switch (code) {
    case "AUTH_INVALID":
      return 401;
    case "BUILDER_MISMATCH":
    case "OWNER_MISMATCH":
    case "GRANT_REVOKED":
    case "GRANT_INVALID":
    case "SIGNED_ARTIFACT_MISSING":
    case "SIGNED_ARTIFACT_INVALID":
    case "SERVER_NOT_REGISTERED":
      return 403;
    case "SCOPE_NOT_FOUND":
      return 404;
    case "VERSION_MISMATCH":
      return 409;
    case "DEADLINE_PASSED":
      return 410;
    case "RESULT_TOO_LARGE":
      return 413;
    case "INTERNAL":
      return 500;
  }
}
