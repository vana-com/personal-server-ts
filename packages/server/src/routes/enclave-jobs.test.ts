import { describe, expect, it, vi } from "vitest";
import type { JobRequestEnvelope } from "@opendatalabs/vana-sdk/protocol/jobs";
import { JobFailure } from "../jobs/worker.js";
import { enclaveJobRoutes } from "./enclave-jobs.js";

const ACCESS_TOKEN = "test-access-token";
const OWNER = "0x1111111111111111111111111111111111111111";
const BUILDER = "0x2222222222222222222222222222222222222222";
const PUBLIC_KEY = `0x04${"11".repeat(64)}` as const;

function envelope(): JobRequestEnvelope {
  return {
    request: {
      v: 1,
      jobId: "job-1",
      owner: OWNER,
      builder: BUILDER,
      builderPublicKey: PUBLIC_KEY,
      grantId: `0x${"33".repeat(32)}`,
      scope: "profile",
      operation: "raw_read",
      pinnedVersion: null,
      deadline: "2030-01-01T00:00:00.000Z",
    },
    auth: "Web3Signed payload.signature",
  };
}

function request(body: unknown, token = ACCESS_TOKEN): Request {
  return new Request("http://localhost/execute", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

describe("POST /enclave/v1/jobs/execute", () => {
  it("rejects requests without the sandbox bearer", async () => {
    const app = enclaveJobRoutes({
      accessToken: ACCESS_TOKEN,
      executeJob: vi.fn(),
    });

    const response = await app.request("/execute", { method: "POST" });

    expect(response.status).toBe(401);
  });

  it("rejects an invalid envelope", async () => {
    const executeJob = vi.fn();
    const app = enclaveJobRoutes({ accessToken: ACCESS_TOKEN, executeJob });

    const response = await app.request(request({ request: {}, auth: 12 }));

    expect(response.status).toBe(400);
    expect(executeJob).not.toHaveBeenCalled();
  });

  it("returns an encrypted job result", async () => {
    const result = {
      resultObjectKey: "jobresults/14800/job-1",
      resultHash: `0x${"44".repeat(32)}` as const,
      resultSize: 10,
    };
    const executeJob = vi.fn().mockResolvedValue(result);
    const app = enclaveJobRoutes({ accessToken: ACCESS_TOKEN, executeJob });

    const response = await app.request(request(envelope()));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(result);
    expect(executeJob).toHaveBeenCalledWith(envelope());
  });

  it("maps a version mismatch to conflict", async () => {
    const executeJob = vi
      .fn()
      .mockRejectedValue(
        new JobFailure("VERSION_MISMATCH", "scope version mismatch", true),
      );
    const app = enclaveJobRoutes({ accessToken: ACCESS_TOKEN, executeJob });

    const response = await app.request(request(envelope()));

    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: {
        code: "VERSION_MISMATCH",
        message: "scope version mismatch",
        retryable: true,
      },
    });
  });
});
