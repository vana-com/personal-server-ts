import { describe, expect, it, vi } from "vitest";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import { pdppRecordsRoutes } from "./pdpp-records.js";
import { pdppBlobsRoutes } from "./pdpp-blobs.js";
import { pdppAuthRoutes } from "./pdpp-auth.js";

const auth = createFixtureAuthorizationService({
  stale: { active: false, inactiveReason: "grant_revoked" },
});

describe("bearer conformance profile", () => {
  it.each(["records", "blobs"])(
    "candidate %s returns the uniform inactive-bearer response",
    async (surface) => {
      const deps = {
        auth,
        store: createMemoryRecordStore(),
        declarations: createStreamDeclarationRegistry([]),
        protocolProfile: "candidate-0.1.0" as const,
      };
      const app =
        surface === "records" ? pdppRecordsRoutes(deps) : pdppBlobsRoutes(deps);
      const response = await app.request(
        surface === "records" ? "/streams" : "/blob_1",
        { headers: { Authorization: "Bearer stale" } },
      );
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toContain(
        'error="invalid_token"',
      );
      expect((await response.json()).error).toMatchObject({
        type: "authentication_error",
        code: "invalid_token",
      });
    },
  );

  it.each([undefined, "current"] as const)(
    "preserves current records behavior for profile %s",
    async (protocolProfile) => {
      const app = pdppRecordsRoutes({
        auth,
        store: createMemoryRecordStore(),
        declarations: createStreamDeclarationRegistry([]),
        protocolProfile,
      });
      const response = await app.request("/streams", {
        headers: { Authorization: "Bearer stale" },
      });
      expect(response.status).toBe(403);
      expect((await response.json()).error.code).toBe("grant_revoked");
    },
  );

  it.each([
    ["GET", "/grants"],
    ["POST", "/revoke"],
    ["POST", "/introspect"],
  ])(
    "candidate AS %s %s challenges an inactive owner bearer",
    async (method, path) => {
      const deps = {
        tokens: {
          resolveToken: () => ({ active: false, inactiveReason: "expired" }),
        },
        protocolProfile: "candidate-0.1.0",
      } as Parameters<typeof pdppAuthRoutes>[0];
      const app = pdppAuthRoutes(deps);
      const response = await app.request(path, {
        method,
        headers: { Authorization: "Bearer stale" },
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toContain(
        'error="invalid_token"',
      );
      expect(response.headers.get("Cache-Control")).toBe("no-store");
      expect((await response.json()).error).toBe("invalid_token");
    },
  );

  it.each([
    ["GET", "/grants"],
    ["POST", "/revoke"],
    ["POST", "/introspect"],
  ])(
    "current AS %s %s keeps its OAuth 401 without a challenge",
    async (method, path) => {
      const deps = {
        tokens: {
          resolveToken: () => ({ active: false, inactiveReason: "expired" }),
        },
        protocolProfile: "current",
      } as Parameters<typeof pdppAuthRoutes>[0];
      const response = await pdppAuthRoutes(deps).request(path, {
        method,
        headers: { Authorization: "Bearer stale" },
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toBeNull();
      expect((await response.json()).error).not.toBe("invalid_token");
    },
  );
});

describe("candidate AS authentication rendering", () => {
  it.each([undefined, "Bearer stale"])(
    "challenges %s without repeating token resolution",
    async (authorization) => {
      const resolveToken = vi.fn(() => ({
        active: false,
        inactiveReason: "expired",
      }));
      const deps = {
        tokens: { resolveToken },
        protocolProfile: "candidate-0.1.0",
      } as unknown as Parameters<typeof pdppAuthRoutes>[0];
      const response = await pdppAuthRoutes(deps).request("/grants", {
        headers: authorization ? { authorization } : {},
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toContain(
        'error="invalid_token"',
      );
      expect(resolveToken).toHaveBeenCalledTimes(authorization ? 1 : 0);
    },
  );
});

describe("AS non-bearer authentication failures", () => {
  it.each([
    ["current", "/owner/token"],
    ["current", "/authorize"],
    ["candidate-0.1.0", "/owner/token"],
    ["candidate-0.1.0", "/authorize"],
  ] as const)(
    "preserves OAuth errors for %s %s without a bearer challenge",
    async (protocolProfile, path) => {
      const resolveToken = vi.fn();
      const deps = {
        tokens: { resolveToken },
        protocolProfile,
        currentSubjectId: () => null,
      } as unknown as Parameters<typeof pdppAuthRoutes>[0];
      const response = await pdppAuthRoutes(deps).request(path, {
        method: "POST",
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("WWW-Authenticate")).toBeNull();
      const body = await response.json();
      expect(body.error).toBe("unauthorized");
      expect(typeof body.error_description).toBe("string");
      expect(resolveToken).not.toHaveBeenCalled();
    },
  );
});
