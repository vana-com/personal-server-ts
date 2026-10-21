/**
 * A PDPP record read is authorized again at two points after the token is
 * first resolved: at admission, right after the chain check's await, and at
 * release, after the handler has built the whole response (chain check and
 * access-log write included). A bearer that ends between resolution and
 * release must never receive the records.
 *
 * Bearers resolve through the real AS token and grant store (SQLite). Grant
 * revocation, token expiry and refresh-family revocation go through the same
 * store and token service the AS routes use.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  openPdppAuthStore,
  PdppTokenService,
  type Grant,
  type PdppAuthStore,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
  type PdppRecordStore,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { coLocatedAuthorizationService } from "../pdpp/records-bootstrap.js";
import type { PdppAuthRouteDeps } from "./pdpp-auth.js";
import {
  pdppRecordsRoutes,
  type PdppChainDecision,
  type PdppRecordsRouteDeps,
} from "./pdpp-records.js";

const declarations = createStreamDeclarationRegistry([
  {
    name: "media",
    semantics: "append_only",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

const GRANT: Grant = {
  version: "0.1.0",
  grant_id: "grt_delivery",
  issued_at: "2026-01-01T00:00:00Z",
  subject: { id: "sub_1" },
  client: { client_id: "client_1" },
  source: { kind: "provider_native", id: "src_1" },
  source_declaration: { version: "1" },
  purpose_code: "test",
  access_mode: "continuous",
  streams: [{ name: "media", instance_ids: ["inst_1"], fields: ["id"] }],
};
const TOKEN = "pdpp_at_delivery_test";
const REFRESH = "pdpp_rt_delivery_test";
const SECRET = "private-record";
const TOKEN_TTL_MS = 60_000;

let dir: string;
let authStore: PdppAuthStore;
let tokens: PdppTokenService;
let records: PdppRecordStore;

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "pdpp-delivery-lease-"));
  authStore = openPdppAuthStore(join(dir, "auth.db"));
  authStore.insertGrant({
    grant: GRANT,
    subjectId: "sub_1",
    reviewDigest: "t",
  });
  const familyId = authStore.createRefreshFamily(GRANT.grant_id);
  expect(
    authStore.issueAccessToken({
      token: TOKEN,
      grantId: GRANT.grant_id,
      subjectId: "sub_1",
      clientId: "client_1",
      tokenKind: "client",
      familyId,
      expiresAt: new Date(Date.now() + TOKEN_TTL_MS).toISOString(),
      consumeSingleUse: false,
    }),
  ).toBe(true);
  authStore.insertRefreshToken(REFRESH, familyId);
  tokens = new PdppTokenService(authStore);
  records = createMemoryRecordStore();
  records.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "media",
        key: SECRET,
        data: { id: SECRET },
        emitted_at: "2026-04-01T00:00:00Z",
      },
    ],
    () => "append_only",
    () => ["id"],
  );
});

afterEach(async () => {
  vi.useRealTimers();
  records.close();
  authStore.close();
  await rm(dir, { recursive: true, force: true });
});

function routes(extra: Partial<PdppRecordsRouteDeps> = {}) {
  return pdppRecordsRoutes({
    store: records,
    auth: coLocatedAuthorizationService({ tokens } as PdppAuthRouteDeps),
    declarations,
    ownerSubjectId: "sub_1",
    instancesForSubject: () => ["inst_1"],
    ...extra,
  });
}

const headers = { Authorization: `Bearer ${TOKEN}` };

/** Ways the bearer ends, each through the real token store. */
const endings: Record<string, () => void> = {
  "the owner revokes the grant": () => {
    expect(authStore.revokeGrant(GRANT.grant_id)).toBe(true);
  },
  "the access token expires": () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + TOKEN_TTL_MS * 2);
  },
  "refresh-token reuse revokes the token family": () => {
    expect(tokens.refresh({ refreshToken: REFRESH }).ok).toBe(true);
    // Presenting the superseded refresh token again is reuse.
    expect(tokens.refresh({ refreshToken: REFRESH }).ok).toBe(false);
  },
};

const readPaths = {
  "a record list": "/streams/media/records",
  "a single record": `/streams/media/records/${SECRET}`,
  "stream metadata": "/streams/media",
};

describe("admission: a bearer that ends while the chain check is in flight", () => {
  for (const [ending, end] of Object.entries(endings)) {
    for (const [read, path] of Object.entries(readPaths)) {
      it(`refuses ${read} when ${ending}`, async () => {
        // The chain lookup is deferred; the bearer ends during it, and then
        // the chain answers that the permission is live.
        let release!: (decision: PdppChainDecision) => void;
        const chainAnswered = new Promise<PdppChainDecision>((resolve) => {
          release = resolve;
        });
        let chainAsked!: () => void;
        const asked = new Promise<void>((resolve) => {
          chainAsked = resolve;
        });
        const app = routes({
          chainEnforcement: {
            authorize: () => {
              chainAsked();
              return chainAnswered;
            },
          },
        });

        const pending = app.request(path, { headers });
        await asked;
        end();
        release({ ok: true });
        const response = await pending;
        const text = await response.text();

        expect(response.status, text).toBeGreaterThanOrEqual(400);
        expect(text).not.toContain(SECRET);
        expect(text).not.toContain("stream_metadata");
      });
    }
  }
});

describe("release: a grant revoked after admission, before the response leaves", () => {
  it("refuses a grant revoked during the chain check", async () => {
    const app = routes({
      chainEnforcement: {
        authorize: async () => {
          authStore.revokeGrant(GRANT.grant_id);
          return { ok: true };
        },
      },
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    expect(authStore.getGrant(GRANT.grant_id)?.revokedAt).toBeTruthy();
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_revoked");
    expect(text).not.toContain(SECRET);
  });

  it("refuses a grant revoked during the access-log write", async () => {
    const recorded: string[] = [];
    const app = routes({
      accessLog: {
        record: async (entry) => {
          recorded.push(entry.outcome);
          authStore.revokeGrant(GRANT.grant_id);
        },
      },
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    // The handler built and logged the read; the release gate stopped it.
    expect(recorded).toEqual(["completed"]);
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_revoked");
    expect(text).not.toContain(SECRET);
  });

  it("still serves the read when the grant stays live (positive control)", async () => {
    const app = routes({
      chainEnforcement: { authorize: async () => ({ ok: true }) },
      accessLog: { record: async () => undefined },
    });
    const response = await app.request("/streams/media/records", { headers });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain(SECRET);
  });
});

describe("release-gate refusals follow the protocol profile", () => {
  function revokedDuringAccessLog(
    protocolProfile: PdppRecordsRouteDeps["protocolProfile"],
  ) {
    return routes({
      protocolProfile,
      accessLog: {
        record: async () => {
          authStore.revokeGrant(GRANT.grant_id);
        },
      },
    }).request("http://rs.test/streams/media/records", { headers });
  }

  it("is 403 grant_revoked under current", async () => {
    const response = await revokedDuringAccessLog("current");
    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("grant_revoked");
    expect(response.headers.get("WWW-Authenticate")).toBeNull();
  });

  it("is 401 invalid_token with the challenge under candidate-0.1.0", async () => {
    const response = await revokedDuringAccessLog("candidate-0.1.0");
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error.code).toBe("invalid_token");
    expect(JSON.stringify(body)).not.toContain(SECRET);
    expect(response.headers.get("WWW-Authenticate")).toBe(
      'Bearer error="invalid_token", resource_metadata="http://rs.test/.well-known/oauth-protected-resource"',
    );
  });
});

describe("chain re-verification at release", () => {
  it("makes no second chain call for a normal request", async () => {
    const authorize = vi.fn(async () => ({ ok: true }) as const);
    const app = routes({ chainEnforcement: { authorize } });
    const response = await app.request("/streams/media/records", { headers });
    expect(response.status).toBe(200);
    expect(authorize).toHaveBeenCalledTimes(1);
  });

  it("asks the chain again when the release comes more than 30 s after it", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const answers: PdppChainDecision[] = [
      { ok: true },
      {
        ok: false,
        retryable: false,
        reason: "permission revoked on chain",
        cause: "revoked",
      },
    ];
    const authorize = vi.fn(async () => answers.shift()!);
    const app = routes({
      chainEnforcement: { authorize },
      accessLog: {
        record: async () => {
          // A slow request: the release comes 31 s after admission.
          vi.setSystemTime(Date.now() + 31_000);
        },
      },
    });
    // The token outlives the slow request.
    authStore.issueAccessToken({
      token: "pdpp_at_long",
      grantId: GRANT.grant_id,
      subjectId: "sub_1",
      clientId: "client_1",
      tokenKind: "client",
      expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
      consumeSingleUse: false,
    });
    const response = await app.request("/streams/media/records", {
      headers: { Authorization: "Bearer pdpp_at_long" },
    });
    const text = await response.text();
    expect(authorize).toHaveBeenCalledTimes(2);
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_revoked");
    expect(text).not.toContain(SECRET);
  });
});
