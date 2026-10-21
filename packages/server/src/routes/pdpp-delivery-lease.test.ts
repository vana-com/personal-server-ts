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
import { REMOTE_GRANT_REVERIFY_AFTER_MS } from "@opendatalabs/personal-server-ts-core/policy";
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

/**
 * The record store, with `hook` run when a handler reads records: after
 * admission and before the release, as slow storage or a concurrent owner
 * action would land.
 */
function storeReading(hook: () => void): PdppRecordStore {
  return new Proxy(records, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver);
      if (typeof value !== "function") return value;
      if (prop === "listRecords" || prop === "getRecord") {
        return (...args: unknown[]) => {
          hook();
          return (value as (...a: unknown[]) => unknown).apply(target, args);
        };
      }
      return (value as (...a: unknown[]) => unknown).bind(target);
    },
  });
}

/** A token that outlives a slow request. */
function longToken(): string {
  authStore.issueAccessToken({
    token: "pdpp_at_long",
    grantId: GRANT.grant_id,
    subjectId: "sub_1",
    clientId: "client_1",
    tokenKind: "client",
    expiresAt: new Date(Date.now() + 3_600_000).toISOString(),
    consumeSingleUse: false,
  });
  return "pdpp_at_long";
}

describe("release: the bearer ends after admission, before the response leaves", () => {
  it("refuses a grant revoked while the handler reads", async () => {
    const app = routes({
      store: storeReading(() => {
        authStore.revokeGrant(GRANT.grant_id);
      }),
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    expect(authStore.getGrant(GRANT.grant_id)?.revokedAt).toBeTruthy();
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_revoked");
    expect(text).not.toContain(SECRET);
  });

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
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_revoked");
    expect(text).not.toContain(SECRET);
  });

  it("refuses a record whose connection is deleted while the handler reads", async () => {
    const bindings = new Map([
      [
        "inst_1",
        {
          sourceId: "src_1" as string | null,
          deletedAt: null as string | null,
        },
      ],
    ]);
    const app = routes({
      bindingStore: {
        getInstanceBinding: (instance: string) =>
          bindings.get(instance) ?? { sourceId: null, deletedAt: null },
      } as unknown as PdppRecordsRouteDeps["bindingStore"],
      store: storeReading(() => {
        bindings.set("inst_1", {
          sourceId: "src_1",
          deletedAt: "2026-10-21T00:00:00Z",
        });
      }),
    });
    for (const path of [
      "/streams/media/records",
      `/streams/media/records/${SECRET}`,
    ]) {
      bindings.set("inst_1", { sourceId: "src_1", deletedAt: null });
      const response = await app.request(path, { headers });
      const text = await response.text();
      expect(response.status, text).toBe(404);
      expect(JSON.parse(text).error.code).toBe("instance_unavailable");
      expect(text).not.toContain(`"id":"${SECRET}"`);
    }
  });

  it("still serves the read when nothing changes (positive control)", async () => {
    const app = routes({
      chainEnforcement: { authorize: async () => ({ ok: true }) },
      accessLog: { record: async () => undefined },
    });
    const response = await app.request("/streams/media/records", { headers });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain(SECRET);
  });
});

describe("the owner access feed records the outcome the release gate decided", () => {
  it("records a refused delivery as denied, never completed", async () => {
    const recorded: string[] = [];
    const app = routes({
      accessLog: {
        record: async (entry) => {
          recorded.push(entry.outcome);
        },
      },
      store: storeReading(() => {
        authStore.revokeGrant(GRANT.grant_id);
      }),
    });
    const response = await app.request("/streams/media/records", { headers });
    expect(response.status).toBe(403);
    await Promise.resolve();
    expect(recorded).toEqual(["denied"]);
  });

  it("records a released read as completed", async () => {
    const recorded: string[] = [];
    const app = routes({
      accessLog: {
        record: async (entry) => {
          recorded.push(entry.outcome);
        },
      },
    });
    const response = await app.request("/streams/media/records", { headers });
    expect(response.status).toBe(200);
    expect(recorded).toEqual(["completed"]);
  });
});

describe("release-gate refusals follow the protocol profile", () => {
  function revokedWhileReading(
    protocolProfile: PdppRecordsRouteDeps["protocolProfile"],
  ) {
    return routes({
      protocolProfile,
      store: storeReading(() => {
        authStore.revokeGrant(GRANT.grant_id);
      }),
    }).request("http://rs.test/streams/media/records", { headers });
  }

  it("is 403 grant_revoked under current", async () => {
    const response = await revokedWhileReading("current");
    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("grant_revoked");
    expect(response.headers.get("WWW-Authenticate")).toBeNull();
  });

  it("is 401 invalid_token with the challenge under candidate-0.1.0", async () => {
    const response = await revokedWhileReading("candidate-0.1.0");
    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error.code).toBe("invalid_token");
    expect(JSON.stringify(body)).not.toContain(SECRET);
    expect(response.headers.get("WWW-Authenticate")).toBe(
      'Bearer error="invalid_token", resource_metadata="http://rs.test/.well-known/oauth-protected-resource"',
    );
  });
});

describe("chain evidence at release", () => {
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
    const token = longToken();
    const app = routes({
      chainEnforcement: { authorize },
      // A slow read: the release comes 31 s after admission.
      store: storeReading(() => vi.setSystemTime(Date.now() + 31_000)),
    });
    const response = await app.request("/streams/media/records", {
      headers: { Authorization: `Bearer ${token}` },
    });
    const text = await response.text();
    expect(authorize).toHaveBeenCalledTimes(2);
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_revoked");
    expect(text).not.toContain(SECRET);
  });

  for (const [ending, end] of Object.entries(endings)) {
    it(`refuses when ${ending} while the second chain call is pending`, async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      let calls = 0;
      const app = routes({
        chainEnforcement: {
          authorize: async () => {
            calls += 1;
            // The re-verification at release: the bearer ends locally while
            // it is in flight, then the chain answers that it is live.
            if (calls === 2) end();
            return { ok: true };
          },
        },
        store: storeReading(() => vi.setSystemTime(Date.now() + 31_000)),
      });
      const response = await app.request("/streams/media/records", {
        headers,
      });
      const text = await response.text();
      expect(calls).toBeGreaterThanOrEqual(2);
      expect(response.status, text).toBeGreaterThanOrEqual(400);
      expect(text).not.toContain(SECRET);
    });
  }

  it("refuses at release once a carried chain expiry passes inside the 30 s window", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const authorize = vi.fn(async (): Promise<PdppChainDecision> => ({
      ok: true,
      expiresAt: new Date(Date.now() + 5_000).toISOString(),
    }));
    const app = routes({
      chainEnforcement: { authorize },
      // 10 s pass: the chain permission expires, the 30 s window does not.
      store: storeReading(() => vi.setSystemTime(Date.now() + 10_000)),
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    expect(authorize).toHaveBeenCalledTimes(1);
    expect(response.status, text).toBe(403);
    expect(JSON.parse(text).error.code).toBe("grant_expired");
    expect(text).not.toContain(SECRET);
  });
});

describe("discovery and metadata hold the bearer's connections", () => {
  for (const path of ["/streams", "/streams/media"]) {
    it(`refuses ${path} when the client's connection is deleted`, async () => {
      let bindingChecks = 0;
      const app = routes({
        bindingStore: {
          getInstanceBinding: () => {
            bindingChecks += 1;
            return { sourceId: "src_1", deletedAt: "2026-10-21T00:00:00Z" };
          },
        } as unknown as PdppRecordsRouteDeps["bindingStore"],
      });
      const response = await app.request(path, { headers });
      const text = await response.text();
      expect(bindingChecks).toBeGreaterThan(0);
      expect(response.status, text).toBe(404);
      expect(JSON.parse(text).error.code).toBe("instance_unavailable");
      expect(text).not.toContain("stream_metadata");
    });
  }
});

describe("the authorization server's locality decides the release check", () => {
  const local = () =>
    coLocatedAuthorizationService({ tokens } as PdppAuthRouteDeps);

  it("a co-located AS: a revocation after the bearer was resolved refuses at release", async () => {
    const as = local();
    const app = routes({
      auth: {
        ...as,
        async resolveToken(token: string) {
          const context = await as.resolveToken(token);
          queueMicrotask(() => authStore.revokeGrant(GRANT.grant_id));
          return context;
        },
      },
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    expect(response.status, text).toBe(403);
    expect(text).not.toContain(SECRET);
  });

  it("an AS with no declared locality fails closed instead of falling back", async () => {
    const as = local();
    const app = routes({
      // Neither "local" nor "remote": the lease cannot know how to re-check.
      auth: {
        resolveToken: (token: string) => as.resolveToken(token),
      } as never,
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    expect(response.status, text).toBe(500);
    expect(text).not.toContain(SECRET);
  });

  describe("a remote AS (introspection), under the remote-staleness policy", () => {
    function remoteApp(after: () => void) {
      const as = local();
      return routes({
        auth: {
          locality: "remote",
          resolveToken: (token: string) => as.resolveToken(token),
        },
        store: storeReading(after),
      });
    }

    it("serves a revocation newer than its last answer within 30 s", async () => {
      const app = remoteApp(() => authStore.revokeGrant(GRANT.grant_id));
      const response = await app.request("/streams/media/records", {
        headers,
      });
      // Documented: the remote answer is at most 30 s old at release.
      expect(response.status).toBe(200);
    });

    it("asks again, and refuses, once its answer is older than 30 s", async () => {
      vi.useFakeTimers({ toFake: ["Date"] });
      const token = longToken();
      const app = remoteApp(() => {
        authStore.revokeGrant(GRANT.grant_id);
        vi.setSystemTime(Date.now() + 31_000);
      });
      const response = await app.request("/streams/media/records", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const text = await response.text();
      expect(response.status, text).toBe(403);
      expect(text).not.toContain(SECRET);
    });
  });
});

describe("a remote AS answer is dated from when introspection started", () => {
  it("refreshes, and refuses, an answer whose introspection took 31 s", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const as = coLocatedAuthorizationService({ tokens } as PdppAuthRouteDeps);
    let calls = 0;
    const app = routes({
      auth: {
        locality: "remote",
        async resolveToken(token: string) {
          calls += 1;
          if (calls > 1) {
            return {
              active: false,
              tokenKind: "client",
              subjectId: "",
              inactiveReason: "grant_revoked",
            };
          }
          const answer = await as.resolveToken(token);
          vi.setSystemTime(Date.now() + 31_000);
          return answer;
        },
      },
    });
    const response = await app.request("/streams/media/records", { headers });
    const text = await response.text();
    expect(calls).toBe(2);
    expect(response.status, text).toBe(403);
    expect(text).not.toContain(SECRET);
  });
});

describe("a read holds exactly the connections it selected", () => {
  const twoConnectionGrant: Grant = {
    ...GRANT,
    grant_id: "grt_two",
    streams: [
      { name: "media", instance_ids: ["inst_1"], fields: ["id"] },
      { name: "other", instance_ids: ["inst_2"], fields: ["id"] },
    ],
  };
  const context = {
    active: true as const,
    tokenKind: "client" as const,
    subjectId: "sub_1",
    clientId: "client_1",
    grant: twoConnectionGrant,
  };
  const fixedAuth = {
    locality: "local" as const,
    resolveToken: async () => context,
    resolveTokenNow: () => context,
  };
  const deletedSecond = {
    getInstanceBinding: (instance: string) => ({
      sourceId: "src_1",
      deletedAt: instance === "inst_2" ? "2026-10-21T19:00:00Z" : null,
    }),
  } as unknown as PdppRecordsRouteDeps["bindingStore"];

  it("deleting an unrelated connection does not refuse a read of another", async () => {
    const response = await routes({
      auth: fixedAuth as never,
      bindingStore: deletedSecond,
    }).request("/streams/media/records", { headers });
    const text = await response.text();
    expect(response.status, text).toBe(200);
    expect(text).toContain(SECRET);
  });

  it("stream discovery, an aggregate, holds all of its connections", async () => {
    const response = await routes({
      auth: fixedAuth as never,
      bindingStore: deletedSecond,
    }).request("/streams", { headers });
    expect(response.status).toBe(404);
  });

  it("a source-scoped owner token holds the connections it resolved", async () => {
    let deleted = false;
    let checks = 0;
    const owner = {
      active: true as const,
      tokenKind: "owner" as const,
      subjectId: "sub_1",
      sourceId: "src_1",
    };
    const app = routes({
      auth: {
        locality: "local",
        resolveToken: async () => owner,
        resolveTokenNow: () => owner,
      } as never,
      instancesForSubject: () => (deleted ? [] : ["inst_1"]),
      instancesForSource: () => (deleted ? [] : ["inst_1"]),
      bindingStore: {
        getInstanceBinding: () => {
          checks += 1;
          return {
            sourceId: "src_1",
            deletedAt: deleted ? "2026-10-21T19:00:00Z" : null,
          };
        },
      } as unknown as PdppRecordsRouteDeps["bindingStore"],
      store: new Proxy(records, {
        get(target, prop, receiver) {
          const value = Reflect.get(target, prop, receiver);
          if (prop === "listStreams") {
            return (...args: unknown[]) => {
              const result = (value as (...a: unknown[]) => unknown).apply(
                target,
                args,
              );
              // The connection is deleted while discovery is built.
              deleted = true;
              return result;
            };
          }
          return typeof value === "function"
            ? (value as (...a: unknown[]) => unknown).bind(target)
            : value;
        },
      }),
    });
    const response = await app.request("/streams", {
      headers: { Authorization: "Bearer owner" },
    });
    const text = await response.text();
    expect(deleted).toBe(true);
    expect(checks).toBeGreaterThan(0);
    expect(response.status, text).toBe(404);
  });
});

/**
 * The remote revocation policy: a grant revoked at a remote authority (here
 * the chain) stops reads within `REMOTE_GRANT_REVERIFY_AFTER_MS`. A release
 * before the bound may succeed on the admitting answer; the first release
 * after it asks again and is refused.
 */
describe("remote revocation stops reads within REMOTE_GRANT_REVERIFY_AFTER_MS", () => {
  function chainRevokedAfterAdmission(elapsedMs: number) {
    let revoked = false;
    const authorize = vi.fn(async (): Promise<PdppChainDecision> =>
      revoked
        ? {
            ok: false,
            retryable: false,
            reason: "permission revoked on chain",
            cause: "revoked",
          }
        : { ok: true },
    );
    const app = routes({
      chainEnforcement: { authorize },
      store: storeReading(() => {
        // Revoked remotely right after admission; the read takes elapsedMs.
        revoked = true;
        vi.setSystemTime(Date.now() + elapsedMs);
      }),
    });
    return { app, authorize };
  }

  it("a release before the bound may succeed", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const token = longToken();
    const { app, authorize } = chainRevokedAfterAdmission(
      REMOTE_GRANT_REVERIFY_AFTER_MS - 1_000,
    );
    const response = await app.request(`/streams/media/records/${SECRET}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(200);
    expect(authorize).toHaveBeenCalledTimes(1);
  });

  it("the first release after the bound is refused", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const token = longToken();
    const { app, authorize } = chainRevokedAfterAdmission(
      REMOTE_GRANT_REVERIFY_AFTER_MS,
    );
    const response = await app.request(`/streams/media/records/${SECRET}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const text = await response.text();
    expect(authorize).toHaveBeenCalledTimes(2);
    expect(response.status, text).toBe(403);
    expect(text).not.toContain(`"id":"${SECRET}"`);
  });
});
