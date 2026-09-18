/**
 * Vana chain enforcement on the PDPP bearer read path.
 *
 * ## What was broken
 *
 * A PDPP access token proved the owner consented. Nothing checked the Vana
 * permission that actually authorizes the read. So a permission revoked on
 * chain kept serving records through PDPP, and the ledger's authority was not
 * enforced for any PDPP client. The legacy `/v1/data/{scope}` path ran the
 * chain check; the bearer path did not.
 *
 * These drive the REAL `pdppRecordsRoutes` over real requests against a real
 * record store. Only the Gateway is mocked, because reading a live chain in a
 * unit test would make the suite depend on a network and a funded deployment,
 * and no chain writes are performed anywhere in this work.
 *
 * ## The properties that matter
 *
 * Revocation must take effect. The owner must match. The grantee must be the
 * app that actually holds the grant. And the case that decides whether the
 * design is honest: when the chain cannot be READ, the answer is not "allow".
 * An outage that opened reads would be an authorization bypass that looks like
 * success in every log.
 *
 * Standalone PDPP stays chain-neutral: with no enforcement configured, the
 * path behaves exactly as before.
 */

import { describe, expect, it } from "vitest";
import { Hono } from "hono";
import {
  createMemoryRecordStore,
  createStreamDeclarationRegistry,
} from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { createFixtureAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth.test-utils";
import type {
  Grant,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  createPdppGrantBinding,
  type ChainPermissionRef,
  type PdppGrantBinding,
  type PdppGrantBindingStore,
} from "@opendatalabs/personal-server-ts-core/grants";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";
import pino from "pino";
import { chainPermissionEnforcement } from "../pdpp/chain-enforcement.js";
import { pdppRecordsRoutes } from "./pdpp-records.js";

const logger = pino({ level: "silent" });

const OWNER = "0x1111111111111111111111111111111111111111" as const;
const GRANTEE = "0x2222222222222222222222222222222222222222" as const;
const OTHER_GRANTEE = "0x3333333333333333333333333333333333333333" as const;
const CONTRACT = "0x4444444444444444444444444444444444444444" as const;
const CHAIN_ID = 1480;
const PERMISSION_ID = "42";
const PDPP_GRANT = "grant_1";
const CLIENT = "client_1";

const DEPLOYMENT = { chainId: CHAIN_ID, contractAddress: CONTRACT };
const PERMISSION: ChainPermissionRef = {
  chainId: CHAIN_ID,
  contractAddress: CONTRACT,
  permissionId: PERMISSION_ID,
};

const declarations = createStreamDeclarationRegistry([
  {
    name: "playlists",
    semantics: "mutable_state",
    primaryKey: ["id"],
    cursorField: "emitted_at",
    requiredFields: ["id"],
  },
]);

function grant(): Grant {
  return {
    version: "0.1.0",
    grant_id: PDPP_GRANT,
    issued_at: "2026-01-01T00:00:00Z",
    subject: { id: "sub_1" },
    client: { client_id: CLIENT },
    source: { kind: "provider_native", id: "src_1" },
    source_declaration: { version: "1" },
    purpose_code: "test",
    access_mode: "continuous",
    streams: [
      {
        name: "playlists",
        fields: ["id", "name"],
        instance_ids: ["inst_1"],
      },
    ],
  } as Grant;
}

/** A live chain grant, as the gateway reports it. */
function chainGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: PERMISSION_ID,
    grantorAddress: OWNER,
    granteeId: GRANTEE,
    revokedAt: null,
    ...overrides,
  } as GatewayGrantResponse;
}

/** The smallest store that satisfies the port. */
function bindingStore(initial?: PdppGrantBinding): PdppGrantBindingStore {
  const byGrant = new Map<string, PdppGrantBinding>();
  if (initial) byGrant.set(initial.pdppGrantId, initial);
  return {
    getByPdppGrantId: (id) => byGrant.get(id) ?? null,
    getByPermission: () => null,
    putBinding: (b) => byGrant.set(b.pdppGrantId, b),
  };
}

function boundBinding(): PdppGrantBinding {
  return createPdppGrantBinding({
    chainGrant: chainGrant(),
    granteeAddress: GRANTEE,
    pdppClientId: CLIENT,
    pdppGrantId: PDPP_GRANT,
    permission: PERMISSION,
    serverOwner: OWNER,
  });
}

interface HarnessOptions {
  binding?: PdppGrantBinding;
  readChainGrant?: (id: string) => Promise<GatewayGrantResponse | null>;
  granteeAddressFor?: (clientId: string) => `0x${string}` | null;
  /** Omit enforcement entirely: the standalone-PDPP path. */
  enforce?: boolean;
  token?: PdppTokenContext;
}

function harness(options: HarnessOptions = {}) {
  const store = createMemoryRecordStore();
  store.ingestBatch(
    [
      {
        instance: "inst_1",
        stream: "playlists",
        key: "pl_1",
        data: { id: "pl_1", name: "First" },
        emitted_at: "2026-04-01T00:00:00.000Z",
      },
    ],
    () => "mutable_state",
    () => ["id"],
  );

  const token: PdppTokenContext = options.token ?? {
    active: true,
    clientId: CLIENT,
    grant: grant(),
    subjectId: "sub_1",
    tokenKind: "client",
  };

  const enforcement =
    options.enforce === false
      ? undefined
      : chainPermissionEnforcement({
          bindings: bindingStore(options.binding ?? boundBinding()),
          deployment: DEPLOYMENT,
          granteeAddressFor: options.granteeAddressFor ?? (() => GRANTEE),
          logger,
          readChainGrant: options.readChainGrant ?? (async () => chainGrant()),
          serverOwner: OWNER,
        });

  const app = new Hono();
  app.route(
    "/v1",
    pdppRecordsRoutes({
      auth: createFixtureAuthorizationService({ "client-tok": token }),
      chainEnforcement: enforcement,
      declarations,
      instancesForSubject: () => ["inst_1"],
      store,
    }),
  );
  return app;
}

function read(app: Hono, token = "client-tok") {
  return app.request("/v1/streams/playlists/records", {
    headers: { Authorization: `Bearer ${token}` },
  });
}

describe("a bound, live chain permission authorizes the read", () => {
  it("serves records when the binding verifies", async () => {
    const response = await read(harness());
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: unknown[] };
    expect(body.data).toHaveLength(1);
  });

  it("still serves the owner's own reads, which no permission mediates", async () => {
    // An owner token is the owner reading their own server. Requiring a
    // grantee permission for it would lock owners out of their own data.
    const app = harness({
      token: { active: true, subjectId: "sub_1", tokenKind: "owner" },
    });
    const response = await read(app);
    expect(response.status).toBe(200);
  });
});

describe("chain revocation actually takes effect", () => {
  it("denies a read once the permission is revoked on chain", async () => {
    // The PDPP token is untouched and still active; only the chain changed.
    const app = harness({
      readChainGrant: async () =>
        chainGrant({ revokedAt: "2026-02-01T00:00:00Z" }),
    });

    const response = await read(app);
    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("grant_revoked");
  });

  it("treats a permission that no longer exists as revoked", async () => {
    // Null is a definite answer from the gateway: no such permission.
    const app = harness({ readChainGrant: async () => null });

    const response = await read(app);
    expect(response.status).toBe(403);
  });
});

describe("the binding must name this owner and this app", () => {
  it("denies when the chain grant belongs to a different owner", async () => {
    const app = harness({
      readChainGrant: async () => chainGrant({ grantorAddress: OTHER_GRANTEE }),
    });

    const response = await read(app);
    expect(response.status).toBe(403);
  });

  it("denies when the caller is not the bound grantee", async () => {
    // Knowing a grant id is not being the app it was issued to.
    const app = harness({ granteeAddressFor: () => OTHER_GRANTEE });

    const response = await read(app);
    expect(response.status).toBe(403);
  });

  it("denies when the client has no grantee address at all", async () => {
    const app = harness({ granteeAddressFor: () => null });

    const response = await read(app);
    expect(response.status).toBe(403);
  });

  it("denies a binding recorded for a different deployment", async () => {
    // permissionId is a per-deployment counter, so a Moksha binding must not
    // authorize a mainnet read.
    const foreign = createPdppGrantBinding({
      chainGrant: chainGrant(),
      granteeAddress: GRANTEE,
      pdppClientId: CLIENT,
      pdppGrantId: PDPP_GRANT,
      permission: { ...PERMISSION, chainId: 14800 },
      serverOwner: OWNER,
    });

    const response = await read(harness({ binding: foreign }));
    expect(response.status).toBe(403);
  });
});

describe("an unverifiable chain denies rather than opens", () => {
  it("does NOT serve records when the gateway cannot be reached", async () => {
    // The decisive case. Failing open here would turn an outage into a silent
    // authorization bypass, because every bypassed read looks successful.
    const app = harness({
      readChainGrant: async () => {
        throw new Error("ECONNREFUSED");
      },
    });

    const response = await read(app);
    expect(response.status).not.toBe(200);
  });

  it("reports an unreachable chain as retryable, not as a dead grant", async () => {
    const app = harness({
      readChainGrant: async () => {
        throw new Error("ECONNREFUSED");
      },
    });

    const response = await read(app);
    // Telling a client with a valid grant that it was revoked would send it
    // to re-consent over an outage.
    expect((await response.json()).error.code).not.toBe("grant_revoked");
    expect(response.headers.get("Retry-After")).toBe("5");
  });

  it("denies when no binding was ever recorded", async () => {
    // "Not bound yet" is indistinguishable from "never bound", so absence is
    // a definite denial rather than a pending state a caller can retry into.
    const app = harness({
      binding: createPdppGrantBinding({
        chainGrant: chainGrant(),
        granteeAddress: GRANTEE,
        pdppClientId: CLIENT,
        // A binding exists, but for a DIFFERENT PDPP grant.
        pdppGrantId: "grant_other",
        permission: PERMISSION,
        serverOwner: OWNER,
      }),
    });

    const response = await read(app);
    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe("grant_revoked");
  });
});

describe("standalone PDPP stays chain-neutral", () => {
  it("serves reads unchanged when no enforcement is configured", async () => {
    // A deployment with no chain must still work. Absence of the port is the
    // neutral path, not a disabled security check.
    const response = await read(harness({ enforce: false }));
    expect(response.status).toBe(200);
  });

  it("enforces nothing on the stream listing either, when unconfigured", async () => {
    const app = harness({ enforce: false });
    const response = await app.request("/v1/streams", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(response.status).toBe(200);
  });
});

describe("the gate covers every client endpoint, not just record reads", () => {
  it("denies the stream listing for a revoked permission", async () => {
    // A check added per-route is a check a later route forgets. This pins that
    // the listing is gated too, so a revoked client cannot enumerate streams.
    const app = harness({
      readChainGrant: async () =>
        chainGrant({ revokedAt: "2026-02-01T00:00:00Z" }),
    });

    const response = await app.request("/v1/streams", {
      headers: { Authorization: "Bearer client-tok" },
    });
    expect(response.status).toBe(403);
  });
});
