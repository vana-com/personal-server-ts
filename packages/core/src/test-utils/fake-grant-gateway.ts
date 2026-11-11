import type { GatewayClient } from "@opendatalabs/vana-sdk/node";

export interface FakeGatewayGrant {
  id: string;
  granteeId: string;
  scopes: string[];
  grantVersion: string;
  expiresAt: string | null;
  revokedAt: string | null;
  expired: boolean;
}

export interface FakeGrantGatewayOptions {
  /** Builder id `getBuilder` returns; the pair's grantee. */
  granteeId?: string;
  /** Mutate a grant after a revoke call, to model a gateway that lies. */
  afterRevoke?: (grant: FakeGatewayGrant) => void;
  /** Fail `revokeGrant` for these ids by throwing. */
  throwOnRevoke?: (id: string) => boolean;
}

/**
 * A gateway that models what the real one does to a replacement:
 *  - one version counter per grantee, shared by registration AND revocation;
 *  - a create or revoke signed at a version not above the counter is a 409,
 *    which the SDK swallows: `createGrant` returns the existing grant's id as
 *    if it had succeeded and `revokeGrant` returns normally;
 *  - registering a new grant does not itself revoke the old one.
 */
export function createFakeGrantGateway(options: FakeGrantGatewayOptions = {}) {
  const granteeId = options.granteeId ?? "0xbuilder";
  const grants = new Map<string, FakeGatewayGrant>();
  let counter = 0n;
  let sequence = 0;
  let lastId: string | undefined;

  /** Existing grants, as if registered before the code under test ran. */
  function seed(
    id: string,
    scopes: string[],
    extra: Partial<FakeGatewayGrant> = {},
  ): FakeGatewayGrant {
    counter += 1n;
    const grant: FakeGatewayGrant = {
      id,
      granteeId,
      scopes,
      grantVersion: counter.toString(),
      expiresAt: null,
      revokedAt: null,
      expired: false,
      ...extra,
    };
    grants.set(id, grant);
    lastId = id;
    return grant;
  }

  const gateway = {
    getBuilder: async () => ({ id: granteeId }),
    getGrant: async (id: string) => {
      const grant = grants.get(id);
      return grant ? { ...grant, scopes: [...grant.scopes] } : null;
    },
    createGrant: async (params: {
      scopes: string[];
      grantVersion: string;
      expiresAt: string;
    }) => {
      const version = BigInt(params.grantVersion);
      if (version <= counter) {
        // 409 swallowed by the SDK: the id comes from the error body.
        return { grantId: lastId ?? "0xunknown" };
      }
      counter = version;
      sequence += 1;
      const id = `0xnew${sequence}`;
      grants.set(id, {
        id,
        granteeId,
        scopes: [...params.scopes],
        grantVersion: version.toString(),
        expiresAt: params.expiresAt === "0" ? null : params.expiresAt,
        revokedAt: null,
        expired: false,
      });
      lastId = id;
      return { grantId: id };
    },
    revokeGrant: async (params: { grantId: string; grantVersion: string }) => {
      if (options.throwOnRevoke?.(params.grantId)) {
        throw new Error("gateway down");
      }
      const version = BigInt(params.grantVersion);
      if (version <= counter) return; // 409 swallowed by the SDK
      counter = version;
      const grant = grants.get(params.grantId);
      if (!grant) return;
      grant.revokedAt = "2026-11-10T10:00:00.000Z";
      options.afterRevoke?.(grant);
    },
  };

  return {
    gateway: gateway as unknown as GatewayClient,
    seed,
    grants,
    counter: () => counter,
  };
}
