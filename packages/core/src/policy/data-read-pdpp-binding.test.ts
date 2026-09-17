/**
 * §6 binding enforced through the REAL read path.
 *
 * These tests call `verifyDataReadPolicy` — the same function the PS data
 * routes call — rather than the binding helpers directly. What is substituted
 * is only the network edge: the gateway/builder lookups are the existing
 * `GrantVerifierPort` / `AuthSessionVerifierPort` ports, given local
 * implementations. Every authorization decision under test is made by real
 * application code:
 *
 *   verifyDataReadPolicy → verifyPdppGrantBinding → the retained binding
 *
 * Limitation, stated plainly: no chain RPC and no live gateway is contacted,
 * so these prove the PS's *enforcement* of a binding, not that a given
 * permission exists on Vana mainnet. Read-time revocation here is the gateway's
 * `revokedAt`, which is the same field the deployed contract's `endBlock`
 * revocation surfaces through the Data Gateway.
 */

import { describe, expect, it } from "vitest";
import type {
  Builder,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";

import {
  createPdppGrantBinding,
  type ChainPermissionRef,
} from "../grants/pdpp-binding.js";
import { createInMemoryPdppGrantBindingStore } from "../grants/pdpp-binding-store.js";

import { verifyDataReadPolicy } from "./data-read.js";

const OWNER = "0x00000000000000000000000000000000000000AA" as const;
const OTHER_OWNER = "0x00000000000000000000000000000000000000BB" as const;
/** App A's stable grantee wallet — the identity §6 requires preserving. */
const APP_A = "0x00000000000000000000000000000000000000C1" as const;
/** App B's stable grantee wallet. A different builder/app. */
const APP_B = "0x00000000000000000000000000000000000000C2" as const;
const CONTRACT = "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF" as const;

const DEPLOYMENT = { chainId: 14800, contractAddress: CONTRACT } as const;

const PERMISSION_A: ChainPermissionRef = {
  chainId: 14800,
  contractAddress: CONTRACT,
  permissionId: "42",
};

const SCOPE = "instagram.posts";

function builderFor(granteeAddress: `0x${string}`): Builder {
  // The gateway keys a builder by its grantee address; `id` is what the chain
  // grant's `granteeId` carries.
  return {
    id: granteeAddress,
    ownerAddress: OWNER,
    granteeAddress,
    publicKey: "0x04key",
    appUrl: "https://app.example.com",
    addedAt: "2026-09-17T10:00:00.000Z",
  } as Builder;
}

function chainGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "42",
    grantorAddress: OWNER,
    granteeId: APP_A,
    scopes: ["instagram.*"],
    status: "confirmed",
    addedAt: "2026-09-17T10:00:00.000Z",
    expiresAt: null,
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: null,
    paidBy: null,
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: null,
    ...overrides,
  } as GatewayGrantResponse;
}

/**
 * Build the ports the real policy takes, plus a retained binding.
 *
 * `grants` is the gateway's view, keyed by grant id, and is what read-time
 * revocation is read from.
 */
function harness(
  options: {
    grants?: Record<string, GatewayGrantResponse>;
    builders?: `0x${string}`[];
    binding?: ReturnType<typeof createPdppGrantBinding>;
  } = {},
) {
  const grants = options.grants ?? { "42": chainGrant() };
  const builders = options.builders ?? [APP_A, APP_B];

  const store = createInMemoryPdppGrantBindingStore();
  const binding =
    options.binding ??
    createPdppGrantBinding({
      pdppGrantId: "pdpp-grant-1",
      permission: PERMISSION_A,
      serverOwner: OWNER,
      granteeAddress: APP_A,
      pdppClientId: "client-app-a",
      chainGrant: chainGrant(),
    });
  store.putBinding(binding);

  return {
    store,
    binding,
    grants,
    ports: {
      authSessionVerifier: {
        async getBuilder(address: string) {
          const match = builders.find(
            (b) => b.toLowerCase() === address.toLowerCase(),
          );
          return match ? builderFor(match) : null;
        },
      },
      grantVerifier: {
        async getGrant(grantId: string) {
          return grants[grantId] ?? null;
        },
      },
      pdppGrantBindings: store,
      chainDeployment: DEPLOYMENT,
    },
  };
}

async function expectPolicyFailure(
  promise: Promise<unknown>,
  errorCode: string,
): Promise<void> {
  let thrown: unknown;
  try {
    await promise;
  } catch (error) {
    thrown = error;
  }
  expect(thrown, "expected the read to be denied").toBeDefined();
  expect((thrown as { errorCode?: string }).errorCode).toBe(errorCode);
}

describe("verifyDataReadPolicy — PDPP §6 grant binding", () => {
  it("allows a read when the PDPP grant, chain grant, owner, and app all bind", async () => {
    const h = harness();
    const grant = await verifyDataReadPolicy(
      {
        signer: APP_A,
        grantId: "42",
        pdppGrantId: "pdpp-grant-1",
        requestedScope: SCOPE,
        serverOwner: OWNER,
      },
      h.ports,
    );
    expect(grant.id).toBe("42");
  });

  it("still allows a plain chain-grant read with no PDPP grant id", async () => {
    // Behavior preservation: the pre-PDPP path is untouched.
    const h = harness();
    const grant = await verifyDataReadPolicy(
      {
        signer: APP_A,
        grantId: "42",
        requestedScope: SCOPE,
        serverOwner: OWNER,
      },
      h.ports,
    );
    expect(grant.id).toBe("42");
  });

  // --- mismatched binding: the three axes §6 names ------------------------

  it("denies a read whose PDPP grant id has no retained binding", async () => {
    const h = harness();
    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-UNKNOWN",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        h.ports,
      ),
      "GRANT_REQUIRED",
    );
  });

  it("denies a read where the wrong APP presents a valid PDPP grant", async () => {
    // App B is a registered builder with its own wallet, and the chain grant
    // is real — but it was bound to App A. This is the core §6 guarantee:
    // one grantee identity per builder/app, enforced.
    const h = harness({
      grants: {
        "42": chainGrant(),
        "43": chainGrant({ id: "43", granteeId: APP_B }),
      },
    });
    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_B,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        h.ports,
      ),
      // The pre-existing chain check fires first: App B is not grant 42's
      // grantee. The binding is defence in depth behind it, not instead of it.
      "INVALID_SIGNATURE",
    );
  });

  it("denies a read where the app swaps in a DIFFERENT chain grant it does own", async () => {
    // App B holds its own valid chain grant 43, and pairs it with App A's
    // PDPP grant. Every individual object is valid; only the binding is not.
    const h = harness({
      grants: {
        "42": chainGrant(),
        "43": chainGrant({ id: "43", granteeId: APP_B }),
      },
    });
    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_B,
          grantId: "43",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        h.ports,
      ),
      "SCOPE_MISMATCH",
    );
  });

  it("denies a read where the OWNER does not match the binding", async () => {
    const h = harness();
    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OTHER_OWNER,
        },
        h.ports,
      ),
      "GRANT_OWNER_MISMATCH",
    );
  });

  it("denies a read when the PS is configured against a different chain", async () => {
    const h = harness();
    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        {
          ...h.ports,
          // Same permission id, different network — a Moksha binding must not
          // authorize a mainnet read.
          chainDeployment: { chainId: 1480, contractAddress: CONTRACT },
        },
      ),
      "SCOPE_MISMATCH",
    );
  });

  it("fails closed when a PDPP read is attempted with no binding store configured", async () => {
    const h = harness();
    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        {
          authSessionVerifier: h.ports.authSessionVerifier,
          grantVerifier: h.ports.grantVerifier,
        },
      ),
      "SERVER_NOT_CONFIGURED",
    );
  });

  // --- revocation ---------------------------------------------------------

  it("denies the read once the chain grant is revoked, with the binding unchanged", async () => {
    const h = harness();

    // The same read succeeds first, so the denial below is attributable to
    // revocation alone rather than to a mis-built request.
    await expect(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        h.ports,
      ),
    ).resolves.toMatchObject({ id: "42" });

    // Revoke at the gateway — exactly what the deployed contract's
    // `revokePermission` surfaces. The retained binding is NOT touched.
    h.grants["42"] = chainGrant({ revokedAt: "2026-09-17T12:00:00.000Z" });

    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        h.ports,
      ),
      "GRANT_REVOKED",
    );

    // The binding record survives revocation unchanged: it asserts a
    // historical consent fact, and is not a status mirror.
    expect(h.store.getByPdppGrantId("pdpp-grant-1")).toEqual(h.binding);
  });

  it("denies the read when the chain grant disappears entirely", async () => {
    const h = harness();
    delete h.grants["42"];

    await expectPolicyFailure(
      verifyDataReadPolicy(
        {
          signer: APP_A,
          grantId: "42",
          pdppGrantId: "pdpp-grant-1",
          requestedScope: SCOPE,
          serverOwner: OWNER,
        },
        h.ports,
      ),
      // Fails closed at the pre-existing chain-grant lookup.
      "GRANT_REQUIRED",
    );
  });

  it("keeps denying after revocation — a retained binding cannot resurrect access", async () => {
    const h = harness();
    h.grants["42"] = chainGrant({ revokedAt: "2026-09-17T12:00:00.000Z" });

    for (let attempt = 0; attempt < 3; attempt++) {
      await expectPolicyFailure(
        verifyDataReadPolicy(
          {
            signer: APP_A,
            grantId: "42",
            pdppGrantId: "pdpp-grant-1",
            requestedScope: SCOPE,
            serverOwner: OWNER,
          },
          h.ports,
        ),
        "GRANT_REVOKED",
      );
    }
  });
});
