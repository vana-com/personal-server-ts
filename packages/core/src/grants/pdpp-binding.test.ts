/**
 * §6 binding unit tests — creation and verification boundaries.
 *
 * These exercise the real binding functions. The only thing faked is the
 * gateway's grant response, which is inert data the real code already treats
 * as untrusted runtime input.
 */

import { describe, expect, it } from "vitest";
import type { GatewayGrantResponse } from "@opendatalabs/vana-sdk/browser";

import {
  createPdppGrantBinding,
  samePermission,
  verifyPdppGrantBinding,
  type ChainPermissionRef,
} from "./pdpp-binding.js";
import { createInMemoryPdppGrantBindingStore } from "./pdpp-binding-store.js";

const OWNER = "0x00000000000000000000000000000000000000AA" as const;
const OTHER_OWNER = "0x00000000000000000000000000000000000000BB" as const;
const GRANTEE = "0x00000000000000000000000000000000000000C1" as const;
const OTHER_GRANTEE = "0x00000000000000000000000000000000000000C2" as const;
const CONTRACT = "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF" as const;

const PERMISSION: ChainPermissionRef = {
  chainId: 14800,
  contractAddress: CONTRACT,
  permissionId: "42",
};

const DEPLOYMENT = { chainId: 14800, contractAddress: CONTRACT } as const;

function chainGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "42",
    grantorAddress: OWNER,
    granteeId: GRANTEE,
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
 * Assert a call fails with a specific catalog error AND a specific reason.
 *
 * `ProtocolError.message` is a fixed catalog string ("Invalid signature"),
 * so matching on it alone would pass for any of several distinct failures.
 * Checking `errorCode` plus `details.reason` pins down which check fired.
 */
function expectFailure(
  fn: () => unknown,
  errorCode: string,
  reason?: RegExp,
): void {
  let thrown: unknown;
  try {
    fn();
  } catch (error) {
    thrown = error;
  }
  expect(thrown, "expected the call to throw").toBeDefined();
  const err = thrown as { errorCode?: string; details?: { reason?: string } };
  expect(err.errorCode).toBe(errorCode);
  if (reason) {
    expect(err.details?.reason ?? "").toMatch(reason);
  }
}

function makeBinding(overrides: Record<string, unknown> = {}) {
  return createPdppGrantBinding({
    pdppGrantId: "pdpp-grant-1",
    permission: PERMISSION,
    serverOwner: OWNER,
    granteeAddress: GRANTEE,
    pdppClientId: "client-app-1",
    chainGrant: chainGrant(),
    ...overrides,
  });
}

describe("createPdppGrantBinding", () => {
  it("binds a consistent PDPP grant to its chain permission", () => {
    const binding = makeBinding();
    expect(binding.pdppGrantId).toBe("pdpp-grant-1");
    expect(binding.permission.permissionId).toBe("42");
    expect(binding.ownerAddress).toBe(OWNER);
    // The app's EXISTING grantee wallet is carried through unchanged.
    expect(binding.granteeAddress).toBe(GRANTEE);
    expect(binding.pdppClientId).toBe("client-app-1");
  });

  it("records no revocation status at all", () => {
    // Revocation must be read live, never mirrored into the immutable record.
    expect(Object.keys(makeBinding())).not.toContain("revokedAt");
  });

  it("is frozen, so a caller cannot retarget it after creation", () => {
    const binding = makeBinding();
    expect(Object.isFrozen(binding)).toBe(true);
  });

  it("rejects a chain grant issued by a different owner", () => {
    expect(() =>
      makeBinding({ chainGrant: chainGrant({ grantorAddress: OTHER_OWNER }) }),
    ).toThrow(/not issued by this server's owner/i);
  });

  it("rejects a chain grant issued to a different app", () => {
    expectFailure(
      () =>
        makeBinding({ chainGrant: chainGrant({ granteeId: OTHER_GRANTEE }) }),
      "INVALID_SIGNATURE",
      /grantee does not match/i,
    );
  });

  it("rejects binding to an already-revoked chain grant", () => {
    expect(() =>
      makeBinding({
        chainGrant: chainGrant({ revokedAt: "2026-09-17T11:00:00.000Z" }),
      }),
    ).toThrow(/revoked/i);
  });

  it("rejects a chain grant whose id is not the permission being bound", () => {
    expectFailure(
      () => makeBinding({ chainGrant: chainGrant({ id: "999" }) }),
      "INVALID_SIGNATURE",
      /does not match the permission/i,
    );
  });
});

describe("verifyPdppGrantBinding", () => {
  const base = {
    binding: makeBinding(),
    pdppGrantId: "pdpp-grant-1",
    serverOwner: OWNER,
    requestSigner: GRANTEE,
    chainGrant: chainGrant(),
    deployment: DEPLOYMENT,
  };

  it("passes when owner, app, chain, record, and revocation all agree", () => {
    expect(() => verifyPdppGrantBinding(base)).not.toThrow();
  });

  it("fails on a mismatched record binding", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({ ...base, pdppGrantId: "pdpp-grant-OTHER" }),
      "SCOPE_MISMATCH",
      /does not match the binding record/i,
    );
  });

  it("fails on a mismatched owner", () => {
    expect(() =>
      verifyPdppGrantBinding({ ...base, serverOwner: OTHER_OWNER }),
    ).toThrow(/owner/i);
  });

  it("fails when the caller is not the bound app", () => {
    expectFailure(
      () => verifyPdppGrantBinding({ ...base, requestSigner: OTHER_GRANTEE }),
      "INVALID_SIGNATURE",
      /not the bound grantee/i,
    );
  });

  it("fails when the binding is for a different chain", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          deployment: { chainId: 1480, contractAddress: CONTRACT },
        }),
      "SCOPE_MISMATCH",
      /different chain deployment/i,
    );
  });

  it("fails when the binding is for a different contract on the same chain", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          deployment: {
            chainId: 14800,
            contractAddress: "0x0000000000000000000000000000000000000999",
          },
        }),
      "SCOPE_MISMATCH",
      /different chain deployment/i,
    );
  });

  it("fails once the chain grant is revoked", () => {
    expect(() =>
      verifyPdppGrantBinding({
        ...base,
        chainGrant: chainGrant({ revokedAt: "2026-09-17T12:00:00.000Z" }),
      }),
    ).toThrow(/revoked/i);
  });

  it("treats a missing chain grant as revoked rather than unknown", () => {
    expect(() => verifyPdppGrantBinding({ ...base, chainGrant: null })).toThrow(
      /revoked/i,
    );
  });

  it("fails when the live chain grant's grantor drifts from the binding", () => {
    expect(() =>
      verifyPdppGrantBinding({
        ...base,
        chainGrant: chainGrant({ grantorAddress: OTHER_OWNER }),
      }),
    ).toThrow(/owner/i);
  });

  it("fails when the live chain grant's grantee drifts from the binding", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrant({ granteeId: OTHER_GRANTEE }),
        }),
      "INVALID_SIGNATURE",
      /no longer matches the bound grantee/i,
    );
  });
});

describe("samePermission", () => {
  it("does not confuse the same permission id on different chains", () => {
    // permissionId is a per-deployment counter, so this is the exact
    // collision a bare id would cause.
    expect(samePermission(PERMISSION, { ...PERMISSION, chainId: 1480 })).toBe(
      false,
    );
  });

  it("does not confuse the same id on different contracts", () => {
    expect(
      samePermission(PERMISSION, {
        ...PERMISSION,
        contractAddress: "0x0000000000000000000000000000000000000999",
      }),
    ).toBe(false);
  });

  it("compares addresses case-insensitively", () => {
    expect(
      samePermission(PERMISSION, {
        ...PERMISSION,
        contractAddress: CONTRACT.toLowerCase() as `0x${string}`,
      }),
    ).toBe(true);
  });
});

describe("PdppGrantBindingStore", () => {
  it("retains and returns a binding by either key", () => {
    const store = createInMemoryPdppGrantBindingStore();
    const binding = makeBinding();
    store.putBinding(binding);

    expect(store.getByPdppGrantId("pdpp-grant-1")).toEqual(binding);
    expect(store.getByPermission(PERMISSION)).toEqual(binding);
  });

  it("returns null for an unknown binding rather than throwing", () => {
    const store = createInMemoryPdppGrantBindingStore();
    expect(store.getByPdppGrantId("nope")).toBeNull();
    expect(store.getByPermission(PERMISSION)).toBeNull();
  });

  it("is idempotent for an identical re-put", () => {
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());
    expect(() => store.putBinding(makeBinding())).not.toThrow();
  });

  it("refuses to follow a rotated grantee wallet onto an existing grant", () => {
    // Context Gateway models grantee-wallet rotation (isCurrent + a partial
    // unique index) but implements none today, so the per-app address is
    // immutable in practice and not by design. If rotation ships, a rotated
    // wallet is a DIFFERENT grantee: the owner's existing consent must not
    // transfer to it silently. This must fail rather than repoint the grant.
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());

    const ROTATED = "0x00000000000000000000000000000000000000FF" as const;
    expectFailure(
      () =>
        store.putBinding(
          makeBinding({
            granteeAddress: ROTATED,
            chainGrant: chainGrant({ granteeId: ROTATED }),
          }),
        ),
      "INVALID_SIGNATURE",
      /different binding already exists for this PDPP grant/i,
    );

    // The originally consented grantee still stands.
    expect(store.getByPdppGrantId("pdpp-grant-1")?.granteeAddress).toBe(
      GRANTEE,
    );
  });

  it("refuses to retarget an existing PDPP grant at a different permission", () => {
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());

    expectFailure(
      () =>
        store.putBinding(
          makeBinding({
            permission: { ...PERMISSION, permissionId: "43" },
            chainGrant: chainGrant({ id: "43" }),
          }),
        ),
      "INVALID_SIGNATURE",
      /different binding already exists for this PDPP grant/i,
    );
  });

  it("refuses to rebind an existing permission to a different PDPP grant", () => {
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());

    expectFailure(
      () => store.putBinding(makeBinding({ pdppGrantId: "pdpp-grant-2" })),
      "INVALID_SIGNATURE",
      /different binding already exists for this permission/i,
    );
  });
});
