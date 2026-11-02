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
  grantVersionStillAuthorizes,
  isValidGrantVersion,
  samePermission,
  verifyPdppGrantBinding,
  type ChainPermissionRef,
  type ResolvedBuilder,
} from "./pdpp-binding.js";
import { createInMemoryPdppGrantBindingStore } from "./pdpp-binding-store.js";

const OWNER = "0x00000000000000000000000000000000000000AA" as const;
const OTHER_OWNER = "0x00000000000000000000000000000000000000BB" as const;
// 20-byte wallet addresses — the app's Context Gateway grantee identity.
const GRANTEE = "0x00000000000000000000000000000000000000C1" as const;
const OTHER_GRANTEE = "0x00000000000000000000000000000000000000C2" as const;
const CONTRACT = "0xD54523048AdD05b4d734aFaE7C68324Ebb7373eF" as const;

// 32-byte builder ids — deliberately shaped and valued differently from any
// wallet address above, since `Builder.id`/`GatewayGrantResponse.granteeId`
// is a distinct bytes32 identifier, not a wallet. Real IDs are keccak256
// digests; these are handwritten but the same shape.
const BUILDER_ID =
  "0x7f532b6a4ee5506cd7fe60e943ec4c80ebd1695508eb3258f959db21f8967f00" as const;
const OTHER_BUILDER_ID =
  "0xf8ba74b1fe36f5a08c1038cb5af7ca1760ba010cb52cabfc35f2d09efb4e0a60" as const;
const ROTATED_BUILDER_ID =
  "0x4868ccc0828d1f29900b39cfc3bfdb8ef69fb43da9fb670816e47ecb1d940b00" as const;

const RESOLVED_BUILDER: ResolvedBuilder = {
  id: BUILDER_ID,
  granteeAddress: GRANTEE,
};
const OTHER_RESOLVED_BUILDER: ResolvedBuilder = {
  id: OTHER_BUILDER_ID,
  granteeAddress: OTHER_GRANTEE,
};

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
    granteeId: BUILDER_ID,
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
 * A chain grant whose `grantVersion` is some untrusted runtime value the SDK
 * type says can't happen (`number`, `null`, `undefined`) — simulating a
 * gateway response that doesn't actually honor its own declared type.
 */
function chainGrantWithRawGrantVersion(
  grantVersion: unknown,
): GatewayGrantResponse {
  return {
    ...chainGrant(),
    grantVersion,
  } as unknown as GatewayGrantResponse;
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
    resolvedBuilder: RESOLVED_BUILDER,
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
    expect(binding.grantVersion).toBe("1");
  });

  it("throws when the chain grant's grantVersion is malformed", () => {
    // A new binding must pin a real version; `null` is reserved for a
    // legacy row a migration preserved, never for something created here.
    expectFailure(
      () =>
        makeBinding({
          chainGrant: chainGrant({ grantVersion: "not-a-number" }),
        }),
      "INVALID_SIGNATURE",
      /grantVersion is missing or malformed/i,
    );
  });

  it("throws when the chain grant's grantVersion is undefined at runtime", () => {
    expectFailure(
      () =>
        makeBinding({
          chainGrant: chainGrantWithRawGrantVersion(undefined),
        }),
      "INVALID_SIGNATURE",
      /grantVersion is missing or malformed/i,
    );
  });

  it("throws when the chain grant's grantVersion is null at runtime", () => {
    expectFailure(
      () => makeBinding({ chainGrant: chainGrantWithRawGrantVersion(null) }),
      "INVALID_SIGNATURE",
      /grantVersion is missing or malformed/i,
    );
  });

  it("throws when the chain grant's grantVersion is a runtime number, despite the string type", () => {
    // The SDK types `grantVersion: string`, but that is not enforced over
    // the wire. A JSON payload can carry a bare number; `isValidGrantVersion`
    // must reject it via `typeof`, not silently accept it through coercion.
    expectFailure(
      () => makeBinding({ chainGrant: chainGrantWithRawGrantVersion(1) }),
      "INVALID_SIGNATURE",
      /grantVersion is missing or malformed/i,
    );
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

  it("rejects a chain grant issued to a different builder id", () => {
    expectFailure(
      () =>
        makeBinding({
          chainGrant: chainGrant({ granteeId: OTHER_BUILDER_ID }),
        }),
      "INVALID_SIGNATURE",
      /builder id/i,
    );
  });

  it("rejects a resolved builder whose wallet is not the requested app address", () => {
    // The caller resolved the WRONG builder for the requested app address —
    // everything downstream would silently verify a different app.
    expectFailure(
      () => makeBinding({ resolvedBuilder: OTHER_RESOLVED_BUILDER }),
      "INVALID_SIGNATURE",
      /resolved builder wallet/i,
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

  it("rejects a wallet address substituted for the registered builder id", () => {
    // Regression proof for the confirmed grantee-ID vs wallet bug: the old
    // implementation compared `chainGrant.granteeId` directly against
    // `granteeAddress` (a wallet). A chain grant naming the CORRECT builder
    // id must be accepted, but one that names something wallet-shaped (as if
    // `granteeId` held an address, which it never does for a real gateway
    // response) must be rejected as the wrong builder — it is not this app's
    // builder id, coincidentally wallet-shaped or not.
    expectFailure(
      () =>
        makeBinding({
          chainGrant: chainGrant({ granteeId: GRANTEE }), // wallet-shaped, not BUILDER_ID
        }),
      "INVALID_SIGNATURE",
      /builder id/i,
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
          chainGrant: chainGrant({ granteeId: OTHER_BUILDER_ID }),
        }),
      "INVALID_SIGNATURE",
      /no longer matches the bound grantee/i,
    );
  });

  it("fails when the live grantVersion is newer than the bound one (re-registration since binding)", () => {
    // A newer version means the grant was re-registered since this binding
    // was verified — including possibly to clear a revocation. This binding
    // never observed that re-registration, so it must not vouch for it.
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrant({ grantVersion: "2" }),
        }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
  });

  it("fails when the live grantVersion is older than the bound one", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrant({ grantVersion: "0" }),
        }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
  });

  it("fails when the binding has no retained version (legacy row)", () => {
    const legacyBinding = { ...base.binding, grantVersion: null };
    expectFailure(
      () => verifyPdppGrantBinding({ ...base, binding: legacyBinding }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
  });

  it("fails when the live grantVersion is malformed", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrant({ grantVersion: "01" }),
        }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
  });

  it("fails when the live grantVersion is a runtime number, despite the string type", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrantWithRawGrantVersion(1),
        }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
  });

  it("fails when the live grantVersion is null or undefined at runtime", () => {
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrantWithRawGrantVersion(null),
        }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          chainGrant: chainGrantWithRawGrantVersion(undefined),
        }),
      "INVALID_SIGNATURE",
      /version no longer matches/i,
    );
  });

  it("rejects builder-id drift despite the correct request signer", () => {
    // Regression proof: the old code compared the live grant's `granteeId`
    // against `binding.granteeAddress` (a wallet). Since `binding.granteeId`
    // now holds the real builder id, a rotation of that id must be caught by
    // THIS check even though `requestSigner` (the wallet) still matches.
    expectFailure(
      () =>
        verifyPdppGrantBinding({
          ...base,
          requestSigner: GRANTEE, // wallet unchanged
          chainGrant: chainGrant({ granteeId: ROTATED_BUILDER_ID }), // builder id rotated
        }),
      "INVALID_SIGNATURE",
      /no longer matches the bound grantee/i,
    );
  });
});

describe("isValidGrantVersion", () => {
  it.each(["1", "42", String(2n ** 256n - 1n)])("accepts %s", (v) =>
    expect(isValidGrantVersion(v)).toBe(true),
  );

  it.each(["0", "-1", "01", "1.5", "abc", "", String(2n ** 256n)])(
    "rejects %s",
    (v) => expect(isValidGrantVersion(v)).toBe(false),
  );

  it.each([1, 42, true, false, null, undefined, {}, [], 1n])(
    // Runtime values the `string` type says can't happen but the wire can
    // still deliver. A bare `typeof` check must reject these before the
    // regex/BigInt coercion gets a chance to accept them — this is the
    // exact case a naive implementation gets wrong: `RegExp.test(1)` and
    // `BigInt(1)` both happily coerce a number, so without the `typeof`
    // guard `isValidGrantVersion(1)` would wrongly return `true`.
    "rejects the non-string runtime value %s",
    (v) => expect(isValidGrantVersion(v)).toBe(false),
  );
});

describe("grantVersionStillAuthorizes", () => {
  it("authorizes an exact match", () => {
    expect(grantVersionStillAuthorizes("3", "3")).toBe(true);
  });

  it("denies null retained version", () => {
    expect(grantVersionStillAuthorizes(null, "3")).toBe(false);
  });

  it("denies a newer live version", () => {
    expect(grantVersionStillAuthorizes("3", "4")).toBe(false);
  });

  it("denies an older live version", () => {
    expect(grantVersionStillAuthorizes("3", "2")).toBe(false);
  });

  it("denies a malformed live version even if it matches as a string", () => {
    expect(grantVersionStillAuthorizes("01", "01")).toBe(false);
  });

  it("denies a runtime-numeric live version, despite the string type", () => {
    expect(grantVersionStillAuthorizes("1", 1)).toBe(false);
  });

  it("denies a null or undefined live version", () => {
    expect(grantVersionStillAuthorizes("1", null)).toBe(false);
    expect(grantVersionStillAuthorizes("1", undefined)).toBe(false);
  });
});

describe("samePermission", () => {
  it("does not confuse the same permission id on different chains", () => {
    // The same grant id must remain scoped to its recorded deployment.
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
    expect(store.getBindingsForPermission(PERMISSION)).toEqual([binding]);
  });

  it("returns null / empty for an unknown binding rather than throwing", () => {
    const store = createInMemoryPdppGrantBindingStore();
    expect(store.getByPdppGrantId("nope")).toBeNull();
    expect(store.getBindingsForPermission(PERMISSION)).toEqual([]);
  });

  it("is idempotent for an identical re-put", () => {
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());
    expect(() => store.putBinding(makeBinding())).not.toThrow();
  });

  it("rejects a new binding with a null grantVersion", () => {
    // `createPdppGrantBinding` already refuses to produce this; this proves
    // the store enforces it independently for a hand-built binding too —
    // `null` must never be creatable through `putBinding`, only readable
    // back from a preserved legacy row.
    const store = createInMemoryPdppGrantBindingStore();
    expectFailure(
      () => store.putBinding({ ...makeBinding(), grantVersion: null }),
      "INVALID_SIGNATURE",
      /grantVersion must be a positive decimal uint256 string/i,
    );
    expect(store.getByPdppGrantId("pdpp-grant-1")).toBeNull();
  });

  it("rejects a new binding with a malformed grantVersion", () => {
    const store = createInMemoryPdppGrantBindingStore();
    expectFailure(
      () => store.putBinding({ ...makeBinding(), grantVersion: "01" }),
      "INVALID_SIGNATURE",
      /grantVersion must be a positive decimal uint256 string/i,
    );
    expect(store.getByPdppGrantId("pdpp-grant-1")).toBeNull();
  });

  it("rejects a new binding with a runtime-numeric grantVersion, despite the string type", () => {
    const store = createInMemoryPdppGrantBindingStore();
    expectFailure(
      () =>
        store.putBinding({
          ...makeBinding(),
          grantVersion: 1 as unknown as string,
        }),
      "INVALID_SIGNATURE",
      /grantVersion must be a positive decimal uint256 string/i,
    );
    expect(store.getByPdppGrantId("pdpp-grant-1")).toBeNull();
  });

  it("refuses to follow a rotated grantee wallet onto an existing grant", () => {
    // Context Gateway models grantee-wallet rotation (isCurrent + a partial
    // unique index) but implements none today, so the per-app address is
    // immutable in practice and not by design. If rotation ships, a rotated
    // wallet is a DIFFERENT grantee: the owner's existing consent must not
    // transfer to it silently. This must fail rather than repoint the grant.
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());

    const ROTATED_WALLET =
      "0x00000000000000000000000000000000000000FF" as const;
    const rotatedBuilder: ResolvedBuilder = {
      id: BUILDER_ID,
      granteeAddress: ROTATED_WALLET,
    };
    expectFailure(
      () =>
        store.putBinding(
          makeBinding({
            granteeAddress: ROTATED_WALLET,
            resolvedBuilder: rotatedBuilder,
            chainGrant: chainGrant({ granteeId: BUILDER_ID }),
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

  it("refuses to follow a rotated builder id onto an existing grant, wallet unchanged", () => {
    // §6's identity is one grantee per builder/app; a builder-id rotation
    // (Context Gateway re-registering the same wallet under a new builder id)
    // is just as much a different grantee as a wallet rotation, and must be
    // rejected the same way rather than silently accepted because the wallet
    // still matches.
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(makeBinding());

    const rotatedIdBuilder: ResolvedBuilder = {
      id: ROTATED_BUILDER_ID,
      granteeAddress: GRANTEE,
    };
    expectFailure(
      () =>
        store.putBinding(
          makeBinding({
            resolvedBuilder: rotatedIdBuilder,
            chainGrant: chainGrant({ granteeId: ROTATED_BUILDER_ID }),
          }),
        ),
      "INVALID_SIGNATURE",
      /different binding already exists for this PDPP grant/i,
    );

    expect(store.getByPdppGrantId("pdpp-grant-1")?.granteeId).toBe(BUILDER_ID);
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

  it("rejects a re-put of the same PDPP grant id at a different retained grantVersion", () => {
    // The retained grantVersion is part of what the binding asserts. A
    // second put for the same grant id claiming a different version is not
    // a benign re-put — it is a conflicting claim about what was verified.
    const store = createInMemoryPdppGrantBindingStore();
    store.putBinding(
      makeBinding({ chainGrant: chainGrant({ grantVersion: "1" }) }),
    );

    expectFailure(
      () =>
        store.putBinding(
          makeBinding({ chainGrant: chainGrant({ grantVersion: "2" }) }),
        ),
      "INVALID_SIGNATURE",
      /different binding already exists for this PDPP grant/i,
    );
  });

  it("lets two distinct PDPP grants bind the same permission at the same version", () => {
    // A single chain permission can be the subject of more than one PDPP
    // consent over time (e.g. re-consent after the app re-requests access).
    // Both bindings must coexist and remain independently retrievable.
    const store = createInMemoryPdppGrantBindingStore();
    const first = makeBinding();
    const second = makeBinding({ pdppGrantId: "pdpp-grant-2" });
    store.putBinding(first);
    store.putBinding(second);

    expect(store.getByPdppGrantId("pdpp-grant-1")).toEqual(first);
    expect(store.getByPdppGrantId("pdpp-grant-2")).toEqual(second);
    expect(store.getBindingsForPermission(PERMISSION)).toEqual([first, second]);
  });
});
