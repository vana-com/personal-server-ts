import { describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import {
  scopeCoveredByWriteGrant,
  verifyDataWritePolicy,
  writeScopePatterns,
} from "./data-write.js";
import { verifyDataReadPolicy } from "./data-read.js";

const BUILDER_ADDRESS = "0x0000000000000000000000000000000000000001";
const BUILDER_ID = "0xbuilder1";
const SERVER_OWNER = "0xOwner" as `0x${string}`;

const builder: Builder = {
  id: BUILDER_ID,
  ownerAddress: "0xOwner",
  granteeAddress: BUILDER_ADDRESS,
  publicKey: "0x04key",
  appUrl: "https://app.example.com",
  addedAt: "2026-01-21T10:00:00.000Z",
};

// Write-grants ride the flat canary grant shape unchanged — the ONLY
// difference from a read-grant is the `write:` prefix on scope entries.
function makeGrant(
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "grant-w-1",
    grantorAddress: "0xOwner",
    granteeId: BUILDER_ID,
    scopes: ["write:notes.entries"],
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: String(Math.floor(Date.now() / 1000) + 3600),
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
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "0",
      dataAccessFee: "0",
      totalDue: "0",
    },
    ...overrides,
  };
}

function makePorts(grant: GatewayGrantResponse | null) {
  return {
    authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
    grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
  };
}

describe("writeScopePatterns", () => {
  it("extracts only write: entries, prefix stripped", () => {
    expect(
      writeScopePatterns([
        "write:notes.entries",
        "instagram.profile",
        "write:chatgpt.*",
      ]),
    ).toEqual(["notes.entries", "chatgpt.*"]);
  });

  it("ignores a bare write: entry with no pattern", () => {
    expect(writeScopePatterns(["write:"])).toEqual([]);
  });
});

describe("scopeCoveredByWriteGrant", () => {
  it("matches exact and wildcard write patterns", () => {
    expect(
      scopeCoveredByWriteGrant("notes.entries", ["write:notes.entries"]),
    ).toBe(true);
    expect(
      scopeCoveredByWriteGrant("chatgpt.conversations", ["write:chatgpt.*"]),
    ).toBe(true);
  });

  it("never matches plain (read) scope entries", () => {
    expect(scopeCoveredByWriteGrant("notes.entries", ["notes.entries"])).toBe(
      false,
    );
    expect(scopeCoveredByWriteGrant("notes.entries", ["notes.*"])).toBe(false);
  });
});

describe("verifyDataWritePolicy", () => {
  it("returns the grant when all invariants pass", async () => {
    const grant = makeGrant();
    const result = await verifyDataWritePolicy(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        requestedScope: "notes.entries",
        serverOwner: SERVER_OWNER,
      },
      makePorts(grant),
    );
    expect(result).toBe(grant);
  });

  it("rejects when the grant only carries READ scopes for the target (separation of powers)", async () => {
    const grant = makeGrant({ scopes: ["notes.entries", "write:other.scope"] });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("a write-grant never satisfies the READ policy for the same scope", async () => {
    const grant = makeGrant();
    await expect(
      verifyDataReadPolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("rejects a grant with no write scopes at all", async () => {
    const grant = makeGrant({ scopes: ["notes.entries"] });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "SCOPE_MISMATCH" });
  });

  it("rejects an unregistered builder", async () => {
    const grant = makeGrant();
    const ports = makePorts(grant);
    ports.authSessionVerifier.getBuilder.mockResolvedValue(null);
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        ports,
      ),
    ).rejects.toMatchObject({ errorCode: "UNREGISTERED_BUILDER" });
  });

  it("rejects a missing grantId", async () => {
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(makeGrant()),
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REQUIRED" });
  });

  it("rejects a revoked grant", async () => {
    const grant = makeGrant({ revokedAt: "2026-01-22T00:00:00.000Z" });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_REVOKED" });
  });

  it("rejects an expired grant", async () => {
    const grant = makeGrant({
      expiresAt: String(Math.floor(Date.now() / 1000) - 60),
    });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_EXPIRED" });
  });

  it("treats a null expiresAt as perpetual", async () => {
    const grant = makeGrant({ expiresAt: null });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).resolves.toBe(grant);
  });

  it("rejects a signer that is not the grant builder", async () => {
    const grant = makeGrant({ granteeId: "0xother-builder" });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "INVALID_SIGNATURE" });
  });

  it("rejects a grant issued by a different owner", async () => {
    const grant = makeGrant({ grantorAddress: "0xSomeoneElse" });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("fails closed on a grantor-less grant", async () => {
    const grant = makeGrant({
      grantorAddress: undefined as unknown as string,
    });
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        makePorts(grant),
      ),
    ).rejects.toMatchObject({ errorCode: "GRANT_OWNER_MISMATCH" });
  });

  it("rejects when the runtime reports unavailable", async () => {
    const grant = makeGrant();
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        {
          ...makePorts(grant),
          runtimeAvailability: { isAvailable: () => false },
        },
      ),
    ).rejects.toMatchObject({ errorCode: "PS_UNAVAILABLE" });
  });

  it("invokes the fee seam after authorization passes, and propagates its rejection", async () => {
    const grant = makeGrant();
    const assertWriteAllowed = vi
      .fn()
      .mockRejectedValue(new Error("fee required"));
    await expect(
      verifyDataWritePolicy(
        {
          signer: BUILDER_ADDRESS,
          grantId: grant.id,
          requestedScope: "notes.entries",
          serverOwner: SERVER_OWNER,
        },
        {
          ...makePorts(grant),
          writeFeeVerifier: { assertWriteAllowed },
        },
      ),
    ).rejects.toThrow("fee required");
    expect(assertWriteAllowed).toHaveBeenCalledWith({
      builder: BUILDER_ADDRESS,
      grant,
      scope: "notes.entries",
    });
  });
});
