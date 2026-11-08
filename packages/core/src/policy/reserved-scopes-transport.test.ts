import { describe, expect, it, vi } from "vitest";
import type {
  Builder,
  GatewayGrantResponse,
} from "@opendatalabs/vana-sdk/browser";
import { ScopeMismatchError } from "../errors/catalog.js";
import { uncoveredSourceScopes } from "../derivatives/registration.js";
import { resolveGrantForRawScopeResource } from "../mcp/resources.js";
import { resolveGrantForScope } from "../mcp/tools.js";
import { isSystemScope } from "./reserved-scopes.js";
import {
  resolveDataListGrantScopes,
  verifyDataReadPolicy,
} from "./data-read.js";
import { scopeCoveredByWriteGrant } from "./data-write.js";

// Stream-sync physical names are transport identifiers (ruling Q7), not data
// scopes. Reserved-scope policy owns the rule that private runtime names are
// never authorized by delegated grants or MCP, so physical names are system.

const PHYSICAL = [
  "pdpp.chatgpt~0123456789abcdef.conversations",
  "pdpp.chatgpt~0123456789abcdef",
  "pdpp.chatgpt~.conversations",
  "pdpp.chatgpt~",
];
const LOGICAL = ["pdpp.chatgpt.conversations", "chatgpt.conversations"];

const BUILDER_ADDRESS = "0x0000000000000000000000000000000000000001";
const BUILDER_ID = "0xbuilder1";
const builder: Builder = {
  id: BUILDER_ID,
  ownerAddress: "0xOwner",
  granteeAddress: BUILDER_ADDRESS,
  publicKey: "0x04key",
  appUrl: "https://app.example.com",
  addedAt: "2026-01-21T10:00:00.000Z",
};

function makeGrant(
  scopes: string[],
  overrides: Partial<GatewayGrantResponse> = {},
): GatewayGrantResponse {
  return {
    id: "grant-123",
    grantorAddress: "0xOwner",
    granteeId: BUILDER_ID,
    scopes,
    status: "confirmed",
    addedAt: "2026-01-21T10:00:00.000Z",
    expiresAt: String(Math.floor(Date.now() / 1000) + 3600),
    expired: false,
    revokedAt: null,
    revocationSignature: null,
    paymentStatus: "paid",
    paidAt: "2026-01-21T10:00:05.000Z",
    paidBy: "0xOwner",
    grantVersion: "1",
    settleTxHash: null,
    settleSubmittedAt: null,
    revocationTxHash: null,
    revocationSubmittedAt: null,
    fee: {
      asset: "0x0000000000000000000000000000000000000000",
      registrationFee: "10000000000000000",
      dataAccessFee: "1000000000000000",
      totalDue: "11000000000000000",
    },
    ...overrides,
  };
}

// Test 4: classification. Mutant: revert isSystemScope to the vana.system.
// and replica checks only, so every physical row below goes red.
describe("isSystemScope classifies transport identifiers", () => {
  it.each(PHYSICAL)("treats physical name %s as system", (name) => {
    expect(isSystemScope(name)).toBe(true);
  });

  it.each(LOGICAL)("leaves logical stream name %s as ordinary data", (name) => {
    expect(isSystemScope(name)).toBe(false);
  });
});

// Test 3: broad and exact grants never authorize a concrete physical name.
describe("grants never authorize physical runtime names", () => {
  const connection = (scopes: string[]) =>
    ({
      grants: [{ grantId: "g1", scopes }],
    }) as never;

  it.each(PHYSICAL)(
    "MCP resolveGrantForScope refuses %s under a wildcard grant",
    (name) => {
      expect(resolveGrantForScope(connection(["*"]), name)).toBeNull();
      expect(resolveGrantForScope(connection(["pdpp.*"]), name)).toBeNull();
      expect(resolveGrantForScope(connection([name]), name)).toBeNull();
    },
  );

  it.each(PHYSICAL)(
    "MCP raw resource resolver refuses %s under a wildcard grant",
    (name) => {
      expect(
        resolveGrantForRawScopeResource(connection(["*"]), name),
      ).toBeNull();
    },
  );

  it("MCP still resolves the logical name under the same wildcard grant", () => {
    expect(
      resolveGrantForScope(
        connection(["pdpp.*"]),
        "pdpp.chatgpt.conversations",
      ),
    ).toMatchObject({ grantId: "g1" });
  });

  it.each(PHYSICAL)(
    "data read policy refuses an explicit physical scope %s before grant lookup",
    async (name) => {
      const getBuilder = vi.fn().mockResolvedValue(builder);
      const getGrant = vi.fn().mockResolvedValue(makeGrant(["*"]));
      await expect(
        verifyDataReadPolicy(
          {
            signer: BUILDER_ADDRESS,
            grantId: "grant-123",
            requestedScope: name,
            serverOwner: "0xOwner",
          },
          {
            authSessionVerifier: { getBuilder },
            grantVerifier: { getGrant },
          } as never,
        ),
      ).rejects.toBeInstanceOf(ScopeMismatchError);
      expect(getGrant).not.toHaveBeenCalled();
    },
  );

  it("data list grant scopes drop exact physical entries and keep logical ones", async () => {
    const grant = makeGrant(["instagram.*", ...PHYSICAL]);
    const scopes = await resolveDataListGrantScopes(
      {
        signer: BUILDER_ADDRESS,
        grantId: grant.id,
        serverOwner: "0xOwner",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn().mockResolvedValue(builder) },
        grantVerifier: { getGrant: vi.fn().mockResolvedValue(grant) },
      } as never,
    );
    expect(scopes).toEqual(["instagram.*"]);
  });

  it.each(PHYSICAL)(
    "a write-all grant never covers physical name %s",
    (name) => {
      expect(scopeCoveredByWriteGrant(name, ["write:*"])).toBe(false);
      expect(scopeCoveredByWriteGrant(name, [`write:${name}`])).toBe(false);
    },
  );
});

// Test 6: derivative consent. A physical source is uncovered even under `*`.
describe("derivative source consent", () => {
  it("reports a physical source as uncovered even under a broad read grant", () => {
    expect(
      uncoveredSourceScopes(
        ["pdpp.chatgpt.conversations", PHYSICAL[0]!],
        ["*", "pdpp.*"],
      ),
    ).toEqual([PHYSICAL[0]]);
  });
});
