import { describe, expect, it } from "vitest";
import {
  concat,
  hexToBytes,
  keccak256,
  pad,
  stringToBytes,
  toBytes,
} from "viem";
import {
  USER_PS_ID_DOMAIN,
  sealingPath,
  userPsId,
  walletPath,
} from "./paths.js";

const OWNER = "0x1234567890AbcdEF1234567890aBcdef12345678" as const;
const CHAIN_ID = 14800;
const FIXED_ID =
  "0x0000000000000000000000000000000000000000000000000000000000000abc" as const;

describe("userPsId", () => {
  it("is keccak256(domain || uint256(chainId) || address)", () => {
    const expected = keccak256(
      concat([
        stringToBytes(USER_PS_ID_DOMAIN),
        pad(toBytes(CHAIN_ID), { size: 32 }),
        hexToBytes(OWNER),
      ]),
    );

    expect(userPsId(CHAIN_ID, OWNER)).toBe(expected);
  });

  it("ignores address casing", () => {
    expect(userPsId(CHAIN_ID, OWNER.toLowerCase() as `0x${string}`)).toBe(
      userPsId(CHAIN_ID, OWNER),
    );
  });

  it("differs by chain and owner", () => {
    const base = userPsId(CHAIN_ID, OWNER);

    expect(userPsId(CHAIN_ID + 1, OWNER)).not.toBe(base);
    expect(
      userPsId(CHAIN_ID, "0x0000000000000000000000000000000000000001"),
    ).not.toBe(base);
  });

  it("rejects a malformed address", () => {
    expect(() => userPsId(CHAIN_ID, "0xnope")).toThrow();
  });
});

describe("paths", () => {
  it("wallet path is exact", () => {
    expect(walletPath(FIXED_ID)).toBe(
      `users/${FIXED_ID}/wallet/ethereum/secp256k1/v1`,
    );
  });

  it("sealing path is exact", () => {
    expect(sealingPath(FIXED_ID)).toBe(
      `users/${FIXED_ID}/secrets/master-signature/v1`,
    );
  });
});
