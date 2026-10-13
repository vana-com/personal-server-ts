import { describe, expect, it } from "vitest";
import { authenticateRequest } from "./request.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../test-utils/wallet.js";

const SERVER_ORIGIN = "http://localhost:8080";
const wallet = createTestWallet(0);

async function authenticate(header: string, now: number) {
  return authenticateRequest({
    request: new Request(`${SERVER_ORIGIN}/v1/data`, {
      method: "GET",
      headers: { Authorization: header },
    }),
    serverOrigin: SERVER_ORIGIN,
    now: () => now,
  });
}

describe("authenticateRequest Web3Signed lifetime", () => {
  const now = 1_800_000_000;

  it("accepts the SDK default lifetime (300 s)", async () => {
    const header = await buildWeb3SignedHeader({
      wallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data",
      iat: now,
      exp: now + 300,
    });
    const result = await authenticate(header, now);
    expect(result.mechanism).toBe("web3-signed");
    expect(result.auth.signer).toBe(wallet.address);
  });

  it("accepts a lifetime exactly at the 15-minute cap", async () => {
    const header = await buildWeb3SignedHeader({
      wallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data",
      iat: now,
      exp: now + 15 * 60,
    });
    await expect(authenticate(header, now)).resolves.toMatchObject({
      mechanism: "web3-signed",
    });
  });

  it("accepts fractional-second timestamps (the SDK verifier allows any finite number)", async () => {
    const header = await buildWeb3SignedHeader({
      wallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data",
      iat: now + 0.25,
      exp: now + 300.75,
    });
    await expect(authenticate(header, now)).resolves.toMatchObject({
      mechanism: "web3-signed",
    });
  });

  it("rejects a signature whose exp - iat exceeds the cap, even while unexpired", async () => {
    // A signer-chosen window: valid for a year. Without a server-side cap a
    // captured copy of this request replays until the grant is revoked.
    const header = await buildWeb3SignedHeader({
      wallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data",
      iat: now,
      exp: now + 365 * 24 * 3600,
    });
    await expect(authenticate(header, now)).rejects.toMatchObject({
      code: 401,
      errorCode: "EXPIRED_TOKEN",
      details: { reason: "Token lifetime exceeds the server cap" },
    });
  });

  it("rejects an over-cap window even when its remaining validity is short", async () => {
    // iat 20 minutes ago, exp 10 minutes ahead: the SDK's exp check passes,
    // but the signer still chose a 30-minute window.
    const header = await buildWeb3SignedHeader({
      wallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: "/v1/data",
      iat: now - 20 * 60,
      exp: now + 10 * 60,
    });
    await expect(authenticate(header, now)).rejects.toMatchObject({
      errorCode: "EXPIRED_TOKEN",
    });
  });
});
