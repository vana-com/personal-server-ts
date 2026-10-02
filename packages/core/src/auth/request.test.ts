import { describe, expect, it } from "vitest";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../test-utils/index.js";
import { authenticateRequest } from "./request.js";

describe("authenticateRequest", () => {
  it("keeps authenticating signed bodies above one MiB outside bounded routes", async () => {
    const wallet = createTestWallet(42);
    const body = new Uint8Array(1024 * 1024 + 1).fill(0x61);
    const path = "/v1/data/example.scope";
    const authorization = await buildWeb3SignedHeader({
      wallet,
      aud: "http://127.0.0.1",
      method: "POST",
      uri: path,
      body,
    });
    const request = new Request(`http://127.0.0.1${path}`, {
      method: "POST",
      headers: { authorization },
      body,
    });

    await expect(
      authenticateRequest({
        request,
        serverOrigin: "http://127.0.0.1",
        serverOwner: wallet.address,
      }),
    ).resolves.toMatchObject({ auth: { signer: wallet.address } });
  });
});
