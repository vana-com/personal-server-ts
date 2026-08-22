import { describe, it, expect } from "vitest";
import {
  parseWeb3SignedHeader,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";
import {
  WRITE_SIGNATURE_HEADER,
  WRITER_ATTRIBUTION_KEY,
  hasReservedWriterKey,
  stampWriterAttribution,
  verifyWriterAttribution,
  type WriterAttribution,
} from "./attribution.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../test-utils/index.js";

const SERVER_ORIGIN = "http://localhost:8080";
const builderWallet = createTestWallet(3);
const otherWallet = createTestWallet(4);
const GRANT_ID = "0xgrant_w1";

async function buildWriteRequest(params: {
  body?: string;
  signer?: typeof builderWallet;
  header?: string | null;
  signedBody?: string;
}): Promise<Request> {
  const body = params.body ?? JSON.stringify({ note: "hello" });
  const bodyBytes = new TextEncoder().encode(params.signedBody ?? body);
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Authorization: "Bearer vana_write_sessiontoken",
  };
  if (params.header !== null) {
    headers[WRITE_SIGNATURE_HEADER] =
      params.header ??
      (await buildWeb3SignedHeader({
        wallet: params.signer ?? builderWallet,
        aud: SERVER_ORIGIN,
        method: "POST",
        uri: "/v1/data/notes.entries",
        body: bodyBytes,
      }));
  }
  return new Request(`${SERVER_ORIGIN}/v1/data/notes.entries`, {
    method: "POST",
    headers,
    body,
  });
}

describe("verifyWriterAttribution", () => {
  it("accepts a valid builder proof and returns a verifiable attribution", async () => {
    const request = await buildWriteRequest({});
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    expect(attribution.builder).toBe(builderWallet.address);
    expect(attribution.grantId).toBe(GRANT_ID);
    expect(attribution.bodyHash).toMatch(/^sha256:[0-9a-f]{64}$/i);

    // The stored compact proof is independently verifiable: re-frame it as a
    // header and run full verification against the original request shape.
    const verified = await verifyWeb3Signed({
      headerValue: `Web3Signed ${attribution.signature}`,
      expectedOrigin: SERVER_ORIGIN,
      expectedMethod: "POST",
      expectedPath: "/v1/data/notes.entries",
      bodyBytes: new TextEncoder().encode(JSON.stringify({ note: "hello" })),
    });
    expect(verified.signer.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
    // And the compact form round-trips through the parser.
    expect(() =>
      parseWeb3SignedHeader(`Web3Signed ${attribution.signature}`),
    ).not.toThrow();
  });

  it("rejects a missing proof header", async () => {
    const request = await buildWriteRequest({ header: null });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      }),
    ).rejects.toMatchObject({ errorCode: "WRITE_ATTRIBUTION_REQUIRED" });
  });

  it("rejects a proof signed by a different key than the session builder", async () => {
    const request = await buildWriteRequest({ signer: otherWallet });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      }),
    ).rejects.toMatchObject({
      errorCode: "WRITE_ATTRIBUTION_SIGNER_MISMATCH",
    });
  });

  it("rejects a proof whose bodyHash does not commit to the received bytes", async () => {
    const request = await buildWriteRequest({
      signedBody: JSON.stringify({ note: "something else" }),
    });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      }),
    ).rejects.toMatchObject({ errorCode: "WRITE_ATTRIBUTION_INVALID" });
  });

  it("rejects a malformed header", async () => {
    const request = await buildWriteRequest({ header: "Web3Signed not.valid" });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      }),
    ).rejects.toMatchObject({ errorCode: "WRITE_ATTRIBUTION_INVALID" });
  });
});

describe("stampWriterAttribution", () => {
  const attribution: WriterAttribution = {
    builder: builderWallet.address,
    grantId: GRANT_ID,
    signature: "payload.sig",
    bodyHash: "abc",
    writtenAt: "2026-08-21T00:00:00.000Z",
  };

  it("stamps the attribution under the reserved key without touching payload fields", () => {
    const stamped = stampWriterAttribution({ note: "hello" }, attribution);
    expect(stamped.note).toBe("hello");
    expect(stamped[WRITER_ATTRIBUTION_KEY]).toEqual(attribution);
  });

  it("hasReservedWriterKey detects caller-supplied attribution", () => {
    expect(hasReservedWriterKey({ note: "x" })).toBe(false);
    expect(hasReservedWriterKey({ [WRITER_ATTRIBUTION_KEY]: {} })).toBe(true);
  });
});
