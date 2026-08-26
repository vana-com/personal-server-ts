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
  verifyStoredWriterAttribution,
  verifyWriterAttribution,
  type WriterAttribution,
} from "./attribution.js";
import { buildBinaryEnvelopeData, sha256Hex } from "../contracts/binary.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "../test-utils/index.js";

const SERVER_ORIGIN = "http://localhost:8080";
const builderWallet = createTestWallet(3);
const otherWallet = createTestWallet(4);
const GRANT_ID = "0xgrant_w1";

const SCOPE = "notes.entries";

async function buildWriteRequest(params: {
  body?: string | Uint8Array;
  contentType?: string;
  signer?: typeof builderWallet;
  header?: string | null;
  signedBody?: string;
  /** grantId claim in the proof; null omits it. Defaults to GRANT_ID. */
  grantId?: string | null;
}): Promise<Request> {
  const body = params.body ?? JSON.stringify({ note: "hello" });
  const bodyBytes =
    params.signedBody !== undefined
      ? new TextEncoder().encode(params.signedBody)
      : typeof body === "string"
        ? new TextEncoder().encode(body)
        : body;
  const headers: Record<string, string> = {
    "Content-Type": params.contentType ?? "application/json",
    Authorization: "Bearer vana_write_sessiontoken",
  };
  if (params.header !== null) {
    headers[WRITE_SIGNATURE_HEADER] =
      params.header ??
      (await buildWeb3SignedHeader({
        wallet: params.signer ?? builderWallet,
        aud: SERVER_ORIGIN,
        method: "POST",
        uri: `/v1/data/${SCOPE}`,
        body: bodyBytes,
        grantId:
          params.grantId === null ? undefined : (params.grantId ?? GRANT_ID),
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

  it("rejects a proof that does not carry the session's grantId as a signed claim", async () => {
    for (const grantId of [null, "0xother_grant"]) {
      const request = await buildWriteRequest({ grantId });
      await expect(
        verifyWriterAttribution({
          request,
          builderAddress: builderWallet.address,
          grantId: GRANT_ID,
          serverOrigin: SERVER_ORIGIN,
        }),
      ).rejects.toMatchObject({
        errorCode: "WRITE_ATTRIBUTION_GRANT_MISMATCH",
      });
    }
  });

  it("rejects a JSON body that would not re-serialize to the signed bytes", async () => {
    // Pretty-printed JSON is validly signed, but the stored (parsed) record
    // could never reproduce these bytes, so the bodyHash would be dead on
    // read-back. Rejected up front instead.
    const request = await buildWriteRequest({
      body: JSON.stringify({ note: "hello", n: 1 }, null, 2),
    });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      }),
    ).rejects.toMatchObject({
      code: 400,
      errorCode: "WRITE_BODY_NOT_CANONICAL",
    });
  });

  it("leaves unparseable JSON to the ingest path (no canonical check)", async () => {
    const request = await buildWriteRequest({ body: "{not json" });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      }),
    ).resolves.toMatchObject({ builder: builderWallet.address });
  });

  it("does not apply the JSON canonical rule to binary bodies", async () => {
    const bytes = new TextEncoder().encode('  { "pretty": true }  ');
    const request = await buildWriteRequest({
      body: bytes,
      contentType: "application/pdf",
    });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    expect(attribution.bodyHash).toMatch(/^sha256:/);
  });
});

describe("verifyStoredWriterAttribution", () => {
  async function storedJsonRecord(body: Record<string, unknown>) {
    const request = await buildWriteRequest({ body: JSON.stringify(body) });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    // What ingest stores: the parsed body with $writtenBy stamped, after a
    // JSON round-trip (the envelope is serialized to disk and parsed back).
    return JSON.parse(
      JSON.stringify(stampWriterAttribution(body, attribution)),
    ) as Record<string, unknown>;
  }

  it("verifies a stored JSON record from the record alone", async () => {
    const data = await storedJsonRecord({
      note: "hello",
      nested: { z: 1, a: [1, 2, { b: null }] },
      unicode: "caf\u00e9 \u2603",
    });
    const verified = await verifyStoredWriterAttribution(
      { scope: SCOPE, data },
      { expectedOrigin: SERVER_ORIGIN },
    );
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
    expect(verified.grantId).toBe(GRANT_ID);
    expect(verified.bodyHash).toBe(
      (data[WRITER_ATTRIBUTION_KEY] as WriterAttribution).bodyHash,
    );
    expect(verified.payload.method).toBe("POST");
    expect(verified.payload.uri).toBe(`/v1/data/${SCOPE}`);
    expect(verified.payload.grantId).toBe(GRANT_ID);
  });

  it("verifies a stored binary record from the decoded bytes", async () => {
    const bytes = new TextEncoder().encode("%PDF-1.7 fake");
    const request = await buildWriteRequest({
      body: bytes,
      contentType: "application/pdf",
    });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    const data = stampWriterAttribution(
      buildBinaryEnvelopeData({
        bytes,
        mimeType: "application/pdf",
        contentHash: await sha256Hex(bytes),
      }),
      attribution,
    );
    const verified = await verifyStoredWriterAttribution({
      scope: SCOPE,
      data: JSON.parse(JSON.stringify(data)),
    });
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
  });

  it("rejects a record whose data was altered after the write", async () => {
    const data = await storedJsonRecord({ note: "hello" });
    data.note = "tampered";
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "BODY_HASH_MISMATCH" });
  });

  it("rejects a record whose attributed builder does not match the proof signer", async () => {
    const data = await storedJsonRecord({ note: "hello" });
    const attribution = data[WRITER_ATTRIBUTION_KEY] as WriterAttribution;
    data[WRITER_ATTRIBUTION_KEY] = {
      ...attribution,
      builder: otherWallet.address,
    };
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "SIGNER_MISMATCH" });
  });

  it("rejects a record with a malformed stored proof", async () => {
    const data = await storedJsonRecord({ note: "hello" });
    const attribution = data[WRITER_ATTRIBUTION_KEY] as WriterAttribution;
    data[WRITER_ATTRIBUTION_KEY] = { ...attribution, signature: "not.valid" };
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "PROOF_INVALID" });
  });

  it("rejects a record without attribution", async () => {
    await expect(
      verifyStoredWriterAttribution({
        scope: SCOPE,
        data: { note: "owner write" },
      }),
    ).rejects.toMatchObject({ reason: "ATTRIBUTION_MISSING" });
  });

  it("rejects an attribution copied onto another scope's record", async () => {
    // Same bytes, same $writtenBy, different scope: the signed uri names the
    // original scope, so the transplanted record must not verify.
    const data = await storedJsonRecord({ note: "hello" });
    await expect(
      verifyStoredWriterAttribution({ scope: "other.scope", data }),
    ).rejects.toMatchObject({ reason: "SCOPE_MISMATCH" });
  });

  it("rejects a stored grantId that is not the grant the builder signed", async () => {
    const data = await storedJsonRecord({ note: "hello" });
    const attribution = data[WRITER_ATTRIBUTION_KEY] as WriterAttribution;
    data[WRITER_ATTRIBUTION_KEY] = { ...attribution, grantId: "0xrelabelled" };
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "GRANT_MISMATCH" });
  });

  it("rejects a proof addressed to a different server when the origin is known", async () => {
    const data = await storedJsonRecord({ note: "hello" });
    await expect(
      verifyStoredWriterAttribution(
        { scope: SCOPE, data },
        { expectedOrigin: "https://other-ps.example" },
      ),
    ).rejects.toMatchObject({ reason: "AUDIENCE_MISMATCH" });
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
