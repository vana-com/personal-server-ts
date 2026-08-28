import { describe, it, expect, vi } from "vitest";
import {
  parseWeb3SignedHeader,
  verifyWeb3Signed,
} from "@opendatalabs/vana-sdk/browser";
import {
  WRITE_SIGNATURE_HEADER,
  WRITER_ATTRIBUTION_KEY,
  binaryWriteSignedBytes,
  hasReservedWriterKey,
  stampWriterAttribution,
  verifyStoredWriterAttribution,
  verifyWriterAttribution,
  type WriterAttribution,
} from "./attribution.js";
import { buildBinaryEnvelopeData, sha256Hex } from "../contracts/binary.js";
import { LINEAGE_KEY, stampLineage } from "../lineage/lineage.js";
import {
  createInMemoryWriteProofReplayStore,
  type WriteProofReplayStore,
} from "./session.js";
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
  filename?: string;
  metadataHeader?: string;
  signer?: typeof builderWallet;
  header?: string | null;
  /** JSON writes: sign these bytes instead of the body. */
  signedBody?: string;
  /** Sign exactly these bytes instead of the request's own representation. */
  signedBytes?: Uint8Array;
  /** grantId claim in the proof; null omits it. Defaults to GRANT_ID. */
  grantId?: string | null;
}): Promise<Request> {
  const body = params.body ?? JSON.stringify({ note: "hello" });
  const contentType = params.contentType ?? "application/json";
  const bodyBytes =
    typeof body === "string" ? new TextEncoder().encode(body) : body;
  const isJson = contentType.toLowerCase().includes("application/json");
  // What a well-behaved builder signs: the body for JSON, the stored
  // representation for binary.
  const toSign =
    params.signedBytes ??
    (params.signedBody !== undefined
      ? new TextEncoder().encode(params.signedBody)
      : isJson
        ? bodyBytes
        : await binaryWriteSignedBytes({
            bytes: bodyBytes,
            contentType,
            filename: params.filename,
            metadataHeader: params.metadataHeader,
          }));
  const headers: Record<string, string> = {
    "Content-Type": contentType,
    Authorization: "Bearer vana_write_sessiontoken",
  };
  if (params.filename) headers["X-Filename"] = params.filename;
  if (params.metadataHeader !== undefined) {
    headers["X-Vana-Metadata"] = params.metadataHeader;
  }
  if (params.header !== null) {
    headers[WRITE_SIGNATURE_HEADER] =
      params.header ??
      (await buildWeb3SignedHeader({
        wallet: params.signer ?? builderWallet,
        aud: SERVER_ORIGIN,
        method: "POST",
        uri: `/v1/data/${SCOPE}`,
        body: toSign,
        grantId:
          params.grantId === null ? undefined : (params.grantId ?? GRANT_ID),
      }));
  }
  return new Request(`${SERVER_ORIGIN}/v1/data/${SCOPE}`, {
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

  it("binds a binary write to its stored representation, not just its bytes", async () => {
    const bytes = new TextEncoder().encode("%PDF-1.7 fake");
    const verifyWith = (request: Request) =>
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      });
    const signedFor = (
      representation: Parameters<typeof binaryWriteSignedBytes>[0],
    ) => binaryWriteSignedBytes({ bytes, ...representation });

    // Baseline: the representation the request carries is what was signed.
    await expect(
      verifyWith(
        await buildWriteRequest({
          body: bytes,
          contentType: "application/pdf",
          filename: "scan.pdf",
          metadataHeader: '{"kind":"dexa"}',
        }),
      ),
    ).resolves.toMatchObject({ builder: builderWallet.address });

    // Content-Type parameters are not part of the stored media type.
    await expect(
      verifyWith(
        await buildWriteRequest({
          body: bytes,
          contentType: "application/pdf; charset=binary",
          signedBytes: await signedFor({ contentType: "application/pdf" }),
        }),
      ),
    ).resolves.toMatchObject({ builder: builderWallet.address });

    // Each caller-controlled representation header is covered by the proof.
    const tampered = [
      buildWriteRequest({
        body: bytes,
        contentType: "image/png",
        signedBytes: await signedFor({ contentType: "application/pdf" }),
      }),
      buildWriteRequest({
        body: bytes,
        contentType: "application/pdf",
        filename: "other.pdf",
        signedBytes: await signedFor({
          contentType: "application/pdf",
          filename: "scan.pdf",
        }),
      }),
      buildWriteRequest({
        body: bytes,
        contentType: "application/pdf",
        metadataHeader: '{"kind":"tampered"}',
        signedBytes: await signedFor({
          contentType: "application/pdf",
          metadataHeader: '{"kind":"dexa"}',
        }),
      }),
    ];
    for (const request of tampered) {
      await expect(verifyWith(await request)).rejects.toMatchObject({
        errorCode: "WRITE_ATTRIBUTION_INVALID",
      });
    }
  });

  it("rejects the same signed bytes re-sent under the other representation", async () => {
    const json = JSON.stringify({ note: "hello" });
    const jsonBytes = new TextEncoder().encode(json);
    const verifyWith = (request: Request) =>
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      });
    // Signed as a JSON write, sent as binary.
    await expect(
      verifyWith(
        await buildWriteRequest({
          body: json,
          contentType: "application/octet-stream",
          signedBytes: jsonBytes,
        }),
      ),
    ).rejects.toMatchObject({ errorCode: "WRITE_ATTRIBUTION_INVALID" });
    // Signed as a binary write, sent as JSON.
    await expect(
      verifyWith(
        await buildWriteRequest({
          body: json,
          contentType: "application/json",
          signedBytes: await binaryWriteSignedBytes({
            bytes: jsonBytes,
            contentType: "application/octet-stream",
          }),
        }),
      ),
    ).rejects.toMatchObject({ errorCode: "WRITE_ATTRIBUTION_INVALID" });
  });

  it("consumes the proof so an identical write is rejected as a replay", async () => {
    const replayStore = createInMemoryWriteProofReplayStore();
    const request = await buildWriteRequest({});
    const verify = () =>
      verifyWriterAttribution({
        request: request.clone(),
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
        replayStore,
      });
    const first = await verify();
    expect(first.builder).toBe(builderWallet.address);
    expect(typeof first.releaseProof).toBe("function");
    await expect(verify()).rejects.toMatchObject({
      code: 401,
      errorCode: "WRITE_ATTRIBUTION_REPLAY",
    });
    // A write that failed before commit hands the proof back: the same
    // proof is accepted again.
    await first.releaseProof?.();
    await expect(verify()).resolves.toMatchObject({
      builder: builderWallet.address,
    });
  });

  it("does not consume the proof of a request that fails verification", async () => {
    const replayStore = createInMemoryWriteProofReplayStore();
    const consume = vi.spyOn(replayStore, "consume");
    const request = await buildWriteRequest({ signer: otherWallet });
    await expect(
      verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
        replayStore,
      }),
    ).rejects.toMatchObject({
      errorCode: "WRITE_ATTRIBUTION_SIGNER_MISMATCH",
    });
    expect(consume).not.toHaveBeenCalled();
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

describe("verifyWriterAttribution request uri binding", () => {
  const LIST = "/v1/derivatives/questions";

  /**
   * A read call on the question API: no body, and the proof signs whatever
   * uri the caller decided to sign.
   */
  async function readRequest(params: {
    signedUri: string;
    requestUri: string;
    method?: string;
    contentType?: string;
    nonce?: unknown;
    iat?: number;
  }): Promise<Request> {
    const method = params.method ?? "GET";
    const headers: Record<string, string> = {
      Authorization: "Bearer vana_write_sessiontoken",
      [WRITE_SIGNATURE_HEADER]: await buildWeb3SignedHeader({
        wallet: builderWallet,
        aud: SERVER_ORIGIN,
        method,
        uri: params.signedUri,
        grantId: GRANT_ID,
        ...(params.nonce === undefined ? {} : { nonce: params.nonce }),
        ...(params.iat === undefined ? {} : { iat: params.iat }),
      }),
    };
    if (params.contentType) headers["Content-Type"] = params.contentType;
    return new Request(`${SERVER_ORIGIN}${params.requestUri}`, {
      method,
      headers,
    });
  }

  function verify(request: Request, replayStore?: WriteProofReplayStore) {
    return verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
      ...(replayStore ? { replayStore } : {}),
    });
  }

  it("refuses a proof signed for one derived scope on a request for another", async () => {
    // The list route authorizes the caller against ?derivedScope=, so the
    // proof that authorized a list on coach.weekly must not authorize the
    // same call on spine.summary.
    const header = await buildWeb3SignedHeader({
      wallet: builderWallet,
      aud: SERVER_ORIGIN,
      method: "GET",
      uri: `${LIST}?derivedScope=coach.weekly`,
      grantId: GRANT_ID,
    });
    const send = (query: string) =>
      verify(
        new Request(`${SERVER_ORIGIN}${LIST}?derivedScope=${query}`, {
          headers: {
            Authorization: "Bearer vana_write_sessiontoken",
            [WRITE_SIGNATURE_HEADER]: header,
          },
        }),
      );
    await expect(send("coach.weekly")).resolves.toMatchObject({
      builder: builderWallet.address,
    });
    await expect(send("spine.summary")).rejects.toMatchObject({
      code: 401,
      errorCode: "WRITE_ATTRIBUTION_INVALID",
    });
  });

  it("refuses a proof that signed only the bare path of a query request", async () => {
    const request = await readRequest({
      signedUri: LIST,
      requestUri: `${LIST}?derivedScope=coach.weekly`,
    });
    await expect(verify(request)).rejects.toMatchObject({
      errorCode: "WRITE_ATTRIBUTION_INVALID",
    });
  });

  it("accepts the matching query whatever order the client signed it in", async () => {
    const matching = await readRequest({
      signedUri: `${LIST}?derivedScope=coach.weekly`,
      requestUri: `${LIST}?derivedScope=coach.weekly`,
    });
    await expect(verify(matching)).resolves.toMatchObject({
      builder: builderWallet.address,
    });

    const reordered = await readRequest({
      signedUri: `${LIST}?derivedScope=coach.weekly&at=2026-08-27`,
      requestUri: `${LIST}?at=2026-08-27&derivedScope=coach.weekly`,
    });
    await expect(verify(reordered)).resolves.toMatchObject({
      builder: builderWallet.address,
    });
  });

  it("leaves a request with no query string signing the bare path", async () => {
    const request = await readRequest({
      signedUri: `${LIST}/q-1`,
      requestUri: `${LIST}/q-1`,
    });
    await expect(verify(request)).resolves.toMatchObject({
      builder: builderWallet.address,
    });
  });

  it("verifies a bodyless method whatever Content-Type it carries", async () => {
    // isJsonContentType treats a missing header as JSON; a bodyless method
    // must not be pushed down either the binary-representation path or the
    // canonical-JSON check because of a stray header.
    const request = await readRequest({
      signedUri: `${LIST}/q-1`,
      requestUri: `${LIST}/q-1`,
      method: "DELETE",
      contentType: "application/octet-stream",
    });
    await expect(verify(request)).resolves.toMatchObject({
      builder: builderWallet.address,
    });
  });

  it("lets a nonce make two identical polls distinct, and refuses a re-used one", async () => {
    const replayStore = createInMemoryWriteProofReplayStore();
    const iat = Math.floor(Date.now() / 1000);
    const poll = (nonce: string, at = iat) =>
      readRequest({
        signedUri: `${LIST}/q-1`,
        requestUri: `${LIST}/q-1`,
        nonce,
        iat: at,
      });

    // Same second, same request: byte-identical without a nonce.
    const noNonce = await readRequest({
      signedUri: `${LIST}/q-1`,
      requestUri: `${LIST}/q-1`,
      iat,
    });
    await expect(verify(noNonce.clone(), replayStore)).resolves.toBeTruthy();
    await expect(verify(noNonce, replayStore)).rejects.toMatchObject({
      errorCode: "WRITE_ATTRIBUTION_REPLAY",
    });

    // With a fresh nonce each poll goes through.
    await expect(verify(await poll("n-1"), replayStore)).resolves.toBeTruthy();
    await expect(verify(await poll("n-2"), replayStore)).resolves.toBeTruthy();

    // The nonce itself is single use: re-using it is a replay even though
    // the rest of the payload changed.
    await expect(
      verify(await poll("n-1", iat + 1), replayStore),
    ).rejects.toMatchObject({
      code: 401,
      errorCode: "WRITE_ATTRIBUTION_REPLAY",
    });
  });

  it("refuses a nonce claim that is not a bounded string", async () => {
    for (const nonce of [42, "", "x".repeat(129)]) {
      const request = await readRequest({
        signedUri: `${LIST}/q-1`,
        requestUri: `${LIST}/q-1`,
        nonce,
      });
      await expect(verify(request)).rejects.toMatchObject({
        code: 401,
        errorCode: "WRITE_ATTRIBUTION_INVALID",
      });
    }
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

  async function storedBinaryRecord() {
    const bytes = new TextEncoder().encode("%PDF-1.7 fake");
    const request = await buildWriteRequest({
      body: bytes,
      contentType: "application/pdf",
      filename: "scan.pdf",
      metadataHeader: '{"kind":"dexa"}',
    });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    // What ingestBinaryDataContract stores for these headers and bytes.
    const data = stampWriterAttribution(
      buildBinaryEnvelopeData({
        bytes,
        mimeType: "application/pdf",
        filename: "scan.pdf",
        contentHash: await sha256Hex(bytes),
        metadata: { kind: "dexa" },
      }),
      attribution,
    );
    return JSON.parse(JSON.stringify(data)) as Record<string, unknown>;
  }

  it("verifies a stored binary record from its stored representation", async () => {
    const data = await storedBinaryRecord();
    const verified = await verifyStoredWriterAttribution({
      scope: SCOPE,
      data,
    });
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
  });

  it("rejects a stored binary record whose representation metadata was altered", async () => {
    for (const patch of [
      { mimeType: "image/png" },
      { filename: "other.pdf" },
      { metadata: { kind: "tampered" } },
    ]) {
      const data = { ...(await storedBinaryRecord()), ...patch };
      await expect(
        verifyStoredWriterAttribution({ scope: SCOPE, data }),
      ).rejects.toMatchObject({ reason: "BODY_HASH_MISMATCH" });
    }
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

describe("verifyStoredWriterAttribution with lineage", () => {
  const SOURCE_ID = `0x${"ab".repeat(32)}` as const;

  async function storedDerivativeRecord() {
    // The builder's own `lineage` field is inside the signed body; the
    // server stamps the validated `$lineage` mirror next to `$writtenBy`.
    const body = { summary: "sleep improved", lineage: [SOURCE_ID] };
    const request = await buildWriteRequest({ body: JSON.stringify(body) });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    const stamped = stampWriterAttribution(
      stampLineage(body, {
        sources: [SOURCE_ID],
        writtenAt: "2026-08-31T09:12:44.000Z",
      }),
      attribution,
    );
    return JSON.parse(JSON.stringify(stamped)) as Record<string, unknown>;
  }

  it("verifies a derivative record: $lineage is stripped like $writtenBy", async () => {
    const data = await storedDerivativeRecord();
    expect(data[LINEAGE_KEY]).toEqual({
      sources: [SOURCE_ID],
      writtenAt: "2026-08-31T09:12:44.000Z",
    });
    const verified = await verifyStoredWriterAttribution(
      { scope: SCOPE, data },
      { expectedOrigin: SERVER_ORIGIN },
    );
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
  });

  it("rejects a $lineage mirror that does not restate the signed lineage field", async () => {
    const data = await storedDerivativeRecord();
    data[LINEAGE_KEY] = {
      sources: [`0x${"cd".repeat(32)}`],
      writtenAt: "2026-08-31T09:12:44.000Z",
    };
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "LINEAGE_MISMATCH" });
  });

  it("rejects a derivative record whose $lineage mirror was removed", async () => {
    const data = await storedDerivativeRecord();
    delete data[LINEAGE_KEY];
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "LINEAGE_MISMATCH" });
  });

  it("rejects a signed lineage field that is not a list, even with no mirror (JSON)", async () => {
    for (const bad of ["invalid", 7, { a: 1 }, ["0xok", 5]]) {
      const body = { note: "root", lineage: bad };
      const request = await buildWriteRequest({ body: JSON.stringify(body) });
      const attribution = await verifyWriterAttribution({
        request,
        builderAddress: builderWallet.address,
        grantId: GRANT_ID,
        serverOrigin: SERVER_ORIGIN,
      });
      const data = JSON.parse(
        JSON.stringify(stampWriterAttribution(body, attribution)),
      ) as Record<string, unknown>;
      await expect(
        verifyStoredWriterAttribution({ scope: SCOPE, data }),
      ).rejects.toMatchObject({ reason: "LINEAGE_MISMATCH" });
    }
  });

  it("treats a signed lineage of null as no statement (JSON)", async () => {
    const body = { note: "root", lineage: null };
    const request = await buildWriteRequest({ body: JSON.stringify(body) });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    const data = JSON.parse(
      JSON.stringify(stampWriterAttribution(body, attribution)),
    ) as Record<string, unknown>;
    const verified = await verifyStoredWriterAttribution({
      scope: SCOPE,
      data,
    });
    expect(verified.builder.toLowerCase()).toBe(
      builderWallet.address.toLowerCase(),
    );
  });

  it("rejects a signed lineage field that is not a list, even with no mirror (binary)", async () => {
    const bytes = new TextEncoder().encode("%PDF-1.7 fake");
    const request = await buildWriteRequest({
      body: bytes,
      contentType: "application/pdf",
      filename: "scan.pdf",
      metadataHeader: '{"kind":"dexa","lineage":"invalid"}',
    });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    const data = JSON.parse(
      JSON.stringify(
        stampWriterAttribution(
          buildBinaryEnvelopeData({
            bytes,
            mimeType: "application/pdf",
            filename: "scan.pdf",
            contentHash: await sha256Hex(bytes),
            metadata: { kind: "dexa", lineage: "invalid" },
          }),
          attribution,
        ),
      ),
    ) as Record<string, unknown>;
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "LINEAGE_MISMATCH" });
  });

  it("rejects a $lineage mirror planted on a root record", async () => {
    const body = { note: "root" };
    const request = await buildWriteRequest({ body: JSON.stringify(body) });
    const attribution = await verifyWriterAttribution({
      request,
      builderAddress: builderWallet.address,
      grantId: GRANT_ID,
      serverOrigin: SERVER_ORIGIN,
    });
    const data = JSON.parse(
      JSON.stringify(
        stampWriterAttribution(
          stampLineage(body, {
            sources: [SOURCE_ID],
            writtenAt: "2026-08-31T09:12:44.000Z",
          }),
          attribution,
        ),
      ),
    ) as Record<string, unknown>;
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "LINEAGE_MISMATCH" });
  });

  it("still rejects a record whose signed lineage field was altered", async () => {
    const data = await storedDerivativeRecord();
    data.lineage = [`0x${"cd".repeat(32)}`];
    await expect(
      verifyStoredWriterAttribution({ scope: SCOPE, data }),
    ).rejects.toMatchObject({ reason: "BODY_HASH_MISMATCH" });
  });
});
