import { describe, expect, it, vi } from "vitest";
import { parseWeb3SignedHeader } from "@opendatalabs/vana-sdk/browser";
import { createRequestSigner } from "../signing/request-signer.js";
import { createTestWallet } from "../test-utils/index.js";
import { createGatewayLineageClient, type LineageView } from "./gateway.js";

const GATEWAY_URL = "https://gateway.example.com/";
const ID = `0x${"ab".repeat(32)}`;
const SOURCE_ID = `0x${"cd".repeat(32)}`;

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function requestSignerFor(wallet: ReturnType<typeof createTestWallet>) {
  return createRequestSigner({
    address: wallet.address,
    publicKey: "0x04" as `0x${string}`,
    signTypedData: vi.fn(),
    signMessage: (message: string) => wallet.signMessage(message),
  });
}

const proof = {
  userSignature: "0xuser",
  gatewaySignature: "0xgw",
  timestamp: 1756630000,
  status: "confirmed",
  estimatedConfirmation: null,
  chainBlockHeight: 42,
};

const view: LineageView = {
  dataPointId: ID,
  ownerAddress: "0xowner",
  scope: "spine.health.summary",
  version: "2",
  deletedAt: null,
  sources: [
    {
      dataPointId: SOURCE_ID,
      scope: "chatgpt.conversations",
      version: "7",
      deletedAt: null,
    },
    { redacted: true },
  ],
  derivatives: [],
};

describe("createGatewayLineageClient", () => {
  it("getDataPoint asks for deleted points too and maps the record", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, {
        data: {
          id: ID,
          ownerAddress: "0xowner",
          scope: "chatgpt.conversations",
          expectedVersion: "3",
          deletedAt: "2026-08-01T00:00:00.000Z",
        },
        proof: {},
      }),
    );
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      fetch: fetchMock,
    });
    const record = await client.getDataPoint(ID);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://gateway.example.com/v1/data/${ID}?includeDeleted=true`,
    );
    expect(record).toEqual({
      dataPointId: ID,
      ownerAddress: "0xowner",
      scope: "chatgpt.conversations",
      version: "3",
      deletedAt: "2026-08-01T00:00:00.000Z",
    });
  });

  it("getDataPoint returns null on 404 and throws on other errors", async () => {
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      fetch: vi
        .fn()
        .mockResolvedValueOnce(jsonResponse(404, { error: "not found" }))
        .mockResolvedValueOnce(jsonResponse(503, { error: "down" })),
    });
    expect(await client.getDataPoint(ID)).toBeNull();
    await expect(client.getDataPoint(ID)).rejects.toThrow(/Gateway error: 503/);
  });

  it("getLineage signs the request as the server: version in the path, grant view as the grantId claim", async () => {
    const wallet = createTestWallet(5);
    // The served view is attested for the grant that was requested.
    const grantView = { ...view, grantId: "0xgrant" };
    const fetchMock = vi
      .fn()
      .mockResolvedValue(jsonResponse(200, { data: grantView, proof }));
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      requestSigner: requestSignerFor(wallet),
      fetch: fetchMock,
    });
    const result = await client.getLineage({
      dataPointId: ID,
      version: "2",
      grantId: "0xgrant",
    });
    expect(result).toEqual({ ok: true, data: grantView, proof });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`https://gateway.example.com/v1/data/${ID}/lineage/2`);
    const header = (init.headers as Record<string, string>).Authorization;
    const { payload } = parseWeb3SignedHeader(header);
    expect(payload.aud).toBe("https://gateway.example.com");
    expect(payload.method).toBe("GET");
    // The version is a path segment inside the signed uri and the grant view
    // is the signed grantId claim.
    expect(payload.uri).toBe(`/v1/data/${ID}/lineage/2`);
    expect(payload.grantId).toBe("0xgrant");
  });

  it("getLineage reports gateway errors with their body instead of throwing", async () => {
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      requestSigner: requestSignerFor(createTestWallet(5)),
      fetch: vi.fn().mockResolvedValue(jsonResponse(404, { error: "nope" })),
    });
    expect(await client.getLineage({ dataPointId: ID })).toEqual({
      ok: false,
      status: 404,
      body: { error: "nope" },
    });
  });

  it("getLineage rejects a 200 without a structurally valid proof", async () => {
    for (const bad of [
      { data: view },
      { data: view, proof: null },
      { data: view, proof: { gatewaySignature: "0x" } },
    ]) {
      const client = createGatewayLineageClient({
        gatewayUrl: GATEWAY_URL,
        requestSigner: requestSignerFor(createTestWallet(5)),
        fetch: vi.fn().mockResolvedValue(jsonResponse(200, bad)),
      });
      const result = await client.getLineage({ dataPointId: ID });
      expect(result.ok).toBe(false);
    }
  });

  it("getLineage rejects a malformed 200 body", async () => {
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      requestSigner: requestSignerFor(createTestWallet(5)),
      fetch: vi.fn().mockResolvedValue(jsonResponse(200, { data: { x: 1 } })),
    });
    const result = await client.getLineage({ dataPointId: ID });
    expect(result.ok).toBe(false);
  });

  it("getDataPoint refuses a record for a different data point than requested", async () => {
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      fetch: vi.fn().mockResolvedValue(
        jsonResponse(200, {
          data: {
            id: SOURCE_ID,
            ownerAddress: "0xowner",
            scope: "chatgpt.conversations",
            expectedVersion: "3",
            deletedAt: null,
          },
          proof: {},
        }),
      ),
    });
    await expect(client.getDataPoint(ID)).rejects.toThrow(/requested/);
  });

  it("getLineage refuses an attested view for another data point or version", async () => {
    const otherPoint = vi
      .fn()
      .mockResolvedValue(
        jsonResponse(200, { data: { ...view, dataPointId: SOURCE_ID }, proof }),
      );
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      requestSigner: requestSignerFor(createTestWallet(5)),
      fetch: otherPoint,
    });
    const byId = await client.getLineage({ dataPointId: ID });
    expect(byId.ok).toBe(false);

    const otherVersion = vi
      .fn()
      .mockResolvedValue(
        jsonResponse(200, { data: { ...view, version: "7" }, proof }),
      );
    const client2 = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      requestSigner: requestSignerFor(createTestWallet(5)),
      fetch: otherVersion,
    });
    const byVersion = await client2.getLineage({
      dataPointId: ID,
      version: "3",
    });
    expect(byVersion.ok).toBe(false);
  });

  it("getLineage refuses a view attested for another grant, or a full view when a grant was requested", async () => {
    const grant = `0x${"11".repeat(32)}`;
    const mk = (body: unknown) =>
      createGatewayLineageClient({
        gatewayUrl: GATEWAY_URL,
        requestSigner: requestSignerFor(createTestWallet(5)),
        fetch: vi.fn().mockResolvedValue(jsonResponse(200, body)),
      });
    // Full owner view (no grantId) served to a builder that asked under a grant.
    const fullToBuilder = await mk({ data: { ...view }, proof }).getLineage({
      dataPointId: ID,
      grantId: grant,
    });
    expect(fullToBuilder.ok).toBe(false);
    // View attested for a different grant.
    const otherGrant = await mk({
      data: { ...view, grantId: `0x${"22".repeat(32)}` },
      proof,
    }).getLineage({ dataPointId: ID, grantId: grant });
    expect(otherGrant.ok).toBe(false);
    // Matching grant, case-insensitive, is accepted.
    const same = await mk({
      data: { ...view, grantId: grant.toUpperCase().replace("0X", "0x") },
      proof,
    }).getLineage({ dataPointId: ID, grantId: grant });
    expect(same.ok).toBe(true);
    // A grant view handed to the owner (who asked for the full view) is refused too.
    const grantToOwner = await mk({
      data: { ...view, grantId: grant },
      proof,
    }).getLineage({ dataPointId: ID });
    expect(grantToOwner.ok).toBe(false);
  });

  it("refuses a view whose redacted node carries any identifier", async () => {
    const mk = (nodes: unknown[]) =>
      createGatewayLineageClient({
        gatewayUrl: GATEWAY_URL,
        requestSigner: requestSignerFor(createTestWallet(5)),
        fetch: vi
          .fn()
          .mockResolvedValue(
            jsonResponse(200, { data: { ...view, sources: nodes }, proof }),
          ),
      });
    for (const leaky of [
      { dataPointId: SOURCE_ID, redacted: true },
      { redacted: true, scope: "oura.sleep" },
      { redacted: true, version: "2" },
    ]) {
      const result = await mk([leaky]).getLineage({ dataPointId: ID });
      expect(result.ok).toBe(false);
    }
    const clean = await mk([{ redacted: true }]).getLineage({
      dataPointId: ID,
    });
    expect(clean.ok).toBe(true);
  });

  it("getLineage is unavailable without a request signer", async () => {
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      fetch: vi.fn(),
    });
    await expect(client.getLineage({ dataPointId: ID })).rejects.toMatchObject({
      errorCode: "LINEAGE_UNAVAILABLE",
      code: 503,
    });
  });

  it("registerDataPoint posts the AddData fields plus lineage and returns the id", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(201, {
        success: true,
        dataPointId: ID,
        expectedVersion: "1",
      }),
    );
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      fetch: fetchMock,
    });
    const result = await client.registerDataPoint({
      ownerAddress: "0xowner",
      scope: "spine.health.summary",
      dataHash: "0xdata",
      metadataHash: "0xmeta",
      expectedVersion: "1",
      signature: "0xsig",
      lineage: [SOURCE_ID],
      lineageSignature: "0xlineagesig",
    });
    expect(result).toEqual({ dataPointId: ID, expectedVersion: "1" });
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe("https://gateway.example.com/v1/data");
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Web3Signed 0xsig",
    );
    expect(JSON.parse(init.body as string)).toEqual({
      ownerAddress: "0xowner",
      scope: "spine.health.summary",
      dataHash: "0xdata",
      metadataHash: "0xmeta",
      expectedVersion: "1",
      lineage: [SOURCE_ID],
      lineageSignature: "0xlineagesig",
    });
  });

  it("registerDataPoint surfaces a 409 in the SDK client's error format", async () => {
    const client = createGatewayLineageClient({
      gatewayUrl: GATEWAY_URL,
      fetch: vi.fn().mockResolvedValue(
        jsonResponse(409, {
          success: false,
          error: "Gap in version sequence: next valid version is 3",
        }),
      ),
    });
    await expect(
      client.registerDataPoint({
        ownerAddress: "0xowner",
        scope: "s.x",
        dataHash: "0xd",
        metadataHash: "0xm",
        expectedVersion: "1",
        signature: "0xsig",
        lineage: [],
        lineageSignature: "0xlineagesig",
      }),
    ).rejects.toThrow(/^Gateway error: 409 Gap in version sequence/);
  });
});
