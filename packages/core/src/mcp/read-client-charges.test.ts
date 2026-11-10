import {
  databaseReadFixture,
  type DatabaseReadFixture,
} from "../../../server/src/localdb/read-fixture.test-utils.js";
import { describe, expect, it, vi } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  dataRegistryDomain,
  escrowPaymentDomain,
  GENERIC_PAYMENT_TYPES,
  RECORD_DATA_ACCESS_TYPES,
} from "@opendatalabs/vana-sdk/browser";
import { handlePersonalServerDataRequest } from "../api/index.js";
import { createMcpDataReadClient, McpDataReadError } from "./read-client.js";
import type { McpToolContext } from "./tools.js";
import { createMcpSessionAuthPort } from "./session.js";
import { encodePaymentHeader, nextPaymentNonce } from "../payment/x402.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { buildDataBlocksAsync } from "../storage/blocks/build.js";
import { readBuiltScopeBlocks } from "../storage/blocks/page.js";
import { buildBinaryEnvelopeData } from "../contracts/binary.js";
import { computeDataPointId } from "../sync/data-point-id.js";

/**
 * What a paid MCP session charges, pinned at the counts the pre-handler storage
 * read path produced. This file passes unchanged on that path and on the
 * handler path, so the counts did not move when MCP reads moved to the handler.
 * Every paid read call that carries a proof settles once through the gateway
 * fetch. Metadata and manifest reads settle nothing. A paged read is never
 * reported as fulfilment; a single uncursored page is.
 *
 * The stream-view cases run the same counts against a real stream view, the
 * path a name with a stream takes. A refused read settles, logs and reports
 * nothing: payment is taken only once the read is known to be served.
 */

const SERVER_ORIGIN = "https://personal-server.test";
const OWNER = "0x0000000000000000000000000000000000000aaa";
const SCOPE = "instagram.profile";
const STREAM_SCOPE = "pdpp.acme.items";
const MISSING_SCOPE = "instagram.missing";
const BINARY_SCOPE = "instagram.media";
const COLLECTED_AT = "2026-06-05T00:00:00Z";
const GRANT_ID = `0x${"ab".repeat(32)}`;
const ASSET = "0x0000000000000000000000000000000000000fee";
const GATEWAY_URL = "https://gateway.test";
const GATEWAY_CONFIG = {
  chainId: 14800,
  contracts: {
    dataRegistry: "0x0000000000000000000000000000000000000001",
    dataPortabilityPermissions: "0x0000000000000000000000000000000000000002",
    dataPortabilityServer: "0x0000000000000000000000000000000000000003",
    dataPortabilityGrantees: "0x0000000000000000000000000000000000000004",
  },
} as never;
/** Small enough that six records take several pages. */
const PAGE_BYTES = 120;
const T = Date.parse("2026-11-01T00:00:00Z");

function createGranteeAccount() {
  return {
    address: "0x1111111111111111111111111111111111111111" as const,
    publicKey: "0x04deadbeef" as const,
    signTypedData: vi.fn(),
    signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
  };
}

const RECORDS = Array.from({ length: 6 }, (_, i) => ({
  id: `item-${i}`,
  text: `record ${i} with a few words of body text`,
}));

interface HarnessOptions {
  /** Serve SCOPE_STREAM from a real stream view. */
  stream?: boolean;
  /** Write the legacy file for SCOPE. Defaults to on for the legacy harness. */
  legacy?: boolean;
  /** Tombstone the stream connector, so its name is deleted. */
  deleteStream?: boolean;
  /** Scope the legacy file is stored under. Defaults to SCOPE. */
  legacyScope?: string;
  /** Items in the legacy file. Defaults to RECORDS. */
  legacyItems?: unknown[];
  /** Runs after a read decision chose its body, before the read settles. */
  afterDecision?: (stream: {
    f: DatabaseReadFixture;
    ns: string;
    service: DatabaseReadFixture["local"]["resolver"];
  }) => Promise<void>;
}

async function harness(options: HarnessOptions = {}) {
  const builder = privateKeyToAccount(generatePrivateKey());
  // The server key signs each access record, as a challenge would.
  const serverAccount = privateKeyToAccount(generatePrivateKey());
  const fee = { totalDue: "100", asset: ASSET };
  const gatewayGrant = {
    id: GRANT_ID,
    grantorAddress: OWNER,
    granteeId: builder.address,
    scopes: [SCOPE, STREAM_SCOPE, MISSING_SCOPE, BINARY_SCOPE],
    revokedAt: null,
    expiresAt: null,
    paymentStatus: "paid",
    fee,
  };
  const gateway = {
    getBuilder: async () => ({ id: builder.address }),
    getGrant: async () => gatewayGrant,
  };

  const storage = createMemoryDataStorage();
  const envelope = {
    version: "1.0",
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    data: { items: RECORDS },
  };
  // The read path's block helpers, as the storage sidecar runs them.
  Object.assign(storage, {
    hasScopeBlocks: async () => true,
    readScopeBlocks: async (
      scope: string,
      collectedAt: string,
      opts: Parameters<typeof readBuiltScopeBlocks>[1],
    ) =>
      readBuiltScopeBlocks(
        await buildDataBlocksAsync({ scope, collectedAt, content: envelope }),
        opts,
      ),
    readBlockManifest: async (scope: string, collectedAt: string) =>
      (await buildDataBlocksAsync({ scope, collectedAt, content: envelope }))
        .manifest,
  });
  /** Adds a legacy version. The newest insert is the latest version. */
  async function writeLegacyVersion(version: {
    fileId: string;
    scope: string;
    collectedAt: string;
    items?: unknown[];
    data?: Record<string, unknown>;
  }) {
    const written = await storage.writeEnvelope({
      version: "1.0",
      scope: version.scope,
      collectedAt: version.collectedAt,
      data: version.data ?? { items: version.items ?? [] },
    } as never);
    storage.insertEntry({
      fileId: version.fileId,
      path: written.path,
      scope: version.scope,
      collectedAt: version.collectedAt,
      sizeBytes: written.sizeBytes,
      dataPointId: null,
    } as never);
  }
  if (options.legacy ?? !options.stream) {
    await writeLegacyVersion({
      fileId: "file-1",
      scope: options.legacyScope ?? SCOPE,
      collectedAt: COLLECTED_AT,
      items: options.legacyItems ?? RECORDS,
    });
  }

  // Pass-through when no stream is wired: the scope has no stream view, so
  // the handler serves the legacy body.
  let streamSyncRead: unknown = { resolve: async () => ({ kind: "pass" }) };
  /** The stream head each read decision served, in order. */
  const servedByDecision: ({ scope: string; version: number } | null)[] = [];
  let fixture: DatabaseReadFixture | undefined;
  let streamNs = "";
  if (options.stream) {
    const f = await databaseReadFixture("acme");
    const ns = "";
    if (options.deleteStream) f.remote.setControl(2, true);
    else await f.remote.head("items", RECORDS, { o: T - 1000 });
    await f.local.apply();
    const service = f.local.resolver;
    fixture = f;
    streamNs = ns;
    // Records what each decision served, then lets a test move the head
    // before the read settles: the settlement must still name the served one.
    streamSyncRead = {
      resolve: async (input: Parameters<typeof service.resolve>[0]) => {
        const decision = await service.resolve(input);
        if (decision.kind === "view") servedByDecision.push(decision.served);
        await options.afterDecision?.({ f, ns, service });
        return decision;
      },
    };
  }

  const paymentFetch = vi.fn(async () => new Response("{}", { status: 200 }));
  const accessLogWrite = vi.fn();
  const readFulfillmentReport = vi.fn().mockResolvedValue(undefined);
  const deps = {
    accountStorageMode: {
      owner: OWNER,
      read: () => (options.stream ? "switched" : "unswitched"),
    },
    storage,
    streamSyncRead,
    accessLogWriter: { write: accessLogWrite },
    readFulfillmentReporter: { report: readFulfillmentReport },
    serverAddress: serverAccount.address,
    serverOwner: OWNER,
    paymentFetch,
  } as never as Parameters<typeof createMcpDataReadClient>[0]["dataApiDeps"];

  const port = createMcpSessionAuthPort({
    builderAddress: builder.address,
    grantId: GRANT_ID,
    authSessionVerifier: gateway as never,
    grantVerifier: gateway as never,
    serverOwner: OWNER,
    payment: {
      dataApiDeps: deps,
      gateway: gateway as never,
      gatewayConfig: GATEWAY_CONFIG,
      gatewayUrl: GATEWAY_URL,
    },
  });
  deps.auth = port as never;

  const client = createMcpDataReadClient({
    serverOrigin: SERVER_ORIGIN,
    granteeAccount: createGranteeAccount() as never,
    dataApiDeps: deps,
  });

  /** One fresh builder-signed x402 proof per paid call, as the app sends. */
  async function proof(bind?: {
    scope: string;
    version: number;
  }): Promise<string> {
    const message = {
      payerAddress: builder.address,
      opType: "grant",
      opId: GRANT_ID,
      asset: ASSET,
      amount: fee.totalDue,
      paymentNonce: nextPaymentNonce().toString(),
    };
    const signature = await builder.signTypedData({
      domain: escrowPaymentDomain(GATEWAY_CONFIG),
      types: GENERIC_PAYMENT_TYPES,
      primaryType: "GenericPayment",
      message: {
        ...message,
        amount: BigInt(message.amount),
        paymentNonce: BigInt(message.paymentNonce),
      },
    });
    // A proof that names the entry it pays for, as a challenge would have.
    let accessRecord: Record<string, string> | undefined;
    if (bind) {
      const recordId = `0x${"cd".repeat(32)}` as const;
      accessRecord = {
        dataPointId: computeDataPointId(OWNER, bind.scope),
        version: String(bind.version),
        accessor: builder.address,
        recordId,
        signature: await serverAccount.signTypedData({
          domain: dataRegistryDomain(GATEWAY_CONFIG),
          types: RECORD_DATA_ACCESS_TYPES,
          primaryType: "RecordDataAccess",
          message: {
            ownerAddress: OWNER,
            scope: bind.scope,
            version: BigInt(bind.version),
            accessor: builder.address,
            recordId,
          },
        }),
      };
    }
    return encodePaymentHeader({
      x402Version: 1,
      scheme: "vana-escrow-grant",
      network: "vana:14800",
      payload: {
        message,
        signature,
        ...(accessRecord ? { accessRecord } : {}),
      },
    } as never);
  }

  /**
   * A plain HTTP GET on `/v1/data/:scope`, with no in-process options. The
   * query and headers carry markers that look like the in-process controls.
   */
  async function httpRead(
    scope: string,
    query: Record<string, string>,
    headers: Record<string, string>,
    payment?: string,
  ): Promise<Response> {
    const search = new URLSearchParams({ grantId: GRANT_ID, ...query });
    // The handler mounted without a base path answers `/:scope`.
    return handlePersonalServerDataRequest(
      new Request(`${SERVER_ORIGIN}/${scope}?${search}`, {
        method: "GET",
        headers: {
          ...headers,
          ...(payment ? { "X-PAYMENT": payment } : {}),
        },
      }),
      deps,
    );
  }

  return {
    client,
    deps,
    writeLegacyVersion,
    paymentFetch,
    accessLogWrite,
    readFulfillmentReport,
    proof,
    httpRead,
    servedByDecision,
    fixture,
    streamNs,
  };
}

/** Pages a whole scope through the MCP read client, paying each page. */
async function readAllPages(
  h: Awaited<ReturnType<typeof harness>>,
  scope: string,
) {
  let cursor: string | undefined;
  let pages = 0;
  do {
    const page = await h.client.readScopeBlocks({
      scope,
      grantId: GRANT_ID,
      cursor,
      maxBytes: PAGE_BYTES,
      payment: await h.proof(),
      tool: "read_scope",
    });
    pages += 1;
    cursor = page.nextCursor;
  } while (cursor);
  return pages;
}

describe("mcp/read-client charges", () => {
  it("settles each paged read call once and never reports a paged read as fulfilment", async () => {
    const h = await harness();
    const pages = await readAllPages(h, SCOPE);

    expect(pages).toBeGreaterThan(1);
    expect(h.paymentFetch).toHaveBeenCalledTimes(pages);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(pages);
    // A paged read never completes in one uncursored call, so it is never
    // reported as fulfilment: the rule that held before this path existed.
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("settles a single-page read once and reports its fulfilment once", async () => {
    const h = await harness();
    const page = await h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
      tool: "read_scope",
    });

    expect(page.nextCursor).toBeUndefined();
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport.mock.calls[0]?.[0]).toMatchObject({
      source: "mcp",
      tool: "read_scope",
      scope: SCOPE,
    });
  });

  it("refuses a page of a paid read that carries no proof, and settles nothing", async () => {
    const h = await harness();
    const first = await h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      maxBytes: PAGE_BYTES,
      payment: await h.proof(),
    });
    expect(first.nextCursor).toBeDefined();
    h.paymentFetch.mockClear();

    const unpaid = h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      cursor: first.nextCursor,
      maxBytes: PAGE_BYTES,
    });
    await expect(unpaid).rejects.toBeInstanceOf(McpDataReadError);
    await expect(unpaid).rejects.toMatchObject({ status: 402 });
    expect(h.paymentFetch).not.toHaveBeenCalled();
  });

  it("lists scope metadata on a paid session without a proof, unlogged and unreported", async () => {
    const h = await harness();
    const metadata = await h.client.getScopeMetadata(SCOPE, GRANT_ID);

    expect(metadata).toMatchObject({
      scope: SCOPE,
      collectedAt: COLLECTED_AT,
      hasBlocks: true,
    });
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("reads a paid session's block manifest without a proof, logged once and never reported", async () => {
    const h = await harness();
    const manifest = await h.client.readBlockManifest({
      scope: SCOPE,
      grantId: GRANT_ID,
    });

    expect(manifest?.blocks.length).toBeGreaterThan(0);
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });
});

describe("mcp/read-client charges on a stream view", () => {
  it("settles each paged read of a view once per page and never reports it as fulfilment", async () => {
    const h = await harness({ stream: true });
    const pages = await readAllPages(h, STREAM_SCOPE);

    expect(pages).toBeGreaterThan(1);
    expect(h.paymentFetch).toHaveBeenCalledTimes(pages);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(pages);
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("settles a single-page view read once, logs once, and reports one mcp fulfilment", async () => {
    const h = await harness({ stream: true });
    const page = await h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
      tool: "read_scope",
    });

    expect(page.nextCursor).toBeUndefined();
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport.mock.calls[0]?.[0]).toMatchObject({
      source: "mcp",
      tool: "read_scope",
      scope: STREAM_SCOPE,
    });
  });

  it("serves the view, not the legacy file, when both exist under the same scope, under one settlement", async () => {
    // A stale legacy file under the stream's own name: the view must win, and
    // the paid read must not pick or charge that file.
    const h = await harness({
      stream: true,
      legacy: true,
      legacyScope: STREAM_SCOPE,
      legacyItems: [{ id: "stale-0", text: "stale legacy record" }],
    });
    const page = await h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
      tool: "read_scope",
    });

    expect(JSON.stringify(page)).toContain("record 0 with a few words");
    expect(JSON.stringify(page)).not.toContain("stale legacy record");
    expect(page.nextCursor).toBeUndefined();
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport.mock.calls[0]?.[0]).toMatchObject({
      source: "mcp",
      tool: "read_scope",
    });
  });

  /** The access record a read sent to the gateway when it settled. */
  function settledAccessRecord(h: Awaited<ReturnType<typeof harness>>) {
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    const init = (
      h.paymentFetch.mock.calls[0] as unknown as [string, RequestInit]
    )[1];
    return (
      JSON.parse(String(init.body)) as { accessRecord?: Record<string, string> }
    ).accessRecord;
  }

  /** What a read of the stream name would serve now, without reading it. */
  async function servedNow(h: Awaited<ReturnType<typeof harness>>) {
    const decision = await (
      h.deps.streamSyncRead as { resolve(i: unknown): Promise<any> }
    ).resolve({
      scope: STREAM_SCOPE,
      connection: null,
      cursor: null,
      legacyFile: false,
      isOwnerView: true,
    });
    await decision.body.cancel();
    h.servedByDecision.pop();
    return decision.served as { scope: string; version: number };
  }

  it("settles against the stream head when the view wins over a legacy file of the same name", async () => {
    const h = await harness({
      stream: true,
      legacy: true,
      legacyScope: STREAM_SCOPE,
      legacyItems: [{ id: "stale-0", text: "stale legacy record" }],
    });
    const head = await servedNow(h);
    const page = await h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(head),
      tool: "read_scope",
    });

    expect(JSON.stringify(page)).not.toContain("stale legacy record");
    // Exactly the head the view served: its registry data point and version,
    // not the legacy file's entry (which has no data point at all).
    expect(h.servedByDecision).toEqual([head]);
    expect(settledAccessRecord(h)).toMatchObject({
      dataPointId: computeDataPointId(OWNER, head.scope),
      version: String(head.version),
    });
  });

  it("settles against the head it served when the head advances before settlement", async () => {
    let advance = false;
    let advanced = false;
    let applying: Promise<void> | undefined;
    const h = await harness({
      stream: true,
      afterDecision: async ({ f }) => {
        if (!advance || advanced) return;
        advanced = true;
        await f.remote.head(
          "items",
          [...RECORDS, { id: "item-late", text: "published late" }],
          { o: T + 1000, version: 2 },
        );
        applying = f.local.apply();
      },
    });
    const validated = await servedNow(h);
    advance = true;
    const page = await h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(validated),
      tool: "read_scope",
    });

    await applying;
    expect(JSON.stringify(page)).not.toContain("published late");
    // The race is real: a later lookup finds a newer head than the one served.
    expect(advanced).toBe(true);
    advance = false;
    expect((await servedNow(h)).version).toBeGreaterThan(validated.version);
    expect(h.servedByDecision).toEqual([validated]);
    expect(settledAccessRecord(h)).toMatchObject({
      dataPointId: computeDataPointId(OWNER, validated.scope),
      version: String(validated.version),
    });
  });

  it("lists view metadata on a paid session without a proof, unlogged and unreported", async () => {
    const h = await harness({ stream: true });
    const metadata = await h.client.getScopeMetadata(STREAM_SCOPE, GRANT_ID);

    expect(metadata).not.toBeNull();
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("reads a view's block manifest without a proof, logged once and never reported", async () => {
    const h = await harness({ stream: true });
    const manifest = await h.client.readBlockManifest({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
    });

    expect(manifest?.blocks.length).toBeGreaterThan(0);
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("refuses a raw read of a view-served name with 409, settling, logging and reporting nothing", async () => {
    const h = await harness({ stream: true });
    const raw = h.client.readRawScopeFile({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
    });

    await expect(raw).rejects.toMatchObject({
      status: 409,
      body: { error: "STREAM_VIEW_NOT_RAW", scope: STREAM_SCOPE },
    });
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });
});

describe("mcp/read-client payment follows the refusal", () => {
  it("refuses a paid read of a missing target before any settlement", async () => {
    const h = await harness();
    const read = h.client.readScopeBlocks({
      scope: MISSING_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
      tool: "read_scope",
    });

    await expect(read).rejects.toBeInstanceOf(McpDataReadError);
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("refuses a paid read of a deleted stream target before any settlement", async () => {
    const h = await harness({ stream: true, deleteStream: true });
    const read = h.client.readScopeBlocks({
      scope: STREAM_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
      tool: "read_scope",
    });

    await expect(read).rejects.toBeInstanceOf(McpDataReadError);
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });
});

describe("HTTP reads ignore in-process markers", () => {
  // Query and headers only: a GET carries no body. None of these is a
  // control the HTTP caller can set; each must change nothing.
  const MARKERS = {
    query: { logAccess: "false", inProcess: "1", metadataOnly: "true" },
    headers: { "x-vana-in-process": "1", "x-metadata-only": "1" },
  };

  it("challenges a marked HTTP read with no proof, settling and logging nothing", async () => {
    const h = await harness();
    const response = await h.httpRead(SCOPE, MARKERS.query, MARKERS.headers);

    expect(response.status).toBe(402);
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("settles a marked HTTP read once, logs it once, and reports it as an api fulfilment", async () => {
    const h = await harness();
    const response = await h.httpRead(
      SCOPE,
      MARKERS.query,
      MARKERS.headers,
      await h.proof(),
    );

    expect(response.status).toBe(200);
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport.mock.calls[0]?.[0]).toMatchObject({
      source: "api",
      scope: SCOPE,
    });
  });

  it("serves an ordinary HTTP read right after an MCP metadata call unchanged", async () => {
    const h = await harness();
    await h.client.getScopeMetadata(SCOPE, GRANT_ID);
    h.accessLogWrite.mockClear();

    const response = await h.httpRead(SCOPE, {}, {}, await h.proof());

    expect(response.status).toBe(200);
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport.mock.calls[0]?.[0]).toMatchObject({
      source: "api",
    });
  });
});

describe("mcp/read-client refusals before any charge or log", () => {
  it("charges and serves one legacy version when the latest changes after the paid read selects it", async () => {
    const h = await harness();
    const realAuth = h.deps.auth;
    let raced = false;
    // Between the paid read's grant check and its body read, a newer version
    // lands. The paid read must still charge, log and serve the version it
    // selected.
    h.deps.auth = {
      ...realAuth,
      authorizeBuilderRead: async (input: {
        request: Request;
        metadataOnly?: boolean;
      }) => {
        const result = await realAuth.authorizeBuilderRead(input as never);
        if (
          !raced &&
          input.metadataOnly &&
          input.request.headers.get("x-payment")
        ) {
          raced = true;
          await h.writeLegacyVersion({
            fileId: "file-2",
            scope: SCOPE,
            collectedAt: "2026-06-06T00:00:00Z",
            items: [{ id: "newer-0", text: "newer version record" }],
          });
        }
        return result;
      },
    } as never;

    const page = await h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
      tool: "read_scope",
    });

    expect(raced).toBe(true);
    expect(JSON.stringify(page)).not.toContain("newer version record");
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
    expect(h.readFulfillmentReport.mock.calls[0]?.[0]).toMatchObject({
      fileId: "file-1",
      source: "mcp",
    });
  });

  it("refuses a malformed cursor before any charge or log", async () => {
    const h = await harness();
    const read = h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      cursor: "not-a-cursor",
      payment: await h.proof(),
      tool: "read_scope",
    });

    await expect(read).rejects.toMatchObject({ status: 400 });
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("refuses a cursor from an older version before any charge or log", async () => {
    const h = await harness();
    const first = await h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      maxBytes: PAGE_BYTES,
      payment: await h.proof(),
      tool: "read_scope",
    });
    expect(first.nextCursor).toBeDefined();
    await h.writeLegacyVersion({
      fileId: "file-2",
      scope: SCOPE,
      collectedAt: "2026-06-06T00:00:00Z",
      items: [{ id: "newer-0", text: "newer version record" }],
    });
    h.paymentFetch.mockClear();
    h.accessLogWrite.mockClear();

    const stale = h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      cursor: first.nextCursor,
      maxBytes: PAGE_BYTES,
      payment: await h.proof(),
      tool: "read_scope",
    });

    await expect(stale).rejects.toMatchObject({ status: 400 });
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
  });

  it("refuses a paid raw read of a non-binary legacy file before any charge or log", async () => {
    const h = await harness();
    const raw = h.client.readRawScopeFile({
      scope: SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
    });

    await expect(raw).rejects.toMatchObject({ status: 400 });
    expect(h.paymentFetch).not.toHaveBeenCalled();
    expect(h.accessLogWrite).not.toHaveBeenCalled();
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });
});

describe("mcp/read-client versions that change mid-request", () => {
  it("serves a validated page or charges and logs nothing when a version lands between the cursor check and the paid read", async () => {
    const h = await harness();
    const first = await h.client.readScopeBlocks({
      scope: SCOPE,
      grantId: GRANT_ID,
      maxBytes: PAGE_BYTES,
      payment: await h.proof(),
      tool: "read_scope",
    });
    expect(first.nextCursor).toBeDefined();
    h.paymentFetch.mockClear();
    h.accessLogWrite.mockClear();

    // A newer version lands after the cursor was minted, between the cursor
    // check (the first lookup of this page) and the paid read's own version
    // selection (the lookup after it). The first lookup still sees the version
    // the cursor was minted from.
    const storage = h.deps.storage as unknown as {
      findEntry: (query: { scope?: string }) => unknown;
    };
    const realFind = storage.findEntry.bind(h.deps.storage);
    // Written now, so the insert below is synchronous.
    const newer = await h.deps.storage.writeEnvelope({
      version: "1.0",
      scope: SCOPE,
      collectedAt: "2026-06-06T00:00:00Z",
      data: { items: [{ id: "newer-0", text: "newer version record" }] },
    } as never);
    let lookups = 0;
    let raced = false;
    storage.findEntry = (query) => {
      const found = realFind(query);
      if (query.scope === SCOPE && !raced) {
        lookups += 1;
        if (lookups === 1) {
          raced = true;
          h.deps.storage.insertEntry({
            fileId: "file-2",
            path: newer.path,
            scope: SCOPE,
            collectedAt: "2026-06-06T00:00:00Z",
            sizeBytes: newer.sizeBytes,
            dataPointId: null,
          } as never);
        }
      }
      return found;
    };

    const outcome = await h.client
      .readScopeBlocks({
        scope: SCOPE,
        grantId: GRANT_ID,
        cursor: first.nextCursor,
        maxBytes: PAGE_BYTES,
        payment: await h.proof(),
        tool: "read_scope",
      })
      .then(
        (page) => ({ served: true as const, page }),
        (error: unknown) => ({ served: false as const, error }),
      );

    expect(raced).toBe(true);
    if (outcome.served) {
      // The page is for the version the cursor was checked against.
      expect(JSON.stringify(outcome.page)).not.toContain(
        "newer version record",
      );
      expect(h.paymentFetch).toHaveBeenCalledTimes(1);
      expect(h.accessLogWrite).toHaveBeenCalledTimes(1);
    } else {
      // Refused: nothing was charged or logged for it.
      expect(outcome.error).toMatchObject({ status: 400 });
      expect(h.paymentFetch).not.toHaveBeenCalled();
      expect(h.accessLogWrite).not.toHaveBeenCalled();
    }
    expect(h.readFulfillmentReport).not.toHaveBeenCalled();
  });

  it("returns the selected binary version's own fileId and collectedAt when a newer version lands after the bytes are selected", async () => {
    const h = await harness();
    const bytes1 = new TextEncoder().encode("first binary version");
    const bytes2 = new TextEncoder().encode("second binary version");
    const hash = `0x${"11".repeat(32)}` as const;
    await h.writeLegacyVersion({
      fileId: "bin-1",
      scope: BINARY_SCOPE,
      collectedAt: COLLECTED_AT,
      data: buildBinaryEnvelopeData({
        bytes: bytes1,
        mimeType: "application/octet-stream",
        contentHash: hash,
      }) as unknown as Record<string, unknown>,
    });

    // The settlement authorization runs after the handler has selected and
    // pinned the bytes. A newer binary version lands there.
    const realAuth = h.deps.auth;
    let raced = false;
    h.deps.auth = {
      ...realAuth,
      authorizeBuilderRead: async (input: {
        request: Request;
        metadataOnly?: boolean;
      }) => {
        const result = await realAuth.authorizeBuilderRead(input as never);
        if (
          !raced &&
          !input.metadataOnly &&
          input.request.headers.get("x-payment")
        ) {
          raced = true;
          await h.writeLegacyVersion({
            fileId: "bin-2",
            scope: BINARY_SCOPE,
            collectedAt: "2026-06-06T00:00:00Z",
            data: buildBinaryEnvelopeData({
              bytes: bytes2,
              mimeType: "application/octet-stream",
              contentHash: hash,
            }) as unknown as Record<string, unknown>,
          });
        }
        return result;
      },
    } as never;

    const raw = await h.client.readRawScopeFile({
      scope: BINARY_SCOPE,
      grantId: GRANT_ID,
      payment: await h.proof(),
    });

    expect(raced).toBe(true);
    expect(raw.contentBase64).toBe(Buffer.from(bytes1).toString("base64"));
    expect(raw.fileId).toBe("bin-1");
    expect(raw.collectedAt).toBe(COLLECTED_AT);
    expect(h.paymentFetch).toHaveBeenCalledTimes(1);
  });
});

describe("#599 MCP account-mode adapters", () => {
  type ReadOptions = Parameters<typeof createMcpDataReadClient>[0];
  type ToolContext = McpToolContext;

  async function adapter(input: {
    mode: "unknown" | "unswitched" | "switched";
    stream?: boolean;
    storage?: boolean;
  }) {
    vi.resetModules();
    let readOptions!: ReadOptions;
    let context!: ToolContext;
    const listScopes = vi.fn().mockResolvedValue({
      status: 200,
      scopes: [],
      total: 0,
    });
    const legacyRead = vi.fn(() => null);
    const legacyList = vi.fn(() => []);
    const streamResolve = vi.fn();
    let mode = input.mode;
    const readMode = vi.fn(() => mode);
    vi.doMock(
      "@opendatalabs/personal-server-ts-core/mcp",
      async (original) => ({
        ...(await original<Record<string, unknown>>()),
        loadMcpGranteeAccount: () => createGranteeAccount(),
        createMcpDataReadClient: (options: ReadOptions) => {
          readOptions = options;
          return { listScopes };
        },
        handleMcpStreamableHttpRequest: async (
          _request: Request,
          options: ToolContext,
        ) => {
          context = options;
          return new Response(null, { status: 204 });
        },
      }),
    );
    vi.doMock("../../../server/src/api-auth.js", () => ({
      createServerApiAuth: () => ({}),
    }));
    try {
      const { executeMcpConnectionRequest } =
        await import("../../../server/src/routes/mcp.js");
      const connection = {
        id: "mode-test",
        grants: [{ grantId: GRANT_ID, scopes: ["write:memory.test"] }],
        granteeAddress: OWNER,
      } as ToolContext["connection"];
      await executeMcpConnectionRequest(
        new Request(`${SERVER_ORIGIN}/mcp`),
        connection,
        {
          logger: { warn: vi.fn(), error: vi.fn() },
          serverOrigin: SERVER_ORIGIN,
          serverOwner: OWNER,
          gateway: {},
          accessLogWriter: { write: vi.fn() },
          accountStorageMode: { owner: OWNER, read: readMode },
          ...(input.storage !== false
            ? { dataStorage: { findEntry: legacyRead, listScopes: legacyList } }
            : {}),
          ...(input.stream
            ? {
                streamSyncRead: {
                  resolve: streamResolve,
                },
              }
            : {}),
        } as never,
      );
      const { MCP_TOOLS } =
        await import("@opendatalabs/personal-server-ts-core/mcp");
      return {
        context,
        readOptions,
        readMode,
        legacyRead,
        legacyList,
        listScopes,
        streamResolve,
        tools: MCP_TOOLS,
        setMode(next: typeof mode) {
          mode = next;
        },
      };
    } finally {
      vi.doUnmock("@opendatalabs/personal-server-ts-core/mcp");
      vi.doUnmock("../../../server/src/api-auth.js");
    }
  }

  it("chooses the read route once from account mode, never reader presence", async () => {
    for (const mode of ["unknown", "unswitched", "switched"] as const) {
      const h = await adapter({ mode, stream: true });
      expect(h.readMode).toHaveBeenCalledTimes(1);
      expect(Boolean(h.readOptions.dataApiDeps.streamSyncRead)).toBe(
        mode === "switched",
      );
      h.setMode(mode === "switched" ? "unswitched" : "switched");
      expect(h.readOptions.dataApiDeps.accountStorageMode?.read()).toBe(mode);
      expect(h.readMode).toHaveBeenCalledTimes(1);
      expect(h.legacyRead).not.toHaveBeenCalled();
      expect(h.streamResolve).not.toHaveBeenCalled();
    }
  });

  it("returns STREAM_LIST_UNAVAILABLE rather than a legacy list without the listing port", async () => {
    const h = await adapter({ mode: "switched", stream: true });
    const deps = {
      ...h.readOptions.dataApiDeps,
      auth: { authorizeBuilderList: vi.fn(async () => undefined) },
    };
    const response = await handlePersonalServerDataRequest(
      new Request(SERVER_ORIGIN + "/"),
      deps as never,
    );
    expect(response.status).toBe(503);
    expect((await response.json()).error.errorCode).toBe(
      "STREAM_LIST_UNAVAILABLE",
    );
    expect(h.legacyList).not.toHaveBeenCalled();
  });

  it("seals legacy storage with throwing operations rather than empty answers", async () => {
    const h = await adapter({ mode: "switched", stream: true });
    const storage = h.readOptions.dataApiDeps.storage;
    expect(() => storage.findEntry({ scope: SCOPE })).toThrow();
    expect(() => Reflect.get(storage, "listScopes")()).toThrow();
    expect(() => storage.readEnvelope(SCOPE, COLLECTED_AT)).toThrow();
    expect(h.legacyRead).not.toHaveBeenCalled();
    expect(h.legacyList).not.toHaveBeenCalled();
  });

  it("refuses remember and forget with 409 STREAM_SYNC_WRITE_UNAVAILABLE before legacy access", async () => {
    const h = await adapter({ mode: "switched", stream: true });
    for (const [name, args] of [
      ["remember", { text: "A test fact", scope: "memory.test" }],
      ["forget", { key: "a-test-key", scope: "memory.test" }],
    ] as const) {
      const tool = h.tools.find((tool) => tool.name === name)!;
      const result = await tool.handler(args, h.context);
      expect(result.isError).toBe(true);
      const body = JSON.parse((result.content[0] as { text: string }).text);
      expect(body).toMatchObject({
        error: "write_unavailable",
        status: 409,
        errorCode: "STREAM_SYNC_WRITE_UNAVAILABLE",
      });
    }
    expect(h.legacyRead).not.toHaveBeenCalled();
    expect(h.legacyList).not.toHaveBeenCalled();
  });
});
