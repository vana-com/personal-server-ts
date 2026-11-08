import { describe, expect, it, vi } from "vitest";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import {
  escrowPaymentDomain,
  GENERIC_PAYMENT_TYPES,
} from "@opendatalabs/vana-sdk/browser";
import { createMcpDataReadClient, McpDataReadError } from "./read-client.js";
import { createMcpSessionAuthPort } from "./session.js";
import { encodePaymentHeader, nextPaymentNonce } from "../payment/x402.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";
import { buildDataBlocksAsync } from "../storage/blocks/build.js";
import { readBuiltScopeBlocks } from "../storage/blocks/page.js";

/**
 * What a paid MCP session charges, pinned at the counts the pre-handler storage
 * read path produced. This file passes unchanged on that path and on the
 * handler path, so the counts did not move when MCP reads moved to the handler.
 * Every paid read call that carries a proof settles once through the gateway
 * fetch. Metadata and manifest reads settle nothing. A paged read is never
 * reported as fulfilment; a single uncursored page is. The stream reader is
 * wired so these assertions run on the handler path that now serves MCP reads.
 */

const SERVER_ORIGIN = "https://personal-server.test";
const SERVER_ADDRESS = "0x0000000000000000000000000000000000000ccc";
const OWNER = "0x0000000000000000000000000000000000000aaa";
const SCOPE = "instagram.profile";
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

function createGranteeAccount() {
  return {
    address: "0x1111111111111111111111111111111111111111" as const,
    publicKey: "0x04deadbeef" as const,
    signTypedData: vi.fn(),
    signMessage: vi.fn().mockResolvedValue(`0x${"11".repeat(65)}`),
  };
}

async function harness() {
  const builder = privateKeyToAccount(generatePrivateKey());
  const fee = { totalDue: "100", asset: ASSET };
  const gatewayGrant = {
    id: GRANT_ID,
    grantorAddress: OWNER,
    granteeId: builder.address,
    scopes: [SCOPE],
    revokedAt: null,
    expiresAt: null,
    paymentStatus: "paid",
    fee,
  };
  const gateway = {
    getBuilder: async () => ({ id: builder.address }),
    getGrant: async () => gatewayGrant,
  };

  const envelope = {
    version: "1.0",
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    data: {
      items: Array.from({ length: 6 }, (_, i) => ({
        id: `item-${i}`,
        text: `record ${i} with a few words of body text`,
      })),
    },
  };
  const storage = createMemoryDataStorage();
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
  const written = await storage.writeEnvelope(envelope as never);
  storage.insertEntry({
    fileId: "file-1",
    path: written.path,
    scope: SCOPE,
    collectedAt: COLLECTED_AT,
    sizeBytes: written.sizeBytes,
    dataPointId: null,
  } as never);

  const paymentFetch = vi.fn(async () => new Response("{}", { status: 200 }));
  const accessLogWrite = vi.fn();
  const readFulfillmentReport = vi.fn().mockResolvedValue(undefined);
  const deps = {
    storage,
    // Pass-through: the scope has no stream view, so the handler serves the
    // legacy body, which is the path these counts were measured on.
    streamSyncRead: { resolve: async () => ({ kind: "pass" }) },
    accessLogWriter: { write: accessLogWrite },
    readFulfillmentReporter: { report: readFulfillmentReport },
    serverAddress: SERVER_ADDRESS,
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
  async function proof(): Promise<string> {
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
    return encodePaymentHeader({
      x402Version: 1,
      scheme: "vana-escrow-grant",
      network: "vana:14800",
      payload: { message, signature },
    } as never);
  }

  return {
    client,
    paymentFetch,
    accessLogWrite,
    readFulfillmentReport,
    proof,
  };
}

describe("mcp/read-client charges", () => {
  it("settles each paged read call once and never reports a paged read as fulfilment", async () => {
    const h = await harness();
    let cursor: string | undefined;
    let pages = 0;
    do {
      const page = await h.client.readScopeBlocks({
        scope: SCOPE,
        grantId: GRANT_ID,
        cursor,
        maxBytes: PAGE_BYTES,
        payment: await h.proof(),
        tool: "read_scope",
      });
      pages += 1;
      cursor = page.nextCursor;
    } while (cursor);

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
