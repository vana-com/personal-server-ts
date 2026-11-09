import { describe, expect, it, vi } from "vitest";
import { Hono } from "hono";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { ImportStatus } from "@opendatalabs/personal-server-ts-core/sync";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { streamSyncImportStatusRoutes } from "./stream-sync-import-status.js";

const OWNER = "0x1111111111111111111111111111111111111111" as const;
const TOKEN = "import-status-test-token";
const granteeWallet = createTestWallet(2);

const STATUS: ImportStatus = {
  complete: true,
  abandoned: false,
  connectors: [
    {
      connector: "conn-a",
      state: "failed",
      attempts: 5,
      staged: 0,
      excluded: [{ reason: "unmapped_stream", rows: 2 }],
    },
  ],
};

function app(importStatus: (() => Promise<ImportStatus>) | undefined) {
  const outer = new Hono();
  outer.route(
    "/v1/stream-sync/import-status",
    streamSyncImportStatusRoutes({
      serverOrigin: "http://127.0.0.1",
      serverOwner: OWNER,
      gateway: {
        getServer: vi.fn().mockResolvedValue(null),
      } as unknown as GatewayClient,
      accessToken: TOKEN,
      importStatus,
    }),
  );
  outer.onError((err, c) =>
    err instanceof ProtocolError
      ? c.json(err.toJSON(), err.code as 401)
      : c.json({ error: String(err) }, 500),
  );
  return (authorization: string | null = `Bearer ${TOKEN}`) =>
    outer.request("/v1/stream-sync/import-status", {
      headers: authorization ? { authorization } : {},
    });
}

describe("stream-sync import status route (STATUS_ROUTE_UNAUTHENTICATED)", () => {
  it("answers the owner with counts per connector and reason, and nothing else", async () => {
    const response = await app(async () => STATUS)();
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(STATUS);
  });

  it("answers 404 when no importer runs", async () => {
    const response = await app(undefined)();
    expect(response.status).toBe(404);
    expect(await response.json()).toMatchObject({
      error: { code: 404, errorCode: "STREAM_SYNC_IMPORT_OFF" },
    });
  });

  it("refuses a caller who is not the owner, a grantee and no auth", async () => {
    const call = app(async () => STATUS);
    expect((await call("Bearer wrong-token")).status).toBe(401);
    const grantee = await buildWeb3SignedHeader({
      wallet: granteeWallet,
      aud: "http://127.0.0.1",
      method: "GET",
      uri: "/v1/stream-sync/import-status",
      grantId: "0xgrant",
    });
    expect((await call(grantee)).status).toBe(401);
    expect((await call(null)).status).toBe(401);
  });
});
