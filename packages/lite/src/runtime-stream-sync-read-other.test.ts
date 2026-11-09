/**
 * The Lite fetch path hands the one account storage mode, and the owner it
 * is bound to, to the group D read entry points: `/v1/sync/file/*`, the Oura
 * requirements read and scope delete.
 */
import { describe, it, expect, vi } from "vitest";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "./runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import {
  buildWeb3SignedHeader,
  createTestWallet,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";
import {
  createAccountStorageMode,
  type AccountStorageModeValue,
} from "@opendatalabs/personal-server-ts-core/api";

const ORIGIN = "https://ps-lite.local";
const owner = createTestWallet(7);

async function signed(method: "GET" | "POST" | "DELETE", path: string) {
  const auth = await buildWeb3SignedHeader({
    wallet: owner,
    aud: ORIGIN,
    method,
    uri: path,
  });
  return new Request(`${ORIGIN}${path}`, {
    method,
    headers: { Authorization: auth },
  });
}

function harness(value: AccountStorageModeValue, boundOwner?: string) {
  const mode = createAccountStorageMode({
    owner: boundOwner,
    source: () => value === "switched",
  });
  const gateway = {} as GatewayClient;
  const sink = {
    async write() {},
    async read() {
      return { logs: [], total: 0, limit: 50, offset: 0 };
    },
  };
  const trigger = vi.fn(async () => undefined);
  const runtime = createPsLiteRuntime({
    active: true,
    storage: createMemoryPsLiteStorage(),
    gateway,
    accessLogReader: sink,
    accessLogWriter: sink,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    syncManager: { trigger, getStatus: vi.fn() } as never,
    accountStorageMode: mode,
    auth: createWeb3SignedPsLiteAuth({
      origin: ORIGIN,
      ownerAddress: owner.address,
      dataReadPolicyPorts: {
        authSessionVerifier: gateway,
        grantVerifier: gateway,
      },
    }),
  });
  return { runtime, trigger };
}

describe("Lite passes the account mode to the group D entry points", () => {
  it("LITE_MODE_DROPPED: a switched account is refused on /v1/sync/file and starts no sync", async () => {
    const h = harness("switched", owner.address);
    const res = await h.runtime.fetch(await signed("POST", "/v1/sync/file/x"));
    expect(res.status).toBe(409);
    expect(h.trigger).not.toHaveBeenCalled();
  });

  it("UNSWITCHED_PARITY: an unswitched account still starts the sync", async () => {
    const h = harness("unswitched", owner.address);
    const res = await h.runtime.fetch(await signed("POST", "/v1/sync/file/x"));
    expect(res.status).toBe(202);
    expect(h.trigger).toHaveBeenCalledTimes(1);
  });

  it("the owner is passed too: a mode bound to another owner answers the retryable 503", async () => {
    const h = harness("switched", "0x2222222222222222222222222222222222222222");
    const res = await h.runtime.fetch(await signed("POST", "/v1/sync/file/x"));
    expect(res.status).toBe(503);
    expect(h.trigger).not.toHaveBeenCalled();
  });

  it("LITE_MODE_DROPPED: a switched account is refused on the Oura requirements read", async () => {
    const h = harness("switched", owner.address);
    const res = await h.runtime.fetch(
      await signed("GET", "/v1/import/oura-browser/requirements"),
    );
    expect(res.status).toBe(409);
  });

  it("UNSWITCHED_PARITY: an unswitched account still gets requirements", async () => {
    const h = harness("unswitched", owner.address);
    const res = await h.runtime.fetch(
      await signed("GET", "/v1/import/oura-browser/requirements"),
    );
    expect(res.status).toBe(200);
  });

  it("LITE_MODE_DROPPED: a switched account's scope delete is refused", async () => {
    const h = harness("switched", owner.address);
    const res = await h.runtime.fetch(
      await signed("DELETE", "/v1/data/instagram.profile"),
    );
    expect(res.status).toBe(409);
  });
});
