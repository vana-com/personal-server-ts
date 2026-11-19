import { describe, expect, it, vi } from "vitest";
import {
  handlePersonalServerDataRequest,
  type PersonalServerDataApiDeps,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

describe("paid stream read refusal before payment", () => {
  it.each([
    [{ kind: "read_not_registered" }, 503, "READ_NOT_REGISTERED"],
    [{ kind: "unavailable", reason: "deleted" }, 410, "DATA_DELETED"],
  ] as const)(
    "refuses %j before requesting a payment",
    async (decision, status, code) => {
      const resolve = vi.fn(async () => decision);
      const authorizeBuilderRead = vi.fn(async () => ({
        builder: "0x1000000000000000000000000000000000000001" as const,
        grantId: "grant",
      }));
      const paymentFetch = vi.fn();
      const getGrant = vi.fn();
      const deps = {
        storage: createMemoryDataStorage(),
        accountStorageMode: { owner: "fixture", read: () => "switched" },
        streamSyncRead: { resolve },
        auth: { authorizeBuilderRead },
        paymentEnabled: true,
        paymentFetch,
        gateway: { getGrant },
        gatewayConfig: { chainId: 14800 },
        gatewayUrl: "https://gateway.test",
      } as unknown as PersonalServerDataApiDeps;
      const response = await handlePersonalServerDataRequest(
        new Request("https://server.test/pdpp.fixture.items"),
        deps,
      );
      expect(response.status).toBe(status);
      expect(JSON.stringify(await response.json())).toContain(code);
      expect(resolve).toHaveBeenCalledWith(
        expect.objectContaining({ requireRegistered: true }),
      );
      expect(authorizeBuilderRead.mock.invocationCallOrder[0]).toBeLessThan(
        resolve.mock.invocationCallOrder[0]!,
      );
      expect(getGrant).not.toHaveBeenCalled();
      expect(paymentFetch).not.toHaveBeenCalled();
      if (status === 503) expect(response.headers.get("retry-after")).toBe("5");
    },
  );
});
