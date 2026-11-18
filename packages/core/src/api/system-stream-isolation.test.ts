import { ScopeMismatchError } from "../errors/catalog.js";
import { expect, it, vi } from "vitest";
import { createGrantContract } from "../contracts/grants.js";
import { verifyDataReadPolicy } from "../policy/data-read.js";
import {
  handlePersonalServerAccessLogsRequest,
  handlePersonalServerDataRequest,
} from "./index.js";
import { createMemoryDataStorage } from "../test-utils/memory-storage.js";

const scope = "pdpp.vana-system-access-v1.events";
const owner = `0x${"12".repeat(20)}` as const;

it("refuses reserved read and write grants before signing", async () => {
  const sign = vi.fn();
  for (const target of [scope, `write:${scope}`, "vana.system.private"]) {
    const result = await createGrantContract({
      serverOwner: owner,
      serverSigner: { signGrantRegistration: sign },
      gateway: {
        getBuilder: vi.fn(async () => ({ id: owner })),
        createGrant: vi.fn(async () => ({ grantId: owner })),
      } as never,
      body: { granteeAddress: owner, scopes: [target] },
    });
    expect(result.status).toBe(400);
  }
  expect(sign).not.toHaveBeenCalled();
});

it("refuses reserved reads before consulting even a wildcard grant", async () => {
  const getGrant = vi.fn();
  await expect(
    verifyDataReadPolicy(
      {
        signer: owner,
        serverOwner: owner,
        requestedScope: scope,
        grantId: "wildcard",
      },
      {
        authSessionVerifier: { getBuilder: vi.fn() },
        grantVerifier: { getGrant },
      } as never,
    ),
  ).rejects.toBeInstanceOf(ScopeMismatchError);
  expect(getGrant).not.toHaveBeenCalled();
});

it("keeps all ordinary data views private while the owner reads history", async () => {
  const read = vi.fn(async () => ({
    logs: [],
    total: 0,
    limit: 50,
    offset: 0,
  }));
  const auth = {
    authorizeOwner: vi.fn(async () => undefined),
    authorizeBuilderRead: vi.fn(async () => ({ grantId: "wildcard" })),
  };
  const resolve = vi.fn();
  for (const suffix of ["", "/versions", "/lineage"]) {
    const response = await handlePersonalServerDataRequest(
      new Request(`https://server.example/${scope}${suffix}`),
      {
        auth,
        storage: createMemoryDataStorage(),
        accountStorageMode: { owner, read: () => "switched" },
        streamSyncRead: { resolve },
        accessLogWriter: { write: vi.fn() },
      } as never,
    );
    expect(response.status).toBe(403);
  }
  expect(resolve).not.toHaveBeenCalled();
  const history = await handlePersonalServerAccessLogsRequest(
    new Request("https://server.example/"),
    { auth, accessLogReader: { read } } as never,
  );
  expect(history.status).toBe(200);
  expect(read).toHaveBeenCalledOnce();
});
