import { createServer } from "node:http";
import { afterEach, expect, it } from "vitest";
import {
  encryptWithPassword,
  decryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { ServerConfigSchema } from "../../schemas/server-config.js";
import { AdditionsBudget } from "../../additions/budget.js";
import { createVanaSyncStorageAdapter } from "./vana.js";

const stops: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const stop of stops.splice(0)) await stop();
});
it("reads real encrypted HTTP blobs through the bounded Vana adapter and shares the scope budget", async () => {
  const plaintext = new TextEncoder().encode(
    JSON.stringify({ scope: "test.source", data: { items: [{ id: "a" }] } }),
  );
  const ciphertext = await encryptWithPassword(
    plaintext,
    "local-throwaway-password",
  );
  const paths: string[] = [];
  const server = createServer((request, response) => {
    paths.push(request.url ?? "");
    response.end(ciphertext);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  stops.push(
    () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  );
  const address = server.address();
  if (!address || typeof address === "string")
    throw new Error("Missing HTTP port");
  const config = ServerConfigSchema.parse({
    storage: {
      backend: "vana",
      config: { vana: { apiUrl: `http://127.0.0.1:${address.port}` } },
    },
    gateway: { chainId: 14800 },
  });
  const owner = "0x1111111111111111111111111111111111111111";
  const adapter = createVanaSyncStorageAdapter({
    config,
    serverOwner: owner,
    serverAccount: {
      address: owner,
      signMessage: async () => {
        throw new Error("Public GET must not sign");
      },
    },
  });
  if (!adapter.downloadBounded)
    throw new Error("Bounded read capability missing");
  const budget = new AdditionsBudget(ciphertext.length * 3, 1000);
  const first = await adapter.downloadBounded(
    adapter.urlForKey("test.source/1"),
    budget,
  );
  expect(await decryptWithPassword(first, "local-throwaway-password")).toEqual(
    plaintext,
  );
  await expect(
    adapter.downloadBounded(adapter.urlForKey("second.source/1"), budget),
  ).rejects.toThrow(/budget/);
  expect(paths).toEqual([
    `/v1/chains/14800/blobs/${owner}/test.source/1`,
    `/v1/chains/14800/blobs/${owner}/second.source/1`,
  ]);
  await expect(
    adapter.downloadBounded(
      "http://other.invalid/blob",
      new AdditionsBudget(1000),
    ),
  ).rejects.toThrow(/namespace/);
});
