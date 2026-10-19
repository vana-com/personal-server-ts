import { privateKeyToAccount } from "viem/accounts";
import { verifyWeb3Signed } from "@opendatalabs/vana-sdk/node";
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

it("authenticates preview upload/read/delete against an independent Storage audience", async () => {
  const owner = privateKeyToAccount(`0x${"45".repeat(32)}`);
  const expected = new Uint8Array([1, 2, 3]);
  const methods: string[] = [];
  const server = createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      if (request.method !== "HEAD") {
        const proof = await verifyWeb3Signed({
          headerValue: request.headers.authorization!,
          expectedOrigin: "https://storage.vana.org",
          expectedMethod: request.method!,
          expectedPath: request.url!,
          bodyBytes: body,
        });
        expect(proof.signer.toLowerCase()).toBe(owner.address.toLowerCase());
      }
      methods.push(request.method!);
      response.end(request.method === "GET" ? expected : undefined);
    } catch (error) {
      response.statusCode = 401;
      response.end(String(error));
    }
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
  if (!address || typeof address === "string") throw new Error("Missing port");
  const endpoint = `http://127.0.0.1:${address.port}`;
  const adapter = createVanaSyncStorageAdapter({
    config: ServerConfigSchema.parse({
      gateway: { chainId: 14800 },
      storage: { config: { vana: { apiUrl: endpoint } } },
    }),
    serverOwner: owner.address,
    serverAccount: {
      address: owner.address,
      signMessage: (message) => owner.signMessage({ message }),
    },
    audience: "https://storage.vana.org",
  });
  const url = await adapter.upload("vana.system.additions/1", expected);
  expect(new URL(url).origin).toBe(endpoint);
  expect(await adapter.download(url)).toEqual(expected);
  expect(await adapter.exists(url)).toBe(true);
  expect(await adapter.delete(url)).toBe(true);
  expect(methods).toEqual(["PUT", "GET", "HEAD", "DELETE"]);
  await expect(adapter.delete("https://other.invalid/blob")).rejects.toThrow(
    /namespace/,
  );
});
