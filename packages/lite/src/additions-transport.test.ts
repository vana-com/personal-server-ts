import { afterEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import { AdditionsBudget } from "@opendatalabs/personal-server-ts-core/additions";
import {
  deriveScopeKey,
  parseWeb3SignedHeader,
} from "@opendatalabs/vana-sdk/browser";
import { keccak256, stringToHex } from "viem";
import { createIndexedDbPsLiteStateStore } from "./state.js";
afterEach(() => vi.unstubAllGlobals());
import { createPsLiteAdditionsTransport } from "./additions-transport.js";

const ownerAddress = "0x1111111111111111111111111111111111111111";
const prepared = {
  scope: "vana.system.additions.spotify.profile",
  expectedVersion: "3",
  dataHash: `0x${"ab".repeat(32)}` as `0x${string}`,
  metadataHash: `0x${"cd".repeat(32)}` as `0x${string}`,
  encrypted: new Uint8Array([34, 67, 89]),
};
function setup(fetcher: typeof fetch) {
  vi.stubGlobal("indexedDB", new IDBFactory());
  const stateStore = createIndexedDbPsLiteStateStore({
    dbName: crypto.randomUUID(),
  });
  const config = ServerConfigSchema.parse({
    gateway: { url: "https://gateway.example" },
    storage: { config: { vana: { apiUrl: "https://storage.example" } } },
  });
  const ownerSigner = {
    signMessageBounded: vi.fn(async () => "0x1234" as const),
    signAddDataBounded: vi.fn(async () => "0x5678" as const),
  };
  const transport = createPsLiteAdditionsTransport({
    config,
    ownerAddress,
    masterKey: new Uint8Array(32).fill(4),
    stateStore,
    ownerSigner,
    fetch: fetcher,
  });
  return { transport, stateStore, config, ownerSigner };
}

describe("bounded owner checkpoint transport", () => {
  it("sends the installed SDK wire contract and retains interrupted publication across restart", async () => {
    const requests: { url: string; init: RequestInit }[] = [];
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      requests.push({ url: String(input), init: init ?? {} });
      return new Response("{}", { status: requests.length === 2 ? 503 : 200 });
    });
    const { transport, stateStore, config, ownerSigner } = setup(fetcher);
    await expect(
      transport.publish(prepared, new AdditionsBudget(100_000)),
    ).rejects.toThrow("registration failed");
    expect(requests[0].url).toBe(
      `https://storage.example/v1/chains/${config.gateway.chainId}/blobs/${ownerAddress}/vana.system.additions.spotify.profile/3`,
    );
    const header = new Headers(requests[0].init.headers).get("authorization");
    expect(parseWeb3SignedHeader(header ?? "").payload).toMatchObject({
      aud: "https://storage.example",
      method: "PUT",
      uri: new URL(requests[0].url).pathname,
    });
    expect(requests[0].init.body).toEqual(prepared.encrypted);
    expect(new Headers(requests[1].init.headers).get("authorization")).toBe(
      "Web3Signed 0x5678",
    );
    expect(
      JSON.parse(
        String(
          requests[1].init.body instanceof Uint8Array
            ? new TextDecoder().decode(requests[1].init.body)
            : requests[1].init.body,
        ),
      ),
    ).toEqual({
      ownerAddress,
      scope: prepared.scope,
      dataHash: prepared.dataHash,
      metadataHash: prepared.metadataHash,
      expectedVersion: "3",
    });
    const restarted = createPsLiteAdditionsTransport({
      config,
      ownerAddress,
      masterKey: new Uint8Array(32).fill(4),
      stateStore,
      ownerSigner,
      fetch: fetcher,
    });
    expect(
      await restarted.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toEqual(prepared);
    await expect(
      restarted.publish(
        { ...prepared, expectedVersion: "4" },
        new AdditionsBudget(100_000),
      ),
    ).rejects.toThrow("reconciled");
    expect(fetcher).toHaveBeenCalledTimes(2);
    await restarted.clearPending(prepared.scope, new AdditionsBudget(100_000));
    expect(
      await restarted.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toBeNull();
  });

  it("migrates an authenticated legacy numeric journal without changing its candidate", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => new Response("{}"));
    const { transport, stateStore, config } = setup(fetcher);
    const candidate = {
      ...prepared,
      encrypted: crypto.getRandomValues(new Uint8Array(60_000)),
    };
    const network = `vana:${config.gateway.chainId}:${new URL(config.gateway.url).origin}`;
    const binding = JSON.stringify([ownerAddress, network, prepared.scope]);
    const journalKey =
      `additions-publication-v1:${keccak256(stringToHex(binding))}` as const;
    const key = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(
        deriveScopeKey(
          new Uint8Array(32).fill(4),
          "ps-lite.additions-journal.v1",
        ),
      ),
      "AES-GCM",
      false,
      ["encrypt"],
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new TextEncoder().encode(binding),
      },
      key,
      new TextEncoder().encode(
        JSON.stringify({
          ...candidate,
          encrypted: Array.from(candidate.encrypted),
        }),
      ),
    );
    await stateStore.set(journalKey, {
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext)),
    });
    const migrationBudget = new AdditionsBudget(8 * 1024 * 1024);
    expect(
      await transport
        .openSession()
        .readPending(prepared.scope, migrationBudget),
    ).toEqual(candidate);
    expect(fetcher).not.toHaveBeenCalled();
    expect(await stateStore.get(journalKey)).toMatchObject({ version: 2 });
    const restarted = transport.openSession();
    const retryBudget = new AdditionsBudget(8 * 1024 * 1024);
    expect(await restarted.readPending(prepared.scope, retryBudget)).toEqual(
      candidate,
    );
    await restarted.publish(candidate, retryBudget);
    expect(fetcher).toHaveBeenCalledTimes(2);
    // Neither a success receipt nor a retry alone retires the verified intent.
    expect(await stateStore.get(journalKey)).not.toBeNull();
    const otherBinding = JSON.stringify([
      ownerAddress,
      network,
      prepared.scope + ".other",
    ]);
    const otherKey =
      `additions-publication-v1:${keccak256(stringToHex(otherBinding))}` as const;
    await stateStore.set(otherKey, await stateStore.get(journalKey));
    await expect(
      transport
        .openSession()
        .readPending(
          prepared.scope + ".other",
          new AdditionsBudget(8 * 1024 * 1024),
        ),
    ).rejects.toThrow();
  });

  it("passes cancellation to the actual signing operation before any network write", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const { transport, ownerSigner } = setup(fetcher);
    const budget = new AdditionsBudget(100_000, 5);
    ownerSigner.signMessageBounded.mockImplementation(
      async (_message, signal?: AbortSignal) => {
        await new Promise<void>((resolve) =>
          signal?.addEventListener("abort", () => resolve(), { once: true }),
        );
        signal?.throwIfAborted();
        return "0x1234";
      },
    );
    await expect(transport.publish(prepared, budget)).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
    expect(
      await transport.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toEqual(prepared);
  });
});
