import { afterEach, describe, expect, it, vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { ServerConfigSchema } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  computeDataPointId,
  TOMBSTONE_DATA_HASH,
  TOMBSTONE_METADATA_HASH,
} from "@opendatalabs/personal-server-ts-core/sync";
import { AdditionsBudget } from "@opendatalabs/personal-server-ts-core/additions";
import {
  createDataFileEnvelope,
  encryptWithPassword,
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
function setup(
  fetcher: typeof fetch,
  storageAudience?: string,
  head = () =>
    ({
      expectedVersion: "2",
      dataHash: `0x${"aa".repeat(32)}`,
      metadataHash: `0x${"bb".repeat(32)}`,
      deletedAt: null as string | null,
      status: "confirmed",
    }) as {
      expectedVersion: string;
      dataHash: string;
      metadataHash: string;
      deletedAt: string | null;
      status: string;
    } | null,
) {
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
  const networkFetch: typeof fetch = async (input, init) => {
    const url = new URL(String(input));
    if (url.pathname.endsWith("/versions")) {
      const scope = url.searchParams.get("scope")!;
      return Response.json({
        data: {
          dataPointId: computeDataPointId(ownerAddress, scope),
          ownerAddress,
          scope,
          head: head(),
          versions: [],
        },
        pagination: {
          limit: Number(url.searchParams.get("limit")),
          hasMore: false,
          nextAfter: null,
        },
      });
    }
    return fetcher(input, init);
  };
  const transport = createPsLiteAdditionsTransport({
    config,
    ownerAddress,
    masterKey: new Uint8Array(32).fill(4),
    stateStore,
    ownerSigner,
    storageAudience,
    fetch: networkFetch,
  });
  return { transport, stateStore, config, ownerSigner, networkFetch };
}

describe("bounded owner checkpoint transport", () => {
  it("sends the installed SDK wire contract and retains interrupted publication across restart", async () => {
    const requests: { url: string; init: RequestInit }[] = [];
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      requests.push({ url: String(input), init: init ?? {} });
      return Response.json(
        { dataPointId: `0x${"11".repeat(32)}` },
        { status: requests.length === 2 ? 503 : 200 },
      );
    });
    const { transport, stateStore, config, ownerSigner, networkFetch } =
      setup(fetcher);
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
      fetch: networkFetch,
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

  it.each([200, 409])(
    "recovers a crash after PUT using the journaled bytes (retry status: %s)",
    async (retryStatus) => {
      const envelope = createDataFileEnvelope(
        prepared.scope,
        "2026-10-21T10:00:00.000Z",
        { version: 1, records: [] },
      );
      const plaintext = new TextEncoder().encode(JSON.stringify(envelope));
      const encrypted = await encryptWithPassword(
        plaintext,
        Array.from(
          deriveScopeKey(new Uint8Array(32).fill(4), prepared.scope),
          (byte) => byte.toString(16).padStart(2, "0"),
        ).join(""),
      );
      const candidate = {
        ...prepared,
        encrypted,
        dataHash: keccak256(plaintext),
        metadataHash: keccak256(
          stringToHex(
            JSON.stringify({
              scope: envelope.scope,
              collectedAt: envelope.collectedAt,
              sizeBytes: encrypted.byteLength,
            }),
          ),
        ),
      };
      let stored: Uint8Array | undefined;
      let crash = true;
      const puts: Uint8Array[] = [];
      const registrations: unknown[] = [];
      const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
        if (init?.method === "PUT") {
          const bytes = Uint8Array.from(init.body as Uint8Array);
          puts.push(bytes);
          if (stored)
            return new Response(retryStatus === 409 ? "BLOB_EXISTS" : "{}", {
              status: retryStatus,
            });
          stored = bytes;
          return Response.json({ dataPointId: `0x${"11".repeat(32)}` });
        }
        if (init?.method === "POST") {
          registrations.push(
            JSON.parse(new TextDecoder().decode(init.body as Uint8Array)),
          );
          if (crash) throw new Error("crash after upload");
          return Response.json({ dataPointId: `0x${"11".repeat(32)}` });
        }
        return new Response(stored);
      });
      const { transport, stateStore, config, ownerSigner, networkFetch } =
        setup(fetcher);
      await expect(
        transport.publish(candidate, new AdditionsBudget(100_000)),
      ).rejects.toThrow("crash after upload");
      crash = false;
      const restarted = createPsLiteAdditionsTransport({
        config,
        ownerAddress,
        masterKey: new Uint8Array(32).fill(4),
        stateStore,
        ownerSigner,
        fetch: networkFetch,
      });
      const pending = await restarted.readPending(
        prepared.scope,
        new AdditionsBudget(100_000),
      );
      expect(pending).toEqual(candidate);
      await expect(
        restarted.publish(pending!, new AdditionsBudget(100_000)),
      ).resolves.toBeDefined();
      expect(puts).toEqual([candidate.encrypted, candidate.encrypted]);
      expect(registrations[1]).toEqual(registrations[0]);
    },
  );

  it("uses registry head plus one instead of a stale or future local version", async () => {
    const requests: { url: string; init: RequestInit }[] = [];
    const fetcher = vi.fn<typeof fetch>(async (input, init) => {
      requests.push({ url: String(input), init: init ?? {} });
      return Response.json({ dataPointId: `0x${"11".repeat(32)}` });
    });
    const { transport } = setup(fetcher);
    for (const expectedVersion of ["1", "99"]) {
      const session = transport.openSession();
      const result = await session.publish(
        { ...prepared, expectedVersion },
        new AdditionsBudget(100_000),
      );
      expect(result.expectedVersion).toBe("3");
      expect(new URL(requests.at(-2)!.url).pathname.endsWith("/3")).toBe(true);
      expect(
        JSON.parse(
          new TextDecoder().decode(requests.at(-1)!.init.body as Uint8Array),
        ).expectedVersion,
      ).toBe("3");
      expect(
        await session.readPending(prepared.scope, new AdditionsBudget(100_000)),
      ).toEqual(prepared);
      await session.clearPending(prepared.scope, new AdditionsBudget(100_000));
    }
  });

  it.each(["2", "4"])(
    "uses only the re-read head after registration 409 (head: %s)",
    async (retryHead) => {
      const puts: string[] = [];
      let registrations = 0;
      let observations = 0;
      const fetcher = vi.fn<typeof fetch>(async (input, init) => {
        if (init?.method === "PUT")
          puts.push(new URL(String(input)).pathname.split("/").at(-1)!);
        if (init?.method === "POST" && ++registrations === 1)
          return Response.json(
            { error: "next valid version is 5" },
            { status: 409 },
          );
        return Response.json({ dataPointId: `0x${"11".repeat(32)}` });
      });
      const { transport } = setup(fetcher, undefined, () => ({
        expectedVersion: observations++ === 0 ? "2" : retryHead,
        dataHash: `0x${"aa".repeat(32)}`,
        metadataHash: `0x${"bb".repeat(32)}`,
        deletedAt: null,
        status: "confirmed",
      }));
      const publication = transport.publish(
        prepared,
        new AdditionsBudget(100_000),
      );
      if (retryHead === "2") {
        await expect(publication).rejects.toMatchObject({
          code: "NEEDS_FENCED_PUBLICATION",
          retryable: false,
        });
        expect(puts).toEqual(["3"]);
      } else {
        await expect(publication).resolves.toMatchObject({
          expectedVersion: "5",
        });
        expect(puts).toEqual(["3", "5"]);
      }
      expect(
        await transport.readPending(
          prepared.scope,
          new AdditionsBudget(100_000),
        ),
      ).toEqual({
        ...prepared,
        expectedVersion: retryHead === "2" ? "3" : "5",
      });
    },
  );

  it("blocks another writer's leftover bytes with a typed non-retryable fence error", async () => {
    const requests: string[] = [];
    const foreignBytes = new Uint8Array([9, 8, 7]);
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      requests.push(init?.method ?? "GET");
      return init?.method === "PUT"
        ? new Response("BLOB_EXISTS", { status: 409 })
        : new Response(foreignBytes);
    });
    const { transport, ownerSigner } = setup(fetcher);
    await expect(
      transport.publish(prepared, new AdditionsBudget(100_000)),
    ).rejects.toMatchObject({
      name: "NeedsFencedPublicationError",
      code: "NEEDS_FENCED_PUBLICATION",
      retryable: false,
      message: expect.stringContaining("fenced publication"),
    });
    expect(requests).toEqual(["PUT", "GET"]);
    expect(ownerSigner.signAddDataBounded).not.toHaveBeenCalled();
    expect(
      await transport.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toEqual(prepared);
  });

  it("requires the gateway fence across an observed deletion without creating a fresh journal", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const { transport, ownerSigner } = setup(fetcher, undefined, () => ({
      expectedVersion: "2",
      dataHash: TOMBSTONE_DATA_HASH,
      metadataHash: TOMBSTONE_METADATA_HASH,
      deletedAt: "2026-10-21T10:00:00.000Z",
      status: "confirmed",
    }));
    await expect(
      transport.publish(prepared, new AdditionsBudget(100_000)),
    ).rejects.toMatchObject({
      code: "NEEDS_FENCED_PUBLICATION",
      retryable: false,
      reason: "publication crosses a deletion",
    });
    expect(fetcher).not.toHaveBeenCalled();
    expect(ownerSigner.signAddDataBounded).not.toHaveBeenCalled();
    expect(
      await transport.readPending(prepared.scope, new AdditionsBudget(100_000)),
    ).toBeNull();
  });

  it.each([true, false])(
    "adopts its live registration only when both commitments match (metadata matches: %s)",
    async (matches) => {
      const methods: string[] = [];
      const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
        methods.push(init?.method ?? "GET");
        return new Response(
          init?.method === "HEAD" ? null : prepared.encrypted,
        );
      });
      const { transport, ownerSigner } = setup(fetcher, undefined, () => ({
        ...prepared,
        metadataHash: matches ? prepared.metadataHash : `0x${"ee".repeat(32)}`,
        expectedVersion: "2",
        deletedAt: null,
        status: "confirmed",
      }));
      const publication = transport.publish(
        prepared,
        new AdditionsBudget(100_000),
      );
      if (matches) {
        await expect(publication).resolves.toMatchObject({
          expectedVersion: "2",
          dataHash: prepared.dataHash,
          metadataHash: prepared.metadataHash,
        });
        expect(
          await transport.readPending(
            prepared.scope,
            new AdditionsBudget(100_000),
          ),
        ).toEqual({ ...prepared, expectedVersion: "2" });
      } else {
        await expect(publication).rejects.toThrow("commitment mismatch");
      }
      expect(methods).toEqual(["HEAD", "GET"]);
      expect(ownerSigner.signAddDataBounded).toHaveBeenCalledTimes(
        matches ? 1 : 0,
      );
    },
  );

  it.each(["dataPointId", "id"])(
    "routes preview bytes and accepts the SDK receipt field %s",
    async (receiptField) => {
      const requests: { url: string; init: RequestInit }[] = [];
      const fetcher = vi.fn<typeof fetch>(async (input, init) => {
        requests.push({ url: String(input), init: init ?? {} });
        return Response.json({ [receiptField]: `0x${"11".repeat(32)}` });
      });
      const { transport } = setup(fetcher, "https://storage.vana.org");
      await transport.publish(prepared, new AdditionsBudget(100_000));
      expect(new URL(requests[0].url).origin).toBe("https://storage.example");
      expect(
        parseWeb3SignedHeader(
          new Headers(requests[0].init.headers).get("authorization") ?? "",
        ).payload.aud,
      ).toBe("https://storage.vana.org");
    },
  );

  it("migrates an authenticated legacy numeric journal without changing its candidate", async () => {
    const fetcher = vi.fn<typeof fetch>(async () =>
      Response.json({ dataPointId: `0x${"11".repeat(32)}` }),
    );
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
    const budget = new AdditionsBudget(100_000, 100);
    let signing = 0;
    ownerSigner.signMessageBounded.mockImplementation(
      async (_message, signal?: AbortSignal) => {
        // Let the registry read finish; cancel the PUT signer after journaling.
        if (++signing === 1) return "0x1234";
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
