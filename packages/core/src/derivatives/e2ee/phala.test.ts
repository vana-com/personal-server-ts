import { describe, expect, it, vi } from "vitest";
import { verifyWeb3Signed } from "@opendatalabs/vana-sdk/browser";
import { createRequestSigner } from "../../signing/request-signer.js";
import { createTestWallet } from "../../test-utils/index.js";
import { createFakeE2eeGateway } from "../../test-utils/e2ee-gateway.js";
import {
  InferenceRequestError,
  createOpenAiCompatibleInferenceProvider,
} from "../inference.js";
import { createPhalaE2eeEncryption } from "./phala.js";

const BASE = "https://relay.test/v1";
const SECRET = "the owner's private notes: slept badly, argued with Bob";

describe("createPhalaE2eeEncryption", () => {
  it("sends only ciphertext and the five headers; the enclave reads the prompt; the answer decrypts", async () => {
    const gateway = await createFakeE2eeGateway({
      respond: ({ messages }) =>
        JSON.stringify({
          answer: `saw ${messages.length} messages`,
          evidence: "e",
        }),
    });
    const encryption = createPhalaE2eeEncryption({
      baseUrl: BASE,
      fetch: gateway.fetch,
    });
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption,
    });
    const result = await provider.chat({
      model: "demo-model",
      messages: [
        { role: "system", content: "You answer from the data." },
        { role: "user", content: SECRET },
      ],
    });
    expect(JSON.parse(result.content)).toEqual({
      answer: "saw 2 messages",
      evidence: "e",
    });
    expect(result.receiptId).toBe("rcpt-1");

    const wire = gateway.requests[0]!;
    const wireText = JSON.stringify(wire.body);
    expect(wireText).not.toContain(SECRET);
    expect(wireText).not.toContain("slept badly");
    expect(wireText).not.toContain("You answer");
    const messages = wire.body.messages as Array<{
      role: string;
      content: string;
    }>;
    expect(messages.map((m) => m.role)).toEqual(["system", "user"]);
    for (const message of messages) {
      expect(message.content).toMatch(/^[0-9a-f]+$/);
      expect(message.content.length).toBeGreaterThan((32 + 12 + 16) * 2);
    }
    expect(wire.body.model).toBe("demo-model");
    expect(wire.headers["x-e2ee-version"]).toBe("2");
    expect(wire.headers["x-client-pub-key"]).toMatch(/^[0-9a-f]{64}$/);
    expect(wire.headers["x-model-pub-key"]).toBe(
      gateway.keyset.e2ee_public_keys[1]!.public_key,
    );
    expect(wire.headers["x-e2ee-nonce"]).toMatch(/^[0-9a-f]{64}$/);
    expect(wire.headers["x-e2ee-timestamp"]).toMatch(/^\d{10}$/);
    expect(
      Math.abs(Number(wire.headers["x-e2ee-timestamp"]) - Date.now() / 1000),
    ).toBeLessThan(5);
    expect(wire.headers["x-signing-algo"]).toBeUndefined();
    expect(gateway.decryptedPrompts[0]).toEqual([
      "You answer from the data.",
      SECRET,
    ]);
    // The response on the wire was ciphertext too.
    expect(encryption.currentKey()?.keysetDigest).toBe(
      await gateway.keysetDigest(),
    );
  });

  it("uses a fresh nonce and client key per request and reuses the verified gateway key", async () => {
    const gateway = await createFakeE2eeGateway();
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: gateway.fetch,
      }),
    });
    const input = {
      model: "demo-model",
      messages: [{ role: "user" as const, content: "x" }],
    };
    await Promise.all([provider.chat(input), provider.chat(input)]);
    await provider.chat(input);
    expect(gateway.attestationRequests).toHaveLength(1);
    const nonces = gateway.requests.map((r) => r.headers["x-e2ee-nonce"]);
    const clientKeys = gateway.requests.map(
      (r) => r.headers["x-client-pub-key"],
    );
    expect(new Set(nonces).size).toBe(3);
    expect(new Set(clientKeys).size).toBe(3);
  });

  it("refetches the key after the TTL and when the served keyset digest changes", async () => {
    let now = 1_788_220_800_000;
    const gateway = await createFakeE2eeGateway();
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: gateway.fetch,
        clock: () => now,
        keyTtlMs: 60_000,
      }),
    });
    const input = {
      model: "demo-model",
      messages: [{ role: "user" as const, content: "x" }],
    };
    await provider.chat(input);
    now += 30_000;
    await provider.chat(input);
    expect(gateway.attestationRequests).toHaveLength(1);
    now += 31_000;
    await provider.chat(input);
    expect(gateway.attestationRequests).toHaveLength(2);
    // Rotation inside the TTL: the request encrypted to the old key is
    // rejected with e2ee_model_key_mismatch, the cache is dropped, and the
    // one re-send carries a freshly verified key.
    await gateway.rotateKey();
    await provider.chat(input);
    expect(gateway.attestationRequests).toHaveLength(3);
    expect(gateway.requests.at(-1)!.headers["x-model-pub-key"]).toBe(
      gateway.keyset.e2ee_public_keys[1]!.public_key,
    );
  });

  it("re-encrypts once on e2ee_model_key_mismatch, then surfaces the status", async () => {
    const gateway = await createFakeE2eeGateway();
    const warn = vi.fn();
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: gateway.fetch,
        logger: { warn },
      }),
    });
    const input = {
      model: "demo-model",
      messages: [{ role: "user" as const, content: "x" }],
    };
    gateway.failNext(1, 400, "e2ee_model_key_mismatch");
    await expect(provider.chat(input)).resolves.toMatchObject({
      receiptId: "rcpt-1",
    });
    expect(gateway.requests).toHaveLength(2);
    expect(gateway.attestationRequests).toHaveLength(2);
    expect(gateway.requests[0]!.headers["x-e2ee-nonce"]).not.toBe(
      gateway.requests[1]!.headers["x-e2ee-nonce"],
    );
    gateway.failNext(2, 400, "e2ee_model_key_mismatch");
    await expect(provider.chat(input)).rejects.toMatchObject({
      name: "InferenceRequestError",
      status: 400,
      errorType: "e2ee_model_key_mismatch",
    });
    expect(gateway.requests).toHaveLength(4);
    // Other rejections are not retried.
    gateway.failNext(1, 400, "e2ee_replay_detected");
    await expect(provider.chat(input)).rejects.toMatchObject({
      status: 400,
      errorType: "e2ee_replay_detected",
    });
    expect(gateway.requests).toHaveLength(5);
  });

  it("fails closed without a verified key: no request leaves", async () => {
    const gateway = await createFakeE2eeGateway({ supportedE2eeVersions: [] });
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: gateway.fetch,
      }),
    });
    await expect(
      provider.chat({
        model: "demo-model",
        messages: [{ role: "user", content: SECRET }],
      }),
    ).rejects.toMatchObject({
      name: "InferenceRequestError",
      status: null,
      retryable: false,
      errorType: "e2ee_attestation_e2ee_unsupported",
    });
    expect(gateway.requests).toHaveLength(0);

    const offline = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: (async () => {
          throw new TypeError("fetch failed");
        }) as unknown as typeof fetch,
      }),
    });
    await expect(
      offline.chat({
        model: "demo-model",
        messages: [{ role: "user", content: SECRET }],
      }),
    ).rejects.toMatchObject({ status: null, retryable: true });
    expect(gateway.requests).toHaveLength(0);
  });

  it("refuses a plaintext or tampered reply instead of using it, without quoting it", async () => {
    const gateway = await createFakeE2eeGateway({
      respond: () =>
        JSON.stringify({ answer: "PLAINTEXT ANSWER", evidence: null }),
    });
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: gateway.fetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: gateway.fetch,
      }),
    });
    const input = {
      model: "demo-model",
      messages: [{ role: "user" as const, content: "x" }],
    };
    gateway.plaintextNext();
    const failure = await provider.chat(input).catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(InferenceRequestError);
    expect((failure as InferenceRequestError).errorType).toBe(
      "e2ee_decryption_failed",
    );
    expect((failure as InferenceRequestError).retryable).toBe(false);
    expect((failure as Error).message).not.toContain("PLAINTEXT");
    expect((failure as Error).message).toContain("choices.0.message.content");

    // A relay that swaps the response id breaks the response AAD.
    const swapping = (async (
      input: string | URL | Request,
      init?: RequestInit,
    ) => {
      const response = await gateway.fetch(input, init);
      if (!String(input).endsWith("/chat/completions")) return response;
      const body = (await response.json()) as Record<string, unknown>;
      return new Response(JSON.stringify({ ...body, id: "chatcmpl-other" }), {
        status: 200,
        headers: response.headers,
      });
    }) as unknown as typeof fetch;
    const viaSwappingRelay = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      fetch: swapping,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        fetch: gateway.fetch,
      }),
    });
    await expect(viaSwappingRelay.chat(input)).rejects.toMatchObject({
      errorType: "e2ee_decryption_failed",
    });
  });

  it("requires a request model (it is bound into every AAD)", async () => {
    const gateway = await createFakeE2eeGateway();
    const encryption = createPhalaE2eeEncryption({
      baseUrl: BASE,
      fetch: gateway.fetch,
    });
    await expect(
      encryption.encryptRequest({
        model: "",
        messages: [],
        headers: new Headers(),
      }),
    ).rejects.toMatchObject({ errorType: "e2ee_invalid_payload_model" });
  });
});

describe("createPhalaE2eeEncryption behind the Vana relay", () => {
  it("signs both the attested-key fetch and the encrypted completion as the server", async () => {
    const wallet = createTestWallet(12);
    const requestSigner = createRequestSigner({
      address: wallet.address,
      publicKey: "0x04" as `0x${string}`,
      signTypedData: vi.fn(),
      signMessage: (message: string) => wallet.signMessage(message),
    });
    const gateway = await createFakeE2eeGateway();
    const sent: Array<{
      url: string;
      authorization: string | undefined;
      body: string | null;
    }> = [];
    const recordingFetch = (async (
      input: string | URL | Request,
      init?: RequestInit,
    ) => {
      sent.push({
        url: String(input),
        authorization:
          new Headers(init?.headers).get("authorization") ?? undefined,
        body: typeof init?.body === "string" ? init.body : null,
      });
      return gateway.fetch(input, init);
    }) as unknown as typeof fetch;
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: BASE,
      requestSigner,
      fetch: recordingFetch,
      encryption: createPhalaE2eeEncryption({
        baseUrl: BASE,
        requestSigner,
        fetch: recordingFetch,
      }),
    });
    const result = await provider.chat({
      model: "demo-model",
      messages: [{ role: "user", content: SECRET }],
    });
    expect(JSON.parse(result.content)).toMatchObject({ answer: "fake answer" });

    const attestation = sent.find((call) => call.url.includes("/aci/"))!;
    const completion = sent.find((call) =>
      call.url.endsWith("/chat/completions"),
    )!;
    const attestationUrl = new URL(attestation.url);
    // Both calls carry a header the relay verifies as this server.
    await expect(
      verifyWeb3Signed({
        headerValue: attestation.authorization,
        expectedOrigin: "https://relay.test",
        expectedMethod: "GET",
        expectedPath: `${attestationUrl.pathname}${attestationUrl.search}`,
      }),
    ).resolves.toMatchObject({ signer: wallet.address });
    // The signed bodyHash covers the ciphertext, never the prompt.
    expect(completion.body).not.toContain(SECRET);
    await expect(
      verifyWeb3Signed({
        headerValue: completion.authorization,
        expectedOrigin: "https://relay.test",
        expectedMethod: "POST",
        expectedPath: "/v1/chat/completions",
        bodyBytes: new TextEncoder().encode(completion.body!),
      }),
    ).resolves.toMatchObject({ signer: wallet.address });
  });
});
