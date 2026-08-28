import { describe, expect, it, vi } from "vitest";
import {
  createFakeInferenceProvider,
  createOpenAiCompatibleInferenceProvider,
  type InferenceRequestEncryption,
} from "./inference.js";

function fetchReplying(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
) {
  return vi.fn(
    async () =>
      new Response(JSON.stringify(body), {
        status: init.status ?? 200,
        headers: { "Content-Type": "application/json", ...init.headers },
      }),
  );
}

const completion = {
  choices: [{ message: { role: "assistant", content: '{"answer":"hi"}' } }],
  usage: { prompt_tokens: 10, completion_tokens: 5, total_tokens: 15 },
};

describe("createOpenAiCompatibleInferenceProvider", () => {
  it("posts an OpenAI chat completion with the Vana routing hint and passes receipts through", async () => {
    const fetchMock = fetchReplying(completion, {
      headers: { "x-receipt-id": "rcpt-1", "x-aci-identity": "aci-1" },
    });
    const provider = createOpenAiCompatibleInferenceProvider({
      baseUrl: "https://relay.example/v1/",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await provider.chat({
      model: "z-ai/glm-5.2",
      messages: [{ role: "user", content: "hello" }],
      maxTokens: 100,
    });
    expect(result).toEqual({
      content: '{"answer":"hi"}',
      usage: { promptTokens: 10, completionTokens: 5, totalTokens: 15 },
      receiptId: "rcpt-1",
      aciIdentity: "aci-1",
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("https://relay.example/v1/chat/completions");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({
      provider: { aci_verified: true, zdr: true },
      model: "z-ai/glm-5.2",
      messages: [{ role: "user", content: "hello" }],
      max_tokens: 100,
    });
    // No key configured: no Authorization header leaves the server.
    expect((init.headers as Headers).get("authorization")).toBeNull();
  });

  it("sends the API key only when configured and defaults the model", async () => {
    const fetchMock = fetchReplying(completion);
    const provider = createOpenAiCompatibleInferenceProvider({
      apiKey: "sk-local",
      model: "my-model",
      fetch: fetchMock as unknown as typeof fetch,
    });
    expect(provider.defaultModel).toBe("my-model");
    await provider.chat({ model: "", messages: [] });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(url).toBe("https://inference.phala.com/v1/chat/completions");
    expect((init.headers as Headers).get("authorization")).toBe(
      "Bearer sk-local",
    );
    expect(JSON.parse(init.body as string).model).toBe("my-model");
  });

  it("fails with the status only on a non-2xx reply (never the body)", async () => {
    const fetchMock = fetchReplying(
      { error: "secret detail that must not leak" },
      { status: 502 },
    );
    const provider = createOpenAiCompatibleInferenceProvider({
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(
      provider.chat({ model: "m", messages: [] }),
    ).rejects.toMatchObject({
      name: "InferenceRequestError",
      status: 502,
      message: "inference request failed with status 502",
    });
  });

  it("fails on a reply without assistant content, empty content included", async () => {
    for (const body of [
      { choices: [] },
      { choices: [{ message: { content: "" } }] },
      { choices: [{ message: { content: "   \n" } }] },
    ]) {
      const provider = createOpenAiCompatibleInferenceProvider({
        fetch: fetchReplying(body) as unknown as typeof fetch,
      });
      await expect(
        provider.chat({ model: "m", messages: [] }),
      ).rejects.toMatchObject({
        name: "InferenceRequestError",
        message: "inference response carried no assistant content",
      });
    }
  });

  it("runs the E2EE seam around the request when one is supplied", async () => {
    const fetchMock = fetchReplying(
      { choices: [{ message: { content: "ENC(reply)" } }] },
      { headers: { "x-e2ee-version": "2" } },
    );
    const encryption: InferenceRequestEncryption = {
      async encryptRequest({ messages, headers }) {
        headers.set("X-E2EE-Version", "2");
        return {
          messages: messages.map((m) => ({
            ...m,
            content: `ENC(${m.content})`,
          })),
        };
      },
      async decryptResponse({ content, headers }) {
        expect(headers.get("x-e2ee-version")).toBe("2");
        return content.replace(/^ENC\((.*)\)$/, "$1");
      },
    };
    const provider = createOpenAiCompatibleInferenceProvider({
      fetch: fetchMock as unknown as typeof fetch,
      encryption,
    });
    const result = await provider.chat({
      model: "m",
      messages: [{ role: "user", content: "hello" }],
    });
    expect(result.content).toBe("reply");
    const [, init] = fetchMock.mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect((init.headers as Headers).get("x-e2ee-version")).toBe("2");
    expect(JSON.parse(init.body as string).messages).toEqual([
      { role: "user", content: "ENC(hello)" },
    ]);
  });
});

describe("createFakeInferenceProvider", () => {
  it("records calls and answers with a JSON object", async () => {
    const provider = createFakeInferenceProvider();
    const result = await provider.chat({ model: "m", messages: [] });
    expect(JSON.parse(result.content)).toEqual({
      answer: "fake answer",
      evidence: "fake evidence",
    });
    expect(provider.calls).toHaveLength(1);
  });
});
