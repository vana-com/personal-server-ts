/**
 * Inference provider adapter for the derivative compute layer.
 *
 * One implementation: OpenAI-compatible chat completions over `fetch`, so it
 * runs unchanged in Node and in the browser (PS-Lite). In production the
 * base URL is the Vana inference relay, which holds the provider key; the
 * optional API key header exists for local development against a provider
 * directly.
 *
 * E2EE SEAM (not implemented): the Phala confidential-inference E2EE v2
 * protocol encrypts each `messages[i].content` to the model's public key
 * and adds the headers X-E2EE-Version, X-Client-Pub-Key, X-Model-Pub-Key,
 * X-E2EE-Nonce and X-E2EE-Timestamp; the response content comes back
 * encrypted to the client key. `InferenceRequestEncryption` below is the
 * hook where that lands: it sees the outgoing messages + headers and the
 * incoming content + headers, and nothing else in this module has to change.
 */

export type InferenceRole = "system" | "user" | "assistant";

export interface InferenceMessage {
  role: InferenceRole;
  content: string;
}

export interface InferenceChatInput {
  model: string;
  messages: InferenceMessage[];
  maxTokens?: number;
}

export interface InferenceUsage {
  promptTokens?: number;
  completionTokens?: number;
  totalTokens?: number;
}

export interface InferenceChatResult {
  content: string;
  usage?: InferenceUsage;
  /** `x-receipt-id` response header when the relay / provider sets one. */
  receiptId?: string;
  /** `x-aci-identity` response header (attested compute identity). */
  aciIdentity?: string;
}

export interface InferenceProvider {
  /** Model used when a registration names none. */
  readonly defaultModel: string;
  chat(input: InferenceChatInput): Promise<InferenceChatResult>;
}

/**
 * E2EE seam. Implement to encrypt message contents end to end (Phala E2EE
 * v2); absent = plaintext over TLS to the relay. Both hooks run inside
 * `createOpenAiCompatibleInferenceProvider`, around the single fetch.
 */
export interface InferenceRequestEncryption {
  /** Encrypt `messages[i].content` and add the X-E2EE-* request headers. */
  encryptRequest(input: {
    messages: InferenceMessage[];
    headers: Headers;
  }): Promise<{ messages: InferenceMessage[] }>;
  /** Decrypt the assistant content using the response headers. */
  decryptResponse(input: {
    content: string;
    headers: Headers;
  }): Promise<string>;
}

export const DEFAULT_INFERENCE_BASE_URL = "https://inference.phala.com/v1";
export const DEFAULT_INFERENCE_MODEL = "z-ai/glm-5.2";
export const DEFAULT_INFERENCE_TIMEOUT_MS = 120_000;
export const DEFAULT_INFERENCE_MAX_TOKENS = 2_048;

export interface OpenAiCompatibleInferenceOptions {
  /** Chat completions base, e.g. `https://inference.phala.com/v1`. */
  baseUrl?: string;
  /** Local development only; production relays hold the key. */
  apiKey?: string;
  model?: string;
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** E2EE seam; see the module comment. */
  encryption?: InferenceRequestEncryption;
  /**
   * Extra body fields sent with every request. Defaults to the Vana / Phala
   * routing hint `{ provider: { aci_verified: true, zdr: true } }`.
   */
  requestFields?: Record<string, unknown>;
}

export const DEFAULT_INFERENCE_REQUEST_FIELDS: Record<string, unknown> = {
  provider: { aci_verified: true, zdr: true },
};

/** Thrown for a non-2xx or malformed provider reply. Carries no prompt text. */
export class InferenceRequestError extends Error {
  constructor(
    message: string,
    public readonly status: number | null,
  ) {
    super(message);
    this.name = "InferenceRequestError";
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readUsage(value: unknown): InferenceUsage | undefined {
  if (!isRecord(value)) return undefined;
  const num = (v: unknown) => (typeof v === "number" ? v : undefined);
  const usage: InferenceUsage = {
    promptTokens: num(value.prompt_tokens),
    completionTokens: num(value.completion_tokens),
    totalTokens: num(value.total_tokens),
  };
  return usage;
}

function readContent(body: unknown): string | null {
  if (!isRecord(body) || !Array.isArray(body.choices)) return null;
  const first: unknown = body.choices[0];
  if (!isRecord(first) || !isRecord(first.message)) return null;
  const content = first.message.content;
  if (typeof content === "string") return content;
  // Some providers return content parts.
  if (Array.isArray(content)) {
    const text = content
      .map((part) =>
        isRecord(part) && typeof part.text === "string" ? part.text : "",
      )
      .join("");
    return text;
  }
  return null;
}

export function createOpenAiCompatibleInferenceProvider(
  options: OpenAiCompatibleInferenceOptions = {},
): InferenceProvider {
  const base = (options.baseUrl ?? DEFAULT_INFERENCE_BASE_URL).replace(
    /\/+$/,
    "",
  );
  const defaultModel = options.model ?? DEFAULT_INFERENCE_MODEL;
  const timeoutMs = options.timeoutMs ?? DEFAULT_INFERENCE_TIMEOUT_MS;
  const doFetch = options.fetch ?? fetch;
  const requestFields =
    options.requestFields ?? DEFAULT_INFERENCE_REQUEST_FIELDS;

  return {
    defaultModel,
    async chat(input) {
      const headers = new Headers({ "Content-Type": "application/json" });
      if (options.apiKey) {
        headers.set("Authorization", `Bearer ${options.apiKey}`);
      }
      let messages = input.messages;
      if (options.encryption) {
        ({ messages } = await options.encryption.encryptRequest({
          messages,
          headers,
        }));
      }
      const body = {
        ...requestFields,
        model: input.model || defaultModel,
        messages,
        max_tokens: input.maxTokens ?? DEFAULT_INFERENCE_MAX_TOKENS,
      };
      let response: Response;
      try {
        response = await doFetch(`${base}/chat/completions`, {
          method: "POST",
          headers,
          body: JSON.stringify(body),
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        // Transport failure: no status, no body. The message is the error
        // class name only; it never carries request contents.
        const name = err instanceof Error ? err.name : "Error";
        throw new InferenceRequestError(
          `inference request failed before a response (${name})`,
          null,
        );
      }
      if (!response.ok) {
        throw new InferenceRequestError(
          `inference request failed with status ${response.status}`,
          response.status,
        );
      }
      let parsed: unknown;
      try {
        parsed = await response.json();
      } catch {
        throw new InferenceRequestError(
          "inference response was not JSON",
          response.status,
        );
      }
      let content = readContent(parsed);
      if (content === null) {
        throw new InferenceRequestError(
          "inference response carried no assistant content",
          response.status,
        );
      }
      if (options.encryption) {
        content = await options.encryption.decryptResponse({
          content,
          headers: response.headers,
        });
      }
      const receiptId = response.headers.get("x-receipt-id") ?? undefined;
      const aciIdentity = response.headers.get("x-aci-identity") ?? undefined;
      return {
        content,
        usage: readUsage(isRecord(parsed) ? parsed.usage : undefined),
        ...(receiptId ? { receiptId } : {}),
        ...(aciIdentity ? { aciIdentity } : {}),
      };
    },
  };
}

export interface FakeInferenceProviderOptions {
  model?: string;
  /** Answer per call; a function sees the input and may throw. */
  respond?: (
    input: InferenceChatInput,
    callIndex: number,
  ) => InferenceChatResult | Promise<InferenceChatResult>;
}

export interface FakeInferenceProvider extends InferenceProvider {
  readonly calls: InferenceChatInput[];
}

/** Test double: records calls, answers with a fixed JSON object by default. */
export function createFakeInferenceProvider(
  options: FakeInferenceProviderOptions = {},
): FakeInferenceProvider {
  const calls: InferenceChatInput[] = [];
  return {
    defaultModel: options.model ?? "fake-model",
    calls,
    async chat(input) {
      calls.push(input);
      if (options.respond) return options.respond(input, calls.length - 1);
      return {
        content: JSON.stringify({
          answer: "fake answer",
          evidence: "fake evidence",
        }),
        receiptId: "fake-receipt",
      };
    },
  };
}
