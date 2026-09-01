/**
 * Inference provider adapter for the derivative compute layer.
 *
 * One implementation: OpenAI-compatible chat completions over `fetch`, so it
 * runs unchanged in Node and in the browser (PS-Lite). In production the
 * base URL is the Vana inference relay, which holds the provider key; the
 * optional API key header exists for local development against a provider
 * directly.
 *
 * RELAY AUTH: the Vana inference relay
 * (`POST /v1/inference/chat/completions` on the data gateway) only forwards
 * a request that is signed by the owner or by one of the owner's ACTIVE
 * registered servers, with the same Web3Signed scheme the lineage read uses
 * (`RequestSigner`, see ../signing/request-signer.ts). Pass `requestSigner`
 * and every relay call carries `Authorization: Web3Signed ...` over the
 * exact bytes that go on the wire. `apiKey` is the local-development
 * alternative (direct provider, `Authorization: Bearer`) and wins when both
 * are set: a bearer key means "not the relay".
 *
 * E2EE SEAM: the Phala confidential-inference E2EE v2 protocol encrypts each
 * `messages[i].content` to the gateway's attested public key and adds the
 * headers X-E2EE-Version, X-Client-Pub-Key, X-Model-Pub-Key, X-E2EE-Nonce
 * and X-E2EE-Timestamp; the response content comes back encrypted to the
 * client key. `InferenceRequestEncryption` below is the hook, implemented
 * by `createPhalaE2eeEncryption` in ./e2ee. This module only knows the
 * shape: encrypt the outgoing messages, decrypt the one response field.
 */

import type { RequestSigner } from "../signing/request-signer.js";

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
 * One encrypted request: the messages to send and the decryptor bound to
 * that request's context (nonce, timestamp, client key), since the response
 * AAD is built from them.
 */
export interface EncryptedInferenceRequest {
  messages: InferenceMessage[];
  /**
   * Decrypt one response field. `field` is the spec field path
   * (`choices.{i}.message.content`), `id` the clear response `id` or "".
   */
  decryptResponse(input: {
    content: string;
    field: string;
    id: string;
    headers: Headers;
  }): Promise<string>;
}

/**
 * E2EE seam. Implement to encrypt message contents end to end (Phala E2EE
 * v2); absent = plaintext over TLS to the relay. Runs inside
 * `createOpenAiCompatibleInferenceProvider`, around the single fetch.
 */
export interface InferenceRequestEncryption {
  /** Encrypt `messages[i].content` and add the X-E2EE-* request headers. */
  encryptRequest(input: {
    model: string;
    messages: InferenceMessage[];
    headers: Headers;
  }): Promise<EncryptedInferenceRequest>;
  /**
   * Called once when the provider rejects the request (non-2xx) with the
   * OpenAI-style `error.type` when the body carries one. Return true to
   * re-encrypt and resend once (e.g. after `e2ee_model_key_mismatch`).
   */
  onRejected?(input: {
    status: number;
    errorType: string | null;
    headers: Headers;
  }): Promise<boolean>;
}

export const DEFAULT_INFERENCE_BASE_URL = "https://inference.phala.com/v1";
export const DEFAULT_INFERENCE_MODEL = "z-ai/glm-5.3-flash";
export const DEFAULT_INFERENCE_TIMEOUT_MS = 120_000;
export const DEFAULT_INFERENCE_MAX_TOKENS = 2_048;

export interface OpenAiCompatibleInferenceOptions {
  /** Chat completions base, e.g. `https://inference.phala.com/v1`. */
  baseUrl?: string;
  /** Local development only; production relays hold the key. */
  apiKey?: string;
  /**
   * Signs every request to the Vana inference relay as this personal server
   * (the same signer the lineage client uses). Ignored when `apiKey` is set,
   * which means the base URL is a provider, not the relay.
   */
  requestSigner?: RequestSigner;
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
  /** OpenAI-style `error.type` of the rejection, when the body had one. */
  public readonly errorType: string | null;
  /**
   * Explicit retry hint. When undefined the compute layer falls back to the
   * status: no response, 429 or 5xx are retried.
   */
  public readonly retryable: boolean | undefined;

  constructor(
    message: string,
    public readonly status: number | null,
    options: { errorType?: string | null; retryable?: boolean } = {},
  ) {
    super(message);
    this.name = "InferenceRequestError";
    this.errorType = options.errorType ?? null;
    this.retryable = options.retryable;
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

interface ReadChoice {
  content: string;
  /**
   * E2EE field path of the content (spec section 5): the choice's `index`
   * member when present, its array position otherwise.
   */
  field: string;
  /** Clear response `id`, "" when absent (bound into the response AAD). */
  id: string;
}

function readContent(body: unknown): ReadChoice | null {
  if (!isRecord(body) || !Array.isArray(body.choices)) return null;
  const first: unknown = body.choices[0];
  if (!isRecord(first) || !isRecord(first.message)) return null;
  const index = typeof first.index === "number" ? first.index : 0;
  const field = `choices.${index}.message.content`;
  const id = typeof body.id === "string" ? body.id : "";
  const content = first.message.content;
  if (typeof content === "string") return { content, field, id };
  // Some providers return content parts.
  if (Array.isArray(content)) {
    const text = content
      .map((part) =>
        isRecord(part) && typeof part.text === "string" ? part.text : "",
      )
      .join("");
    return { content: text, field, id };
  }
  return null;
}

/** OpenAI-style `{ error: { type } }` of a rejection; never its message. */
async function readErrorType(response: Response): Promise<string | null> {
  try {
    const body: unknown = await response.json();
    if (isRecord(body) && isRecord(body.error)) {
      return typeof body.error.type === "string" ? body.error.type : null;
    }
  } catch {
    // Not JSON: no type to report.
  }
  return null;
}

/**
 * Sign one relay request. A signer that cannot sign (locked key, wallet
 * gone) is a permanent failure: the request is never sent unsigned, and the
 * compute layer must not retry it into a storm.
 */
async function signOrThrow(
  signer: RequestSigner,
  params: { aud: string; method: string; uri: string; body?: Uint8Array },
): Promise<string> {
  try {
    return await signer.signRequest(params);
  } catch (err) {
    const name = err instanceof Error ? err.name : "Error";
    throw new InferenceRequestError(
      `inference request could not be signed (${name})`,
      null,
      { errorType: "relay_signing_failed", retryable: false },
    );
  }
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

  const encryption = options.encryption;
  // A bearer key means the base URL is a provider, not the relay: the relay
  // never takes one, so the key wins and no signature is produced.
  const requestSigner = options.apiKey ? undefined : options.requestSigner;
  const chatUrl = new URL(`${base}/chat/completions`);

  /** One send; `rejected` reports a non-2xx so the caller may retry once. */
  async function send(
    input: InferenceChatInput,
  ): Promise<
    | { ok: true; result: InferenceChatResult }
    | { ok: false; error: InferenceRequestError; retry: boolean }
  > {
    const headers = new Headers({ "Content-Type": "application/json" });
    if (options.apiKey) {
      headers.set("Authorization", `Bearer ${options.apiKey}`);
    }
    const model = input.model || defaultModel;
    let messages = input.messages;
    let encrypted: EncryptedInferenceRequest | null = null;
    if (encryption) {
      encrypted = await encryption.encryptRequest({
        model,
        messages,
        headers,
      });
      messages = encrypted.messages;
    }
    const body = {
      ...requestFields,
      model,
      messages,
      max_tokens: input.maxTokens ?? DEFAULT_INFERENCE_MAX_TOKENS,
    };
    // Serialized ONCE, after encryption: the bytes that are hashed into the
    // signature are the bytes that go on the wire (ciphertext included).
    const payload = JSON.stringify(body);
    if (requestSigner) {
      headers.set(
        "Authorization",
        await signOrThrow(requestSigner, {
          aud: chatUrl.origin,
          method: "POST",
          uri: `${chatUrl.pathname}${chatUrl.search}`,
          body: new TextEncoder().encode(payload),
        }),
      );
    }
    let response: Response;
    try {
      response = await doFetch(chatUrl.toString(), {
        method: "POST",
        headers,
        body: payload,
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
      const errorType = await readErrorType(response);
      const retry =
        (await encryption?.onRejected?.({
          status: response.status,
          errorType,
          headers: response.headers,
        })) === true;
      return {
        ok: false,
        retry,
        error: new InferenceRequestError(
          `inference request failed with status ${response.status}${
            errorType ? ` (${errorType})` : ""
          }`,
          response.status,
          { errorType },
        ),
      };
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
    const choice = readContent(parsed);
    if (choice === null) {
      throw new InferenceRequestError(
        "inference response carried no assistant content",
        response.status,
      );
    }
    let content = choice.content;
    if (encrypted) {
      // Fail closed: a reply that is not valid ciphertext for this request
      // is an error, never used as plaintext.
      content = await encrypted.decryptResponse({
        content,
        field: choice.field,
        id: choice.id,
        headers: response.headers,
      });
    }
    if (content.trim() === "") {
      // An empty reply must never become a "ready" derivative.
      throw new InferenceRequestError(
        "inference response carried no assistant content",
        response.status,
      );
    }
    const receiptId = response.headers.get("x-receipt-id") ?? undefined;
    const aciIdentity = response.headers.get("x-aci-identity") ?? undefined;
    return {
      ok: true,
      result: {
        content,
        usage: readUsage(isRecord(parsed) ? parsed.usage : undefined),
        ...(receiptId ? { receiptId } : {}),
        ...(aciIdentity ? { aciIdentity } : {}),
      },
    };
  }

  return {
    defaultModel,
    async chat(input) {
      const first = await send(input);
      if (first.ok) return first.result;
      if (!first.retry) throw first.error;
      // The encryption asked for one re-send (fresh key, fresh nonce).
      const second = await send(input);
      if (second.ok) return second.result;
      throw second.error;
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
