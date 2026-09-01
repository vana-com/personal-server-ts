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
export const DEFAULT_INFERENCE_MODEL = "z-ai/glm-5.2";
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

/**
 * What went wrong, as a value rather than as prose.
 *
 * Callers used to tell these apart by matching on `message`, because status
 * and `errorType` cannot: `emptyContent` and `malformedToolCall` both arrive
 * as a 200 with no `error` object at all. That put a retry policy downstream
 * of an error string — `agent/loop.ts` doubled its completion budget for both,
 * which is right for one and pointless for the other. The distinction is made
 * here, where the response body is in scope, and travels as data.
 */
export type InferenceErrorCode =
  /** No response at all: DNS, TLS, timeout, abort. */
  | "transport"
  /** The relay signer refused. Permanent — never retry into a storm. */
  | "relaySigningFailed"
  /** A non-2xx. `status` and `errorType` carry the detail. */
  | "httpError"
  /** 2xx whose body did not parse. */
  | "notJson"
  /** The E2EE seam failed: key fetch, encryption or decryption. */
  | "e2ee"
  /**
   * 2xx carrying no usable assistant content, cause unstated.
   *
   * A reasoning model that spent its whole allowance thinking lands here, so
   * a larger completion budget is a reasonable response.
   */
  | "emptyContent"
  /**
   * 2xx carrying no assistant content *because the provider dropped a tool
   * call it could not parse* — `finish_reason` says so.
   *
   * Distinct from `emptyContent` in the only way that matters operationally:
   * the model was not short of room, so re-asking with a larger budget cannot
   * help. See {@link TOOL_CALL_FINISH_REASON}.
   */
  | "malformedToolCall";

/**
 * `finish_reason` values meaning "the content you wanted became a tool call".
 *
 * Gemini's OpenAI-compat surface reports a dropped tool call as
 * `"function_call_filter: MALFORMED_FUNCTION_CALL"` on a 200 with no content;
 * OpenAI's own `"tool_calls"` is the same situation for us, since this client
 * never sends tools (E2EE encrypts message content per field and a tool-only
 * reply has no content to decrypt — see `query/agent/loop.ts`). Either way the
 * reply is unusable for a reason that has nothing to do with the token budget.
 */
const TOOL_CALL_FINISH_REASON =
  /malformed_function_call|malformed_tool_call|function_call_filter|^tool_calls$/i;

/** Thrown for a non-2xx or malformed provider reply. Carries no prompt text. */
export class InferenceRequestError extends Error {
  /** OpenAI-style `error.type` of the rejection, when the body had one. */
  public readonly errorType: string | null;
  /**
   * Explicit retry hint. When undefined the compute layer falls back to the
   * status: no response, 429 or 5xx are retried.
   */
  public readonly retryable: boolean | undefined;
  /** Structured discriminator; see {@link InferenceErrorCode}. */
  public readonly code: InferenceErrorCode;
  /**
   * The choice's `finish_reason`, when the reply had one.
   *
   * Kept beside `code` because it is the *evidence* for the classification and
   * a provider can invent a value this module has never seen. A diagnostic
   * that says only "malformedToolCall" cannot be checked against the wire.
   */
  public readonly finishReason: string | null;

  constructor(
    message: string,
    public readonly status: number | null,
    options: {
      errorType?: string | null;
      retryable?: boolean;
      code: InferenceErrorCode;
      finishReason?: string | null;
    },
  ) {
    super(message);
    this.name = "InferenceRequestError";
    this.errorType = options.errorType ?? null;
    this.retryable = options.retryable;
    this.code = options.code;
    this.finishReason = options.finishReason ?? null;
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

/** `choices[0].finish_reason` of a parsed body, when it carries one. */
function readFinishReason(body: unknown): string | null {
  if (!isRecord(body) || !Array.isArray(body.choices)) return null;
  const first: unknown = body.choices[0];
  if (!isRecord(first)) return null;
  return typeof first.finish_reason === "string" ? first.finish_reason : null;
}

/**
 * Why a 2xx carried no usable content: a dropped tool call, or nothing said.
 *
 * Reads the classification off `finish_reason` rather than guessing from the
 * shape of the missing content, because the two look identical on the wire —
 * both arrive as a `message` with no `content` — and only `finish_reason`
 * distinguishes them.
 */
function classifyEmptyReply(finishReason: string | null): {
  code: InferenceErrorCode;
  finishReason: string | null;
} {
  return {
    code:
      finishReason !== null && TOOL_CALL_FINISH_REASON.test(finishReason)
        ? "malformedToolCall"
        : "emptyContent",
    finishReason,
  };
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
      {
        errorType: "relay_signing_failed",
        retryable: false,
        code: "relaySigningFailed",
      },
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
        { code: "transport" },
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
          { errorType, code: "httpError" },
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
        { code: "notJson" },
      );
    }
    const choice = readContent(parsed);
    if (choice === null) {
      throw new InferenceRequestError(
        "inference response carried no assistant content",
        response.status,
        classifyEmptyReply(readFinishReason(parsed)),
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
        classifyEmptyReply(readFinishReason(parsed)),
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
