/**
 * `InferenceRequestEncryption` for the Phala confidential-inference gateway
 * (E2EE v2, X25519 suite). Per request:
 *
 *   1. get the gateway's attested E2EE key (cached for a short TTL, shared
 *      across concurrent computes, re-fetched on `e2ee_model_key_mismatch`
 *      or when the served `X-ACI-Keyset-Digest` no longer matches the pin)
 *   2. generate a fresh client X25519 key pair, a 32-byte nonce and the
 *      Unix-seconds timestamp; set the five X-E2EE-* request headers
 *   3. encrypt every `messages.{m}.content` to the gateway key under the
 *      request AAD
 *   4. hand back a decryptor bound to that request context: the response
 *      field (`choices.{i}.message.content`) is encrypted to the client key
 *      under the response AAD, which also binds the clear response `id`
 *
 * Fail closed: no verified key means no request; a response field that is
 * not valid ciphertext for this request is an error, never accepted as
 * plaintext. Error messages carry no prompt or answer text.
 */

import {
  InferenceRequestError,
  type EncryptedInferenceRequest,
  type InferenceMessage,
  type InferenceRequestEncryption,
} from "../inference.js";
import { requestFieldAad, responseFieldAad } from "./aad.js";
import {
  E2eeAttestationError,
  fetchGatewayE2eeKey,
  type AciAttestationReport,
  type GatewayE2eeKey,
} from "./attestation.js";
import {
  E2eeCipherError,
  bytesToHex,
  decryptField,
  encryptField,
  generateX25519KeyPair,
  randomBytes,
} from "./suite.js";

export const E2EE_HEADER_VERSION = "X-E2EE-Version";
export const E2EE_HEADER_CLIENT_PUB_KEY = "X-Client-Pub-Key";
export const E2EE_HEADER_MODEL_PUB_KEY = "X-Model-Pub-Key";
export const E2EE_HEADER_NONCE = "X-E2EE-Nonce";
export const E2EE_HEADER_TIMESTAMP = "X-E2EE-Timestamp";
export const ACI_HEADER_KEYSET_DIGEST = "X-ACI-Keyset-Digest";

export const DEFAULT_E2EE_KEY_TTL_MS = 5 * 60_000;

export interface PhalaE2eeEncryptionOptions {
  /** Chat completions base; the attestation report is fetched through it. */
  baseUrl: string;
  fetch?: typeof fetch;
  /** Milliseconds since epoch (default Date.now). */
  clock?: () => number;
  /** How long a verified key is reused before a fresh report is fetched. */
  keyTtlMs?: number;
  /** Require this keyset `key_id` (default: select by algo only). */
  expectedKeyId?: string;
  /** Hardware evidence verification hook; see attestation.ts. */
  verifyEvidence?: (report: AciAttestationReport) => Promise<void>;
  /** Fallback origin for the attestation route; `null` disables it. */
  fallbackAttestationBaseUrl?: string | null;
  logger?: {
    info?(payload: Record<string, unknown>, message: string): void;
    warn?(payload: Record<string, unknown>, message: string): void;
  };
}

export interface PhalaE2eeEncryption extends InferenceRequestEncryption {
  /** Drop the cached key; the next request fetches a fresh report. */
  invalidateKey(): void;
  /** The verified key currently in use, if any (diagnostics). */
  currentKey(): GatewayE2eeKey | null;
}

function keyFetchError(err: unknown): InferenceRequestError {
  if (err instanceof E2eeAttestationError) {
    return new InferenceRequestError(
      `e2ee key fetch failed (${err.code}): ${err.message}`,
      null,
      {
        errorType: `e2ee_attestation_${err.code}`,
        retryable: err.code === "fetch_failed",
      },
    );
  }
  const name = err instanceof Error ? err.name : "Error";
  return new InferenceRequestError(`e2ee key fetch failed (${name})`, null, {
    retryable: false,
  });
}

export function createPhalaE2eeEncryption(
  options: PhalaE2eeEncryptionOptions,
): PhalaE2eeEncryption {
  const clock = options.clock ?? Date.now;
  const ttlMs = options.keyTtlMs ?? DEFAULT_E2EE_KEY_TTL_MS;
  let cached: { key: GatewayE2eeKey; fetchedAt: number } | null = null;
  let inFlight: Promise<GatewayE2eeKey> | null = null;

  const fetchKey = async (): Promise<GatewayE2eeKey> => {
    const key = await fetchGatewayE2eeKey({
      baseUrl: options.baseUrl,
      fetch: options.fetch,
      clock,
      expectedKeyId: options.expectedKeyId,
      verifyEvidence: options.verifyEvidence,
      fallbackBaseUrl: options.fallbackAttestationBaseUrl,
    });
    options.logger?.info?.(
      {
        keyId: key.keyId,
        algo: key.algo,
        keysetDigest: key.keysetDigest,
        notAfter: key.notAfter,
        source: key.source,
        evidenceVerified: Boolean(options.verifyEvidence),
      },
      "E2EE gateway key verified",
    );
    return key;
  };

  const getKey = async (): Promise<GatewayE2eeKey> => {
    const now = clock();
    if (
      cached &&
      now - cached.fetchedAt < ttlMs &&
      Math.floor(now / 1000) < cached.key.notAfter
    ) {
      return cached.key;
    }
    if (!inFlight) {
      inFlight = fetchKey()
        .then((key) => {
          cached = { key, fetchedAt: clock() };
          return key;
        })
        .finally(() => {
          inFlight = null;
        });
    }
    try {
      return await inFlight;
    } catch (err) {
      throw keyFetchError(err);
    }
  };

  const invalidateKey = () => {
    cached = null;
  };

  return {
    invalidateKey,
    currentKey: () => cached?.key ?? null,

    async encryptRequest({ model, messages, headers }) {
      if (typeof model !== "string" || model === "") {
        // The AAD binds the model; the gateway rejects a missing one anyway.
        throw new InferenceRequestError(
          "e2ee requires a non-empty request model",
          null,
          { errorType: "e2ee_invalid_payload_model", retryable: false },
        );
      }
      const gatewayKey = await getKey();
      const client = await generateX25519KeyPair();
      const context = {
        algo: gatewayKey.algo,
        model,
        nonce: bytesToHex(randomBytes(32)),
        ts: Math.floor(clock() / 1000),
      };
      headers.set(E2EE_HEADER_VERSION, "2");
      headers.set(E2EE_HEADER_CLIENT_PUB_KEY, bytesToHex(client.publicKey));
      headers.set(E2EE_HEADER_MODEL_PUB_KEY, gatewayKey.publicKeyHex);
      headers.set(E2EE_HEADER_NONCE, context.nonce);
      headers.set(E2EE_HEADER_TIMESTAMP, String(context.ts));

      const encrypted: InferenceMessage[] = [];
      for (let index = 0; index < messages.length; index += 1) {
        const message = messages[index]!;
        let content: string;
        try {
          content = await encryptField({
            plaintext: message.content,
            recipientPublicKey: gatewayKey.publicKey,
            aad: requestFieldAad(context, `messages.${index}.content`),
          });
        } catch (err) {
          const name = err instanceof Error ? err.name : "Error";
          throw new InferenceRequestError(
            `e2ee request encryption failed (${name})`,
            null,
            { retryable: false },
          );
        }
        encrypted.push({ ...message, content });
      }

      const request: EncryptedInferenceRequest = {
        messages: encrypted,
        async decryptResponse({ content, field, id, headers: response }) {
          const served = response.get(ACI_HEADER_KEYSET_DIGEST);
          if (served && served !== gatewayKey.keysetDigest) {
            // The gateway rotated its keyset: re-verify before the next
            // request. This reply was still encrypted for our client key.
            options.logger?.warn?.(
              { pinned: gatewayKey.keysetDigest, served },
              "E2EE keyset digest changed; refetching the attestation report",
            );
            invalidateKey();
          }
          try {
            return await decryptField({
              wire: content,
              privateKey: client.privateKey,
              aad: responseFieldAad(context, field, id),
            });
          } catch (err) {
            const detail =
              err instanceof E2eeCipherError ? err.message : "unexpected error";
            throw new InferenceRequestError(
              `e2ee response decryption failed for ${field} (${detail})`,
              null,
              { errorType: "e2ee_decryption_failed", retryable: false },
            );
          }
        },
      };
      return request;
    },

    async onRejected({ errorType }) {
      if (errorType === "e2ee_model_key_mismatch") {
        options.logger?.warn?.(
          { keyId: cached?.key.keyId ?? null },
          "E2EE model key rejected by the gateway; refetching the attestation report",
        );
        invalidateKey();
        return true;
      }
      return false;
    },
  };
}
