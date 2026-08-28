/**
 * A fake Phala-style ACI gateway behind a `fetch` function, for tests of the
 * E2EE v2 client: serves the attestation report for its keyset and a chat
 * completions endpoint that behaves like the enclave (validates the five
 * headers, decrypts the request fields, encrypts the answer to the client
 * key). It records what the "relay" saw on the wire and what the "enclave"
 * decrypted, so a test can assert the two differ.
 */

import { requestFieldAad, responseFieldAad } from "../derivatives/e2ee/aad.js";
import {
  reportDataFor,
  workloadKeysetDigest,
  type AciAttestationReport,
  type AciWorkloadKeyset,
} from "../derivatives/e2ee/attestation.js";
import {
  E2EE_ALGO_X25519,
  bytesToHex,
  decryptField,
  encryptField,
  generateX25519KeyPair,
  hexToBytes,
  importX25519PrivateKey,
  type E2eeKeyPair,
} from "../derivatives/e2ee/suite.js";

/** The spec test-vector service key: seed 32 x 0x03. */
export const TEST_VECTOR_SERVICE_SEED = new Uint8Array(32).fill(3);
export const TEST_VECTOR_SERVICE_PUBLIC_KEY_HEX =
  "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22";

export async function testVectorServiceKeyPair(): Promise<E2eeKeyPair> {
  return importX25519PrivateKey(
    TEST_VECTOR_SERVICE_SEED,
    hexToBytes(TEST_VECTOR_SERVICE_PUBLIC_KEY_HEX),
  );
}

export interface FakeE2eeGatewayRequest {
  url: string;
  headers: Record<string, string>;
  /** The JSON body exactly as the relay would see it. */
  body: Record<string, unknown>;
}

export interface FakeE2eeGatewayOptions {
  /** Chat completions base the gateway answers on (default relay.test/v1). */
  baseUrl?: string;
  /** Service key (default: the spec test-vector key). */
  serviceKey?: E2eeKeyPair;
  keyId?: string;
  notAfter?: number;
  /** Plaintext answer for a decrypted prompt (default: fixed JSON answer). */
  respond?: (input: {
    model: string;
    messages: Array<{ role: string; content: string }>;
  }) => string | Promise<string>;
  /** false = 404 on the attestation route (a relay without passthrough). */
  attestationRoute?: boolean;
  /** Advertised E2EE versions (default ["2"]). */
  supportedE2eeVersions?: string[];
  /** Response id put on completions (default chatcmpl-test). */
  responseId?: string;
}

export interface FakeE2eeGateway {
  fetch: typeof fetch;
  keyset: AciWorkloadKeyset;
  /** Every chat completion request, as seen on the wire. */
  requests: FakeE2eeGatewayRequest[];
  /** Attestation report requests (url only). */
  attestationRequests: string[];
  /** Decrypted message contents per request, as the enclave saw them. */
  decryptedPrompts: string[][];
  /** Replace the service key: a keyset rotation with a fresh digest. */
  rotateKey(): Promise<void>;
  /** Serve the next N chat requests as this OpenAI-style error. */
  failNext(count: number, status: number, errorType: string): void;
  /** Serve the next chat response with plaintext content (no E2EE). */
  plaintextNext(): void;
  keysetDigest(): Promise<string>;
}

function jsonResponse(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function errorResponse(status: number, type: string): Response {
  return jsonResponse(status, {
    error: { type, message: `fake gateway: ${type}` },
  });
}

export async function createFakeE2eeGateway(
  options: FakeE2eeGatewayOptions = {},
): Promise<FakeE2eeGateway> {
  const baseUrl = (options.baseUrl ?? "https://relay.test/v1").replace(
    /\/+$/,
    "",
  );
  let serviceKey = options.serviceKey ?? (await testVectorServiceKeyPair());
  const keyId = options.keyId ?? "dstack-kms-e2ee-x25519-v1";
  const notAfter =
    options.notAfter ?? Math.floor(Date.now() / 1000) + 30 * 24 * 3600;
  const responseId = options.responseId ?? "chatcmpl-test";
  const respond =
    options.respond ??
    (() =>
      JSON.stringify({ answer: "fake answer", evidence: "fake evidence" }));

  const buildKeyset = (): AciWorkloadKeyset => ({
    subject: null,
    not_after: notAfter,
    receipt_signing_keys: [
      {
        key_id: "dstack-kms-receipt-ed25519-v1",
        algo: "ed25519",
        public_key: "00".repeat(32),
      },
    ],
    e2ee_public_keys: [
      {
        key_id: "dstack-kms-e2ee-v1",
        algo: "secp256k1-aes-256-gcm-hkdf-sha256",
        public_key: "04" + "11".repeat(64),
      },
      {
        key_id: keyId,
        algo: E2EE_ALGO_X25519,
        public_key: bytesToHex(serviceKey.publicKey),
      },
    ],
    tls_public_keys: [{ spki_sha256: "22".repeat(32), domain: "relay.test" }],
  });

  const gateway: FakeE2eeGateway = {
    fetch: undefined as unknown as typeof fetch,
    keyset: buildKeyset(),
    requests: [],
    attestationRequests: [],
    decryptedPrompts: [],
    async rotateKey() {
      serviceKey = await generateX25519KeyPair();
      gateway.keyset = buildKeyset();
    },
    failNext(count, status, errorType) {
      pendingFailures = { count, status, errorType };
    },
    plaintextNext() {
      plaintextOnce = true;
    },
    keysetDigest: () => workloadKeysetDigest(gateway.keyset),
  };
  let pendingFailures: {
    count: number;
    status: number;
    errorType: string;
  } | null = null;
  let plaintextOnce = false;

  const serveAttestation = async (url: URL): Promise<Response> => {
    gateway.attestationRequests.push(url.toString());
    if (options.attestationRoute === false) {
      return jsonResponse(404, { error: "not found" });
    }
    const nonce = url.searchParams.get("nonce");
    if (!nonce || !/^[0-9a-f]{64}$/.test(nonce)) {
      return errorResponse(400, "invalid_request_error");
    }
    const digest = await workloadKeysetDigest(gateway.keyset);
    const reportData = await reportDataFor(digest, nonce);
    const report: AciAttestationReport = {
      api_version: "aci/1",
      workload_keyset_digest: digest,
      attestation: {
        tee_type: "tdx",
        workload_keyset: gateway.keyset,
        report_data: reportData,
        source_provenance: {
          repo_url: "https://github.com/Dstack-TEE/private-ai-gateway.git",
          repo_commit: "d567f6b4c4d93e33037ea202db04db86a8ad881c",
          image_digest: null,
          image_provenance: null,
        },
        evidence: {
          quote: "0400",
          quote_report_data: reportData + "0".repeat(64),
        },
      },
      service_capabilities: {
        supported_e2ee_versions: options.supportedE2eeVersions ?? ["2"],
        serving: "aggregator",
      },
    };
    return jsonResponse(200, report);
  };

  const serveChat = async (
    url: URL,
    init: RequestInit | undefined,
  ): Promise<Response> => {
    const headers = new Headers(init?.headers);
    const headerRecord: Record<string, string> = {};
    headers.forEach((value, key) => {
      headerRecord[key] = value;
    });
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    gateway.requests.push({ url: url.toString(), headers: headerRecord, body });
    const digest = await workloadKeysetDigest(gateway.keyset);
    const common = { "X-ACI-Keyset-Digest": digest, "X-Receipt-Id": "rcpt-1" };

    if (pendingFailures && pendingFailures.count > 0) {
      pendingFailures.count -= 1;
      return errorResponse(pendingFailures.status, pendingFailures.errorType);
    }
    const required = [
      "x-e2ee-version",
      "x-client-pub-key",
      "x-model-pub-key",
      "x-e2ee-nonce",
      "x-e2ee-timestamp",
    ];
    const present = required.filter((name) => headers.has(name));
    if (present.length !== required.length) {
      return errorResponse(400, "e2ee_header_missing");
    }
    if (headers.get("x-e2ee-version") !== "2") {
      return errorResponse(400, "e2ee_invalid_version");
    }
    if (headers.get("x-model-pub-key") !== bytesToHex(serviceKey.publicKey)) {
      return errorResponse(400, "e2ee_model_key_mismatch");
    }
    const nonce = headers.get("x-e2ee-nonce")!;
    if (!/^[0-9a-fA-F]{64}$/.test(nonce)) {
      return errorResponse(400, "e2ee_invalid_nonce");
    }
    const ts = Number(headers.get("x-e2ee-timestamp"));
    if (!Number.isInteger(ts)) {
      return errorResponse(400, "e2ee_invalid_timestamp");
    }
    if (typeof body.model !== "string") {
      return errorResponse(400, "e2ee_invalid_payload_model");
    }
    let clientPublicKey: Uint8Array;
    try {
      clientPublicKey = hexToBytes(headers.get("x-client-pub-key")!);
      if (clientPublicKey.length !== 32) throw new Error("length");
    } catch {
      return errorResponse(400, "e2ee_invalid_public_key");
    }
    const context = {
      algo: E2EE_ALGO_X25519,
      model: body.model,
      nonce,
      ts,
    };
    const messages = Array.isArray(body.messages) ? body.messages : [];
    const decrypted: Array<{ role: string; content: string }> = [];
    for (let index = 0; index < messages.length; index += 1) {
      const message = messages[index] as { role: string; content: unknown };
      if (typeof message.content !== "string") {
        return errorResponse(400, "e2ee_decryption_failed");
      }
      try {
        decrypted.push({
          role: message.role,
          content: await decryptField({
            wire: message.content,
            privateKey: serviceKey.privateKey,
            aad: requestFieldAad(context, `messages.${index}.content`),
          }),
        });
      } catch {
        return errorResponse(400, "e2ee_decryption_failed");
      }
    }
    if (decrypted.length === 0) {
      return errorResponse(400, "e2ee_decryption_failed");
    }
    gateway.decryptedPrompts.push(decrypted.map((m) => m.content));
    const answer = await respond({ model: body.model, messages: decrypted });
    if (plaintextOnce) {
      plaintextOnce = false;
      return jsonResponse(
        200,
        {
          id: responseId,
          choices: [
            { index: 0, message: { role: "assistant", content: answer } },
          ],
        },
        common,
      );
    }
    const content = await encryptField({
      plaintext: answer,
      recipientPublicKey: clientPublicKey,
      aad: responseFieldAad(context, "choices.0.message.content", responseId),
    });
    return jsonResponse(
      200,
      {
        id: responseId,
        object: "chat.completion",
        model: body.model,
        choices: [
          {
            index: 0,
            finish_reason: "stop",
            message: { role: "assistant", content },
          },
        ],
        usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 },
      },
      {
        ...common,
        "X-E2EE-Applied": "true",
        "X-E2EE-Version": "2",
        "X-E2EE-Algo": E2EE_ALGO_X25519,
      },
    );
  };

  gateway.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit,
  ) => {
    const url = new URL(
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.toString()
          : input.url,
    );
    const path = url.origin + url.pathname;
    if (path === `${baseUrl}/aci/attestation`) return serveAttestation(url);
    if (path === `${baseUrl}/chat/completions`) return serveChat(url, init);
    return jsonResponse(404, { error: "not found" });
  }) as typeof fetch;

  return gateway;
}
