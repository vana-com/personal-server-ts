import type { PsLiteRuntime } from "./runtime.js";

export interface PsLiteBridgeRequest {
  requestId: string;
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  /** Base64-encoded request body, matching the browser-local relay PoC. */
  body: string;
}

export interface PsLiteBridgeResponse {
  requestId: string;
  status: number;
  headers: Record<string, string>;
  /** Base64-encoded response body for relay transport. */
  body: string;
  /** Decoded response body for same-context consumers and tests. */
  textBody: string;
}

function decodeBase64(input: string): Uint8Array {
  if (!input) return new Uint8Array();
  const binary =
    typeof globalThis.atob === "function"
      ? globalThis.atob(input)
      : Buffer.from(input, "base64").toString("binary");
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return typeof globalThis.btoa === "function"
    ? globalThis.btoa(binary)
    : Buffer.from(binary, "binary").toString("base64");
}

function headersToRecord(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  headers.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

function buildRequest(
  origin: string,
  bridgeRequest: PsLiteBridgeRequest,
): Request {
  const query = bridgeRequest.query
    ? `?${bridgeRequest.query.replace(/^\?/, "")}`
    : "";
  const url = `${origin.replace(/\/+$/, "")}${bridgeRequest.path}${query}`;
  const method = bridgeRequest.method.toUpperCase();
  const hasBody = method !== "GET" && method !== "HEAD";
  const body = hasBody
    ? decodeBase64(bridgeRequest.body).slice().buffer
    : undefined;

  return new Request(url, {
    method,
    headers: bridgeRequest.headers,
    body,
  });
}

export async function handlePsLiteBridgeRequest(
  runtime: PsLiteRuntime,
  bridgeRequest: PsLiteBridgeRequest,
  options: { origin?: string } = {},
): Promise<PsLiteBridgeResponse> {
  const request = buildRequest(
    options.origin ?? "https://ps-lite.local",
    bridgeRequest,
  );
  const response = await runtime.fetch(request);
  const bytes = new Uint8Array(await response.arrayBuffer());

  return {
    requestId: bridgeRequest.requestId,
    status: response.status,
    headers: headersToRecord(response.headers),
    body: encodeBase64(bytes),
    textBody: new TextDecoder().decode(bytes),
  };
}
