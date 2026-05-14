import {
  handlePsLiteBridgeRequest,
  type PsLiteBridgeRequest,
  type PsLiteBridgeResponse,
} from "./bridge.js";
import { createRustlsPsLiteRelayTlsFactory } from "./relay-tls.js";
import type { PsLiteRuntime } from "./runtime.js";

const DATA_FRAME_TYPE = 1;
const HEADER_BYTES = 5;
const DEFAULT_CONTROL_URL = "wss://control.34.16.49.200.sslip.io:8443";
const DEFAULT_PUBLIC_SUFFIX = "34.16.49.200.sslip.io";
const DEFAULT_ORIGIN = "https://ps-lite.local";

export interface PsLiteRelayClientOptions {
  sessionId: string;
  runtime: PsLiteRuntime;
  controlUrl?: string;
  publicSuffix?: string;
  certIssuerUrl?: string;
  origin?: string;
  webSocketFactory?: PsLiteRelayWebSocketFactory;
  tls?: PsLiteRelayTlsFactory | false;
  logger?: (line: string) => void;
  onStatus?: (status: PsLiteRelayStatus) => void;
}

export type PsLiteRelayStatus =
  | "connecting"
  | "connected"
  | "disconnected"
  | "closed"
  | "error";

export interface PsLiteRelayClient {
  readonly sessionId: string;
  readonly url: string;
  close(reason?: string): void;
}

export interface PsLiteRelayWebSocketFactory {
  (url: string): PsLiteRelayWebSocket;
}

export interface PsLiteRelayWebSocket {
  binaryType: string;
  readonly readyState: number;
  readonly OPEN: number;
  readonly CONNECTING: number;
  onopen: (() => void) | null;
  onmessage:
    | ((event: { data: string | ArrayBuffer | Uint8Array }) => void)
    | null;
  onclose: (() => void) | null;
  onerror: (() => void) | null;
  send(data: string | Uint8Array): void;
  close(code?: number, reason?: string): void;
}

export interface PsLiteRelayTlsFactory {
  prepare?(input: PsLiteRelayTlsPrepareInput): Promise<void>;
  createStream(input: PsLiteRelayTlsStreamInput): Promise<PsLiteRelayTlsStream>;
}

export interface PsLiteRelayTlsPrepareInput {
  sessionId: string;
  issueToken?: string;
}

export interface PsLiteRelayTlsStreamInput {
  sessionId: string;
  streamId: number;
  issueToken?: string;
}

export interface PsLiteRelayTlsStream {
  processTls(payload: Uint8Array): PsLiteRelayTlsStep;
  writePlaintext(payload: Uint8Array, endStream: boolean): PsLiteRelayTlsStep;
  close?(): void;
}

export interface PsLiteRelayTlsStep {
  plaintext: Uint8Array;
  tls: Uint8Array;
  handshaking?: boolean;
}

interface StreamState {
  streamId: number;
  plaintext: string;
  tls?: PsLiteRelayTlsStream;
}

interface ControlMessage {
  type: string;
  streamId?: number;
  issueToken?: string;
  reason?: string;
}

interface ParsedHttpRequest {
  method: string;
  path: string;
  query: string;
  headers: Record<string, string>;
  body: Uint8Array;
}

export function psLiteRelayControlUrl(
  sessionId: string,
  controlUrl = DEFAULT_CONTROL_URL,
): string {
  return `${controlUrl.replace(/\/+$/, "")}/browser/${sessionId}`;
}

export function psLiteRelayPublicUrl(
  sessionId: string,
  publicSuffix = DEFAULT_PUBLIC_SUFFIX,
): string {
  return `https://${sessionId}.${publicSuffix.replace(/^\./, "")}`;
}

export function startPsLiteRelayClient(
  options: PsLiteRelayClientOptions,
): PsLiteRelayClient {
  const baseControlUrl = options.controlUrl ?? DEFAULT_CONTROL_URL;
  const controlUrl = psLiteRelayControlUrl(options.sessionId, baseControlUrl);
  const socket = createSocket(options.webSocketFactory, controlUrl);
  const tls =
    options.tls === undefined
      ? createRustlsPsLiteRelayTlsFactory({
          controlUrl: baseControlUrl,
          publicSuffix: options.publicSuffix,
          certIssuerUrl: options.certIssuerUrl,
          logger: options.logger,
        })
      : options.tls;
  const streams = new Map<number, StreamState>();
  const pendingStreamData = new Map<number, Uint8Array[]>();
  const origin = options.origin ?? DEFAULT_ORIGIN;
  let issueToken: string | undefined;
  let closed = false;

  socket.binaryType = "arraybuffer";
  options.onStatus?.("connecting");

  const log = (line: string) => options.logger?.(line);

  const sendText = (message: unknown) => {
    if (socket.readyState === socket.OPEN) {
      socket.send(JSON.stringify(message));
    }
  };

  const sendData = (streamId: number, payload: Uint8Array) => {
    if (socket.readyState === socket.OPEN) {
      socket.send(encodeDataFrame(streamId, payload));
    }
  };

  const closeStream = (streamId: number, reason: string) => {
    const stream = streams.get(streamId);
    stream?.tls?.close?.();
    streams.delete(streamId);
    pendingStreamData.delete(streamId);
    sendText({ type: "stream.close", streamId, reason });
  };

  const writePlaintextResponse = (
    stream: StreamState,
    responseBytes: Uint8Array,
  ) => {
    if (!stream.tls) {
      sendData(stream.streamId, responseBytes);
      return;
    }

    const step = stream.tls.writePlaintext(responseBytes, true);
    if (step.tls.length > 0) {
      sendData(stream.streamId, step.tls);
    }
  };

  const drainHttpRequests = async (stream: StreamState) => {
    while (true) {
      const parsed = parseHttpRequest(stream.plaintext);
      if (!parsed) {
        return;
      }

      stream.plaintext = stream.plaintext.slice(parsed.consumedBytes);
      const response = await handleRelayHttpRequest(
        options.runtime,
        parsed.request,
        origin,
      );
      writePlaintextResponse(stream, textToBytes(response));
      closeStream(stream.streamId, "http_response_sent");
      return;
    }
  };

  const handlePlaintext = (stream: StreamState, plaintext: Uint8Array) => {
    if (plaintext.length === 0) {
      return;
    }
    stream.plaintext += bytesToBinary(plaintext);
    void drainHttpRequests(stream).catch((error: unknown) => {
      log(error instanceof Error ? error.message : String(error));
      closeStream(stream.streamId, "handler_error");
    });
  };

  const processPayload = (stream: StreamState, payload: Uint8Array) => {
    if (!stream.tls) {
      handlePlaintext(stream, payload);
      return;
    }

    try {
      const step = stream.tls.processTls(payload);
      if (step.tls.length > 0) {
        sendData(stream.streamId, step.tls);
      }
      handlePlaintext(stream, step.plaintext);
    } catch (error) {
      log(error instanceof Error ? error.message : String(error));
      closeStream(stream.streamId, "tls_error");
    }
  };

  const openStream = async (streamId: number) => {
    const stream: StreamState = {
      streamId,
      plaintext: "",
    };

    if (tls) {
      stream.tls = await tls.createStream({
        sessionId: options.sessionId,
        streamId,
        issueToken,
      });
    }

    streams.set(streamId, stream);
    const buffered = pendingStreamData.get(streamId) ?? [];
    pendingStreamData.delete(streamId);
    for (const payload of buffered) {
      processPayload(stream, payload);
    }
  };

  const handleControl = (message: ControlMessage) => {
    if (message.type === "session.ready") {
      issueToken = message.issueToken;
      options.onStatus?.("connected");
      if (tls && tls.prepare) {
        void tls
          .prepare({
            sessionId: options.sessionId,
            issueToken,
          })
          .catch((error: unknown) => {
            log(error instanceof Error ? error.message : String(error));
          });
      }
      return;
    }

    if (message.type === "pong") {
      return;
    }

    if (
      message.type === "stream.open" &&
      typeof message.streamId === "number"
    ) {
      void openStream(message.streamId).catch((error: unknown) => {
        log(error instanceof Error ? error.message : String(error));
        if (typeof message.streamId === "number") {
          closeStream(message.streamId, "stream_open_error");
        }
      });
      return;
    }

    if (
      message.type === "stream.close" &&
      typeof message.streamId === "number"
    ) {
      streams.get(message.streamId)?.tls?.close?.();
      streams.delete(message.streamId);
      pendingStreamData.delete(message.streamId);
    }
  };

  const handleDataFrame = (data: string | ArrayBuffer | Uint8Array) => {
    const frame = decodeDataFrame(data);
    if (!frame) {
      return;
    }

    const stream = streams.get(frame.streamId);
    if (!stream) {
      const buffered = pendingStreamData.get(frame.streamId) ?? [];
      buffered.push(frame.payload);
      pendingStreamData.set(frame.streamId, buffered);
      return;
    }

    processPayload(stream, frame.payload);
  };

  socket.onopen = () => options.onStatus?.("connected");
  socket.onmessage = (event) => {
    if (typeof event.data === "string") {
      handleControl(JSON.parse(event.data) as ControlMessage);
      return;
    }
    handleDataFrame(event.data);
  };
  socket.onclose = () => {
    streams.forEach((stream) => stream.tls?.close?.());
    streams.clear();
    pendingStreamData.clear();
    options.onStatus?.(closed ? "closed" : "disconnected");
  };
  socket.onerror = () => options.onStatus?.("error");

  return {
    sessionId: options.sessionId,
    url: controlUrl,
    close(reason = "closed") {
      closed = true;
      streams.forEach((stream) => stream.tls?.close?.());
      streams.clear();
      pendingStreamData.clear();
      socket.close(1000, reason);
    },
  };
}

async function handleRelayHttpRequest(
  runtime: PsLiteRuntime,
  request: ParsedHttpRequest,
  origin: string,
): Promise<string> {
  const bridgeRequest: PsLiteBridgeRequest = {
    requestId: crypto.randomUUID(),
    method: request.method,
    path: request.path,
    query: request.query,
    headers: request.headers,
    body: encodeBase64(request.body),
  };
  const bridgeResponse = await handlePsLiteBridgeRequest(
    runtime,
    bridgeRequest,
    {
      origin,
    },
  );
  return buildHttpResponse(bridgeResponse);
}

function buildHttpResponse(response: PsLiteBridgeResponse): string {
  const responseHeaders = {
    "cache-control": "no-store",
    connection: "close",
    ...response.headers,
  };
  const bodyBytes = decodeBase64(response.body);
  const head = [
    `HTTP/1.1 ${response.status} ${httpStatusText(response.status)}`,
    ...Object.entries(responseHeaders).map(
      ([key, value]) => `${key}: ${value}`,
    ),
    `content-length: ${bodyBytes.length}`,
    "",
    "",
  ].join("\r\n");
  return head + bytesToBinary(bodyBytes);
}

function createSocket(
  factory: PsLiteRelayWebSocketFactory | undefined,
  url: string,
): PsLiteRelayWebSocket {
  if (factory) {
    return factory(url);
  }
  if (typeof WebSocket === "undefined") {
    throw new Error("WebSocket is required to start PS Lite relay client");
  }
  return new WebSocket(url) as PsLiteRelayWebSocket;
}

export function encodeDataFrame(
  streamId: number,
  payload: Uint8Array,
): Uint8Array {
  const frame = new Uint8Array(HEADER_BYTES + payload.length);
  frame[0] = DATA_FRAME_TYPE;
  writeUint32(frame, 1, streamId);
  frame.set(payload, HEADER_BYTES);
  return frame;
}

export function decodeDataFrame(
  data: string | ArrayBuffer | Uint8Array,
): { streamId: number; payload: Uint8Array } | null {
  const frame =
    typeof data === "string"
      ? textToBytes(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data);
  if (frame.length < HEADER_BYTES || frame[0] !== DATA_FRAME_TYPE) {
    return null;
  }
  return {
    streamId: readUint32(frame, 1),
    payload: frame.slice(HEADER_BYTES),
  };
}

function parseHttpRequest(
  buffer: string,
): { request: ParsedHttpRequest; consumedBytes: number } | undefined {
  const headerEnd = buffer.indexOf("\r\n\r\n");
  if (headerEnd === -1) {
    return undefined;
  }

  const headerBlock = buffer.slice(0, headerEnd);
  const lines = headerBlock.split("\r\n");
  const [method, target] = lines[0]?.split(" ") ?? [];
  if (!method || !target) {
    return undefined;
  }

  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const separator = line.indexOf(":");
    if (separator === -1) {
      continue;
    }
    headers[line.slice(0, separator).trim().toLowerCase()] = line
      .slice(separator + 1)
      .trim();
  }

  const bodyStart = headerEnd + 4;
  const contentLength = Number(headers["content-length"] ?? "0");
  const requestEnd = bodyStart + contentLength;
  if (buffer.length < requestEnd) {
    return undefined;
  }

  const url = new URL(target, DEFAULT_ORIGIN);
  return {
    consumedBytes: requestEnd,
    request: {
      method,
      path: url.pathname,
      query: url.searchParams.toString(),
      headers,
      body: binaryToBytes(buffer.slice(bodyStart, requestEnd)),
    },
  };
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

function decodeBase64(input: string): Uint8Array {
  if (!input) return new Uint8Array();
  const binary =
    typeof globalThis.atob === "function"
      ? globalThis.atob(input)
      : Buffer.from(input, "base64").toString("binary");
  return binaryToBytes(binary);
}

function textToBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function binaryToBytes(value: string): Uint8Array {
  return Uint8Array.from(value, (char) => char.charCodeAt(0));
}

function bytesToBinary(bytes: Uint8Array): string {
  let result = "";
  for (const byte of bytes) {
    result += String.fromCharCode(byte);
  }
  return result;
}

function writeUint32(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset] * 0x1000000 +
    ((bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3])
  );
}

function httpStatusText(status: number): string {
  if (status === 200) return "OK";
  if (status === 201) return "Created";
  if (status === 204) return "No Content";
  if (status === 400) return "Bad Request";
  if (status === 401) return "Unauthorized";
  if (status === 403) return "Forbidden";
  if (status === 404) return "Not Found";
  if (status === 405) return "Method Not Allowed";
  if (status === 413) return "Content Too Large";
  if (status === 500) return "Internal Server Error";
  if (status === 503) return "Service Unavailable";
  return "Error";
}
