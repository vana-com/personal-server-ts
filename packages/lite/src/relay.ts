import type { PersonalServerReadFulfillmentReporter } from "@opendatalabs/personal-server-ts-core/api";
import {
  handlePsLiteBridgeRequest,
  type PsLiteBridgeRequest,
  type PsLiteBridgeResponse,
} from "./bridge.js";
import { createRustlsPsLiteRelayTlsFactory } from "./relay-tls.js";
import type { PsLiteRuntime } from "./runtime.js";

const DATA_FRAME_TYPE = 1;
const HEADER_BYTES = 5;
const RESPONSE_CHUNK_BYTES = 16 * 1024;
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
  /** Heartbeat ping cadence (ms). Default 20_000. */
  heartbeatIntervalMs?: number;
  /**
   * Force-reconnect when a ping the client actually sent goes unanswered by
   * ANY relay frame for this long, measured by wall clock (ms). Default 45_000.
   */
  heartbeatTimeoutMs?: number;
  /** First reconnect backoff delay (ms); doubles up to the max. Default 1_000. */
  reconnectInitialDelayMs?: number;
  /** Max reconnect backoff delay (ms). Default 30_000. */
  reconnectMaxDelayMs?: number;
}

export type PsLiteRelayStatus =
  "connecting" | "connected" | "disconnected" | "closed" | "replaced" | "error";

/**
 * Close code the relay sends to the losing side when a new connection claims
 * the same sessionId. Terminal for this client: reconnecting would evict the
 * winner right back and the two tabs would trade the session every backoff
 * tick (observed live as a 1012 eviction loop every ~2s with two app tabs).
 */
export const RELAY_CLOSE_SESSION_REPLACED = 1012;

/**
 * A heartbeat tick arriving more than this many intervals after the previous
 * one means the tab's timers were throttled (Chrome backgrounds clamp them to
 * >= 1/min), not that the tunnel is dead. Such a tick probes with a fresh ping
 * instead of closing on stale elapsed time (BUI-665).
 */
const HEARTBEAT_LATE_FIRE_FACTOR = 2;

export interface PsLiteRelayClient {
  readonly sessionId: string;
  readonly url: string;
  close(reason?: string): void;
  /**
   * Resolves once the relay has finished delivering everything in flight: no
   * HTTP streams open and the socket's send buffer empty. A non-OPEN socket
   * counts as drained (its buffered bytes died with it and reconnect starts
   * from a clean slate). Resolves after `timeoutMs` regardless, so callers can
   * never deadlock on a wedged tunnel.
   */
  whenDrained(options?: {
    /** Max time to wait before resolving anyway (ms). Default 20_000. */
    timeoutMs?: number;
    /** Drain-state poll cadence (ms). Default 50. */
    pollIntervalMs?: number;
  }): Promise<void>;
}

export interface PsLiteRelayWebSocketFactory {
  (url: string): PsLiteRelayWebSocket;
}

/**
 * Subset of the standard CloseEvent the relay client reads. Browser
 * WebSockets pass a full CloseEvent here; fakes may call onclose with
 * nothing (treated as an abnormal close).
 */
export interface PsLiteRelayCloseEvent {
  code?: number;
  reason?: string;
}

export interface PsLiteRelayWebSocket {
  binaryType: string;
  readonly readyState: number;
  readonly OPEN: number;
  readonly CONNECTING: number;
  /**
   * Bytes accepted by send() but not yet flushed to the network (standard
   * WebSocket.bufferedAmount). Optional so lightweight fakes can omit it;
   * treated as 0 when absent.
   */
  readonly bufferedAmount?: number;
  onopen: (() => void) | null;
  onmessage:
    ((event: { data: string | ArrayBuffer | Uint8Array }) => void) | null;
  onclose: ((event?: PsLiteRelayCloseEvent) => void) | null;
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

/**
 * Defers read-fulfillment reports until the relay has delivered the in-flight
 * response. The core data handler reports fulfillment as soon as it BUILDS the
 * response, but over the relay the (potentially multi-MB) body still has to be
 * pumped through TLS over the WebSocket. Consumers act on the report
 * immediately — the DCR approval page closes the tab hosting this PS — so an
 * eager report kills the tunnel mid-transfer and the builder gets a truncated
 * body (UND_ERR_RES_CONTENT_LENGTH_MISMATCH) after escrow already settled.
 * Gating the report on relay drain makes "fulfilled" mean "delivered".
 *
 * `getRelayClient` is late-bound: the runtime needs the reporter at
 * construction time, before the relay client exists. When it returns
 * undefined (relay disabled / not started yet), reports pass straight through.
 */
export function createRelayDrainGatedReadFulfillmentReporter(
  reporter: PersonalServerReadFulfillmentReporter,
  getRelayClient: () => Pick<PsLiteRelayClient, "whenDrained"> | undefined,
): PersonalServerReadFulfillmentReporter {
  return {
    async report(event) {
      await getRelayClient()?.whenDrained();
      return reporter.report(event);
    },
  };
}

export function startPsLiteRelayClient(
  options: PsLiteRelayClientOptions,
): PsLiteRelayClient {
  const baseControlUrl = options.controlUrl ?? DEFAULT_CONTROL_URL;
  const controlUrl = psLiteRelayControlUrl(options.sessionId, baseControlUrl);
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
  // Resilience knobs. Defaults chosen so a backgrounded mobile tab whose socket
  // went half-open (no `onclose` ever fires) is detected within ~1 missed
  // heartbeat and reconnected with capped exponential backoff.
  const heartbeatIntervalMs = options.heartbeatIntervalMs ?? 20_000;
  const heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? 45_000;
  const reconnectInitialDelayMs = options.reconnectInitialDelayMs ?? 1_000;
  const reconnectMaxDelayMs = options.reconnectMaxDelayMs ?? 30_000;
  let issueToken: string | undefined;
  let closed = false;
  // `socket` is reassigned on every (re)connect; all the closures below read it
  // lazily at call time, so they always act on the current socket.
  let socket: PsLiteRelayWebSocket;
  let reconnectAttempts = 0;
  let heartbeatTimer: ReturnType<typeof setInterval> | undefined;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  // Liveness is evidence-based (BUI-665): ANY frame from the relay — data,
  // control, pong — proves the tunnel is alive. The heartbeat declares it dead
  // only when a ping it actually SENT went unanswered by any frame for the
  // full timeout window, measured by wall clock. A late-firing throttled timer
  // that finds recent frames must never kill a healthy socket.
  let lastFrameReceivedAt = 0;
  // Wall-clock send time of the oldest ping not yet answered by any frame;
  // undefined when the tunnel has proven itself since the last ping.
  let unansweredPingSentAt: number | undefined;
  let lastHeartbeatCheckAt = 0;
  let heartbeatGraceUsed = false;

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
      for (const chunk of chunks(responseBytes, RESPONSE_CHUNK_BYTES)) {
        sendData(stream.streamId, chunk);
      }
      return;
    }

    const responseChunks = chunks(responseBytes, RESPONSE_CHUNK_BYTES);
    for (let index = 0; index < responseChunks.length; index += 1) {
      const step = stream.tls.writePlaintext(
        responseChunks[index],
        index === responseChunks.length - 1,
      );
      for (const chunk of chunks(step.tls, RESPONSE_CHUNK_BYTES)) {
        if (chunk.length > 0) {
          sendData(stream.streamId, chunk);
        }
      }
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
      // `response` is a binary (latin1) string: buildHttpResponse appends the
      // body via bytesToBinary, so each char code 0x00–0xFF is one body byte.
      // It must be turned back into bytes the same way (binaryToBytes), NOT
      // UTF-8 re-encoded — textToBytes would expand every byte >= 0x80 into a
      // 2-byte sequence, corrupting binary payloads (e.g. OpenPGP-encrypted
      // files fail downstream with "not a valid OpenPGP message"). ASCII/JSON
      // bodies survive UTF-8, which is why only encrypted binary downloads broke.
      writePlaintextResponse(stream, binaryToBytes(response));
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
      // Liveness is recorded for every frame in socket.onmessage; the pong
      // carries no other payload.
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

  const stopHeartbeat = () => {
    if (heartbeatTimer !== undefined) {
      clearInterval(heartbeatTimer);
      heartbeatTimer = undefined;
    }
  };

  const heartbeatTick = () => {
    if (socket.readyState !== socket.OPEN) {
      return;
    }
    const now = Date.now();
    // A tick arriving well past its cadence means the tab's timers were
    // throttled — the elapsed time says nothing about the tunnel.
    const firedLate =
      now - lastHeartbeatCheckAt >
      heartbeatIntervalMs * HEARTBEAT_LATE_FIRE_FACTOR;
    lastHeartbeatCheckAt = now;

    if (
      unansweredPingSentAt !== undefined &&
      lastFrameReceivedAt >= unansweredPingSentAt
    ) {
      // A frame arrived since the ping went out — pong, data, or control all
      // count as proof of life.
      unansweredPingSentAt = undefined;
      heartbeatGraceUsed = false;
    }

    const pingUnansweredForFullWindow =
      unansweredPingSentAt !== undefined &&
      now - unansweredPingSentAt > heartbeatTimeoutMs;

    if (pingUnansweredForFullWindow && firedLate && !heartbeatGraceUsed) {
      // Throttling, not deadness: the ping (and its answer) may have been
      // stalled along with the tab. Probe with a fresh ping and re-check on
      // the next tick instead of killing a usually-healthy socket.
      heartbeatGraceUsed = true;
      unansweredPingSentAt = undefined;
    } else if (pingUnansweredForFullWindow) {
      // A backgrounded/suspended tab can leave the socket half-open: it never
      // fires `onclose`, so reconnect-on-close alone never triggers. A ping we
      // actually sent drew no frame at all for the full wall-clock window —
      // the tunnel really is dead; force it closed → onclose → reconnect.
      log("relay heartbeat timeout — forcing reconnect");
      try {
        socket.close(4000, "heartbeat_timeout");
      } catch {
        // Ignore: a socket that can't be closed will be replaced on reconnect.
      }
      return;
    }

    sendText({ type: "ping" });
    if (unansweredPingSentAt === undefined) {
      unansweredPingSentAt = now;
    }
  };

  const startHeartbeat = () => {
    stopHeartbeat();
    lastFrameReceivedAt = Date.now();
    lastHeartbeatCheckAt = Date.now();
    unansweredPingSentAt = undefined;
    heartbeatGraceUsed = false;
    heartbeatTimer = setInterval(heartbeatTick, heartbeatIntervalMs);
  };

  const scheduleReconnect = () => {
    if (closed || reconnectTimer !== undefined) {
      return;
    }
    const delay = Math.min(
      reconnectMaxDelayMs,
      reconnectInitialDelayMs * 2 ** reconnectAttempts,
    );
    reconnectAttempts += 1;
    reconnectTimer = setTimeout(() => {
      reconnectTimer = undefined;
      connect();
    }, delay);
  };

  function connect(): void {
    // Terminal states (intentional close, or a 1012 session takeover) must
    // never re-open a socket, even if a stale timer or event slips through.
    if (closed) {
      return;
    }
    issueToken = undefined;
    socket = createSocket(options.webSocketFactory, controlUrl);
    socket.binaryType = "arraybuffer";
    options.onStatus?.("connecting");

    socket.onopen = () => {
      reconnectAttempts = 0;
      startHeartbeat();
      options.onStatus?.("connected");
    };
    socket.onmessage = (event) => {
      lastFrameReceivedAt = Date.now();
      if (typeof event.data === "string") {
        handleControl(JSON.parse(event.data) as ControlMessage);
        return;
      }
      handleDataFrame(event.data);
    };
    socket.onclose = (event) => {
      stopHeartbeat();
      streams.forEach((stream) => stream.tls?.close?.());
      streams.clear();
      pendingStreamData.clear();
      issueToken = undefined;
      if (closed) {
        options.onStatus?.("closed");
        return;
      }
      if (event?.code === RELAY_CLOSE_SESSION_REPLACED) {
        // Another connection (typically a second tab) now owns this session.
        // Reconnecting would evict it and start a session tug-of-war, so this
        // client steps down for good and lets the host surface the handoff.
        closed = true;
        // Cancel any reconnect already scheduled by an earlier drop so a
        // pending timer can't fire connect() after we've stepped down.
        if (reconnectTimer !== undefined) {
          clearTimeout(reconnectTimer);
          reconnectTimer = undefined;
        }
        log("relay session replaced by another connection — not reconnecting");
        options.onStatus?.("replaced");
        return;
      }
      options.onStatus?.("disconnected");
      scheduleReconnect();
    };
    socket.onerror = () => {
      if (closed) {
        return;
      }
      options.onStatus?.("error");
    };
  }

  connect();

  // Drained = no HTTP streams in flight and nothing queued in the socket's
  // send buffer. Only an OPEN socket can still be flushing; a closed or
  // reconnecting socket's buffered bytes are gone either way.
  const isDrained = () => {
    if (streams.size > 0) {
      return false;
    }
    if (!closed && socket.readyState === socket.OPEN) {
      return (socket.bufferedAmount ?? 0) === 0;
    }
    return true;
  };

  return {
    sessionId: options.sessionId,
    url: controlUrl,
    async whenDrained({ timeoutMs = 20_000, pollIntervalMs = 50 } = {}) {
      const deadline = Date.now() + timeoutMs;
      while (!isDrained() && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
      }
    },
    close(reason = "closed") {
      closed = true;
      stopHeartbeat();
      if (reconnectTimer !== undefined) {
        clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
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
  // Large exports (e.g. chatgpt.conversations) are big JSON streamed over the
  // relay's WebSocket tunnel; an uncompressed body inflates transfer time and the
  // window for a mid-stream drop (truncated read → UND_ERR_RES_CONTENT_LENGTH_MISMATCH).
  // gzip when the client accepts it and the payload is large enough to be worth it;
  // the SDK/undici sends Accept-Encoding and auto-decompresses. See BUI-591.
  const bodyBytes = decodeBase64(bridgeResponse.body);
  const acceptsGzip = (request.headers["accept-encoding"] ?? "").includes(
    "gzip",
  );
  const alreadyEncoded = Boolean(bridgeResponse.headers?.["content-encoding"]);
  if (
    acceptsGzip &&
    !alreadyEncoded &&
    bodyBytes.length >= GZIP_MIN_BYTES &&
    typeof CompressionStream !== "undefined"
  ) {
    const gzipped = await gzipBytes(bodyBytes);
    return buildHttpResponse(bridgeResponse, {
      bodyOverride: gzipped,
      contentEncoding: "gzip",
    });
  }
  return buildHttpResponse(bridgeResponse, { bodyOverride: bodyBytes });
}

// Responses below this size aren't worth the gzip overhead, and small reads
// already complete reliably over the relay.
const GZIP_MIN_BYTES = 1024;

async function gzipBytes(input: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream("gzip");
  const writer = cs.writable.getWriter();
  // Copy into a fresh ArrayBuffer-backed view: TS types the stream's chunk as
  // BufferSource, which excludes the generic Uint8Array<ArrayBufferLike>.
  const chunk = new Uint8Array(input);
  const writeDone = writer.write(chunk).then(() => writer.close());
  const reader = cs.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      total += value.length;
    }
  }
  await writeDone;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function buildHttpResponse(
  response: PsLiteBridgeResponse,
  opts?: { bodyOverride?: Uint8Array; contentEncoding?: string },
): string {
  const responseHeaders: Record<string, string> = {
    "cache-control": "no-store",
    connection: "close",
    ...response.headers,
  };
  // We always emit an authoritative content-length below, computed from the
  // exact bytes we write (gzip changes the length vs. the upstream value). Drop
  // any upstream copy first — the core raw-data path sets Content-Length and the
  // bridge lowercases it, so without this the head would carry two conflicting
  // content-length values and clients reject that (the same mismatch class this
  // change fixes). Match case-insensitively in case the name wasn't normalized.
  for (const key of Object.keys(responseHeaders)) {
    if (key.toLowerCase() === "content-length") {
      delete responseHeaders[key];
    }
  }
  if (opts?.contentEncoding) {
    responseHeaders["content-encoding"] = opts.contentEncoding;
  }
  const bodyBytes = opts?.bodyOverride ?? decodeBase64(response.body);
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

function chunks(bytes: Uint8Array, chunkBytes: number): Uint8Array[] {
  if (bytes.length === 0) return [bytes];
  const result: Uint8Array[] = [];
  for (let offset = 0; offset < bytes.length; offset += chunkBytes) {
    result.push(bytes.slice(offset, offset + chunkBytes));
  }
  return result;
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
