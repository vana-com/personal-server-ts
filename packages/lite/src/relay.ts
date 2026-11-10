import type { PersonalServerReadFulfillmentReporter } from "@opendatalabs/personal-server-ts-core/api";
import { parseDataScopeContract } from "@opendatalabs/personal-server-ts-core/contracts";
import {
  handlePsLiteBridgeRequest,
  type PsLiteBridgeRequest,
  type PsLiteBridgeResponse,
} from "./bridge.js";
import { createRustlsPsLiteRelayTlsFactory } from "./relay-tls.js";
import type { PsLiteRelayTlsIdentityStore } from "./relay-tls.js";
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
  /** Host-owned cache for the issued relay certificate identity. */
  tlsIdentityStore?: PsLiteRelayTlsIdentityStore;
  logger?: (line: string) => void;
  onStatus?: (
    status: PsLiteRelayStatus,
    detail?: PsLiteRelayStatusDetail,
  ) => void;
  /** Heartbeat ping cadence (ms). Default 2_000. */
  heartbeatIntervalMs?: number;
  /**
   * Force-reconnect when a ping the client actually sent goes unanswered by
   * ANY relay frame for this long, measured by wall clock (ms). Default 10_000.
   */
  heartbeatTimeoutMs?: number;
  /** First reconnect backoff delay (ms); doubles up to the max. Default 1_000. */
  reconnectInitialDelayMs?: number;
  /** Max reconnect backoff delay (ms). Default 30_000. */
  reconnectMaxDelayMs?: number;
  /**
   * Read-reliability telemetry hook: one `ps_read_received` and one
   * `ps_read_finished` per relayed `/v1/data/<scope>` HTTP request. Hosts
   * forward the events to their analytics; a throwing hook never affects the
   * relay.
   *
   * These count HTTP requests (attempts), not logical reads. A paid builder
   * read is at least two requests: the first answers 402 (`payment_required`)
   * and the paid retry answers 200; a requester's transport retry repeats the
   * whole exchange. Dashboards must treat `payment_required` as a step, not a
   * failure, and take the number of logical reads from the requester side.
   */
  onReadEvent?: (event: PsLiteReadEvent) => void;
  /**
   * Where the app's visibility comes from, for `appVisibility` and
   * `hiddenDuring`. Default: `document.visibilityState` and its
   * `visibilitychange` events. A host whose document does not reflect the app
   * (PS-Lite in a headless WebView on mobile, where the document is never the
   * screen) must pass its own source, or `() => "unknown"`; the events then
   * omit `hiddenDuring` and carry `appVisibility: "unknown"` instead of a
   * value that is constant and wrong.
   */
  appVisibility?: () => PsLiteAppVisibility;
}

/**
 * How a relayed read ended, as seen by the PS-Lite relay client. `ok` and
 * `empty` mean the response was handed to the socket, not that the requester
 * received it: delivery comes from joining the relay's `relay_stream_ended`
 * on streamRef (`bytes_unflushed` there is what the requester never got).
 * `payment_required` is the expected first answer of a paid read, a step on
 * the way to `ok`, not a failed read.
 */
export type PsLiteReadOutcome =
  | "ok"
  | "empty"
  | "denied"
  | "payment_required"
  | "not_found"
  | "error"
  | "handler_error"
  | "tls_error"
  | "stream_closed";

export type PsLiteAppVisibility = "visible" | "hidden" | "unknown";

interface PsLiteReadEventIds {
  /**
   * Epoch ms when the fact happened on the device: the request was parsed
   * (`ps_read_received`) or the response was handed to the socket or given up
   * (`ps_read_finished`). Taken at that moment, not when the hook runs: the
   * hook is deferred to a later task, which in a suspended WebView may be the
   * moment the app resumes.
   */
  at: number;
  /** `<streamRef or local uuid>:<seq>`; random, never derived from user data. */
  readRef: string;
  /** Relay-generated per-TCP-stream UUID from `stream.open` (old relays: absent). */
  streamRef?: string;
  /** Random 16-hex tag of the WebSocket connection that carried the read. */
  connTag: string;
  /**
   * Scope from the request path (`/v1/data/<scope>`), query dropped. Read
   * before auth, so anything that is not a valid scope (or is longer than 128
   * chars) is reported as "invalid".
   */
  scope: string;
  method: string;
}

/**
 * Read telemetry emitted by the relay client. Carries no data content, no
 * addresses, grant ids, sessionId, IPs or SNI.
 */
export type PsLiteReadEvent =
  | (PsLiteReadEventIds & {
      type: "ps_read_received";
      appVisibility: PsLiteAppVisibility;
    })
  | (PsLiteReadEventIds & {
      type: "ps_read_finished";
      /**
       * First 12 hex of sha256(lowercased grantee address), "owner", or
       * absent. A pseudonym, not an anonymous id: builders are a small public
       * set, so their addresses map back to it.
       */
      granteeRef?: string;
      /** HTTP status written; absent when no response was produced. */
      status?: number;
      outcome: PsLiteReadOutcome;
      /** Plaintext HTTP response bytes written (head + body, after gzip). */
      bytesOut: number;
      gzip: boolean;
      durationMs: number;
      /**
       * The app was hidden at any point between received and finished. Absent
       * when the visibility source never knew (`appVisibility` "unknown"
       * throughout), so an unknowing host cannot look like a visible one.
       */
      hiddenDuring?: boolean;
    });

export type PsLiteRelayStatus =
  "connecting" | "connected" | "disconnected" | "closed" | "replaced" | "error";

/**
 * Extra context for a relay status transition — the WebSocket close code/reason
 * on `disconnected` / `closed` / `replaced`. Lets consumers distinguish an
 * abnormal drop (1006) from a takeover (1012) or a clean close (1000) for
 * reliability telemetry. Optional and additive: 1-arg `onStatus` handlers stay
 * valid.
 */
export interface PsLiteRelayStatusDetail {
  code?: number;
  reason?: string;
  /** Random 16-hex tag of the current WebSocket connection (`?tag=`). */
  connTag?: string;
}

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
  socket: PsLiteRelayWebSocket;
  closed: boolean;
  ready: boolean;
  handling: boolean;
  tls?: PsLiteRelayTlsStream;
  /** Relay-generated stream id from `stream.open`, when the relay sends one. */
  streamRef?: string;
  /** connTag of the socket this stream arrived on. */
  connTag: string;
  /** HTTP requests seen on this stream (read_ref suffix). */
  requestSeq: number;
  activeRead?: ReadTracker;
}

interface ReadTracker {
  ids: Omit<PsLiteReadEventIds, "at">;
  startedAt: number;
  /** undefined until the visibility source reports visible or hidden. */
  hiddenDuring: boolean | undefined;
  done: boolean;
}

type ReadFinish = {
  /** "classify" defers the empty-body check to the async dispatch. */
  outcome: PsLiteReadOutcome | "classify";
  status?: number;
  granteeRef?: Promise<string | undefined>;
  bytesOut?: number;
  gzip?: boolean;
  body?: Uint8Array;
  contentType?: string;
};

interface ControlMessage {
  type: string;
  streamId?: number;
  streamRef?: unknown;
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
  connTag?: string,
): string {
  const base = `${controlUrl.replace(/\/+$/, "")}/browser/${sessionId}`;
  return connTag ? `${base}?tag=${encodeURIComponent(connTag)}` : base;
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
          identityStore: options.tlsIdentityStore,
          logger: options.logger,
        })
      : options.tls;
  const streams = new Map<number, StreamState>();
  const pendingStreamData = new Map<number, Uint8Array[]>();
  const origin = options.origin ?? DEFAULT_ORIGIN;
  // On-schedule timers detect a half-open socket within 14s and start the
  // first reconnect within 15s, below the consumer's 20s request budget.
  // Throttled timers retain the evidence-based grace window below.
  const heartbeatIntervalMs = options.heartbeatIntervalMs ?? 2_000;
  const heartbeatTimeoutMs = options.heartbeatTimeoutMs ?? 10_000;
  const reconnectInitialDelayMs = options.reconnectInitialDelayMs ?? 1_000;
  const reconnectMaxDelayMs = options.reconnectMaxDelayMs ?? 30_000;
  let issueToken: string | undefined;
  let closed = false;
  // Every stream and callback belongs to one socket, never its replacement.
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
  // Fresh per WebSocket connection; joins device and relay telemetry.
  let connTag = randomConnTag();

  const log = (line: string) => options.logger?.(line);

  const emitStatus = (
    status: PsLiteRelayStatus,
    detail?: PsLiteRelayStatusDetail,
  ) => options.onStatus?.(status, { ...detail, connTag });

  const logHookError = (error: unknown) =>
    log(
      `relay read event hook failed: ${error instanceof Error ? error.message : String(error)}`,
    );

  // Read events never run on the response path. They are queued and one
  // shared timer drains the whole queue in a later macrotask (after the
  // response is written and the stream closed). Each event resolves on its
  // own, so a slow one never holds back the rest, and the hook's result is
  // never awaited. The queue is capped: throttled timers in a hidden tab must
  // not let it grow without bound.
  type ReadEventProducer = () => PsLiteReadEvent | Promise<PsLiteReadEvent>;
  const readQueue: ReadEventProducer[] = [];
  let readFlushTimer: ReturnType<typeof setTimeout> | undefined;
  let droppedReadEvents = 0;
  const flushReadEvents = () => {
    readFlushTimer = undefined;
    const batch = readQueue.splice(0);
    const hook = options.onReadEvent;
    if (closed || !hook) return;
    if (droppedReadEvents > 0) {
      log(`relay read events dropped (queue full): ${droppedReadEvents}`);
      droppedReadEvents = 0;
    }
    for (const produce of batch) {
      void Promise.resolve()
        .then(produce)
        .then((event) => hook(event))
        .catch(logHookError);
    }
  };
  const dispatchReadEvent = (produce: ReadEventProducer) => {
    if (closed || !options.onReadEvent) return;
    if (readQueue.length >= MAX_QUEUED_READ_EVENTS) {
      readQueue.shift();
      droppedReadEvents += 1;
    }
    readQueue.push(produce);
    readFlushTimer ??= setTimeout(flushReadEvents, 0);
  };
  const stopReadEvents = () => {
    readQueue.length = 0;
    if (readFlushTimer !== undefined) {
      clearTimeout(readFlushTimer);
      readFlushTimer = undefined;
    }
  };

  // The host decides where visibility comes from (see
  // PsLiteRelayClientOptions.appVisibility); the document is the default.
  const appVisibility = (): PsLiteAppVisibility => {
    try {
      const state = options.appVisibility
        ? options.appVisibility()
        : documentVisibility();
      return state === "visible" || state === "hidden" ? state : "unknown";
    } catch {
      return "unknown";
    }
  };
  const sampleHidden = (tracker: ReadTracker) => {
    const visibility = appVisibility();
    if (visibility === "hidden") tracker.hiddenDuring = true;
    else if (visibility === "visible") tracker.hiddenDuring ??= false;
    return visibility;
  };

  const beginRead = (
    stream: StreamState,
    request: ParsedHttpRequest,
  ): ReadTracker | undefined => {
    const seq = stream.requestSeq;
    stream.requestSeq += 1;
    const scope = relayReadScope(request);
    if (scope === undefined) return undefined;
    const tracker: ReadTracker = {
      ids: {
        readRef: `${stream.streamRef ?? crypto.randomUUID()}:${seq}`,
        ...(stream.streamRef ? { streamRef: stream.streamRef } : {}),
        connTag: stream.connTag,
        scope,
        method: request.method.toUpperCase(),
      },
      startedAt: Date.now(),
      hiddenDuring: undefined,
      done: false,
    };
    const visibility = sampleHidden(tracker);
    stream.activeRead = tracker;
    const received: PsLiteReadEvent = {
      type: "ps_read_received",
      at: tracker.startedAt,
      ...tracker.ids,
      appVisibility: visibility,
    };
    dispatchReadEvent(() => received);
    return tracker;
  };

  /** Records the end synchronously; builds and dispatches the event later. */
  const finishRead = (tracker: ReadTracker | undefined, result: ReadFinish) => {
    if (!tracker || tracker.done) return;
    tracker.done = true;
    sampleHidden(tracker);
    const finishedAt = Date.now();
    const durationMs = Math.max(0, finishedAt - tracker.startedAt);
    const hiddenDuring = tracker.hiddenDuring;
    // Keep only what the empty check can use: a body over the cap is never
    // empty, so a large body is not held while the event waits.
    const emptyCheckBody =
      result.body && result.body.length <= EMPTY_CHECK_MAX_BYTES
        ? result.body
        : undefined;
    const { status, contentType, granteeRef: granteeRefPromise } = result;
    const outcomeOrClassify = result.outcome;
    const bytesOut = result.bytesOut ?? 0;
    const gzip = result.gzip ?? false;
    dispatchReadEvent(async () => {
      const outcome =
        outcomeOrClassify === "classify"
          ? classifyReadOutcome(status ?? 0, emptyCheckBody, contentType)
          : outcomeOrClassify;
      const granteeRef = validGranteeRef(
        granteeRefPromise
          ? await withTimeout(granteeRefPromise, GRANTEE_REF_WAIT_MS)
          : undefined,
      );
      return {
        type: "ps_read_finished",
        at: finishedAt,
        ...tracker.ids,
        ...(granteeRef ? { granteeRef } : {}),
        ...(status !== undefined ? { status } : {}),
        outcome,
        bytesOut,
        gzip,
        durationMs,
        ...(hiddenDuring !== undefined ? { hiddenDuring } : {}),
      };
    });
  };

  // hidden_during: a read in flight while the page/webview goes hidden. Only
  // the document's own events when the document is the visibility source.
  const visibilityDocument = options.appVisibility
    ? undefined
    : readVisibilityDocument();
  const onVisibilityChange = () => {
    if (visibilityDocument?.visibilityState !== "hidden") return;
    for (const stream of streams.values()) {
      if (stream.activeRead && !stream.activeRead.done) {
        stream.activeRead.hiddenDuring = true;
      }
    }
  };
  let visibilityListening = false;
  if (visibilityDocument) {
    try {
      visibilityDocument.addEventListener(
        "visibilitychange",
        onVisibilityChange,
      );
      visibilityListening = true;
    } catch {
      // No listener: hiddenDuring falls back to the received/finished samples.
    }
  }
  const stopVisibilityListener = () => {
    if (!visibilityListening || !visibilityDocument) return;
    visibilityListening = false;
    try {
      visibilityDocument.removeEventListener(
        "visibilitychange",
        onVisibilityChange,
      );
    } catch {
      // Ignore.
    }
  };

  const isLive = (stream: StreamState) =>
    !closed &&
    !stream.closed &&
    stream.socket === socket &&
    socket.readyState === socket.OPEN &&
    streams.get(stream.streamId) === stream;

  const sendText = (message: unknown, target = socket) => {
    if (!closed && target === socket && target.readyState === target.OPEN) {
      target.send(JSON.stringify(message));
    }
  };

  const sendData = (stream: StreamState, payload: Uint8Array) => {
    if (isLive(stream)) {
      stream.socket.send(encodeDataFrame(stream.streamId, payload));
    }
  };

  const disposeStream = (stream: StreamState) => {
    if (stream.closed) return;
    stream.closed = true;
    // A read still in flight when its stream dies never reaches the wire.
    finishRead(stream.activeRead, { outcome: "stream_closed" });
    if (streams.get(stream.streamId) === stream) {
      streams.delete(stream.streamId);
      pendingStreamData.delete(stream.streamId);
    }
    // Invalidate before calling external code that may re-enter the client.
    const connection = stream.tls;
    stream.tls = undefined;
    connection?.close?.();
  };

  const closeStream = (stream: StreamState, reason: string) => {
    if (!isLive(stream)) return;
    disposeStream(stream);
    sendText(
      { type: "stream.close", streamId: stream.streamId, reason },
      stream.socket,
    );
  };

  const disposeStreams = () => {
    for (const stream of [...streams.values()]) disposeStream(stream);
    pendingStreamData.clear();
  };

  /** Returns false when the stream died before the last chunk was sent. */
  const writePlaintextResponse = (
    stream: StreamState,
    responseBytes: Uint8Array,
  ): boolean => {
    if (!isLive(stream)) return false;
    if (!stream.tls) {
      for (const chunk of chunks(responseBytes, RESPONSE_CHUNK_BYTES)) {
        sendData(stream, chunk);
      }
      return isLive(stream);
    }

    const responseChunks = chunks(responseBytes, RESPONSE_CHUNK_BYTES);
    for (let index = 0; index < responseChunks.length; index += 1) {
      if (!isLive(stream)) return false;
      const step = stream.tls.writePlaintext(
        responseChunks[index],
        index === responseChunks.length - 1,
      );
      for (const chunk of chunks(step.tls, RESPONSE_CHUNK_BYTES)) {
        if (chunk.length > 0) {
          sendData(stream, chunk);
        }
      }
    }
    return isLive(stream);
  };

  const drainHttpRequests = async (stream: StreamState) => {
    while (isLive(stream)) {
      const parsed = parseHttpRequest(stream.plaintext);
      if (!parsed) {
        return;
      }

      stream.plaintext = stream.plaintext.slice(parsed.consumedBytes);
      const read = beginRead(stream, parsed.request);
      let relayed: RelayHttpResult;
      try {
        relayed = await handleRelayHttpRequest(
          options.runtime,
          parsed.request,
          origin,
          Boolean(read),
        );
      } catch (error) {
        finishRead(read, { outcome: "handler_error" });
        throw error;
      }
      const { response } = relayed;
      const finish = (outcome: ReadFinish["outcome"]): ReadFinish => ({
        outcome,
        status: relayed.status,
        granteeRef: relayed.granteeRef,
        bytesOut: response.length,
        gzip: relayed.gzip,
      });
      if (!isLive(stream)) {
        finishRead(read, { ...finish("stream_closed"), bytesOut: 0 });
        return;
      }
      // `response` is a binary (latin1) string: buildHttpResponse appends the
      // body via bytesToBinary, so each char code 0x00–0xFF is one body byte.
      // It must be turned back into bytes the same way (binaryToBytes), NOT
      // UTF-8 re-encoded — textToBytes would expand every byte >= 0x80 into a
      // 2-byte sequence, corrupting binary payloads (e.g. OpenPGP-encrypted
      // files fail downstream with "not a valid OpenPGP message"). ASCII/JSON
      // bodies survive UTF-8, which is why only encrypted binary downloads broke.
      let written: boolean;
      try {
        written = writePlaintextResponse(stream, binaryToBytes(response));
      } catch (error) {
        finishRead(read, { ...finish("tls_error"), bytesOut: 0 });
        throw error;
      }
      // Finish before closeStream: disposal would report stream_closed.
      finishRead(
        read,
        written
          ? {
              ...finish("classify"),
              body: relayed.plainBody,
              contentType: relayed.contentType,
            }
          : finish("stream_closed"),
      );
      closeStream(stream, "http_response_sent");
      return;
    }
  };

  const handlePlaintext = (stream: StreamState, plaintext: Uint8Array) => {
    if (!isLive(stream) || stream.handling || plaintext.length === 0) {
      return;
    }
    stream.plaintext += bytesToBinary(plaintext);
    if (!parseHttpRequest(stream.plaintext)) return;
    stream.handling = true;
    void drainHttpRequests(stream).catch((error: unknown) => {
      if (!isLive(stream)) return;
      log(error instanceof Error ? error.message : String(error));
      closeStream(stream, "handler_error");
    });
  };

  const processPayload = (stream: StreamState, payload: Uint8Array) => {
    if (!isLive(stream) || !stream.ready) return;
    if (!stream.tls) {
      handlePlaintext(stream, payload);
      return;
    }

    try {
      const step = stream.tls.processTls(payload);
      if (step.tls.length > 0) {
        sendData(stream, step.tls);
      }
      handlePlaintext(stream, step.plaintext);
    } catch (error) {
      log(error instanceof Error ? error.message : String(error));
      closeStream(stream, "tls_error");
    }
  };

  const openStream = async (streamId: number, streamRef?: string) => {
    const previous = streams.get(streamId);
    if (previous) disposeStream(previous);
    const stream: StreamState = {
      streamId,
      plaintext: "",
      socket,
      closed: false,
      ready: !tls,
      handling: false,
      ...(streamRef ? { streamRef } : {}),
      connTag,
      requestSeq: 0,
    };
    // Register before awaiting creation so cancellation can invalidate it.
    streams.set(streamId, stream);
    try {
      if (tls) {
        const connection = await tls.createStream({
          sessionId: options.sessionId,
          streamId,
          issueToken,
        });
        if (!isLive(stream)) {
          connection.close?.();
          return;
        }
        stream.tls = connection;
        stream.ready = true;
      }
      if (!isLive(stream)) return;
      const buffered = pendingStreamData.get(streamId) ?? [];
      pendingStreamData.delete(streamId);
      for (const payload of buffered) processPayload(stream, payload);
    } catch (error) {
      if (!isLive(stream)) return;
      log(error instanceof Error ? error.message : String(error));
      closeStream(stream, "stream_open_error");
    }
  };

  const handleControl = (message: ControlMessage) => {
    if (message.type === "session.ready") {
      issueToken = message.issueToken;
      emitStatus("connected");
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
      void openStream(message.streamId, parseStreamRef(message.streamRef));
      return;
    }

    if (
      message.type === "stream.close" &&
      typeof message.streamId === "number"
    ) {
      const stream = streams.get(message.streamId);
      if (stream) disposeStream(stream);
      pendingStreamData.delete(message.streamId);
    }
  };

  const handleDataFrame = (data: string | ArrayBuffer | Uint8Array) => {
    const frame = decodeDataFrame(data);
    if (!frame) {
      return;
    }

    const stream = streams.get(frame.streamId);
    if (!stream || !stream.ready) {
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
    connTag = randomConnTag();
    socket = createSocket(
      options.webSocketFactory,
      psLiteRelayControlUrl(options.sessionId, baseControlUrl, connTag),
    );
    const currentSocket = socket;
    const isCurrent = () => !closed && socket === currentSocket;
    const acceptsFrames = () =>
      isCurrent() && currentSocket.readyState === currentSocket.OPEN;
    socket.binaryType = "arraybuffer";
    emitStatus("connecting");

    socket.onopen = () => {
      if (!acceptsFrames()) return;
      reconnectAttempts = 0;
      startHeartbeat();
      emitStatus("connected");
    };
    socket.onmessage = (event) => {
      if (!acceptsFrames()) return;
      lastFrameReceivedAt = Date.now();
      if (typeof event.data === "string") {
        handleControl(JSON.parse(event.data) as ControlMessage);
        return;
      }
      handleDataFrame(event.data);
    };
    socket.onclose = (event) => {
      if (socket !== currentSocket) return;
      stopHeartbeat();
      disposeStreams();
      issueToken = undefined;
      const detail = { code: event?.code, reason: event?.reason };
      if (closed) {
        stopVisibilityListener();
        stopReadEvents();
        emitStatus("closed", detail);
        return;
      }
      if (event?.code === RELAY_CLOSE_SESSION_REPLACED) {
        // Another connection (typically a second tab) now owns this session.
        // Reconnecting would evict it and start a session tug-of-war, so this
        // client steps down for good and lets the host surface the handoff.
        closed = true;
        stopVisibilityListener();
        stopReadEvents();
        // Cancel any reconnect already scheduled by an earlier drop so a
        // pending timer can't fire connect() after we've stepped down.
        if (reconnectTimer !== undefined) {
          clearTimeout(reconnectTimer);
          reconnectTimer = undefined;
        }
        log("relay session replaced by another connection — not reconnecting");
        emitStatus("replaced", detail);
        return;
      }
      emitStatus("disconnected", detail);
      scheduleReconnect();
    };
    socket.onerror = () => {
      if (!isCurrent() || currentSocket.readyState > currentSocket.OPEN) {
        return;
      }
      emitStatus("error");
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
      if (closed) return;
      closed = true;
      stopHeartbeat();
      stopVisibilityListener();
      stopReadEvents();
      if (reconnectTimer !== undefined) {
        clearTimeout(reconnectTimer);
        reconnectTimer = undefined;
      }
      disposeStreams();
      socket.close(1000, reason);
    },
  };
}

interface RelayHttpResult {
  /** Full HTTP/1.1 response as a binary (latin1) string. */
  response: string;
  status: number;
  /** Body before gzip, for the empty-result check. */
  plainBody: Uint8Array;
  contentType?: string;
  gzip: boolean;
  granteeRef?: Promise<string | undefined>;
}

async function handleRelayHttpRequest(
  runtime: PsLiteRuntime,
  request: ParsedHttpRequest,
  origin: string,
  isRead: boolean,
): Promise<RelayHttpResult> {
  const bridgeRequest: PsLiteBridgeRequest = {
    requestId: crypto.randomUUID(),
    method: request.method,
    path: request.path,
    query: request.query,
    headers: request.headers,
    body: encodeBase64(request.body),
  };
  // The grantee label travels in-process (an observer on the Request
  // object), never as a header a requester could set or read.
  let granteeRef: Promise<string | undefined> | undefined;
  const bridgeResponse = await handlePsLiteBridgeRequest(
    runtime,
    bridgeRequest,
    {
      origin,
      ...(isRead
        ? {
            onReadGrantee: (ref: Promise<string | undefined>) => {
              granteeRef = ref;
            },
          }
        : {}),
    },
  );
  const contentType = headerValue(bridgeResponse.headers, "content-type");
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
  const base = {
    status: bridgeResponse.status,
    plainBody: bodyBytes,
    ...(contentType !== undefined ? { contentType } : {}),
    ...(granteeRef ? { granteeRef } : {}),
  };
  if (
    acceptsGzip &&
    !alreadyEncoded &&
    bodyBytes.length >= GZIP_MIN_BYTES &&
    typeof CompressionStream !== "undefined"
  ) {
    const gzipped = await gzipBytes(bodyBytes);
    return {
      ...base,
      gzip: true,
      response: buildHttpResponse(bridgeResponse, {
        bodyOverride: gzipped,
        contentEncoding: "gzip",
      }),
    };
  }
  return {
    ...base,
    gzip: false,
    response: buildHttpResponse(bridgeResponse, { bodyOverride: bodyBytes }),
  };
}

function headerValue(
  headers: Record<string, string>,
  name: string,
): string | undefined {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) return value;
  }
  return undefined;
}

const DATA_PATH_PREFIX = "/v1/data/";

/** Scope of a relayed read, or undefined when the request is not a read. */
function relayReadScope(request: ParsedHttpRequest): string | undefined {
  const method = request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") return undefined;
  if (!request.path.startsWith(DATA_PATH_PREFIX)) return undefined;
  // Only the data read itself (`/v1/data/<scope>`) counts. Sub-routes such as
  // `/versions` and `/lineage` are metadata reads and would skew read rates.
  const rest = request.path.slice(DATA_PATH_PREFIX.length).split("?")[0];
  if (!rest || rest.includes("/")) return undefined;
  const segment = rest;
  let scope: string;
  try {
    scope = decodeURIComponent(segment);
  } catch {
    return INVALID_SCOPE;
  }
  if (scope.length > MAX_SCOPE_LENGTH) return INVALID_SCOPE;
  const parsed = parseDataScopeContract(scope);
  return parsed.ok ? parsed.scope : INVALID_SCOPE;
}

const INVALID_SCOPE = "invalid";
const MAX_SCOPE_LENGTH = 128;
// Hashing resolves in microseconds; the cap only keeps a stuck promise from
// holding back later events.
const GRANTEE_REF_WAIT_MS = 1_000;
// Read events waiting for the next flush; the oldest are dropped beyond this.
const MAX_QUEUED_READ_EVENTS = 200;

function validGranteeRef(value: unknown): string | undefined {
  return typeof value === "string" && /^(owner|[0-9a-f]{12})$/.test(value)
    ? value
    : undefined;
}

async function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
): Promise<T | undefined> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise.catch(() => undefined),
      new Promise<undefined>((resolve) => {
        timer = setTimeout(() => resolve(undefined), ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

// Bodies larger than this are never "empty"; skip parsing them.
const EMPTY_CHECK_MAX_BYTES = 64 * 1024;

function classifyReadOutcome(
  status: number,
  body: Uint8Array | undefined,
  contentType?: string,
): PsLiteReadOutcome {
  if (status === 401 || status === 403) return "denied";
  if (status === 402) return "payment_required";
  if (status === 404) return "not_found";
  if (status >= 400) return "error";
  if (status < 200 || status >= 300) return "ok";
  return body && isEmptyJsonBody(body, contentType) ? "empty" : "ok";
}

function isEmptyJsonBody(body: Uint8Array, contentType?: string): boolean {
  if (body.length === 0 || body.length > EMPTY_CHECK_MAX_BYTES) return false;
  if (contentType !== undefined && !/json/i.test(contentType)) return false;
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return false;
  }
  if (isEmptyValue(value)) return true;
  if (value && typeof value === "object" && !Array.isArray(value)) {
    const record = value as Record<string, unknown>;
    if (!("data" in record)) return false;
    const data = record.data;
    if (isEmptyValue(data)) return true;
    // `{ data: { sleep: [], readiness: [] } }`: every collection empty.
    if (data && typeof data === "object" && !Array.isArray(data)) {
      const values = Object.values(data as Record<string, unknown>);
      return values.length > 0 && values.every(isEmptyValue);
    }
  }
  return false;
}

function isEmptyValue(value: unknown): boolean {
  if (value === null || value === undefined || value === "") return true;
  if (Array.isArray(value)) return value.length === 0;
  if (typeof value === "object") {
    return Object.keys(value as Record<string, unknown>).length === 0;
  }
  return false;
}

function parseStreamRef(value: unknown): string | undefined {
  return typeof value === "string" && /^[A-Za-z0-9-]{1,64}$/.test(value)
    ? value
    : undefined;
}

function randomConnTag(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

interface VisibilityDocument {
  visibilityState?: string;
  addEventListener(type: string, listener: () => void): void;
  removeEventListener(type: string, listener: () => void): void;
}

function readVisibilityDocument(): VisibilityDocument | undefined {
  const candidate = (globalThis as { document?: unknown }).document as
    Partial<VisibilityDocument> | undefined;
  if (
    !candidate ||
    typeof candidate.addEventListener !== "function" ||
    typeof candidate.removeEventListener !== "function"
  ) {
    return undefined;
  }
  return candidate as VisibilityDocument;
}

function documentVisibility(): PsLiteAppVisibility {
  const state = (globalThis as { document?: { visibilityState?: unknown } })
    .document?.visibilityState;
  return state === "visible" || state === "hidden" ? state : "unknown";
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
