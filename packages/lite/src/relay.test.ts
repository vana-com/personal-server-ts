import { afterEach, describe, expect, it, vi } from "vitest";
import { createBearerTokenPsLiteAuth, createPsLiteRuntime } from "./runtime.js";
import {
  createMemoryPsLiteAccessLogStore,
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./test-support/memory.js";
import { createMockPsLiteGateway } from "./test-support/gateway.js";
import {
  buildHttpResponse,
  createRelayDrainGatedReadFulfillmentReporter,
  decodeDataFrame,
  encodeDataFrame,
  psLiteRelayControlUrl,
  startPsLiteRelayClient,
  type PsLiteRelayClientOptions,
  type PsLiteRelayWebSocket,
} from "./relay.js";

type PsLiteRuntimeOptions = Parameters<typeof createPsLiteRuntime>[0];

function createTestRuntime(options: Partial<PsLiteRuntimeOptions> = {}) {
  const accessLogStore = createMemoryPsLiteAccessLogStore();
  const defaults: PsLiteRuntimeOptions = {
    storage: createMemoryPsLiteStorage(),
    gateway: createMockPsLiteGateway(),
    accessLogReader: accessLogStore,
    accessLogWriter: accessLogStore,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
  };
  return createPsLiteRuntime({
    ...defaults,
    ...options,
    storage: options.storage ?? defaults.storage,
    gateway: options.gateway ?? defaults.gateway,
    accessLogReader: options.accessLogReader ?? defaults.accessLogReader,
    accessLogWriter: options.accessLogWriter ?? defaults.accessLogWriter,
    tokenStore: options.tokenStore ?? defaults.tokenStore,
    saveConfig: options.saveConfig ?? defaults.saveConfig,
    stateCapabilities: {
      ...defaults.stateCapabilities,
      ...options.stateCapabilities,
    },
  });
}

class FakeRelayWebSocket implements PsLiteRelayWebSocket {
  binaryType = "arraybuffer";
  readyState = 1;
  readonly OPEN = 1;
  readonly CONNECTING = 0;
  bufferedAmount = 0;
  onopen: (() => void) | null = null;
  onmessage:
    | ((event: { data: string | ArrayBuffer | Uint8Array }) => void)
    | null = null;
  onclose: ((event?: { code?: number; reason?: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  readonly sent: Array<string | Uint8Array> = [];

  send(data: string | Uint8Array): void {
    this.sent.push(data);
  }

  close(code?: number, reason?: string): void {
    this.readyState = 3;
    this.onclose?.({ code, reason });
  }

  receive(data: string | Uint8Array): void {
    this.onmessage?.({ data });
  }
}

function httpRequest(
  method: string,
  target: string,
  headers: Record<string, string>,
  body = "",
): Uint8Array {
  const mergedHeaders = {
    host: "relay.test",
    ...headers,
    "content-length": String(new TextEncoder().encode(body).length),
  };
  const head = [
    `${method} ${target} HTTP/1.1`,
    ...Object.entries(mergedHeaders).map(([key, value]) => `${key}: ${value}`),
    "",
    "",
  ].join("\r\n");
  return new TextEncoder().encode(head + body);
}

function sentDataFrames(socket: FakeRelayWebSocket) {
  return socket.sent
    .filter((message): message is Uint8Array => message instanceof Uint8Array)
    .map((message) => decodeDataFrame(message))
    .filter((frame): frame is NonNullable<typeof frame> => frame !== null);
}

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function flushRelayTasks() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("startPsLiteRelayClient", () => {
  it("adapts PoC relay streams into the browser PS Lite API runtime", async () => {
    const sockets: FakeRelayWebSocket[] = [];
    const runtime = createTestRuntime({
      storage: createMemoryPsLiteStorage(),
      auth: createBearerTokenPsLiteAuth({
        ownerToken: "owner-token",
        builderToken: "builder-token",
      }),
      active: true,
      now: () => new Date("2026-05-08T00:00:00.000Z"),
    });

    const client = startPsLiteRelayClient({
      sessionId: "session123",
      runtime,
      controlUrl: "wss://relay.example",
      tls: false,
      webSocketFactory(url) {
        expect(url).toBe("wss://relay.example/browser/session123");
        const socket = new FakeRelayWebSocket();
        sockets.push(socket);
        return socket;
      },
    });

    expect(client.url).toBe("wss://relay.example/browser/session123");
    const socket = sockets[0];
    socket.receive(JSON.stringify({ type: "session.ready" }));

    socket.receive(JSON.stringify({ type: "stream.open", streamId: 1 }));
    socket.receive(
      encodeDataFrame(
        1,
        httpRequest(
          "POST",
          "/v1/data/instagram.profile",
          {
            authorization: "Bearer owner-token",
            "content-type": "application/json",
          },
          JSON.stringify({ username: "relay_user" }),
        ),
      ),
    );
    await flushRelayTasks();

    socket.receive(JSON.stringify({ type: "stream.open", streamId: 2 }));
    socket.receive(
      encodeDataFrame(
        2,
        httpRequest("GET", "/v1/data/instagram.profile?grantId=grant-1", {
          authorization: "Bearer builder-token",
        }),
      ),
    );
    await flushRelayTasks();

    const frames = sentDataFrames(socket);
    expect(new TextDecoder().decode(frames[0].payload)).toContain(
      "HTTP/1.1 201 Created",
    );

    const readResponse = new TextDecoder().decode(frames[1].payload);
    expect(readResponse).toContain("HTTP/1.1 200 OK");
    expect(readResponse).toContain('"username":"relay_user"');
    expect(
      socket.sent.filter(
        (message) =>
          typeof message === "string" &&
          JSON.parse(message).type === "stream.close",
      ),
    ).toHaveLength(2);
  });

  it("chunks large relay responses instead of sending one oversized frame", async () => {
    const socket = new FakeRelayWebSocket();
    const body = JSON.stringify({ payload: "x".repeat(210_000) });

    startPsLiteRelayClient({
      sessionId: "large-response-session",
      runtime: {
        fetch: async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      } as ReturnType<typeof createTestRuntime>,
      tls: false,
      webSocketFactory: () => socket,
    });

    socket.receive(JSON.stringify({ type: "session.ready" }));
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 1 }));
    socket.receive(encodeDataFrame(1, httpRequest("GET", "/large", {})));
    await flushRelayTasks();

    const frames = sentDataFrames(socket);
    expect(frames.length).toBeGreaterThan(1);
    for (const frame of frames) {
      expect(frame.payload.length).toBeLessThanOrEqual(16 * 1024);
    }

    const response = new TextDecoder().decode(
      concatBytes(frames.map((frame) => frame.payload)),
    );
    expect(response).toContain("HTTP/1.1 200 OK");
    expect(response).toContain(`content-length: ${body.length}`);
    expect(response.endsWith(body)).toBe(true);
  });

  it("chunks large TLS relay responses and closes only after the final chunk", async () => {
    const socket = new FakeRelayWebSocket();
    const body = JSON.stringify({ payload: "x".repeat(210_000) });
    const closeFlags: boolean[] = [];

    startPsLiteRelayClient({
      sessionId: "large-tls-response-session",
      runtime: {
        fetch: async () =>
          new Response(body, {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      } as ReturnType<typeof createTestRuntime>,
      webSocketFactory: () => socket,
      tls: {
        async createStream() {
          return {
            processTls(payload) {
              return { plaintext: payload, tls: new Uint8Array() };
            },
            writePlaintext(payload, endStream) {
              closeFlags.push(endStream);
              const expanded = new Uint8Array(payload.length + 1024);
              expanded.set(payload);
              return { plaintext: new Uint8Array(), tls: expanded };
            },
          };
        },
      },
    });

    socket.receive(JSON.stringify({ type: "session.ready" }));
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 1 }));
    await flushRelayTasks();
    socket.receive(encodeDataFrame(1, httpRequest("GET", "/large", {})));
    await flushRelayTasks();

    const frames = sentDataFrames(socket);
    expect(frames.length).toBeGreaterThan(1);
    expect(frames.length).toBeGreaterThan(closeFlags.length);
    for (const frame of frames) {
      expect(frame.payload.length).toBeLessThanOrEqual(16 * 1024);
    }
    expect(closeFlags.length).toBeGreaterThan(1);
    expect(closeFlags.slice(0, -1).every((flag) => flag === false)).toBe(true);
    expect(closeFlags.at(-1)).toBe(true);
  });

  it("returns ps_unavailable over the relay when browser runtime is inactive", async () => {
    const socket = new FakeRelayWebSocket();
    startPsLiteRelayClient({
      sessionId: "session123",
      runtime: createTestRuntime({
        storage: createMemoryPsLiteStorage(),
        active: false,
      }),
      tls: false,
      webSocketFactory: () => socket,
    });

    socket.receive(JSON.stringify({ type: "session.ready" }));
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 1 }));
    socket.receive(
      encodeDataFrame(1, httpRequest("GET", "/v1/data/instagram.profile", {})),
    );
    await flushRelayTasks();

    const [frame] = sentDataFrames(socket);
    const response = new TextDecoder().decode(frame.payload);
    expect(response).toContain("HTTP/1.1 503 Service Unavailable");
    expect(response).toContain("PS_UNAVAILABLE");
  });

  it("accepts an injected TLS adapter for public TCP relay streams", async () => {
    const socket = new FakeRelayWebSocket();
    let closed = false;
    const tlsInputs: unknown[] = [];
    const prepareInputs: unknown[] = [];

    startPsLiteRelayClient({
      sessionId: "session123",
      runtime: createTestRuntime({
        storage: createMemoryPsLiteStorage(),
        active: true,
      }),
      webSocketFactory: () => socket,
      tls: {
        async prepare(input) {
          prepareInputs.push(input);
        },
        async createStream(input) {
          tlsInputs.push(input);
          return {
            processTls(payload) {
              return { plaintext: payload, tls: new Uint8Array() };
            },
            writePlaintext(payload) {
              return { plaintext: new Uint8Array(), tls: payload };
            },
            close() {
              closed = true;
            },
          };
        },
      },
    });

    socket.receive(
      JSON.stringify({ type: "session.ready", issueToken: "issue-token" }),
    );
    await flushRelayTasks();
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 7 }));
    await flushRelayTasks();
    socket.receive(encodeDataFrame(7, httpRequest("GET", "/health", {})));
    await flushRelayTasks();

    expect(prepareInputs).toEqual([
      {
        sessionId: "session123",
        issueToken: "issue-token",
      },
    ]);
    expect(tlsInputs).toEqual([
      {
        sessionId: "session123",
        streamId: 7,
        issueToken: "issue-token",
      },
    ]);
    const [frame] = sentDataFrames(socket);
    expect(new TextDecoder().decode(frame.payload)).toContain(
      "HTTP/1.1 200 OK",
    );
    expect(closed).toBe(true);
  });

  it("builds the same browser control URL as the PoC relay", () => {
    expect(psLiteRelayControlUrl("abc123")).toBe(
      "wss://control.34.16.49.200.sslip.io:8443/browser/abc123",
    );
  });
});

describe("buildHttpResponse binary safety", () => {
  // Regression: response bodies are emitted as a latin1 string (one char code
  // per byte) and the relay must turn them back into bytes via charCodeAt
  // (binaryToBytes), NOT TextEncoder. UTF-8 re-encoding expands every byte
  // >= 0x80 into a multi-byte sequence, corrupting binary payloads — e.g. an
  // OpenPGP-encrypted file then fails downstream with "not a valid OpenPGP
  // message". ASCII/JSON bodies are unaffected, which masked the bug.
  function base64(bytes: Uint8Array): string {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return Buffer.from(binary, "binary").toString("base64");
  }
  function bodyOf(wire: Uint8Array): Uint8Array {
    let head = "";
    for (const byte of wire) head += String.fromCharCode(byte);
    const sep = head.indexOf("\r\n\r\n");
    return wire.slice(sep + 4);
  }

  it("round-trips a binary body through charCodeAt conversion intact", () => {
    // Bytes >= 0x80 incl. an OpenPGP SKESK header (0xc3) and a NUL.
    const body = new Uint8Array([
      0xc3, 0x2e, 0x04, 0x09, 0xff, 0x80, 0x00, 0xfe,
    ]);
    const responseString = buildHttpResponse({
      status: 200,
      headers: { "content-type": "application/octet-stream" },
      body: base64(body),
    });

    // The fixed conversion (binaryToBytes / charCodeAt).
    const wire = Uint8Array.from(responseString, (char) => char.charCodeAt(0));
    expect(Array.from(bodyOf(wire))).toEqual(Array.from(body));

    // The previous buggy conversion (textToBytes / TextEncoder) corrupts it:
    // high bytes balloon into multi-byte UTF-8, so the body no longer matches.
    const corrupted = new TextEncoder().encode(responseString);
    expect(corrupted.length).toBeGreaterThan(wire.length);
    expect(Array.from(bodyOf(corrupted))).not.toEqual(Array.from(body));
  });

  it("round-trips a JSON/text body intact (the conversion supports both)", () => {
    const json = '{"username":"relay_user","emoji_free":true}';
    const body = new TextEncoder().encode(json);
    const responseString = buildHttpResponse({
      status: 200,
      headers: { "content-type": "application/json" },
      body: base64(body),
    });

    const wire = Uint8Array.from(responseString, (char) => char.charCodeAt(0));
    expect(Array.from(bodyOf(wire))).toEqual(Array.from(body));
    expect(new TextDecoder().decode(bodyOf(wire))).toBe(json);
    // content-length must match the actual body bytes for both text and binary.
    const headText = responseString.slice(
      0,
      responseString.indexOf("\r\n\r\n"),
    );
    expect(headText).toContain(`content-length: ${body.length}`);
  });

  it("uses the pre-encoded body override and emits content-encoding + matching content-length (BUI-591 gzip path)", () => {
    const original = new TextEncoder().encode(
      JSON.stringify({
        conversations: Array.from({ length: 50 }, (_, i) => i),
      }),
    );
    // Stand-in for the gzipped body the relay produces (gzip magic + high bytes).
    const encoded = new Uint8Array([
      0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ]);
    const responseString = buildHttpResponse(
      {
        status: 200,
        headers: { "content-type": "application/json" },
        body: base64(original),
      },
      { bodyOverride: encoded, contentEncoding: "gzip" },
    );

    const headText = responseString.slice(
      0,
      responseString.indexOf("\r\n\r\n"),
    );
    expect(headText.toLowerCase()).toContain("content-encoding: gzip");
    // content-length must reflect the encoded body, not the original.
    expect(headText).toContain(`content-length: ${encoded.length}`);
    const wire = Uint8Array.from(responseString, (char) => char.charCodeAt(0));
    expect(Array.from(bodyOf(wire))).toEqual(Array.from(encoded));
  });

  it("drops the upstream content-length so the gzip response carries exactly one, matching the compressed body (BUI-591)", () => {
    const original = new TextEncoder().encode(
      JSON.stringify({
        conversations: Array.from({ length: 50 }, (_, i) => i),
      }),
    );
    const encoded = new Uint8Array([
      0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ]);
    const responseString = buildHttpResponse(
      {
        status: 200,
        headers: {
          "content-type": "application/json",
          // The core raw-data path sets Content-Length; the bridge lowercases it.
          // This is the original (uncompressed) length — it must not survive.
          "content-length": String(original.length),
        },
        body: base64(original),
      },
      { bodyOverride: encoded, contentEncoding: "gzip" },
    );

    const headText = responseString.slice(
      0,
      responseString.indexOf("\r\n\r\n"),
    );
    const contentLengthLines = headText
      .split("\r\n")
      .filter((line) => line.toLowerCase().startsWith("content-length:"));
    expect(contentLengthLines).toEqual([`content-length: ${encoded.length}`]);
    // The stale uncompressed length must not appear anywhere in the head.
    expect(headText).not.toContain(`content-length: ${original.length}`);
  });
});

describe("startPsLiteRelayClient resilience", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  function startWithSockets(extra: Partial<PsLiteRelayClientOptions> = {}) {
    const sockets: FakeRelayWebSocket[] = [];
    const client = startPsLiteRelayClient({
      sessionId: "s1",
      runtime: createTestRuntime(),
      controlUrl: "wss://relay.example",
      tls: false,
      reconnectInitialDelayMs: 1_000,
      reconnectMaxDelayMs: 5_000,
      heartbeatIntervalMs: 1_000,
      heartbeatTimeoutMs: 2_500,
      webSocketFactory() {
        const socket = new FakeRelayWebSocket();
        sockets.push(socket);
        return socket;
      },
      ...extra,
    });
    return { sockets, client };
  }

  function pingCount(socket: FakeRelayWebSocket): number {
    return socket.sent.filter(
      (message): message is string =>
        typeof message === "string" &&
        (JSON.parse(message) as { type?: string }).type === "ping",
    ).length;
  }

  it("reconnects with backoff after an unexpected socket close", () => {
    vi.useFakeTimers();
    const { sockets } = startWithSockets();
    sockets[0].onopen?.();
    expect(sockets).toHaveLength(1);

    // Relay drops the connection (NOT an intentional client.close()).
    sockets[0].close();
    expect(sockets).toHaveLength(1); // reconnect is scheduled, not immediate

    vi.advanceTimersByTime(1_000); // reconnectInitialDelayMs elapses
    expect(sockets).toHaveLength(2); // reconnected
  });

  it("force-reconnects a half-open socket when pongs stop (heartbeat timeout)", () => {
    vi.useFakeTimers();
    const { sockets } = startWithSockets();
    sockets[0].onopen?.();

    vi.advanceTimersByTime(1_000); // first heartbeat tick → ping
    expect(pingCount(sockets[0])).toBeGreaterThanOrEqual(1);

    // No pong ever arrives → a later tick crosses heartbeatTimeoutMs and
    // force-closes the stale socket, which schedules a reconnect.
    vi.advanceTimersByTime(2_500);
    vi.advanceTimersByTime(1_000); // reconnect backoff elapses
    expect(sockets.length).toBeGreaterThanOrEqual(2);
  });

  it("stops for good when the relay replaces the session (close 1012)", () => {
    vi.useFakeTimers();
    const statuses: string[] = [];
    const { sockets } = startWithSockets({
      onStatus: (status) => statuses.push(status),
    });
    sockets[0].onopen?.();

    // Another tab claimed the same sessionId; the relay evicts this side.
    sockets[0].close(1012, "session replaced");
    vi.advanceTimersByTime(60_000);
    expect(sockets).toHaveLength(1); // no reconnect — ever
    expect(statuses).toContain("replaced");
    expect(statuses).not.toContain("disconnected");
  });

  it("cancels an already-scheduled reconnect when a 1012 lands mid-backoff", () => {
    vi.useFakeTimers();
    const statuses: string[] = [];
    const { sockets } = startWithSockets({
      onStatus: (status) => statuses.push(status),
    });
    sockets[0].onopen?.();

    // First an ordinary drop schedules a reconnect...
    sockets[0].close();
    // ...then, before the backoff elapses, a 1012 takeover arrives.
    sockets[0].close(1012, "session replaced");
    vi.advanceTimersByTime(60_000);

    // The pending reconnect timer must have been cancelled: no new socket.
    expect(sockets).toHaveLength(1);
    expect(statuses).toContain("replaced");
  });

  it("does not reconnect after an intentional close()", () => {
    vi.useFakeTimers();
    const statuses: string[] = [];
    const { sockets, client } = startWithSockets({
      onStatus: (status) => statuses.push(status),
    });
    sockets[0].onopen?.();

    client.close();
    vi.advanceTimersByTime(10_000);
    expect(sockets).toHaveLength(1);
    expect(statuses).toContain("closed");
  });
});

describe("whenDrained + drain-gated read fulfillment", () => {
  function startClient() {
    const sockets: FakeRelayWebSocket[] = [];
    const client = startPsLiteRelayClient({
      sessionId: "drain1",
      runtime: createTestRuntime(),
      controlUrl: "wss://relay.example",
      tls: false,
      webSocketFactory() {
        const socket = new FakeRelayWebSocket();
        sockets.push(socket);
        return socket;
      },
    });
    return { client, socket: sockets[0] };
  }

  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("resolves immediately when nothing is in flight", async () => {
    const { client } = startClient();
    await client.whenDrained({ pollIntervalMs: 5, timeoutMs: 100 });
    client.close();
  });

  it("waits for open streams and the socket send buffer to drain", async () => {
    const { client, socket } = startClient();
    socket.receive(JSON.stringify({ type: "session.ready" }));
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 7 }));
    await flushRelayTasks();

    let drained = false;
    const wait = client.whenDrained({ pollIntervalMs: 5 }).then(() => {
      drained = true;
    });

    await sleep(25);
    expect(drained).toBe(false); // stream in flight

    // Stream closes but the socket still holds unflushed response bytes.
    socket.bufferedAmount = 4096;
    socket.receive(JSON.stringify({ type: "stream.close", streamId: 7 }));
    await sleep(25);
    expect(drained).toBe(false); // buffer still flushing

    socket.bufferedAmount = 0;
    await wait;
    expect(drained).toBe(true);
    client.close();
  });

  it("resolves after timeoutMs even when never drained (no deadlock)", async () => {
    const { client, socket } = startClient();
    socket.receive(JSON.stringify({ type: "session.ready" }));
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 9 }));
    await flushRelayTasks();
    await client.whenDrained({ pollIntervalMs: 5, timeoutMs: 50 });
    client.close();
  });

  it("drain-gated reporter defers the report until the relay is drained", async () => {
    const events: unknown[] = [];
    const reporter = {
      report: async (event: never) => {
        events.push(event);
      },
    };

    // Without a relay client the report passes straight through.
    const passthrough = createRelayDrainGatedReadFulfillmentReporter(
      reporter,
      () => undefined,
    );
    await passthrough.report({ grantId: "g0" } as never);
    expect(events).toHaveLength(1);

    // With a relay mid-delivery, the report lands only after drain.
    const { client, socket } = startClient();
    socket.receive(JSON.stringify({ type: "session.ready" }));
    socket.receive(JSON.stringify({ type: "stream.open", streamId: 3 }));
    await flushRelayTasks();

    const gated = createRelayDrainGatedReadFulfillmentReporter(
      reporter,
      () => client,
    );
    const pending = gated.report({ grantId: "g1" } as never);
    await sleep(25);
    expect(events).toHaveLength(1); // still deferred: stream open

    socket.receive(JSON.stringify({ type: "stream.close", streamId: 3 }));
    await pending;
    expect(events).toHaveLength(2); // delivered -> reported
    client.close();
  });
});
