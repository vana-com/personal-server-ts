import { describe, expect, it } from "vitest";
import {
  createBearerTokenPsLiteAuth,
  createMemoryPsLiteStorage,
  createPsLiteRuntime,
} from "./runtime.js";
import {
  decodeDataFrame,
  encodeDataFrame,
  psLiteRelayControlUrl,
  startPsLiteRelayClient,
  type PsLiteRelayWebSocket,
} from "./relay.js";

class FakeRelayWebSocket implements PsLiteRelayWebSocket {
  binaryType = "arraybuffer";
  readyState = 1;
  readonly OPEN = 1;
  readonly CONNECTING = 0;
  onopen: (() => void) | null = null;
  onmessage:
    | ((event: { data: string | ArrayBuffer | Uint8Array }) => void)
    | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readonly sent: Array<string | Uint8Array> = [];

  send(data: string | Uint8Array): void {
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
    this.onclose?.();
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

async function flushRelayTasks() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe("startPsLiteRelayClient", () => {
  it("adapts PoC relay streams into the browser PS Lite API runtime", async () => {
    const sockets: FakeRelayWebSocket[] = [];
    const runtime = createPsLiteRuntime({
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

  it("returns ps_unavailable over the relay when browser runtime is inactive", async () => {
    const socket = new FakeRelayWebSocket();
    startPsLiteRelayClient({
      sessionId: "session123",
      runtime: createPsLiteRuntime({
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
      runtime: createPsLiteRuntime({
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
