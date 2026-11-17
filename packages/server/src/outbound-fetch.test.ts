/**
 * The Node host's outbound `fetch` reuses a connection across a gap longer
 * than Node's own 4 s idle limit, against a peer that sends no `Keep-Alive`
 * hint (the data gateway and storage send none). Real sockets, real `fetch`.
 */
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { createServer as createTlsServer } from "node:https";
import { generateKeyPairSync } from "node:crypto";
import type { AddressInfo, Socket } from "node:net";
import forge from "node-forge";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createGatewayStreamSyncRegistry } from "@opendatalabs/personal-server-ts-core/stream-sync";
import { createKeepAliveFetch } from "./outbound-fetch.js";

const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

/** A peer like the gateway: keeps a connection open and sends no hint. */
async function peer(
  onRequest: (
    request: IncomingMessage,
    response: ServerResponse,
    sockets: Socket[],
  ) => void = (_request, response) => response.end("ok"),
) {
  const sockets: Socket[] = [];
  const server = createServer((request, response) => {
    // An explicit `Connection` header leaves out the `Keep-Alive: timeout=`
    // hint Node would add, so the client has only its own idle limit.
    response.setHeader("connection", "keep-alive");
    onRequest(request, response, sockets);
  });
  server.keepAliveTimeout = 60_000;
  server.on("connection", (socket) => sockets.push(socket));
  servers.push(server);
  await new Promise<void>((resolve) =>
    server.listen(0, "127.0.0.1", () => resolve()),
  );
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/`, sockets };
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe("createKeepAliveFetch", () => {
  it("reuses the socket for a request sent 6 s after the last one", async () => {
    const { url, sockets } = await peer();
    const { fetch: send } = createKeepAliveFetch();

    expect(await (await send(url)).text()).toBe("ok");
    await sleep(6_000);
    expect(await (await send(url)).text()).toBe("ok");

    expect(sockets).toHaveLength(1);
  }, 15_000);

  it("is needed: Node's default fetch opens a second connection after the same gap", async () => {
    const { url, sockets } = await peer();

    await (await fetch(url)).text();
    await sleep(6_000);
    await (await fetch(url)).text();

    expect(sockets).toHaveLength(2);
  }, 15_000);

  it("sends a PUT body over the reused socket", async () => {
    const received: string[] = [];
    const { url, sockets } = await peer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        received.push(`${request.method} ${Buffer.concat(chunks).length}`);
        response.statusCode = 201;
        response.end();
      });
    });
    const { fetch: send } = createKeepAliveFetch();

    for (const size of [1024 * 1024, 2048]) {
      await (
        await send(url, { method: "PUT", body: new Uint8Array(size) })
      ).text();
      // Right after a body is read the pool may not yet count its connection
      // as idle, and then opens a second one beside it. That is not a failure
      // to reuse, so the test lets the connection settle.
      await sleep(50);
    }

    expect(received).toEqual(["PUT 1048576", "PUT 2048"]);
    expect(sockets).toHaveLength(1);
  });

  it("still succeeds when the peer closed the idle socket before the next request", async () => {
    const { url, sockets } = await peer();
    const { fetch: send } = createKeepAliveFetch();

    expect(await (await send(url)).text()).toBe("ok");
    for (const socket of sockets) socket.destroy();
    await sleep(100);
    expect(await (await send(url)).text()).toBe("ok");

    expect(sockets).toHaveLength(2);
  });

  it("wraps the globalThis.fetch of its creation, so a wrapper installed on it applies", async () => {
    const original = globalThis.fetch;
    const seen: string[] = [];
    globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
      seen.push(String(input));
      return original(input, init);
    }) as typeof fetch;
    try {
      const { url } = await peer();
      const { fetch: send } = createKeepAliveFetch();
      globalThis.fetch = original;
      await (await send(url)).text();
      expect(seen).toEqual([url]);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("a reused socket the server resets", () => {
  const owner = "0x1111111111111111111111111111111111111111";

  /**
   * A peer that answers the first request of each connection with a 404 and
   * resets the connection on the next one without a reply: what a client sees
   * when the server closed the idle connection as the request went out.
   */
  async function resettingPeer() {
    const received: string[] = [];
    const perSocket = new Map<Socket, number>();
    const { url, sockets } = await peer((request, response) => {
      received.push(`${request.method} ${request.url}`);
      const count = (perSocket.get(request.socket) ?? 0) + 1;
      perSocket.set(request.socket, count);
      if (count > 1) return request.socket.destroy();
      response.statusCode = 404;
      response.end("{}");
    });
    return { url, sockets, received };
  }

  it("lets a registry read retry once, instead of reporting the registry unreachable", async () => {
    const { url, sockets } = await resettingPeer();
    const registry = createGatewayStreamSyncRegistry({
      gatewayUrl: url,
      ownerAddress: owner,
      fetch: createKeepAliveFetch().fetch,
    });

    expect(await registry.read("pdpp.a~b")).toEqual({ found: false });
    await sleep(100);
    expect(await registry.read("pdpp.c~d")).toEqual({ found: false });

    expect(sockets).toHaveLength(2);
  });

  it("does not send a POST again: the first may have reached the peer", async () => {
    const { url, received } = await resettingPeer();
    const { fetch: send } = createKeepAliveFetch();
    await (await send(url, { method: "POST", body: "a" })).text();
    await sleep(100);

    await expect(send(url, { method: "POST", body: "b" })).rejects.toThrow(
      "fetch failed",
    );

    expect(received).toEqual(["POST /", "POST /"]);
  });

  it("does not send a GET again when its connection had answered nothing", async () => {
    const received: string[] = [];
    const { url } = await peer((request) => {
      received.push(String(request.method));
      request.socket.destroy();
    });
    const { fetch: send } = createKeepAliveFetch();

    await expect(send(url)).rejects.toThrow("fetch failed");

    expect(received).toEqual(["GET"]);
  });
});

describe("an aborted GET", () => {
  it("is not sent again, even on a connection that had answered before", async () => {
    const received: string[] = [];
    let arrived!: () => void;
    const secondArrived = new Promise<void>((resolve) => (arrived = resolve));
    const { url } = await peer((request, response) => {
      received.push(`${request.method} ${request.url}`);
      if (received.length === 1) return response.end("ok");
      arrived();
    });
    const sent = vi.fn(globalThis.fetch);
    const { fetch: send } = createKeepAliveFetch(sent);
    await (await send(url)).text();
    await sleep(50);
    const controller = new AbortController();
    const pending = send(url, { signal: controller.signal });
    const aborted = expect(pending).rejects.toMatchObject({
      name: "AbortError",
    });
    await secondArrived;

    controller.abort();

    await aborted;
    await sleep(100);
    expect(received).toEqual(["GET /", "GET /"]);
    // An aborted request is not handed to the transport a second time.
    expect(sent).toHaveBeenCalledTimes(2);
  });
});

/** A self-signed certificate for 127.0.0.1, made with the host's own crypto. */
function selfSigned() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const cert = forge.pki.createCertificate();
  cert.publicKey = forge.pki.publicKeyFromPem(
    publicKey.export({ type: "spki", format: "pem" }).toString(),
  );
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 3_600_000);
  const subject = [{ name: "commonName", value: "127.0.0.1" }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  const key = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  cert.sign(
    forge.pki.privateKeyFromPem(
      privateKey.export({ type: "pkcs1", format: "pem" }).toString(),
    ),
    forge.md.sha256.create(),
  );
  return { key, cert: forge.pki.certificateToPem(cert) };
}

describe("over HTTPS", () => {
  it("retries a registry read once when the server reset a reused connection", async () => {
    vi.stubEnv("NODE_TLS_REJECT_UNAUTHORIZED", "0");
    try {
      const perSocket = new Map<Socket, number>();
      const sockets: Socket[] = [];
      const server = createTlsServer(selfSigned(), (request, response) => {
        const count = (perSocket.get(request.socket) ?? 0) + 1;
        perSocket.set(request.socket, count);
        if (count > 1) return request.socket.destroy();
        response.statusCode = 404;
        response.setHeader("connection", "keep-alive");
        response.end("{}");
      });
      server.on("secureConnection", (socket) => sockets.push(socket));
      servers.push(server as unknown as Server);
      await new Promise<void>((resolve) =>
        server.listen(0, "127.0.0.1", () => resolve()),
      );
      const url = `https://127.0.0.1:${(server.address() as AddressInfo).port}/`;
      const registry = createGatewayStreamSyncRegistry({
        gatewayUrl: url,
        ownerAddress: "0x1111111111111111111111111111111111111111",
        fetch: createKeepAliveFetch().fetch,
      });

      expect(await registry.read("pdpp.a~b")).toEqual({ found: false });
      await sleep(100);
      expect(await registry.read("pdpp.c~d")).toEqual({ found: false });

      expect(sockets).toHaveLength(2);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe("close", () => {
  it("closes the pooled connections, so the server sees them end", async () => {
    const { url, sockets } = await peer();
    const { fetch: send, close } = createKeepAliveFetch();
    await (await send(url)).text();
    expect(sockets).toHaveLength(1);
    const closed = new Promise<void>((resolve) =>
      sockets[0]!.once("close", () => resolve()),
    );

    await close();

    await closed;
    expect(sockets[0]!.destroyed).toBe(true);
  });

  it("lets a request in flight finish before it closes the pool", async () => {
    let arrived!: () => void;
    const requestArrived = new Promise<void>((resolve) => (arrived = resolve));
    const { url, sockets } = await peer((_request, response) => {
      arrived();
      setTimeout(() => response.end("late"), 200);
    });
    const { fetch: send, close } = createKeepAliveFetch();
    const inFlight = send(url);
    await requestArrived;

    const closing = close();

    expect(await (await inFlight).text()).toBe("late");
    await closing;
    await sleep(50);
    expect(sockets[0]!.destroyed).toBe(true);
  });

  it("aborts a request that is still in flight once the grace time has passed", async () => {
    let arrived!: () => void;
    const requestArrived = new Promise<void>((resolve) => (arrived = resolve));
    const { url } = await peer(() => arrived());
    const { fetch: send, close } = createKeepAliveFetch();
    const inFlight = send(url);
    const failed = expect(inFlight).rejects.toMatchObject({
      name: "AbortError",
    });
    await requestArrived;

    await close({ graceMs: 100 });

    await failed;
  });
});
