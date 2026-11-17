import {
  PersonalServerClientError,
  PersonalServerReadInterrupted,
} from "@opendatalabs/personal-server-ts-core/client";
import { describe, expect, it } from "vitest";
import { createPersonalServerClient } from "./personal-server-client.js";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** A fetch that records each request and answers from `reply`. */
function recordingFetch(reply: (request: Request) => Response) {
  const requests: Request[] = [];
  return {
    requests,
    fetch: async (request: Request) => {
      requests.push(request);
      return reply(request);
    },
  };
}

describe("createPersonalServerClient", () => {
  it("reads the data listing over the given fetch, origin and bearer auth", async () => {
    const server = recordingFetch(() =>
      json({ scopes: [{ scope: "a.b" }], total: 1, limit: 2, offset: 4 }),
    );
    const client = createPersonalServerClient({
      fetch: server.fetch,
      origin: "https://ps.example",
      auth: { bearerToken: "owner-token" },
    });

    const page = await client.listData({ limit: 2, offset: 4 });

    expect(page.total).toBe(1);
    expect(server.requests).toHaveLength(1);
    const [request] = server.requests;
    expect(request.method).toBe("GET");
    expect(request.url).toBe("https://ps.example/v1/data?limit=2&offset=4");
    expect(request.headers.get("Authorization")).toBe("Bearer owner-token");
  });

  it("lets a call's own auth replace the default", async () => {
    const server = recordingFetch(() => json({ scopes: [], total: 0 }));
    const client = createPersonalServerClient({
      fetch: server.fetch,
      origin: "https://ps.example",
      auth: { bearerToken: "default" },
    });

    await client.listData({ auth: { bearerToken: "builder" } });

    expect(server.requests[0].headers.get("Authorization")).toBe(
      "Bearer builder",
    );
  });

  it("sends no Authorization header when there is no auth", async () => {
    const server = recordingFetch(() => json({ scopes: [], total: 0 }));
    const client = createPersonalServerClient({
      fetch: server.fetch,
      origin: "https://ps.example",
    });

    await client.listData();

    expect(server.requests[0].headers.has("Authorization")).toBe(false);
    expect(server.requests[0].url).toBe("https://ps.example/v1/data");
  });

  it("reads the origin on every call, as a relay URL arrives late", async () => {
    const server = recordingFetch(() => json({ scopes: [], total: 0 }));
    let origin = "https://local.example";
    const client = createPersonalServerClient({
      fetch: server.fetch,
      origin: () => origin,
    });

    await client.listData();
    origin = "https://relay.example";
    await client.listData();

    expect(server.requests.map((r) => new URL(r.url).origin)).toEqual([
      "https://local.example",
      "https://relay.example",
    ]);
  });

  it("builds each read and the sync calls on their routes", async () => {
    const server = recordingFetch(() => json({}));
    const client = createPersonalServerClient({
      fetch: server.fetch,
      origin: "https://ps.example",
    });

    await client.readData("a.b", { at: "2026-01-01" });
    await client.listVersions("a.b", { limit: 5 });
    await client.listAccessLogs({ offset: 3 });
    await client.syncStatus();
    await client.syncNow();

    expect(server.requests.map((r) => `${r.method} ${r.url}`)).toEqual([
      "GET https://ps.example/v1/data/a.b?at=2026-01-01",
      "GET https://ps.example/v1/data/a.b/versions?limit=5",
      "GET https://ps.example/v1/access-logs?offset=3",
      "GET https://ps.example/v1/sync/status",
      "POST https://ps.example/v1/sync/trigger",
    ]);
  });

  it("throws the client error for a refused request", async () => {
    const server = recordingFetch(() =>
      json({ error: { code: "UNAUTHORIZED" } }, 401),
    );
    const client = createPersonalServerClient({
      fetch: server.fetch,
      origin: "https://ps.example",
    });

    await expect(client.listData()).rejects.toBeInstanceOf(
      PersonalServerClientError,
    );
  });

  describe("readData when its body stops before the end", () => {
    const envelope = { records: [{ id: "a" }] };
    /** A 200 whose body starts and then errors, as a view that moved does. */
    const interrupted = (reason: unknown = new TypeError("network error")) =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"records":['));
          },
          pull(controller) {
            controller.error(reason);
          },
        }),
        { status: 200 },
      );
    const clientOver = (
      replies: (() => Response)[],
      server = recordingFetch(() => {
        const next = replies.shift();
        if (!next) throw new Error("more reads than expected");
        return next();
      }),
    ) => ({
      server,
      client: createPersonalServerClient({
        fetch: server.fetch,
        origin: "https://ps.example",
        auth: { bearerToken: "owner-token" },
      }),
    });

    it("reads again, as a new request, and returns the settled body", async () => {
      const { server, client } = clientOver([
        () => interrupted(),
        () => json(envelope),
      ]);
      await expect(client.readData("a.b")).resolves.toEqual(envelope);
      expect(server.requests).toHaveLength(2);
      expect(server.requests[1]).not.toBe(server.requests[0]);
      expect(server.requests[1].headers.get("Authorization")).toBe(
        "Bearer owner-token",
      );
    });

    it("ends with the typed error, not a loop, when every read is interrupted", async () => {
      const replies = Array.from({ length: 10 }, () => () => interrupted());
      const { server, client } = clientOver(replies);
      const error = await client.readData("a.b").catch((e: unknown) => e);
      expect(error).toBeInstanceOf(PersonalServerReadInterrupted);
      expect(error).toMatchObject({ errorCode: "READ_INTERRUPTED" });
      expect(server.requests).toHaveLength(3);
    });

    it("does not read again after an error status", async () => {
      const { server, client } = clientOver([
        () => json({ error: "FORBIDDEN", message: "no" }, 403),
        () => json(envelope),
      ]);
      await expect(client.readData("a.b")).rejects.toBeInstanceOf(
        PersonalServerClientError,
      );
      expect(server.requests).toHaveLength(1);
    });

    it("does not read again for a call that is not a data read", async () => {
      const { server, client } = clientOver([
        () => interrupted(),
        () => json({ scopes: [], total: 0 }),
      ]);
      await expect(client.listData()).rejects.toBeInstanceOf(
        PersonalServerReadInterrupted,
      );
      expect(server.requests).toHaveLength(1);
    });
  });
});
