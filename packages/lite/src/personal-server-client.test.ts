import { PersonalServerClientError } from "@opendatalabs/personal-server-ts-core/client";
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
});
