import { describe, expect, it, vi } from "vitest";

import {
  ConnectionLifetimeChanged,
  InvalidConnectionLifetime,
} from "../localdb/delete-lifetime.js";
import {
  handleOwnerConnectorDelete,
  handleOwnerConnectorLifetime,
  ownerConnectorRefusal,
  type ConnectionDeletePort,
  type OwnerConnectorDeleteDeps,
} from "./owner-connector-delete.js";

/**
 * The five-part additions ledger for one of the connector's streams: the
 * durable additions service publishes one ledger per source scope, so the
 * ledger for source scope `<connector>.<stream>` is
 * `vana.system.additions.<connector>.<stream>`. It belongs to the additions
 * service, not to the connector's data, so a connector delete must not name
 * it.
 */
const ADDITIONS_LEDGER = "vana.system.additions.fixture.items";

function makeDeps(): {
  deps: OwnerConnectorDeleteDeps;
  authorizeOwner: ReturnType<typeof vi.fn>;
  readMode: ReturnType<typeof vi.fn>;
  requestConnectionDelete: ReturnType<typeof vi.fn>;
} {
  const authorizeOwner = vi.fn(async () => {});
  const readMode = vi.fn(() => "switched" as const);
  const requestConnectionDelete = vi.fn(async () => ({
    deleteId: "delete-1",
    fenced: true,
  }));
  const connectionDelete: ConnectionDeletePort = {
    requestConnectionDelete,
  };
  const deps: OwnerConnectorDeleteDeps = {
    authorizeOwner,
    mode: { read: readMode },
    owner: "owner-1",
    connectionDelete,
  };
  return { deps, authorizeOwner, readMode, requestConnectionDelete };
}

function deleteRequest(): Request {
  return new Request("https://example.test/v1/owner/connectors/fixture", {
    method: "DELETE",
  });
}

describe("ownerConnectorRefusal envelope", () => {
  it("sends refusal JSON with a no-store cache directive", () => {
    const reply = ownerConnectorRefusal(
      503,
      "FIXTURE_UNAVAILABLE",
      "Try again soon",
    );
    expect(reply.status).toBe(503);
    expect(reply.headers.get("content-type")).toBe("application/json");
    expect(reply.headers.get("cache-control")).toBe("no-store");
  });

  it("preserves the display message and mirrors the status in the error body", async () => {
    const message = 'Résumé: "try again"';
    const reply = ownerConnectorRefusal(409, "FIXTURE_CONFLICT", message);
    expect(await reply.json()).toEqual({
      error: { code: 409, errorCode: "FIXTURE_CONFLICT", message },
    });
  });
});

describe("handleOwnerConnectorDelete (PS-2 W6 owner-delete)", () => {
  it("calls ConnectionDeleter.requestConnectionDelete with the connector id and answers 202 with the deleteId", async () => {
    const { deps, authorizeOwner, readMode, requestConnectionDelete } =
      makeDeps();
    const response = await handleOwnerConnectorDelete(
      deleteRequest(),
      "fixture",
      deps,
    );

    expect(authorizeOwner).toHaveBeenCalledTimes(1);
    expect(readMode).toHaveBeenCalledWith("owner-1");
    expect(requestConnectionDelete).toHaveBeenCalledTimes(1);
    expect(requestConnectionDelete).toHaveBeenCalledWith("fixture");
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      deleteId: "delete-1",
      fenced: true,
    });
  });

  it("carries the three-part delete status on the 202, so no app says deleted before all three parts are done", async () => {
    const { deps } = makeDeps();
    const deleteStatus = {
      fence: { state: "done" },
      legacy: { state: "blocked", reason: "owner_stream_sync_required" },
      storage: { state: "pending" },
    } as const;
    const response = await handleOwnerConnectorDelete(
      deleteRequest(),
      "fixture",
      {
        ...deps,
        connectionDelete: {
          ...deps.connectionDelete!,
          deleteStatusSnapshot: vi.fn(async () => deleteStatus),
        },
      },
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      deleteId: "delete-1",
      fenced: true,
      deleteStatus,
    });
  });

  it("answers a delete request from the status held here, never from a read that can wait on the network", async () => {
    const { deps } = makeDeps();
    const snapshot = {
      fence: { state: "pending" },
      legacy: { state: "pending" },
      storage: { state: "pending" },
    } as const;
    const deleteStatus = vi.fn(() => new Promise<never>(() => {}));
    const response = await handleOwnerConnectorDelete(
      deleteRequest(),
      "fixture",
      {
        ...deps,
        connectionDelete: {
          ...deps.connectionDelete!,
          deleteStatus,
          deleteStatusSnapshot: vi.fn(async () => snapshot),
        },
      },
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      deleteId: "delete-1",
      fenced: true,
      deleteStatus: snapshot,
    });
    expect(deleteStatus).not.toHaveBeenCalled();
  });

  it("tells a caller whose delete could not reach the registry that it is still pending", async () => {
    const { deps, requestConnectionDelete } = makeDeps();
    requestConnectionDelete.mockResolvedValueOnce({
      deleteId: "delete-2",
      fenced: false,
    });
    const response = await handleOwnerConnectorDelete(
      deleteRequest(),
      "fixture",
      deps,
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      deleteId: "delete-2",
      fenced: false,
    });
  });

  it("for a switched owner, the delete touches no scope path, not even the connector's five-part additions ledger", async () => {
    const fetchSpy = vi.fn(async () => new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchSpy);
    try {
      const { deps, requestConnectionDelete } = makeDeps();
      const response = await handleOwnerConnectorDelete(
        deleteRequest(),
        "fixture",
        deps,
      );

      expect(response.status).toBe(202);
      expect(requestConnectionDelete).toHaveBeenCalledTimes(1);
      expect(requestConnectionDelete).toHaveBeenCalledWith("fixture");
      expect(fetchSpy).not.toHaveBeenCalled();
      // The whole delete is the one port call above: no call the route made
      // names any scope, so the additions ledger is never touched.
      const calls = JSON.stringify(requestConnectionDelete.mock.calls);
      expect(calls).not.toContain("vana.system.");
      expect(calls).not.toContain(ADDITIONS_LEDGER);
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("passes the lifetime the request names to the writer, and nothing when it names none", async () => {
    const { deps, requestConnectionDelete } = makeDeps();
    const named = await handleOwnerConnectorDelete(
      new Request(
        "https://example.test/v1/owner/connectors/fixture?lifetime=v1%3A%401",
        { method: "DELETE" },
      ),
      "fixture",
      deps,
    );
    expect(named.status).toBe(202);
    expect(requestConnectionDelete).toHaveBeenLastCalledWith("fixture", {
      lifetime: "v1:@1",
    });
    await handleOwnerConnectorDelete(deleteRequest(), "fixture", deps);
    expect(requestConnectionDelete).toHaveBeenLastCalledWith("fixture");
  });

  it("answers 409 CONNECTION_LIFETIME_CHANGED when the connector now holds another lifetime (mutant: LIFETIME_REFUSAL_IS_500)", async () => {
    const { deps, requestConnectionDelete } = makeDeps();
    requestConnectionDelete.mockRejectedValueOnce(
      new ConnectionLifetimeChanged("fixture"),
    );
    const response = await handleOwnerConnectorDelete(
      new Request(
        "https://example.test/v1/owner/connectors/fixture?lifetime=v1%3A%401",
        {
          method: "DELETE",
        },
      ),
      "fixture",
      deps,
    );
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({
      error: {
        code: 409,
        errorCode: "CONNECTION_LIFETIME_CHANGED",
        message: expect.any(String),
      },
    });
  });

  it("answers 400 INVALID_LIFETIME for a lifetime the server did not name", async () => {
    const { deps, requestConnectionDelete } = makeDeps();
    requestConnectionDelete.mockRejectedValueOnce(
      new InvalidConnectionLifetime(),
    );
    const response = await handleOwnerConnectorDelete(
      new Request(
        "https://example.test/v1/owner/connectors/fixture?lifetime=zz",
        {
          method: "DELETE",
        },
      ),
      "fixture",
      deps,
    );
    expect(response.status).toBe(400);
    expect((await response.json()).error.errorCode).toBe("INVALID_LIFETIME");
  });
});

describe("handleOwnerConnectorLifetime", () => {
  const getRequest = () =>
    new Request("https://example.test/v1/owner/connectors/fixture", {
      method: "GET",
    });
  function lifetimeDeps() {
    const { deps, authorizeOwner } = makeDeps();
    const readConnectionLifetime = vi.fn(async () => "v1:@3");
    return {
      deps: {
        ...deps,
        connectionDelete: {
          ...deps.connectionDelete!,
          readConnectionLifetime,
        },
      } satisfies OwnerConnectorDeleteDeps,
      authorizeOwner,
      readConnectionLifetime,
    };
  }

  it("answers the lifetime the connector holds, to the owner of a switched account", async () => {
    const { deps, authorizeOwner, readConnectionLifetime } = lifetimeDeps();
    const response = await handleOwnerConnectorLifetime(
      getRequest(),
      "fixture",
      deps,
    );
    expect(authorizeOwner).toHaveBeenCalledTimes(1);
    expect(readConnectionLifetime).toHaveBeenCalledWith("fixture");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ lifetime: "v1:@3" });
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("answers the delete status beside the lifetime, for a caller that polls", async () => {
    const { deps } = lifetimeDeps();
    const deleteStatus = {
      fence: { state: "done" },
      legacy: { state: "done" },
      storage: { state: "blocked", reason: "needs_another_device" },
    } as const;
    const response = await handleOwnerConnectorLifetime(
      getRequest(),
      "fixture",
      {
        ...deps,
        connectionDelete: {
          ...deps.connectionDelete!,
          deleteStatus: vi.fn(async () => deleteStatus),
        },
      },
    );
    expect(await response.json()).toEqual({ lifetime: "v1:@3", deleteStatus });
  });

  it("refuses what the delete refuses: a bad id, an unswitched account, an unknown mode, no writer (mutant: LIFETIME_SKIPS_MODE)", async () => {
    const bad = await handleOwnerConnectorLifetime(
      getRequest(),
      "a~b",
      lifetimeDeps().deps,
    );
    expect(bad.status).toBe(400);
    const unswitched = lifetimeDeps();
    unswitched.deps.mode = { read: () => "unswitched" };
    expect(
      (
        await handleOwnerConnectorLifetime(
          getRequest(),
          "fixture",
          unswitched.deps,
        )
      ).status,
    ).toBe(409);
    const unknown = lifetimeDeps();
    unknown.deps.mode = { read: () => "unknown" };
    expect(
      (
        await handleOwnerConnectorLifetime(
          getRequest(),
          "fixture",
          unknown.deps,
        )
      ).status,
    ).toBe(503);
    const unread = lifetimeDeps();
    unread.deps.connectionDelete = { requestConnectionDelete: vi.fn() };
    const noReader = await handleOwnerConnectorLifetime(
      getRequest(),
      "fixture",
      unread.deps,
    );
    expect(noReader.status).toBe(503);
    expect((await noReader.json()).error.errorCode).toBe(
      "STREAM_SYNC_UNAVAILABLE",
    );
  });
});
