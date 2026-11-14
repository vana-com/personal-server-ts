import { describe, expect, it, vi } from "vitest";

import {
  handleOwnerConnectorDelete,
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
});
