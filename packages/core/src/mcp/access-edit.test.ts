import { withStrictMcpGrantRegistration } from "./grant-registration.js";
import { handleMcpStreamableHttpRequest } from "./server.js";
import type { McpDataReadClient } from "./read-client.js";
import { describe, expect, it, vi } from "vitest";
import { createInMemoryMcpConnectionStore } from "./store.js";
import {
  approveMcpConnection,
  approveMcpScopeAccessRequest,
  liveMcpGrants,
  createMcpConnection,
  editMcpConnectionAccess,
  requestMcpScopeAccess,
} from "./connection-api.js";

const A = "instagram.profile";
const B = "youtube.history";
async function setup() {
  const store = createInMemoryMcpConnectionStore();
  const created = await createMcpConnection(
    { displayName: "Maple" },
    { store, publicOrigin: "https://ps.test" },
  );
  await approveMcpConnection(
    {
      connectionId: created.connectionId,
      grants: [{ grantId: "0xgrant", scopes: [A, B] }],
    },
    { store },
  );
  await requestMcpScopeAccess(
    { connectionId: created.connectionId, scopes: ["spotify.profile"] },
    { store },
  );
  const gateway = {
    getGrant: vi.fn(async () => ({
      id: "0xgrant",
      scopes: [A, B],
      grantVersion: "4",
      expiresAt: null,
      revokedAt: null,
      expired: false,
    })),
    getBuilder: vi.fn(async () => ({ id: "0xbuilder" })),
    createGrant: vi.fn(async () => ({ grantId: "0xgrant" })),
  };
  const options = {
    store,
    gateway: gateway as never,
    serverOwner: "0xowner" as `0x${string}`,
    serverSigner: {
      signGrantRegistration: vi.fn(async () => "0xsig" as `0x${string}`),
    },
  };
  return { store, id: created.connectionId, gateway, options };
}

describe("owner access edit", () => {
  it("narrows under the same grant at the next version and keeps the request pending", async () => {
    const { store, id, gateway, options } = await setup();
    const before = await store.getById(id);
    const result = await editMcpConnectionAccess(
      { connectionId: id, scopes: [A] },
      options,
    );
    expect(gateway.createGrant).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ scopes: [A], grantVersion: "5" }),
    );
    expect(result.grants).toEqual([{ grantId: "0xgrant", scopes: [A] }]);
    expect(result.scopeAccessRequest).toEqual(before!.scopeAccessRequest);
    expect((await store.getById(id))!.grants).toEqual(result.grants);
  });
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

it.each([
  { scopes: [] },
  { scopes: ["spotify.profile"] },
  { scopes: [A, "not-a-scope"] },
])("rejects invalid narrowing %j without a write", async ({ scopes }) => {
  const { id, options, gateway, store } = await setup();
  const before = await store.getById(id);
  await expect(
    editMcpConnectionAccess({ connectionId: id, scopes }, options),
  ).rejects.toMatchObject({ status: 400 });
  expect(gateway.createGrant).not.toHaveBeenCalled();
  expect(gateway.getGrant).not.toHaveBeenCalled();
  expect(await store.getById(id)).toEqual(before);
});

it("treats reordered duplicate scopes as a no-op without looking up the gateway", async () => {
  const { id, options, gateway, store } = await setup();
  const before = await store.getById(id);
  expect(
    await editMcpConnectionAccess(
      { connectionId: id, scopes: [B, A, A] },
      options,
    ),
  ).toEqual(before);
  expect(gateway.createGrant).not.toHaveBeenCalled();
  expect(gateway.getGrant).not.toHaveBeenCalled();
});

it.each(["approve", "edit"])(
  "gateway serializes approve/edit when %s wins",
  async (winner) => {
    const { id, store, gateway, options } = await setup();
    const initial = (await gateway.getGrant())!;
    let state = structuredClone(initial);
    const readBarrier = deferred();
    let reads = 0;
    gateway.getGrant.mockImplementation(async () => {
      const snapshot = structuredClone(state);
      if (++reads === 2) readBarrier.resolve();
      await readBarrier.promise;
      return snapshot;
    });
    const gates = { approve: deferred(), edit: deferred() };
    const entered = { approve: deferred(), edit: deferred() };
    let accepted = 0;
    const http = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (_url, init) => {
        const params = JSON.parse(String(init!.body));
        const kind = params.scopes.includes("spotify.profile")
          ? "approve"
          : "edit";
        entered[kind].resolve();
        await gates[kind].promise;
        if (BigInt(params.grantVersion) <= BigInt(state.grantVersion)) {
          return Response.json(
            { error: "Stale grantVersion", grantId: state.id },
            { status: 409 },
          );
        }
        ++accepted;
        state = {
          ...state,
          scopes: params.scopes,
          grantVersion: params.grantVersion,
        };
        return Response.json({ grantId: state.id }, { status: 201 });
      });
    try {
      const strict = {
        ...options,
        gateway: withStrictMcpGrantRegistration(
          gateway,
          "https://gateway.test",
        ) as never,
      };
      const pending = {
        approve: approveMcpScopeAccessRequest(
          { connectionId: id, scopes: ["spotify.profile"] },
          strict,
        ).then(
          (value) => ({ value }),
          (error) => ({ error }),
        ),
        edit: editMcpConnectionAccess(
          { connectionId: id, scopes: [A] },
          strict,
        ).then(
          (value) => ({ value }),
          (error) => ({ error }),
        ),
      };
      await Promise.all([entered.approve.promise, entered.edit.promise]);
      gates[winner as "approve" | "edit"].resolve();
      expect(await pending[winner as "approve" | "edit"]).toHaveProperty(
        "value",
      );
      const afterWinner = await store.getById(id);
      const loser = winner === "approve" ? "edit" : "approve";
      gates[loser].resolve();
      expect(await pending[loser]).toMatchObject({
        error: { status: 409, code: "RETRY" },
      });
      expect(accepted).toBe(1);
      expect(await store.getById(id)).toEqual(afterWinner);
      expect(afterWinner!.grants[0].scopes).toEqual(
        winner === "edit" ? [A] : [A, "spotify.profile", B].sort(),
      );
      expect(gateway.createGrant).not.toHaveBeenCalled();
    } finally {
      http.mockRestore();
    }
  },
);

it("maps the gateway's 503 settlement-in-flight refusal to a retry without changing local state", async () => {
  const { id, options, gateway, store } = await setup();
  const before = await store.getById(id);
  const http = vi.spyOn(globalThis, "fetch").mockResolvedValue(
    Response.json(
      {
        error:
          "Grant settlement is in flight; retry once the registration tx confirms",
      },
      { status: 503 },
    ),
  );
  try {
    await expect(
      editMcpConnectionAccess(
        { connectionId: id, scopes: [A] },
        {
          ...options,
          gateway: withStrictMcpGrantRegistration(
            gateway,
            "https://gateway.test",
          ) as never,
        },
      ),
    ).rejects.toMatchObject({ status: 409, code: "RETRY" });
    expect(await store.getById(id)).toEqual(before);
  } finally {
    http.mockRestore();
  }
});

it.each(["cas", "crash"])(
  "reads no removed data or metadata after gateway accept and local %s failure",
  async (failure) => {
    const { id, store, gateway, options } = await setup();
    const state = await gateway.getGrant();
    gateway.getGrant.mockImplementation(async () => structuredClone(state));
    const mutation = store.mutate.bind(store);
    const changed = deferred();
    const proceed = deferred();
    const http = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (_url, init) => {
        const params = JSON.parse(String(init!.body));
        state.scopes = params.scopes;
        state.grantVersion = params.grantVersion;
        changed.resolve();
        await proceed.promise;
        return Response.json({ grantId: state.id }, { status: 201 });
      });
    if (failure === "crash")
      store.mutate = vi.fn(async () => {
        throw new Error("process stopped before commit");
      });
    const edit = editMcpConnectionAccess(
      { connectionId: id, scopes: [A] },
      {
        ...options,
        gateway: withStrictMcpGrantRegistration(
          gateway,
          "https://gateway.test",
        ) as never,
      },
    ).catch((error) => error);
    try {
      await changed.promise;
      if (failure === "cas") {
        // Change and restore a field: only the record revision reveals this ABA.
        await mutation(id, (record) => ({ ...record, displayName: "changed" }));
        await mutation(id, (record) => ({ ...record, displayName: "Maple" }));
      }
      const awaitRecord = (await store.getById(id))!;
      const readClient = {
        getScopeMetadata: vi.fn(async () => null),
        readScopeBlocks: vi.fn(async () => {
          throw new Error("must not read B");
        }),
        listScopes: vi.fn(async () => ({
          status: 200,
          scopes: [],
          total: 0,
          limit: 100,
          offset: 0,
        })),
      } as unknown as McpDataReadClient;
      for (const name of [
        "read_scope",
        "list_scope_blocks",
        "list_granted_scopes",
        "search_personal_context",
      ]) {
        const response = await handleMcpStreamableHttpRequest(
          new Request("https://ps.test/mcp", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json, text/event-stream",
            },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: "tools/call",
              params: {
                name,
                arguments: { scope: B, scopes: [B], query: "secret" },
              },
            }),
          }),
          {
            connection: (await store.getById(id))!,
            readClient,
            verifyGrantsLive: () =>
              liveMcpGrants(awaitRecord, gateway as never),
          },
        );
        const body = await response.text();
        if (name === "list_granted_scopes") expect(body).not.toContain(B);
        else expect(body).toContain("scope_not_granted");
      }
      expect(readClient.getScopeMetadata).not.toHaveBeenCalledWith(B);
      expect(readClient.readScopeBlocks).not.toHaveBeenCalled();
      proceed.resolve();
      expect(await edit).toMatchObject(
        failure === "cas"
          ? { status: 409 }
          : { message: "process stopped before commit" },
      );
      expect((await store.getById(id))!.grants[0].scopes).toEqual([A, B]);
      // Gateway now holds [A]@5 while local still says [A, B]: a follow-up
      // edit to [B] must not re-sign a scope the gateway already removed.
      const createCalls = gateway.createGrant.mock.calls.length;
      http.mockClear();
      store.mutate = mutation;
      await expect(
        editMcpConnectionAccess({ connectionId: id, scopes: [B] }, options),
      ).rejects.toMatchObject({ status: 409 });
      expect(gateway.createGrant.mock.calls.length).toBe(createCalls);
      expect(http).not.toHaveBeenCalled();
      expect((await store.getById(id))!.grants[0].scopes).toEqual([A, B]);
    } finally {
      proceed.resolve();
      await edit;
      http.mockRestore();
    }
  },
);

it("rejects an edit to a scope the gateway no longer holds even though the stored grant still lists it", async () => {
  const { id, options, gateway, store } = await setup();
  gateway.getGrant.mockImplementation(async () => ({
    id: "0xgrant",
    scopes: [A],
    grantVersion: "5",
    expiresAt: null,
    revokedAt: null,
    expired: false,
  }));
  await expect(
    editMcpConnectionAccess({ connectionId: id, scopes: [B] }, options),
  ).rejects.toMatchObject({ status: 409 });
  expect(gateway.createGrant).not.toHaveBeenCalled();
  expect((await store.getById(id))!.grants[0].scopes).toEqual([A, B]);
});

it.each([
  { revokedAt: "2026-01-01T00:00:00Z", expired: false },
  { revokedAt: null, expired: true },
])("rejects an edit when the live grant is not live %j", async (state) => {
  const { id, options, gateway, store } = await setup();
  gateway.getGrant.mockImplementation(async () => ({
    id: "0xgrant",
    scopes: [A, B],
    grantVersion: "4",
    expiresAt: state.expired ? "1" : null,
    ...state,
  }));
  await expect(
    editMcpConnectionAccess({ connectionId: id, scopes: [A] }, options),
  ).rejects.toMatchObject({ status: 409 });
  expect(gateway.createGrant).not.toHaveBeenCalled();
  expect((await store.getById(id))!.grants[0].scopes).toEqual([A, B]);
});
