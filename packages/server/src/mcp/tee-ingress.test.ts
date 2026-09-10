import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createMcpOAuthAuthorization } from "@opendatalabs/personal-server-ts-core/mcp";
import { openMcpDurableState } from "./durable-state.js";
import {
  createTeeMcpIngress,
  McpOwnerAccessRevokedError,
  OWNER_ACCESS_REVOKED_CODE,
} from "./tee-ingress.js";

const dirs: string[] = [];
const OWNER = "0x1111111111111111111111111111111111111111";
afterEach(async () => {
  await Promise.all(
    dirs.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});
describe("TEE MCP ingress", () => {
  it("keeps OAuth unapproved when fleet membership fails and retries before any MCP call", async () => {
    const dir = await mkdtemp(join(tmpdir(), "tee-membership-"));
    dirs.push(dir);
    const state = await openMcpDurableState({
      path: join(dir, "state"),
      key: randomBytes(32),
    });
    const authorization = await createMcpOAuthAuthorization(
      {
        clientId: "claude",
        redirectUri: "https://claude.ai/api/mcp/auth_callback",
        codeChallenge: "a".repeat(43),
        codeChallengeMethod: "S256",
      },
      {
        connectionStore: state.connections,
        authorizationStore: state.authorizations,
        publicOrigin: "https://mcp-dev.vana.org",
      },
    );
    const beforeOwnerApproval = vi
      .fn()
      .mockRejectedValue(new Error("membership unavailable"));
    const app = createTeeMcpIngress({
      state,
      origin: "https://mcp-dev.vana.org",
      approvalUrl: "https://vana.example/mcp",
      allowedRedirectUris: ["https://claude.ai/api/mcp/auth_callback"],
      gateway: {} as never,
      verifyGrants: vi.fn(),
      registerGrantee: vi.fn(),
      dispatch: vi.fn(),
      ownerReady: async () => true,
      beforeOwnerApproval,
    });
    const approve = () =>
      app.request(
        `/v1/mcp/oauth/authorizations/${authorization.authorizationId}/approve`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            owner: OWNER,
            chainId: 14800,
            grants: [{ grantId: "0xabc", scopes: ["spotify.profile"] }],
          }),
        },
      );
    expect((await approve()).status).toBe(503);
    const record = await state.authorizations.getById(
      authorization.authorizationId,
    );
    expect(record?.status).toBe("pending");
    expect(await state.getOwner(record!.connectionId)).toBeNull();
    beforeOwnerApproval.mockResolvedValue(undefined);
    expect((await approve()).status).toBe(200);
    expect(beforeOwnerApproval).toHaveBeenLastCalledWith({
      owner: OWNER,
      chainId: 14800,
    });
    expect(
      (await state.connections.getById(record!.connectionId))?.status,
    ).toBe("approved");
  });
  it.each(["restart", "migration"])(
    "redeems PKCE once and keeps the bearer owner binding after %s",
    async (mode) => {
      const dir = await mkdtemp(join(tmpdir(), "tee-oauth-"));
      dirs.push(dir);
      const path = join(dir, "state");
      const key = randomBytes(32);
      let state = await openMcpDurableState({ path, key });
      const redirectUri = "https://claude.ai/api/mcp/auth_callback";
      const verifier = "v".repeat(48);
      const authorization = await createMcpOAuthAuthorization(
        {
          clientId: "claude",
          redirectUri,
          codeChallenge: createHash("sha256")
            .update(verifier)
            .digest("base64url"),
          codeChallengeMethod: "S256",
        },
        {
          connectionStore: state.connections,
          authorizationStore: state.authorizations,
          publicOrigin: "https://mcp-dev.vana.org",
        },
      );
      const dispatch = vi
        .fn()
        .mockResolvedValue(
          Response.json({ jsonrpc: "2.0", id: 1, result: { tools: [] } }),
        );
      const verifyGrants = vi.fn().mockResolvedValue(undefined);
      const create = () =>
        createTeeMcpIngress({
          state,
          origin: "https://mcp-dev.vana.org",
          approvalUrl: "https://vana.example/mcp",
          allowedRedirectUris: [redirectUri],
          gateway: {} as never,
          verifyGrants,
          registerGrantee: vi.fn(),
          dispatch,
        });
      let app = create();
      const approved = await app.request(
        `/v1/mcp/oauth/authorizations/${authorization.authorizationId}/approve`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            owner: OWNER,
            chainId: 14800,
            grants: [{ grantId: "0xabc", scopes: ["spotify.profile"] }],
          }),
        },
      );
      expect(approved.status).toBe(200);
      const redirect = new URL((await approved.json()).redirectTo);
      const tokenBody = new URLSearchParams({
        grant_type: "authorization_code",
        code: redirect.searchParams.get("code")!,
        client_id: "claude",
        redirect_uri: redirectUri,
        code_verifier: verifier,
      });
      const tokens = await Promise.all(
        [0, 1].map(() =>
          app.request("/mcp/oauth/token", {
            method: "POST",
            body: tokenBody.toString(),
          }),
        ),
      );
      expect(tokens.map((response) => response.status).sort()).toEqual([
        200, 400,
      ]);
      const token = (
        await tokens.find((response) => response.status === 200)!.json()
      ).access_token;
      if (mode === "migration") {
        const snapshot = await state.fenceAndExport(
          "oauth-migration",
          "new-central-app",
        );
        const blocked = await app.request("/mcp", {
          method: "POST",
          headers: { authorization: `Bearer ${token}` },
          body: "{}",
        });
        expect(blocked.status).toBe(503);
        state = await openMcpDurableState({
          path: join(dir, "central-state"),
          key: randomBytes(32),
        });
        await state.importSnapshot(snapshot, "oauth-migration");
        snapshot.fill(0);
      } else {
        state = await openMcpDurableState({ path, key });
      }
      app = create();
      const response = await app.request("/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
      });
      expect(response.status).toBe(200);
      expect(dispatch.mock.calls[0]?.[2]).toEqual({
        owner: OWNER,
        chainId: 14800,
      });
      const replay = await app.request("/mcp/oauth/token", {
        method: "POST",
        body: tokenBody.toString(),
      });
      expect(replay.status).toBe(400);
      verifyGrants.mockRejectedValue(new Error("revoked"));
      const revoked = await app.request("/mcp", {
        method: "POST",
        headers: { authorization: `Bearer ${token}` },
        body: "{}",
      });
      expect(revoked.status).toBe(403);
      expect(dispatch).toHaveBeenCalledTimes(1);
    },
  );

  it("answers a revoked owner with a specific non-retryable code and keeps 503 for unrelated failures", async () => {
    const dir = await mkdtemp(join(tmpdir(), "tee-revoked-"));
    dirs.push(dir);
    const state = await openMcpDurableState({
      path: join(dir, "state"),
      key: randomBytes(32),
    });
    const token = randomBytes(32).toString("hex");
    const connection = {
      id: "connection-1",
      displayName: "Claude",
      granteeAddress: OWNER,
      granteePublicKey: "0x02",
      encryptedGranteePrivateKey: { kind: "plaintext", privateKey: "0x01" },
      tokenHash: createHash("sha256").update(token).digest("hex"),
      status: "approved",
      grants: [{ grantId: "0xabc", scopes: ["spotify.profile"] }],
      createdAt: new Date().toISOString(),
    } as never;
    await state.connections.create(connection);
    await state.bindOwner("connection-1", { owner: OWNER, chainId: 14800 });
    const dispatch = vi
      .fn()
      .mockRejectedValue(new McpOwnerAccessRevokedError());
    const app = createTeeMcpIngress({
      state,
      origin: "https://mcp-dev.vana.org",
      approvalUrl: "https://vana.example/mcp",
      allowedRedirectUris: ["https://claude.ai/api/mcp/auth_callback"],
      gateway: {} as never,
      verifyGrants: vi.fn(),
      registerGrantee: vi.fn(),
      dispatch,
    });
    const call = () =>
      app.request("/mcp", {
        method: "POST",
        headers: {
          authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
      });
    const revoked = await call();
    expect(revoked.status).toBe(403);
    const body = await revoked.json();
    expect(body.error).toBe(OWNER_ACCESS_REVOKED_CODE);
    expect(JSON.stringify(body)).not.toContain(OWNER);
    dispatch.mockRejectedValue(new Error("worker unavailable"));
    const unavailable = await call();
    expect(unavailable.status).toBe(503);
    expect((await unavailable.json()).error).toBe("MCP request unavailable");
  });
  it("does not bind an owner or approve OAuth when signed grant verification fails", async () => {
    const dir = await mkdtemp(join(tmpdir(), "tee-mcp-"));
    dirs.push(dir);
    const state = await openMcpDurableState({
      path: join(dir, "state"),
      key: randomBytes(32),
    });
    const authorization = await createMcpOAuthAuthorization(
      {
        clientId: "claude",
        redirectUri: "https://claude.ai/api/mcp/auth_callback",
        codeChallenge: "a".repeat(43),
        codeChallengeMethod: "S256",
      },
      {
        connectionStore: state.connections,
        authorizationStore: state.authorizations,
        publicOrigin: "https://mcp-dev.vana.org",
      },
    );
    const verifyGrants = vi.fn().mockRejectedValue(new Error("wrong owner"));
    const dispatch = vi.fn();
    const app = createTeeMcpIngress({
      state,
      origin: "https://mcp-dev.vana.org",
      approvalUrl: "https://vana.example/mcp",
      allowedRedirectUris: ["https://claude.ai/api/mcp/auth_callback"],
      gateway: {} as never,
      verifyGrants,
      registerGrantee: vi.fn(),
      dispatch,
    });
    const response = await app.request(
      `/v1/mcp/oauth/authorizations/${authorization.authorizationId}/approve`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          owner: "0x1111111111111111111111111111111111111111",
          chainId: 14800,
          grants: [{ grantId: "0xabc", scopes: ["spotify.profile"] }],
        }),
      },
    );
    expect(response.status).toBe(403);
    expect(await state.getOwner(authorization.connectionId)).toBeNull();
    expect(
      (await state.authorizations.getById(authorization.authorizationId))
        ?.status,
    ).toBe("pending");
    expect(dispatch).not.toHaveBeenCalled();
  });
});
