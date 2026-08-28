import {
  authenticateRequest,
  type AuthenticatedRequest,
  type SessionTokenVerifierPort,
} from "@opendatalabs/personal-server-ts-core/auth";
import type {
  PersonalServerApiAuthPort,
  PersonalServerReadAuthInput,
  PersonalServerWriteAuthInput,
  PersonalServerWriteAuthResult,
} from "@opendatalabs/personal-server-ts-core/api";
import {
  verifyDataReadPolicy,
  verifyDataWritePolicy,
} from "@opendatalabs/personal-server-ts-core/policy";
import {
  createInMemoryWriteProofReplayStore,
  hashWriteSessionToken,
  verifyWriterAttribution,
  type WriteProofReplayStore,
  type WriteSessionStore,
} from "@opendatalabs/personal-server-ts-core/write";
import {
  NotOwnerError,
  ProtocolError,
  UnregisteredBuilderError,
} from "@opendatalabs/personal-server-ts-core/errors";
import type {
  DataStoragePort,
  RuntimeAvailabilityPort,
} from "@opendatalabs/personal-server-ts-core/ports";
import type { GatewayClient } from "@opendatalabs/vana-sdk/node";

export interface ServerApiAuthDeps {
  serverOrigin: string | (() => string);
  serverOwner?: `0x${string}`;
  gateway: GatewayClient;
  devToken?: string;
  accessToken?: string;
  tokenStore?: SessionTokenVerifierPort;
  dataStorage?: Pick<DataStoragePort, "findEntry">;
  runtimeAvailability?: RuntimeAvailabilityPort;
  /**
   * Write API sessions. When present, POST /v1/data/:scope accepts a bearer
   * write-session token (minted by POST /v1/write/session) and authorizes the
   * write as the session's builder via verifyDataWritePolicy + the
   * X-Vana-Write-Signature attribution proof. Absent = owner-only ingest,
   * exactly as before.
   */
  writeSessionStore?: WriteSessionStore;
  /**
   * Replay guard for per-write proofs (X-Vana-Write-Signature). Defaults to
   * an in-memory store so replay protection is always on when write sessions
   * are enabled; hosts may supply a shared store.
   */
  writeProofReplayStore?: WriteProofReplayStore;
}

function serverNotConfigured(): ProtocolError {
  return new ProtocolError(
    500,
    "SERVER_NOT_CONFIGURED",
    "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
  );
}

function isOwner(
  signer: string,
  serverOwner: `0x${string}` | undefined,
): boolean {
  return Boolean(
    serverOwner && signer.toLowerCase() === serverOwner.toLowerCase(),
  );
}

async function authenticate(
  request: Request,
  deps: ServerApiAuthDeps,
): Promise<AuthenticatedRequest> {
  return authenticateRequest({
    request,
    serverOrigin: deps.serverOrigin,
    devToken: deps.devToken,
    accessToken: deps.accessToken,
    sessionTokenVerifier: deps.tokenStore,
    serverOwner: deps.serverOwner,
  });
}

async function assertRegisteredBuilder(
  gateway: GatewayClient,
  signer: `0x${string}`,
): Promise<void> {
  // vana-sdk 3.14.0's GatewayClient always exposes isRegisteredBuilder, so the
  // legacy getBuilder feature-detect fallback is now unreachable (its else
  // branch narrows the client to `never`). Query registration directly, matching
  // middleware/builder-check.ts.
  if (await gateway.isRegisteredBuilder(signer)) return;
  throw new UnregisteredBuilderError();
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  return header.slice(7);
}

export function createServerApiAuth(
  deps: ServerApiAuthDeps,
): PersonalServerApiAuthPort {
  const writeProofReplayStore =
    deps.writeProofReplayStore ?? createInMemoryWriteProofReplayStore();

  async function authorizeOwner(request: Request): Promise<void> {
    const result = await authenticate(request, deps);
    if (result.isPolicyBypass) return;
    if (!deps.serverOwner) throw serverNotConfigured();
    if (!isOwner(result.auth.signer, deps.serverOwner)) {
      throw new NotOwnerError({
        signer: result.auth.signer,
        expected: deps.serverOwner,
      });
    }
  }

  /**
   * Delegated ingest. A bearer token that resolves to a live write session
   * authorizes as the session builder: the write policy re-runs against the
   * LIVE grant (revocation / expiry / scope coverage stay authoritative per
   * write), and the builder's X-Vana-Write-Signature payload proof is
   * verified and returned for the handler to store with the record. Any
   * other credential (owner Web3Signed, dev token, control-plane token,
   * unknown bearer) falls through to the owner path unchanged.
   */
  async function authorizeWrite(
    input: PersonalServerWriteAuthInput,
  ): Promise<PersonalServerWriteAuthResult | void> {
    const token = bearerToken(input.request);
    if (token && deps.writeSessionStore) {
      const session = await deps.writeSessionStore.getByTokenHash(
        await hashWriteSessionToken(token),
      );
      if (session) {
        if (!deps.serverOwner) throw serverNotConfigured();
        const grant = await verifyDataWritePolicy(
          {
            signer: session.builderAddress,
            grantId: session.grantId,
            requestedScope: input.scope,
            serverOwner: deps.serverOwner,
          },
          {
            authSessionVerifier: deps.gateway,
            grantVerifier: deps.gateway,
            runtimeAvailability: deps.runtimeAvailability,
            // Fee seam intentionally not wired: builder writes are free in
            // the demo slice (write fee mechanics undecided).
          },
        );
        // releaseProof is a rollback hook for the handler, never part of the
        // stored attribution record.
        const { releaseProof, ...attribution } = await verifyWriterAttribution({
          request: input.request,
          builderAddress: session.builderAddress,
          grantId: grant.id,
          serverOrigin: deps.serverOrigin,
          replayStore: writeProofReplayStore,
        });
        return {
          builder: session.builderAddress,
          grantId: grant.id,
          grantScopes: grant.scopes ?? [],
          attribution,
          releaseProof,
        };
      }
    }
    await authorizeOwner(input.request);
  }

  return {
    authorizeOwner,
    authorizeWrite,

    async authorizeBuilderList(request) {
      const result = await authenticate(request, deps);
      if (
        result.isPolicyBypass ||
        isOwner(result.auth.signer, deps.serverOwner)
      ) {
        return;
      }
      await assertRegisteredBuilder(deps.gateway, result.auth.signer);
    },

    async authorizeBuilderRead(input: PersonalServerReadAuthInput) {
      const result = await authenticate(input.request, deps);
      if (result.isPolicyBypass) {
        return { builder: result.auth.signer, grantId: "policy-bypass" };
      }
      // Owner-exempt read paths. We allow two mechanisms here:
      //   - web3-signed: per-request signature by the owner wallet. Already
      //     gated on a fresh cryptographic proof per request.
      //   - control-plane-token: a static bearer set by the parent host
      //     process at boot. Never crosses an interactive surface, so it
      //     has the same threat model as the host process itself.
      // Intentionally NOT exempted:
      //   - cli-session-token: an interactive bearer issued via /auth/device.
      //     These flow through terminals / copy-paste / shell history, so we
      //     keep them on the grant path so that any leaked CLI session can
      //     still only read what an explicit grant authorizes.
      // Defense-in-depth justification: any owner-identified credential can
      // already mint a grant via authorizeOwner, so blocking owner reads in
      // general does not meaningfully shrink the blast radius of a stolen
      // token. The cli-session-token exception preserves the audit-log
      // signal for the one credential class that's most prone to leakage.
      if (
        isOwner(result.auth.signer, deps.serverOwner) &&
        (result.mechanism === "web3-signed" ||
          result.mechanism === "control-plane-token")
      ) {
        return { builder: result.auth.signer, grantId: "owner" };
      }

      // Fail closed: a builder grant read can't be authorized if we can't
      // identify this server's owner to bind the grant to.
      if (!deps.serverOwner) throw serverNotConfigured();

      const selectedEntry = deps.dataStorage?.findEntry({
        scope: input.scope,
        fileId: input.fileId,
      });
      const grant = await verifyDataReadPolicy(
        {
          signer: result.auth.signer,
          grantId: result.auth.payload.grantId ?? input.grantId,
          requestedScope: input.scope,
          fileId: input.fileId ?? selectedEntry?.fileId ?? undefined,
          serverOwner: deps.serverOwner,
        },
        {
          authSessionVerifier: deps.gateway,
          grantVerifier: deps.gateway,
          runtimeAvailability: deps.runtimeAvailability,
        },
      );
      return { builder: result.auth.signer, grantId: grant.id };
    },
  };
}
