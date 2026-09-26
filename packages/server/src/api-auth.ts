import {
  authenticateRequest,
  type AuthenticatedRequest,
  type SessionTokenVerifierPort,
} from "@opendatalabs/personal-server-ts-core/auth";
import type {
  PersonalServerApiAuthPort,
  PersonalServerReadAuthInput,
  PersonalServerScopeAuthInput,
  PersonalServerWriteAuthInput,
} from "@opendatalabs/personal-server-ts-core/api";
import { verifyDataReadPolicy } from "@opendatalabs/personal-server-ts-core/policy";
import {
  createInMemoryWriteProofReplayStore,
  createWriteSessionAuthorization,
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
import type {
  PdppAuthorizationService,
  PdppTokenContext,
} from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
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
  /**
   * PDPP owner bearer bridge for the legacy reconciler path. When supplied,
   * POST /v1/data/:scope and GET /v1/data/:scope/versions may accept a PDPP
   * owner token, but only when the token's live instance scope maps to the
   * legacy source namespace. It never authorizes DELETE or broad owner reads.
   */
  pdppOwnerBearer?: {
    auth: PdppAuthorizationService;
    configuredMethods: Map<string, string[]>;
    ownerSubjectId?: string;
    instancesForSubject?: (subjectId: string) => string[];
  };
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

function bearerToken(request: Request): string | undefined {
  const header = request.headers.get("authorization");
  if (!header) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1]?.trim();
}

function legacyNamespace(scope: string): string {
  return scope.split(".", 1)[0] ?? "";
}

function pdppBridgeError(
  errorCode: string,
  message: string,
  details?: Record<string, unknown>,
): ProtocolError {
  return new ProtocolError(403, errorCode, message, details);
}

export function createServerApiAuth(
  deps: ServerApiAuthDeps,
): PersonalServerApiAuthPort {
  const writeProofReplayStore =
    deps.writeProofReplayStore ?? createInMemoryWriteProofReplayStore();
  // The write-session half of this port is protocol, not runtime: the browser
  // build's adapters call the same factory, so a delegated write is checked
  // identically wherever the Personal Server runs.
  const writeSessions = createWriteSessionAuthorization({
    serverOrigin: deps.serverOrigin,
    serverOwner: deps.serverOwner,
    sessionStore: deps.writeSessionStore,
    replayStore: writeProofReplayStore,
    policyPorts: {
      authSessionVerifier: deps.gateway,
      grantVerifier: deps.gateway,
      runtimeAvailability: deps.runtimeAvailability,
      // Fee seam intentionally not wired: builder writes are free in the
      // demo slice (write fee mechanics undecided).
    },
  });

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

  async function authorizePdppOwnerBearerForScope(
    input: PersonalServerScopeAuthInput,
  ): Promise<boolean> {
    if (!deps.pdppOwnerBearer) return false;
    const token = bearerToken(input.request);
    if (!token) return false;

    const context = await deps.pdppOwnerBearer.auth.resolveToken(token);
    if (!context.active) return false;
    assertPdppOwnerBearerForScope(context, input.scope, deps);
    return true;
  }

  function assertPdppOwnerBearerForScope(
    context: PdppTokenContext,
    scope: string,
    authDeps: ServerApiAuthDeps,
  ): void {
    const bridge = authDeps.pdppOwnerBearer;
    if (!bridge) return;

    if (context.tokenKind !== "owner") {
      throw pdppBridgeError(
        "PDPP_CLIENT_BEARER_NOT_OWNER",
        "PDPP client bearer tokens cannot authorize legacy data owner writes",
      );
    }

    if (
      !context.subjectId ||
      !bridge.ownerSubjectId ||
      context.subjectId.toLowerCase() !== bridge.ownerSubjectId.toLowerCase()
    ) {
      throw pdppBridgeError(
        "PDPP_OWNER_BEARER_FOREIGN",
        "PDPP owner bearer token belongs to a different subject",
        {
          subjectId: context.subjectId,
          expectedSubjectId: bridge.ownerSubjectId,
        },
      );
    }

    if (!context.instanceIds || context.instanceIds.length !== 1) {
      throw pdppBridgeError(
        "PDPP_OWNER_BEARER_UNSCOPED_INSTANCE",
        "PDPP owner bearer token must be scoped to exactly one legacy source instance",
      );
    }

    const currentInstances = bridge.instancesForSubject?.(context.subjectId);
    if (!currentInstances || currentInstances.length === 0) {
      throw pdppBridgeError(
        "PDPP_OWNER_BEARER_FOREIGN",
        "PDPP owner bearer token is not scoped to a currently owned instance",
        { subjectId: context.subjectId },
      );
    }

    const current = new Set(currentInstances);
    const liveInstanceIds = context.instanceIds.filter((instance) =>
      current.has(instance),
    );
    if (liveInstanceIds.length === 0) {
      throw pdppBridgeError(
        "PDPP_OWNER_BEARER_FOREIGN",
        "PDPP owner bearer token is not scoped to a currently owned instance",
        { subjectId: context.subjectId },
      );
    }
    const namespace = legacyNamespace(scope);
    const [liveInstance] = liveInstanceIds;
    const matchesScope =
      liveInstance.split(":", 1)[0] === namespace &&
      bridge.configuredMethods.has(liveInstance);

    if (!matchesScope) {
      throw pdppBridgeError(
        "PDPP_OWNER_BEARER_SCOPE_MISMATCH",
        "PDPP owner bearer token is not scoped to the requested legacy source namespace",
        { scope, instanceIds: liveInstanceIds },
      );
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
  async function authorizeWrite(input: PersonalServerWriteAuthInput) {
    const delegated = await writeSessions.authorizeSessionWrite(input);
    if (delegated) return delegated;
    if (await authorizePdppOwnerBearerForScope(input)) return;
    await authorizeOwner(input.request);
  }

  /**
   * Identity-only recognition of a write-session caller: the bearer must
   * resolve to a live session and the request must carry that builder's
   * valid proof, but NO grant policy runs (there is no scope to run it
   * against). Callers use it only to choose between error shapes, never to
   * release data, so a revoked or narrowed grant getting a 404 instead of a
   * 401 discloses nothing. Returns undefined for any other credential.
   */
  async function authorizeWriteSession(request: Request) {
    return writeSessions.recognizeWriteSession(request);
  }

  return {
    authorizeOwner,
    authorizeWrite,
    authorizeWriteSession,

    async authorizeScopeVersions(input) {
      if (await authorizePdppOwnerBearerForScope(input)) return;
      const result = await authenticate(input.request, deps);
      if (
        result.isPolicyBypass ||
        isOwner(result.auth.signer, deps.serverOwner)
      ) {
        return;
      }
      await assertRegisteredBuilder(deps.gateway, result.auth.signer);
    },

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
