import {
  authenticateRequest,
  type AuthenticatedRequest,
  type SessionTokenVerifierPort,
} from "@opendatalabs/personal-server-ts-core/auth";
import type {
  PersonalServerApiAuthPort,
  PersonalServerReadAuthInput,
} from "@opendatalabs/personal-server-ts-core/api";
import { verifyDataReadPolicy } from "@opendatalabs/personal-server-ts-core/policy";
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
  if ("isRegisteredBuilder" in gateway) {
    if (await gateway.isRegisteredBuilder(signer)) return;
    throw new UnregisteredBuilderError();
  }
  const builder = await gateway.getBuilder(signer);
  if (!builder) throw new UnregisteredBuilderError();
}

export function createServerApiAuth(
  deps: ServerApiAuthDeps,
): PersonalServerApiAuthPort {
  return {
    async authorizeOwner(request) {
      const result = await authenticate(request, deps);
      if (result.isPolicyBypass) return;
      if (!deps.serverOwner) throw serverNotConfigured();
      if (!isOwner(result.auth.signer, deps.serverOwner)) {
        throw new NotOwnerError({
          signer: result.auth.signer,
          expected: deps.serverOwner,
        });
      }
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
