import type {
  CreateGrantParams,
  DataPortabilityGatewayConfig,
  GatewayClient,
  RevokeGrantParams,
} from "@opendatalabs/vana-sdk/browser";
import {
  isDataPortabilityGatewayConfig,
  verifyGrantRegistration,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../signing/index.js";
import {
  contractError,
  contractOk,
  contractProtocolError,
  type ContractResult,
} from "./http.js";

// Canary 87b4310 verify body matches the structured GrantRegistration
// payload: top-level scopes, grantVersion, expiresAt. No JSON `grant`
// blob, no `fileIds`. grantVersion and expiresAt are decimal-string
// uint256s on the wire (same encoding the gateway accepts).
export interface VerifyGrantRequestBody {
  grantorAddress: `0x${string}`;
  granteeId: `0x${string}`;
  scopes: string[];
  grantVersion: string;
  expiresAt: string;
  signature: `0x${string}`;
}

// Caller-facing create-grant body. `grantVersion` is optional — defaults
// to "1" for first registration. Re-registration callers must increment.
// (The gateway returns 409 with the current grantVersion on collision so
// callers can retry.)
export interface CreateGrantRequestBody {
  granteeAddress: `0x${string}`;
  scopes: string[];
  /** Unix seconds; 0 = no expiry. Default 0 when omitted. */
  expiresAt?: number;
  /** Decimal uint256 string; default "1". */
  grantVersion?: string;
}

export interface CreateGrantContractInput {
  gateway: Pick<GatewayClient, "getBuilder" | "createGrant">;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<ServerSigner, "signGrantRegistration">;
  body: unknown;
}

export interface RevokeGrantContractInput {
  gateway: Pick<GatewayClient, "getGrant" | "revokeGrant">;
  serverOwner?: `0x${string}`;
  serverSigner?: Partial<Pick<ServerSigner, "signGrantRevocation">>;
  grantId: string;
}

export interface ListGrantsContractInput {
  gateway: Pick<GatewayClient, "listGrantsByUser">;
  serverOwner?: `0x${string}`;
}

export interface VerifyGrantContractInput {
  body: unknown;
  gatewayConfig?: DataPortabilityGatewayConfig;
  nowSeconds?: number;
}

function isStringArray(value: unknown): value is string[] {
  return (
    Array.isArray(value) && value.every((entry) => typeof entry === "string")
  );
}

function isValidCreateBody(body: unknown): body is CreateGrantRequestBody {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return false;
  }
  const b = body as Record<string, unknown>;
  if (
    typeof b.granteeAddress !== "string" ||
    !b.granteeAddress.startsWith("0x")
  ) {
    return false;
  }
  if (!isStringArray(b.scopes) || b.scopes.length === 0) return false;
  if (b.expiresAt !== undefined && typeof b.expiresAt !== "number") {
    return false;
  }
  if (b.grantVersion !== undefined && typeof b.grantVersion !== "string") {
    return false;
  }
  return true;
}

function isValidVerifyBody(body: unknown): body is VerifyGrantRequestBody {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    return false;
  }
  const b = body as Record<string, unknown>;
  if (
    typeof b.grantorAddress !== "string" ||
    !b.grantorAddress.startsWith("0x")
  ) {
    return false;
  }
  if (typeof b.granteeId !== "string" || !b.granteeId.startsWith("0x")) {
    return false;
  }
  if (!isStringArray(b.scopes) || b.scopes.length === 0) return false;
  if (typeof b.grantVersion !== "string") return false;
  if (typeof b.expiresAt !== "string") return false;
  if (typeof b.signature !== "string" || !b.signature.startsWith("0x")) {
    return false;
  }
  return true;
}

function isValidGrantId(grantId: string): grantId is `0x${string}` {
  return grantId.startsWith("0x") && grantId.length > 2;
}

function serverOwnerNotConfigured(): ContractResult {
  return contractProtocolError(
    500,
    "SERVER_NOT_CONFIGURED",
    "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
  );
}

// Bigint conversion guard. Returns null on non-numeric / negative input.
function toUint256(value: bigint | number | string): bigint | null {
  try {
    const big = typeof value === "bigint" ? value : BigInt(value);
    if (big < 0n) return null;
    return big;
  } catch {
    return null;
  }
}

export async function listGrantsContract(
  input: ListGrantsContractInput,
): Promise<ContractResult> {
  if (!input.serverOwner) return serverOwnerNotConfigured();
  const grants = await input.gateway.listGrantsByUser(input.serverOwner);
  return contractOk({ grants });
}

export async function createGrantContract(
  input: CreateGrantContractInput,
): Promise<ContractResult> {
  if (!input.serverOwner) return serverOwnerNotConfigured();
  if (!input.serverSigner) {
    return contractProtocolError(
      500,
      "SERVER_SIGNER_NOT_CONFIGURED",
      "Server signer not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
    );
  }
  if (!isValidCreateBody(input.body)) {
    return contractError(
      400,
      "INVALID_BODY",
      "Body must include granteeAddress (0x string) and scopes (non-empty string array)",
    );
  }

  const { granteeAddress, scopes, expiresAt, grantVersion } = input.body;
  const builder = await input.gateway.getBuilder(granteeAddress);
  if (!builder) {
    return contractProtocolError(
      404,
      "BUILDER_NOT_REGISTERED",
      `Builder ${granteeAddress} is not registered on-chain`,
    );
  }

  // Default to first-registration grantVersion=1. Re-registration callers
  // are expected to pass a strictly higher value. The gateway returns 409
  // on stale versions so retries can rebase against the live counter.
  const grantVersionBig = toUint256(grantVersion ?? "1");
  if (grantVersionBig === null || grantVersionBig < 1n) {
    return contractError(
      400,
      "INVALID_BODY",
      "grantVersion must be a uint256 >= 1",
    );
  }
  const expiresAtBig = BigInt(expiresAt ?? 0);

  const signature = await input.serverSigner.signGrantRegistration({
    grantorAddress: input.serverOwner,
    granteeId: builder.id as `0x${string}`,
    scopes,
    grantVersion: grantVersionBig,
    expiresAt: expiresAtBig,
  });

  const params: CreateGrantParams = {
    grantorAddress: input.serverOwner,
    granteeId: builder.id,
    scopes,
    grantVersion: grantVersionBig.toString(),
    expiresAt: expiresAtBig.toString(),
    signature,
  };
  const result = await input.gateway.createGrant(params);
  return contractOk({ grantId: result.grantId }, 201);
}

export async function revokeGrantContract(
  input: RevokeGrantContractInput,
): Promise<ContractResult> {
  if (!input.serverOwner) return serverOwnerNotConfigured();
  if (!input.serverSigner?.signGrantRevocation) {
    return contractProtocolError(
      500,
      "SERVER_SIGNER_NOT_CONFIGURED",
      "Server signer not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
    );
  }
  if (!isValidGrantId(input.grantId)) {
    return contractError(
      400,
      "INVALID_GRANT_ID",
      "Grant id must be a non-empty 0x string",
    );
  }

  // Canary GrantRevocation shares the (grantor, grantee) monotonic nonce
  // with registration: both events advance the same grantVersion counter.
  // Fetch the current grant to read its grantVersion, then increment so
  // the on-chain CAS check accepts the revocation.
  const current = await input.gateway.getGrant(input.grantId);
  if (!current) {
    return contractProtocolError(
      404,
      "GRANT_NOT_FOUND",
      `Grant ${input.grantId} not found`,
    );
  }
  const currentVersion = toUint256(current.grantVersion);
  if (currentVersion === null) {
    return contractProtocolError(
      500,
      "INVALID_GRANT_STATE",
      `Grant ${input.grantId} has unparseable grantVersion`,
    );
  }
  const nextVersion = currentVersion + 1n;

  const signature = await input.serverSigner.signGrantRevocation({
    grantorAddress: input.serverOwner,
    grantId: input.grantId,
    grantVersion: nextVersion,
  });
  const params: RevokeGrantParams = {
    grantorAddress: input.serverOwner,
    grantId: input.grantId,
    grantVersion: nextVersion.toString(),
    signature,
  };
  await input.gateway.revokeGrant(params);
  return contractOk({ status: "revoked", grantId: input.grantId });
}

export async function verifyGrantContract({
  body,
  gatewayConfig,
  nowSeconds = Math.floor(Date.now() / 1000),
}: VerifyGrantContractInput): Promise<ContractResult> {
  if (!isValidVerifyBody(body)) {
    return contractError(
      400,
      "INVALID_BODY",
      "Body must include grantorAddress, granteeId, scopes, grantVersion, expiresAt, and signature",
    );
  }
  if (!isDataPortabilityGatewayConfig(gatewayConfig)) {
    return contractProtocolError(
      500,
      "SERVER_NOT_CONFIGURED",
      "Gateway config is not configured",
    );
  }

  const result = await verifyGrantRegistration({
    gatewayConfig,
    grantorAddress: body.grantorAddress,
    granteeId: body.granteeId,
    scopes: body.scopes,
    grantVersion: body.grantVersion,
    expiresAt: body.expiresAt,
    signature: body.signature,
    nowSeconds,
  });
  if (!result.valid) {
    return contractOk({ valid: false, error: result.error });
  }

  return contractOk({
    valid: true,
    grantorAddress: result.grantorAddress,
    granteeId: result.granteeId,
    scopes: result.scopes,
    grantVersion: result.grantVersion,
    expiresAt: result.expiresAt,
  });
}
