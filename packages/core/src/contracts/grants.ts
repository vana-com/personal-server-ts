import { verifyTypedData } from "viem";
import type {
  CreateGrantParams,
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import {
  GRANT_REGISTRATION_TYPES,
  grantRegistrationDomain,
} from "@opendatalabs/vana-sdk/browser";
import type { ServerSigner } from "../signing/index.js";
import {
  contractError,
  contractOk,
  contractProtocolError,
  type ContractResult,
} from "./http.js";

export interface VerifyGrantRequestBody {
  grantorAddress: `0x${string}`;
  granteeId: `0x${string}`;
  grant: string;
  fileIds?: Array<string | number>;
  signature: `0x${string}`;
}

export interface CreateGrantRequestBody {
  granteeAddress: `0x${string}`;
  scopes: string[];
  expiresAt?: number;
  nonce?: number;
}

export interface CreateGrantContractInput {
  gateway: Pick<GatewayClient, "getBuilder" | "createGrant">;
  serverOwner?: `0x${string}`;
  serverSigner?: Pick<ServerSigner, "signGrantRegistration">;
  body: unknown;
  now?: () => number;
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

interface ParsedGrantPayload {
  user?: `0x${string}`;
  builder?: `0x${string}`;
  scopes: string[];
  expiresAt: number;
  nonce?: number;
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
  if (!Array.isArray(b.scopes) || b.scopes.length === 0) return false;
  if (!b.scopes.every((scope) => typeof scope === "string")) return false;
  if (b.expiresAt !== undefined && typeof b.expiresAt !== "number") {
    return false;
  }
  if (b.nonce !== undefined && typeof b.nonce !== "number") return false;
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
  if (typeof b.grant !== "string" || b.grant.length === 0) return false;
  if (
    b.fileIds !== undefined &&
    (!Array.isArray(b.fileIds) ||
      !b.fileIds.every(
        (fileId) => typeof fileId === "string" || typeof fileId === "number",
      ))
  ) {
    return false;
  }
  if (typeof b.signature !== "string" || !b.signature.startsWith("0x")) {
    return false;
  }
  return true;
}

function parseGrantPayload(grant: string): ParsedGrantPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(grant);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  const value = parsed as Record<string, unknown>;
  if (!Array.isArray(value.scopes) || value.scopes.length === 0) return null;
  if (!value.scopes.every((scope) => typeof scope === "string")) return null;
  if (typeof value.expiresAt !== "number") return null;
  if (
    value.user !== undefined &&
    (typeof value.user !== "string" || !value.user.startsWith("0x"))
  ) {
    return null;
  }
  if (
    value.builder !== undefined &&
    (typeof value.builder !== "string" || !value.builder.startsWith("0x"))
  ) {
    return null;
  }
  if (value.nonce !== undefined && typeof value.nonce !== "number") {
    return null;
  }
  return {
    user: value.user as `0x${string}` | undefined,
    builder: value.builder as `0x${string}` | undefined,
    scopes: value.scopes as string[],
    expiresAt: value.expiresAt,
    nonce: value.nonce,
  };
}

function fileIdsToBigInt(
  fileIds: Array<string | number> | undefined,
): bigint[] | null {
  try {
    return (fileIds ?? []).map((fileId) => BigInt(fileId));
  } catch {
    return null;
  }
}

function serverOwnerNotConfigured(): ContractResult {
  return contractProtocolError(
    500,
    "SERVER_NOT_CONFIGURED",
    "Server owner address not configured. Set VANA_MASTER_KEY_SIGNATURE environment variable.",
  );
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

  const { granteeAddress, scopes, expiresAt, nonce } = input.body;
  const builder = await input.gateway.getBuilder(granteeAddress);
  if (!builder) {
    return contractProtocolError(
      404,
      "BUILDER_NOT_REGISTERED",
      `Builder ${granteeAddress} is not registered on-chain`,
    );
  }

  const grantPayload = JSON.stringify({
    user: input.serverOwner,
    builder: granteeAddress,
    scopes,
    expiresAt: expiresAt ?? 0,
    nonce: nonce ?? input.now?.() ?? Date.now(),
  });

  const signature = await input.serverSigner.signGrantRegistration({
    grantorAddress: input.serverOwner,
    granteeId: builder.id as `0x${string}`,
    grant: grantPayload,
    fileIds: [],
  });

  const params: CreateGrantParams = {
    grantorAddress: input.serverOwner,
    granteeId: builder.id,
    grant: grantPayload,
    fileIds: [],
    signature,
  };
  const result = await input.gateway.createGrant(params);
  return contractOk({ grantId: result.grantId }, 201);
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
      "Body must include grantorAddress, granteeId, grant, optional fileIds, and signature",
    );
  }
  if (!gatewayConfig) {
    return contractProtocolError(
      500,
      "SERVER_NOT_CONFIGURED",
      "Gateway config is not configured",
    );
  }

  const payload = parseGrantPayload(body.grant);
  if (!payload) {
    return contractError(
      400,
      "INVALID_BODY",
      "Grant must be JSON with scopes and expiresAt",
    );
  }

  const fileIds = fileIdsToBigInt(body.fileIds);
  if (!fileIds) {
    return contractError(
      400,
      "INVALID_BODY",
      "fileIds must contain integer values",
    );
  }
  let valid: boolean;
  try {
    valid = await verifyTypedData({
      address: body.grantorAddress,
      domain: grantRegistrationDomain(gatewayConfig),
      types: GRANT_REGISTRATION_TYPES,
      primaryType: "GrantRegistration",
      message: {
        grantorAddress: body.grantorAddress,
        granteeId: body.granteeId,
        grant: body.grant,
        fileIds,
      },
      signature: body.signature,
    });
  } catch {
    return contractOk({
      valid: false,
      error: "EIP-712 signature verification failed",
    });
  }

  if (!valid) {
    return contractOk({
      valid: false,
      error: "Grant signature does not match grantor",
    });
  }

  if (payload.expiresAt > 0 && payload.expiresAt < nowSeconds) {
    return contractOk({ valid: false, error: "Grant has expired" });
  }

  return contractOk({
    valid: true,
    grantorAddress: body.grantorAddress,
    granteeId: body.granteeId,
    user: payload.user ?? body.grantorAddress,
    builder: payload.builder,
    scopes: payload.scopes,
    expiresAt: payload.expiresAt,
    fileIds: body.fileIds ?? [],
  });
}
