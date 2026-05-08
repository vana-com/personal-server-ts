import { verifyTypedData } from "viem";
import type {
  CreateGrantParams,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import { GRANT_DOMAIN, GRANT_TYPES } from "../grants/index.js";
import type { ServerSigner } from "../signing/index.js";
import {
  contractError,
  contractOk,
  contractProtocolError,
  type ContractResult,
} from "./http.js";

export interface VerifyGrantRequestBody {
  grantId: string;
  payload: {
    user: `0x${string}`;
    builder: `0x${string}`;
    scopes: string[];
    expiresAt: number;
    nonce: number;
  };
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
  if (typeof b.grantId !== "string" || b.grantId.length === 0) return false;
  if (typeof b.signature !== "string" || !b.signature.startsWith("0x")) {
    return false;
  }
  if (
    b.payload === null ||
    typeof b.payload !== "object" ||
    Array.isArray(b.payload)
  ) {
    return false;
  }
  const p = b.payload as Record<string, unknown>;
  if (typeof p.user !== "string" || !p.user.startsWith("0x")) return false;
  if (typeof p.builder !== "string" || !p.builder.startsWith("0x")) {
    return false;
  }
  if (!Array.isArray(p.scopes) || p.scopes.length === 0) return false;
  if (!p.scopes.every((scope) => typeof scope === "string")) return false;
  if (typeof p.expiresAt !== "number") return false;
  if (typeof p.nonce !== "number") return false;
  return true;
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

export async function verifyGrantContract(
  body: unknown,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<ContractResult> {
  if (!isValidVerifyBody(body)) {
    return contractError(
      400,
      "INVALID_BODY",
      "Body must include grantId (string), payload (object with user, builder, scopes, expiresAt, nonce), and signature (0x string)",
    );
  }

  const { payload, signature } = body;
  let valid: boolean;
  try {
    valid = await verifyTypedData({
      address: payload.user,
      domain: GRANT_DOMAIN,
      types: GRANT_TYPES,
      primaryType: "Grant",
      message: {
        user: payload.user,
        builder: payload.builder,
        scopes: payload.scopes,
        expiresAt: BigInt(payload.expiresAt),
        nonce: BigInt(payload.nonce),
      },
      signature,
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
      error: "Grant signature does not match user",
    });
  }

  if (payload.expiresAt > 0 && payload.expiresAt < nowSeconds) {
    return contractOk({ valid: false, error: "Grant has expired" });
  }

  return contractOk({
    valid: true,
    user: payload.user,
    builder: payload.builder,
    scopes: payload.scopes,
    expiresAt: payload.expiresAt,
  });
}
