import type {
  Builder,
  DataPortabilityGatewayConfig,
  GatewayClient,
} from "@opendatalabs/vana-sdk/browser";
import {
  BUILDER_REGISTRATION_TYPES,
  builderRegistrationDomain,
  type BuilderRegistrationMessage,
} from "@opendatalabs/vana-sdk/browser";
import { loadMcpGranteeAccount } from "./grantee.js";
import type { McpConnectionRecord } from "./types.js";

export interface EnsureMcpGranteeRegisteredInput {
  connection: McpConnectionRecord;
  gateway: Pick<GatewayClient, "getBuilder">;
  gatewayConfig: DataPortabilityGatewayConfig;
  gatewayUrl: string;
  appUrl: string;
  fetch?: typeof fetch;
}

export interface EnsureMcpGranteeRegisteredOutput {
  alreadyRegistered: boolean;
  builder: Builder | null;
  granteeAddress: `0x${string}`;
}

export class McpGranteeRegistrationError extends Error {
  constructor(
    public code: string,
    message: string,
    public status?: number,
    public body?: unknown,
  ) {
    super(message);
    this.name = "McpGranteeRegistrationError";
  }
}

export async function ensureMcpGranteeRegistered(
  input: EnsureMcpGranteeRegisteredInput,
): Promise<EnsureMcpGranteeRegisteredOutput> {
  const existing = await input.gateway.getBuilder(
    input.connection.granteeAddress,
  );
  if (existing) {
    return {
      alreadyRegistered: true,
      builder: existing,
      granteeAddress: input.connection.granteeAddress,
    };
  }

  const account = loadMcpGranteeAccount({
    address: input.connection.granteeAddress,
    publicKey: input.connection.granteePublicKey,
    encryptedPrivateKey: input.connection.encryptedGranteePrivateKey,
  });
  const message: BuilderRegistrationMessage = {
    ownerAddress: account.address,
    granteeAddress: account.address,
    publicKey: account.publicKey,
    appUrl: input.appUrl,
  };
  const signature = await account.signTypedData({
    domain: builderRegistrationDomain(input.gatewayConfig),
    types: BUILDER_REGISTRATION_TYPES,
    primaryType: "BuilderRegistration",
    message: message as unknown as Record<string, unknown>,
  });

  const doFetch = input.fetch ?? globalThis.fetch;
  const response = await doFetch(
    `${input.gatewayUrl.replace(/\/+$/u, "")}/v1/builders`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Web3Signed ${signature}`,
      },
      body: JSON.stringify(message),
    },
  );
  const body = await parseJsonResponse(response);

  if (response.status === 201) {
    return {
      alreadyRegistered: false,
      builder: null,
      granteeAddress: input.connection.granteeAddress,
    };
  }

  if (response.status === 409) {
    const registered = await input.gateway.getBuilder(
      input.connection.granteeAddress,
    );
    if (registered) {
      return {
        alreadyRegistered: true,
        builder: registered,
        granteeAddress: input.connection.granteeAddress,
      };
    }
  }

  throw new McpGranteeRegistrationError(
    response.status === 409 ? "registration_conflict" : "gateway_error",
    `Data Gateway rejected MCP grantee registration (${response.status})`,
    response.status,
    body,
  );
}

export function appUrlFromOAuthRedirectUri(
  redirectUri: string,
  fallback: string,
): string {
  try {
    return new URL(redirectUri).origin;
  } catch {
    return fallback;
  }
}

async function parseJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}
