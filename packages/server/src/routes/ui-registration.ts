import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import {
  createGatewayClient,
  serverRegistrationDomain,
  SERVER_REGISTRATION_TYPES,
  type DataPortabilityGatewayConfig,
} from "@opendatalabs/vana-sdk/node";
import { privateKeyToAccount } from "viem/accounts";

interface RegistrationCandidate {
  ownerAddress: `0x${string}`;
  serverAddress: `0x${string}`;
  publicKey: `0x${string}`;
  serverUrl: string;
}

export interface UiRegistrationRouteDeps {
  devToken: string;
  ownerPrivateKey?: `0x${string}`;
  /** Called when registration is confirmed (fresh or already registered). */
  onRegistered?: (serverId: string | null) => void;
}

function isHexAddress(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function normalizePrivateKey(value: string): `0x${string}` | null {
  const normalized = value.startsWith("0x") ? value : `0x${value}`;
  return /^0x[0-9a-fA-F]{64}$/.test(normalized)
    ? (normalized as `0x${string}`)
    : null;
}

function parseGatewayConfig(
  value: unknown,
): (DataPortabilityGatewayConfig & { url: string }) | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  const contracts = record.contracts as Record<string, unknown> | undefined;
  if (
    typeof record.url !== "string" ||
    typeof record.chainId !== "number" ||
    !contracts ||
    typeof contracts.dataPortabilityServer !== "string"
  ) {
    return null;
  }
  return value as DataPortabilityGatewayConfig & { url: string };
}

function parseCandidate(value: unknown): RegistrationCandidate | null {
  if (!value || typeof value !== "object") return null;
  const record = value as Record<string, unknown>;
  if (
    !isHexAddress(record.ownerAddress) ||
    !isHexAddress(record.serverAddress) ||
    typeof record.publicKey !== "string" ||
    !record.publicKey.startsWith("0x") ||
    typeof record.serverUrl !== "string"
  ) {
    return null;
  }
  return {
    ownerAddress: record.ownerAddress,
    serverAddress: record.serverAddress,
    publicKey: record.publicKey as `0x${string}`,
    serverUrl: record.serverUrl,
  };
}

function isLocalUrl(serverUrl: string): boolean {
  try {
    const url = new URL(serverUrl);
    const hostname = url.hostname.toLowerCase();
    return (
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "0.0.0.0" ||
      hostname === "[::1]" ||
      hostname === "ps-lite.local" ||
      hostname.startsWith("10.") ||
      hostname.startsWith("192.168.") ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(hostname)
    );
  } catch {
    return true;
  }
}

export function uiRegistrationRoutes(deps: UiRegistrationRouteDeps): Hono {
  const app = new Hono();

  const requireDevToken: MiddlewareHandler = async (c, next) => {
    const authHeader = c.req.header("authorization");
    if (authHeader !== `Bearer ${deps.devToken}`) {
      return c.json(
        {
          error: {
            code: 401,
            errorCode: "UNAUTHORIZED",
            message: "Invalid dev token",
          },
        },
        401,
      );
    }
    await next();
  };

  app.get("/registration", requireDevToken, (c) => {
    return c.json({
      ownerPrivateKeyConfigured: Boolean(deps.ownerPrivateKey),
    });
  });

  app.post("/registration/server", requireDevToken, async (c) => {
    if (!deps.ownerPrivateKey) {
      return c.json(
        {
          error: {
            code: 503,
            errorCode: "OWNER_PRIVATE_KEY_NOT_CONFIGURED",
            message: "Set VANA_OWNER_PRIVATE_KEY to register servers.",
          },
        },
        503,
      );
    }

    const ownerPrivateKey = normalizePrivateKey(deps.ownerPrivateKey);
    if (!ownerPrivateKey) {
      return c.json(
        {
          error: {
            code: 500,
            errorCode: "INVALID_OWNER_PRIVATE_KEY",
            message:
              "VANA_OWNER_PRIVATE_KEY must be a 32-byte hex private key.",
          },
        },
        500,
      );
    }

    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "INVALID_BODY",
            message: "Invalid JSON body",
          },
        },
        400,
      );
    }

    const record = body as Record<string, unknown>;
    const gatewayConfig = parseGatewayConfig(record.gatewayConfig);
    const candidate = parseCandidate(record.registration);
    if (!gatewayConfig || !candidate) {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "INVALID_REGISTRATION",
            message: "Registration payload is incomplete.",
          },
        },
        400,
      );
    }
    if (isLocalUrl(candidate.serverUrl)) {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "PUBLIC_API_URL_REQUIRED",
            message: "Register using the public PS API URL.",
          },
        },
        400,
      );
    }

    const account = privateKeyToAccount(ownerPrivateKey);
    if (
      account.address.toLowerCase() !== candidate.ownerAddress.toLowerCase()
    ) {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "OWNER_KEY_MISMATCH",
            message:
              "VANA_OWNER_PRIVATE_KEY does not match registration owner.",
          },
        },
        400,
      );
    }

    const gateway = createGatewayClient(gatewayConfig.url);
    const existing = await gateway.getServer(candidate.serverAddress);
    if (existing?.id) {
      deps.onRegistered?.(existing.id);
      return c.json({
        alreadyRegistered: true,
        serverId: existing.id,
        candidate,
      });
    }

    const signature = await account.signTypedData({
      domain: serverRegistrationDomain(gatewayConfig),
      types: SERVER_REGISTRATION_TYPES,
      primaryType: "ServerRegistration",
      message: candidate,
    });
    const result = await gateway.registerServer({
      ...candidate,
      signature,
    });
    deps.onRegistered?.(result.serverId ?? null);

    return c.json({
      ...result,
      candidate,
    });
  });

  app.post("/rpc/files", requireDevToken, async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "INVALID_BODY",
            message: "Invalid JSON body",
          },
        },
        400,
      );
    }

    const record = body as Record<string, unknown>;
    const gatewayUrl = record.gatewayUrl;
    const fileIds = record.fileIds;
    if (
      typeof gatewayUrl !== "string" ||
      !Array.isArray(fileIds) ||
      !fileIds.every((fileId) => typeof fileId === "string")
    ) {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "INVALID_RPC_FILE_CHECK",
            message: "gatewayUrl and fileIds are required.",
          },
        },
        400,
      );
    }

    const gateway = createGatewayClient(gatewayUrl);
    const results: Record<string, { registered: boolean; error?: string }> = {};
    await Promise.all(
      fileIds.map(async (fileId) => {
        try {
          const dataPoint = await gateway.getDataPoint(fileId);
          results[fileId] = { registered: Boolean(dataPoint) };
        } catch (err) {
          results[fileId] = {
            registered: false,
            error: err instanceof Error ? err.message : String(err),
          };
        }
      }),
    );

    return c.json({ files: results });
  });

  return app;
}
