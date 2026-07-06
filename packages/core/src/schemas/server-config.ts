import { z } from "zod";

export const DEFAULTS = {
  server: {
    port: 8080,
    origin: "http://localhost:8080",
  },
  logging: {
    level: "info" as const,
    pretty: false,
  },
  storage: {
    backend: "local" as const,
    config: {
      vana: {
        apiUrl: "https://storage.vana.org",
      },
    },
  },
  gateway: {
    url: "https://data-gateway-env-dev-opendatalabs.vercel.app",
    chainId: 14800,
    contracts: {
      // DataRegistryV2 — addData, recordDataAccess
      dataRegistry: "0x8f1eFCdff3d0d5BB535e32620721c7EBed151867",
      // DataPortabilityPermissionsV2 — grant register/revoke
      dataPortabilityPermissions: "0x4d3FA76064D88e0454cFc4CaD7e5FeC3e3124011",
      // DataPortabilityServersV2 — server registration / trust check
      dataPortabilityServer: "0xCae2CE0e9caa6643ed28186cF57bd40Bd9E17Eab",
      // DataPortabilityGrantees (v1 retained)
      dataPortabilityGrantees: "0x8325C0A0948483EdA023A1A2Fd895e62C5131234",
      // DataPortabilityEscrow — verifyingContract for the EIP-712 domain
      // backing /v1/escrow/pay (X402 payment validation).
      dataPortabilityEscrow: "0x07d7769081adc3a3DBe91f5E4B98E9A5a6B292e3",
      // FeeRegistry — declared for SDK-type compatibility. The personal
      // server doesn't call FeeRegistry directly; fees are read off
      // gateway.getGrant().fee, which the gateway re-resolves per request.
      feeRegistry: "0xb4FA18443E0FA6cdC0280D20b8cCDB2377D13Bf2",
      // Schema registration (POST /v1/schemas) is signed against the Data
    },
  },
  devUi: {
    enabled: true,
  },
  payment: {
    // Off by default. When true, data reads are gated on the grant's
    // payment status from DP RPC (BUI-398).
    enabled: false,
  },
  sync: {
    enabled: false,
    lastProcessedTimestamp: null,
  },
  tunnel: {
    enabled: true,
    serverAddr: "frpc.server.vana.org",
    serverPort: 7000,
  },
};

export const StorageBackend = z.enum([
  "local",
  "vana",
  "ipfs",
  "gdrive",
  "dropbox",
]);

export const VanaStorageConfigSchema = z.object({
  apiUrl: z.url().default(DEFAULTS.storage.config.vana.apiUrl),
});

export const ServerConfigSchema = z.object({
  server: z
    .object({
      port: z.number().int().min(1).max(65535).default(DEFAULTS.server.port),
      origin: z.url().default(DEFAULTS.server.origin),
    })
    .default(DEFAULTS.server),
  logging: z
    .object({
      level: z
        .enum(["fatal", "error", "warn", "info", "debug"])
        .default(DEFAULTS.logging.level),
      pretty: z.boolean().default(DEFAULTS.logging.pretty),
    })
    .default(DEFAULTS.logging),
  storage: z
    .object({
      backend: StorageBackend.default(DEFAULTS.storage.backend),
      config: z
        .object({
          vana: VanaStorageConfigSchema.optional(),
        })
        .default({}),
    })
    .default(DEFAULTS.storage),
  gateway: z
    .object({
      url: z.url().default(DEFAULTS.gateway.url),
      chainId: z.number().int().positive().default(DEFAULTS.gateway.chainId),
      contracts: z
        .object({
          dataRegistry: z
            .string()
            .startsWith("0x")
            .default(DEFAULTS.gateway.contracts.dataRegistry),
          dataPortabilityPermissions: z
            .string()
            .startsWith("0x")
            .default(DEFAULTS.gateway.contracts.dataPortabilityPermissions),
          dataPortabilityServer: z
            .string()
            .startsWith("0x")
            .default(DEFAULTS.gateway.contracts.dataPortabilityServer),
          dataPortabilityGrantees: z
            .string()
            .startsWith("0x")
            .default(DEFAULTS.gateway.contracts.dataPortabilityGrantees),
          dataPortabilityEscrow: z
            .string()
            .startsWith("0x")
            .default(DEFAULTS.gateway.contracts.dataPortabilityEscrow),
          feeRegistry: z
            .string()
            .startsWith("0x")
            .default(DEFAULTS.gateway.contracts.feeRegistry),
        })
        .default(DEFAULTS.gateway.contracts),
    })
    .default(DEFAULTS.gateway),
  devUi: z
    .object({
      enabled: z.boolean().default(DEFAULTS.devUi.enabled),
    })
    .default(DEFAULTS.devUi),
  payment: z
    .object({
      enabled: z.boolean().default(DEFAULTS.payment.enabled),
    })
    .default(DEFAULTS.payment),
  sync: z
    .object({
      enabled: z.boolean().default(DEFAULTS.sync.enabled),
      lastProcessedTimestamp: z
        .string()
        .datetime()
        .nullable()
        .default(DEFAULTS.sync.lastProcessedTimestamp),
    })
    .default(DEFAULTS.sync),
  tunnel: z
    .object({
      enabled: z.boolean().default(DEFAULTS.tunnel.enabled),
      serverAddr: z.string().default(DEFAULTS.tunnel.serverAddr),
      serverPort: z
        .number()
        .int()
        .min(1)
        .max(65535)
        .default(DEFAULTS.tunnel.serverPort),
    })
    .default(DEFAULTS.tunnel),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;
export type LoggingConfig = ServerConfig["logging"];

/** Chain + contract config needed for EIP-712 signing. */
export type GatewayConfig = {
  chainId: number;
  contracts: {
    dataRegistry: string;
    dataPortabilityPermissions: string;
    dataPortabilityServer: string;
    dataPortabilityGrantees: string;
    // verifyingContract for the EIP-712 domain backing /v1/escrow/pay.
    dataPortabilityEscrow: string;
    // Required by the SDK's DataPortabilityContracts type for structural
    // compatibility; not invoked directly from the personal server.
    feeRegistry: string;
  };
};
