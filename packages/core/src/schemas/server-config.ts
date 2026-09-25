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
  inference: {
    // OpenAI-compatible chat completions endpoint the derivative compute
    // layer calls. Point it at the Vana inference relay (which holds the
    // provider key) or straight at a provider for local development.
    baseUrl: "https://inference.phala.com/v1",
    model: "z-ai/glm-5.3-flash",
    // End to end encryption of prompt and answer to the Phala gateway
    // (E2EE v2): the relay only sees ciphertext. Set false only for local
    // development against a provider without ACI attestation.
    e2ee: true,
    // Newest-first items kept per source scope when a prompt is assembled.
    maxSourceItems: 50,
    // Quiet period after a source scope changes before a recompute starts.
    recomputeDebounceMs: 5_000,
  },
  pdpp: {
    // The PDPP Authorization Server is opt-in. Off by default so an existing
    // deployment gains no new authorization surface on upgrade.
    enabled: false,
    // Absolute file paths of retained SourceDeclaration documents. There is
    // deliberately no trust-all option and no default: an AS that accepts any
    // declaration it can reach will issue grants over data it was never meant
    // to speak for. Empty means this server retains none and issues nothing.
    // An entry may pin the file's sha256 (hex, over the exact bytes); a file
    // whose bytes no longer match is refused. The installer that verified
    // the signed artifact writes that digest.
    declarationPaths: [] as Array<string | { path: string; sha256: string }>,
    // At most one acquisition method may write each retained source. The
    // declaration path ties an artifact method id to the source it produces.
    methods: [] as Array<{ method_id: string; declaration_path: string }>,
    // Require PKCE (RFC 7636, S256) on the authorization-code flow. PDPP
    // clients are public clients; without a verifier an intercepted code is
    // redeemable by whoever intercepted it.
    requirePkce: true,
    // Registered clients. `redirect_uri` is validated by EXACT match against
    // this list (RFC 6749 §3.1.2.2), because the authorization code is
    // delivered through that redirect: an unvalidated target is code
    // exfiltration, and PKCE does not help when the attacker chose the
    // challenge. Empty means no client may start an authorization flow.
    clients: [] as Array<{
      clientId: string;
      redirectUris: string[];
      // Optional operator policy: cap how long a grant issued to this client
      // stays active, in seconds. Unset means no AS-imposed expiry, exactly
      // today's behavior. This is deployment policy, not something a client
      // can request — there is deliberately no client-supplied expiry field.
      grantLifetimeSeconds?: number;
    }>,
    // Hosts this deployment allows to resolve URL-hosted (§6) client
    // identities. Empty means no client_id is ever fetched: registration in
    // `clients` above stays the only way a client is admitted, and this
    // server performs no outbound request for an unregistered one.
    urlHostedClientHosts: [] as string[],
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
      /**
       * A preinstalled frpc executable to run instead of downloading one
       * into the storage root. A host that ships inside a signed, notarized
       * bundle (the Desktop app) sets this so the tunnel client carries the
       * same signature as everything else it runs; an ad-hoc binary fetched
       * into the user's home directory is what endpoint security flags.
       * Absent = download and manage the binary as before.
       */
      binaryPath: z.string().min(1).optional(),
    })
    .default(DEFAULTS.tunnel),
  inference: z
    .object({
      baseUrl: z.url().default(DEFAULTS.inference.baseUrl),
      model: z.string().min(1).default(DEFAULTS.inference.model),
      e2ee: z.boolean().default(DEFAULTS.inference.e2ee),
      maxSourceItems: z
        .number()
        .int()
        .min(1)
        .max(10_000)
        .default(DEFAULTS.inference.maxSourceItems),
      recomputeDebounceMs: z
        .number()
        .int()
        .min(0)
        .max(3_600_000)
        .default(DEFAULTS.inference.recomputeDebounceMs),
    })
    .default(DEFAULTS.inference),
  pdpp: z
    .object({
      enabled: z.boolean().default(DEFAULTS.pdpp.enabled),
      // No trust-all switch by design. A declaration is trusted because an
      // operator retained this exact document, not because it was reachable.
      declarationPaths: z
        .array(
          z.union([
            z.string().min(1),
            z.object({
              path: z.string().min(1),
              sha256: z
                .string()
                .regex(/^[0-9a-f]{64}$/, "lowercase hex sha256"),
            }),
          ]),
        )
        .default(DEFAULTS.pdpp.declarationPaths),
      methods: z
        .array(
          z.object({
            method_id: z.string().min(1),
            declaration_path: z.string().min(1),
          }),
        )
        .default(DEFAULTS.pdpp.methods),
      requirePkce: z.boolean().default(DEFAULTS.pdpp.requirePkce),
      clients: z
        .array(
          z.object({
            clientId: z.string().min(1),
            // Absolute URIs only; the AS additionally enforces https (or
            // loopback http) and exact matching at request time.
            redirectUris: z.array(z.string().min(1)).min(1),
            // Bounded well under the Date range limit (~±8.64e15ms, itself
            // below Number.MAX_SAFE_INTEGER) so
            // `Date.now() + grantLifetimeSeconds * 1000` can never overflow
            // into an invalid or wrapped instant. 100 years is generous for
            // an operator policy and nowhere near that limit.
            grantLifetimeSeconds: z
              .number()
              .int()
              .positive()
              .max(100 * 365 * 24 * 60 * 60)
              .optional(),
          }),
        )
        .default(DEFAULTS.pdpp.clients),
      // Opt-in allowlist: no host here means no client_id URL is ever
      // fetched. A static registration in `clients` remains first choice and
      // is always checked before this path runs.
      urlHostedClientHosts: z
        .array(z.string().min(1))
        .default(DEFAULTS.pdpp.urlHostedClientHosts),
    })
    .default(DEFAULTS.pdpp),
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

/**
 * Model ids that shipped as {@link DEFAULTS}`.inference.model` before the
 * current one.
 *
 * A persisted config that still names one of these was never a choice anyone
 * made. Both persistence paths materialize schema defaults into the stored
 * config on first boot — `loadConfig` writes the parsed config back to
 * `server.json`, PS Lite stores the parsed config under its config key — so
 * every install pins whatever default it first ran, and Desktop then hands
 * that pinned value back as an explicit `configDefaults` entry. Without a
 * forward step a default bump reaches new installs only.
 *
 * Anything outside this list is left alone: it can only have come from an
 * operator editing the config or a host choosing a model, and that choice
 * outranks ours.
 */
export const SUPERSEDED_INFERENCE_MODELS: readonly string[] = ["z-ai/glm-5.2"];

/**
 * Move a superseded default model forward to the current one.
 *
 * Returns the same object when there is nothing to move, so a caller can
 * persist on identity change alone:
 *
 * ```ts
 * const next = withCurrentInferenceModel(stored);
 * if (next !== stored) await save(next);
 * ```
 */
export function withCurrentInferenceModel(config: ServerConfig): ServerConfig {
  const model = config.inference.model;
  if (
    model === DEFAULTS.inference.model ||
    !SUPERSEDED_INFERENCE_MODELS.includes(model)
  ) {
    return config;
  }
  return {
    ...config,
    inference: { ...config.inference, model: DEFAULTS.inference.model },
  };
}
