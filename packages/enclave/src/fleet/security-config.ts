import { createPublicKey, verify } from "node:crypto";

export interface FleetSecurityConfigPayload {
  version: 1;
  purpose: "vana.fleet.security-config";
  role: "controller" | "worker";
  appId: string;
  instanceId: string;
  nodeId: string;
  issuedAt: string;
  /** Null explicitly signs a deployment-lifetime policy; strings retain bounded expiry. */
  expiresAt: string | null;
  env: Record<string, string>;
}

const DOMAIN = "vana.fleet.security-config.v1\0";
const MAX_BYTES = 128 * 1024;
const MAX_VALIDITY_MS = 24 * 60 * 60 * 1_000;
const COMMON_KEYS = [
  "CHAIN_ID",
  "NODE_ID",
  "GATEWAY_URL",
  "VERCEL_PROTECTION_BYPASS",
  "MCP_PUBLIC_ORIGIN",
  "MCP_APPROVAL_URL",
  "MCP_STATE_PATH",
  "MCP_REDIRECT_URIS",
  "MCP_INGRESS_HOST",
  "MCP_INGRESS_PORT",
  "MCP_MIGRATION_REQUIRED",
  "FLEET_PEER_HOST",
  "FLEET_PEER_PORT",
];
const CONTROLLER_KEYS = [
  "CONTROLLER_TERM",
  "FLEET_STATE_PATH",
  "FLEET_WORKERS_JSON",
  "FLEET_GATEWAY_TOKEN",
  "FLEET_CONTROLLER_GATEWAY_TOKEN",
  "FLEET_CONTROLLER_ADMIN_TOKEN",
  "FLEET_CONTROL_HOST",
  "FLEET_CONTROL_PORT",
  "FLEET_ADMIN_HOST",
  "FLEET_ADMIN_PORT",
];
const WORKER_KEYS = [
  "ENCLAVE_AGENT_SECRET",
  "ENCLAVE_AGENT_HOST",
  "ENCLAVE_AGENT_PORT",
  "NODE_SECRET",
  "STORAGE_API_URL",
  "SANDBOX_AGENT_URL",
  "PS_IMAGE",
  "DOCKER_HOST",
  "SANDBOX_RUNTIME",
  "SANDBOX_MAX",
  "SANDBOX_MEMORY",
  "SANDBOX_CPUS",
  "SANDBOX_PIDS_LIMIT",
  "SANDBOX_IDLE_TTL_SECONDS",
  "SANDBOX_SYNC",
  "SANDBOX_DEBUG",
  "LEASE_SECONDS",
  "WORK_DELAY_MS",
  "JOB_RESULT_MAX_BYTES",
  "DATA_REGISTRY_CONTRACT",
  "DATA_PORTABILITY_SERVER_CONTRACT",
  "DATA_PORTABILITY_GRANTEES_CONTRACT",
  "DATA_PORTABILITY_PERMISSIONS_CONTRACT",
  "FLEET_ENABLED",
  "FLEET_PEER_POLICIES",
];
const MCP_REQUIRED = [
  "MCP_PUBLIC_ORIGIN",
  "MCP_APPROVAL_URL",
  "MCP_STATE_PATH",
  "MCP_REDIRECT_URIS",
];
const REQUIRED = {
  controller: [
    "CONTROLLER_TERM",
    "FLEET_STATE_PATH",
    "FLEET_WORKERS_JSON",
    "FLEET_GATEWAY_TOKEN",
    "FLEET_CONTROLLER_GATEWAY_TOKEN",
    "FLEET_CONTROLLER_ADMIN_TOKEN",
    "MCP_MIGRATION_REQUIRED",
    ...MCP_REQUIRED,
  ],
  worker: [
    "ENCLAVE_AGENT_SECRET",
    "NODE_SECRET",
    "STORAGE_API_URL",
    "PS_IMAGE",
    "SANDBOX_RUNTIME",
    "FLEET_ENABLED",
    "FLEET_PEER_POLICIES",
  ],
} as const;
/** Bundle metadata an operator may safely read back. Never carries `env`. */
export interface FleetConfigValidity {
  role: FleetSecurityConfigPayload["role"];
  nodeId: string;
  appId: string;
  instanceId: string;
  issuedAt: string;
  /** Null is the signed deployment-lifetime policy, not an absent value. */
  expiresAt: string | null;
}
const verifiedEnvironments = new WeakMap<object, FleetConfigValidity>();
const invalid = (): Error => new Error("Invalid fleet security configuration");

function record(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}
function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return (
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}
function boundedString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256;
}
function validatePayload(value: unknown): FleetSecurityConfigPayload {
  if (
    !record(value) ||
    !exactKeys(value, [
      "version",
      "purpose",
      "role",
      "appId",
      "instanceId",
      "nodeId",
      "issuedAt",
      "expiresAt",
      "env",
    ]) ||
    value.version !== 1 ||
    value.purpose !== "vana.fleet.security-config" ||
    (value.role !== "controller" && value.role !== "worker") ||
    !boundedString(value.appId) ||
    !boundedString(value.instanceId) ||
    !boundedString(value.nodeId) ||
    typeof value.issuedAt !== "string" ||
    (value.expiresAt !== null && typeof value.expiresAt !== "string") ||
    !record(value.env)
  )
    throw invalid();
  const allowed = new Set([
    ...COMMON_KEYS,
    ...(value.role === "controller" ? CONTROLLER_KEYS : WORKER_KEYS),
  ]);
  if (
    Object.entries(value.env).some(
      ([key, item]) =>
        !allowed.has(key) ||
        typeof item !== "string" ||
        item.length > 64 * 1024 ||
        item.includes("\0"),
    )
  )
    throw invalid();
  const env = value.env as Record<string, string>;
  for (const key of [
    "CHAIN_ID",
    "NODE_ID",
    "GATEWAY_URL",
    ...REQUIRED[value.role],
  ])
    if (!env[key]) throw invalid();
  if (
    env.CHAIN_ID !== "14800" ||
    env.NODE_ID !== value.nodeId ||
    (value.role === "controller" &&
      (env.CONTROLLER_TERM !== "1" ||
        !["0", "1"].includes(env.MCP_MIGRATION_REQUIRED!))) ||
    (value.role === "worker" &&
      (env.SANDBOX_RUNTIME !== "docker" ||
        !["true", "false"].includes(env.FLEET_ENABLED!)))
  )
    throw invalid();
  if (env.MCP_PUBLIC_ORIGIN && MCP_REQUIRED.some((key) => !env[key]))
    throw invalid();
  const issued = Date.parse(value.issuedAt);
  const expires = value.expiresAt === null ? null : Date.parse(value.expiresAt);
  if (
    !Number.isFinite(issued) ||
    new Date(issued).toISOString() !== value.issuedAt ||
    (expires !== null &&
      (!Number.isFinite(expires) ||
        new Date(expires).toISOString() !== value.expiresAt ||
        expires <= issued ||
        expires - issued > MAX_VALIDITY_MS))
  )
    throw invalid();
  return value as unknown as FleetSecurityConfigPayload;
}

/** Stable signing bytes, with ASCII/UTF-16 key ordering rather than locale rules.
 * There are no arbitrary nested objects: metadata and env values are strings.
 * The caller may sign only an operator-reviewed complete configuration. */
export function canonicalFleetConfigPayload(
  payload: FleetSecurityConfigPayload,
): Buffer {
  const value = validatePayload(payload);
  const ordered = Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [
        key,
        key === "env"
          ? Object.fromEntries(
              Object.keys(value.env)
                .sort()
                .map((name) => [name, value.env[name]]),
            )
          : value[key as keyof FleetSecurityConfigPayload],
      ]),
  );
  const bytes = Buffer.from(DOMAIN + JSON.stringify(ordered));
  if (bytes.length > MAX_BYTES) throw invalid();
  return bytes;
}

/** Only this module can mark an environment after signature AND TEE identity
 * verification. The frozen map contains no inherited host environment values. */
export function isVerifiedFleetEnvironment(env: NodeJS.ProcessEnv): boolean {
  return verifiedEnvironments.has(env);
}

/** Signed lifetime of a verified environment, for health and status surfaces.
 * Operators and the pool loop need the window without ever seeing the bundle. */
export function fleetConfigValidity(
  env: NodeJS.ProcessEnv,
): FleetConfigValidity | undefined {
  const validity = verifiedEnvironments.get(env);
  return validity && { ...validity };
}

/** Authenticates encrypted-env sender independently of dstack confidentiality.
 * FLEET_CONFIG_PUBLIC_KEY must be a literal in measured compose, never an
 * allowed unmeasured substitution. The OS/image launcher must exclude injection
 * variables (e.g. NODE_OPTIONS) before Node starts; this cannot undo boot code.
 * Finite expiry is checked at startup; signed expiresAt:null is deployment-lived.
 * A valid bundle can be replayed for this same instance within its signed window
 * (indefinitely when explicitly non-expiring). Expiry relies on the runtime wall clock;
 * this is not disk rollback protection or a remote freshness proof. This
 * initial deployment verifier intentionally supports Moksha (14800) only. */
export async function verifiedFleetEnvironment(
  raw: NodeJS.ProcessEnv,
  options: {
    role: FleetSecurityConfigPayload["role"];
    identity(): Promise<{ appId: string; instanceId: string }>;
    now?: () => number;
  },
): Promise<NodeJS.ProcessEnv> {
  try {
    const wire = raw.FLEET_SIGNED_CONFIG,
      publicKey = raw.FLEET_CONFIG_PUBLIC_KEY;
    if (
      !wire ||
      Buffer.byteLength(wire) > MAX_BYTES ||
      !wire.startsWith("base64:") ||
      !publicKey ||
      publicKey.length > 1024
    )
      throw invalid();
    // dstack 0.5.x writes env values through a systemd EnvironmentFile whose
    // quoting does not preserve nested JSON backslashes. Only canonical base64
    // transport is accepted; authentication still covers the decoded payload.
    const encoded = wire.slice("base64:".length);
    const bytes = Buffer.from(encoded, "base64");
    const document = bytes.toString("utf8");
    if (
      !bytes.length ||
      bytes.toString("base64") !== encoded ||
      !Buffer.from(document, "utf8").equals(bytes)
    )
      throw invalid();
    const parsed: unknown = JSON.parse(document);
    if (
      !record(parsed) ||
      !exactKeys(parsed, ["payload", "signature"]) ||
      typeof parsed.signature !== "string"
    )
      throw invalid();
    const payload = validatePayload(parsed.payload);
    if (payload.role !== options.role) throw invalid();
    const checkTime = () => {
      const now = (options.now ?? Date.now)();
      if (
        !Number.isFinite(now) ||
        Date.parse(payload.issuedAt) > now + 60_000 ||
        (payload.expiresAt !== null && Date.parse(payload.expiresAt) <= now)
      )
        throw invalid();
    };
    checkTime();
    const signature = Buffer.from(parsed.signature, "base64");
    const keyBytes = Buffer.from(publicKey, "base64");
    if (
      signature.length !== 64 ||
      signature.toString("base64") !== parsed.signature ||
      keyBytes.toString("base64") !== publicKey
    )
      throw invalid();
    const key = createPublicKey({ key: keyBytes, format: "der", type: "spki" });
    if (
      key.asymmetricKeyType !== "ed25519" ||
      !key.export({ format: "der", type: "spki" }).equals(keyBytes) ||
      !verify(null, canonicalFleetConfigPayload(payload), key, signature)
    )
      throw invalid();
    // Public info only, after sender authentication; no derivation/unseal here.
    const actual = await options.identity();
    if (
      actual.appId !== payload.appId ||
      actual.instanceId !== payload.instanceId
    )
      throw invalid();
    checkTime();
    const env: NodeJS.ProcessEnv = Object.freeze(
      Object.assign(Object.create(null), payload.env),
    );
    verifiedEnvironments.set(env, {
      role: payload.role,
      nodeId: payload.nodeId,
      appId: payload.appId,
      instanceId: payload.instanceId,
      issuedAt: payload.issuedAt,
      expiresAt: payload.expiresAt,
    });
    return env;
  } catch {
    // Parse/crypto/provider errors can contain input; never log bundle contents.
    throw invalid();
  }
}
