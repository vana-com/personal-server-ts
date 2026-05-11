import {
  buildWeb3SignedHeader,
  type DataPortabilityGatewayConfig,
  type GatewayClient,
  type RegisterServerParams,
  type RegisterServerResult,
  SERVER_REGISTRATION_TYPES,
  serverRegistrationDomain,
  type Web3SignedSignFn,
} from "@opendatalabs/vana-sdk/browser";

export type PersonalServerKind = "node" | "lite";

export type PersonalServerStatus =
  | "starting"
  | "ready"
  | "unavailable"
  | "stopped"
  | "error";

export interface PersonalServerIdentity {
  address: `0x${string}`;
  publicKey: `0x${string}`;
  serverId: string | null;
}

export interface PersonalServerUrls {
  local: string | null;
  public: string | null;
  apiOrigin: string | null;
  registration: string | null;
}

export type PersonalServerRegistrationCandidate = Omit<
  RegisterServerParams,
  "signature"
>;

export interface PersonalServerRegistrationRequest {
  gatewayConfig: DataPortabilityGatewayConfig;
  candidate: PersonalServerRegistrationCandidate;
  typedData: {
    domain: ReturnType<typeof serverRegistrationDomain>;
    types: typeof SERVER_REGISTRATION_TYPES;
    primaryType: "ServerRegistration";
    message: PersonalServerRegistrationCandidate;
  };
}

export interface PersonalServerInfo {
  kind: PersonalServerKind;
  status: PersonalServerStatus;
  ownerAddress: `0x${string}` | null;
  server: PersonalServerIdentity | null;
  urls: PersonalServerUrls;
  registration: {
    registered: boolean;
    candidate: PersonalServerRegistrationCandidate | null;
  };
  gatewayUrl: string | null;
  gatewayConfig: DataPortabilityGatewayConfig | null;
  checkedAt?: string;
  details?: unknown;
}

export interface PersonalServerReadyOptions {
  publicUrl?: boolean;
}

export interface PersonalServerInfoOptions {
  refresh?: boolean;
}

export interface PersonalServerPrepareRegistrationOptions {
  serverUrl?: string;
}

export interface PersonalServerSubmitRegistrationOptions {
  signature: `0x${string}`;
}

export type PersonalServerOwnerAuth =
  | { signMessage: Web3SignedSignFn }
  | { bearerToken: string };

export type PersonalServerPostDataOptions = PersonalServerOwnerAuth & {
  headers?: Record<string, string>;
};

export interface PersonalServerHandle {
  readonly kind: PersonalServerKind;
  ready(options?: PersonalServerReadyOptions): Promise<PersonalServerInfo>;
  info(options?: PersonalServerInfoOptions): Promise<PersonalServerInfo>;
  prepareRegistration(
    options?: PersonalServerPrepareRegistrationOptions,
  ): Promise<PersonalServerRegistrationRequest>;
  submitRegistration(
    options: PersonalServerSubmitRegistrationOptions,
  ): Promise<RegisterServerResult>;
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
  postData(
    scope: string,
    body: unknown,
    options: PersonalServerPostDataOptions,
  ): Promise<{ scope: string; collectedAt: string; status: string }>;
  stop(): Promise<void>;
}

export interface PersonalServerHealthRegistration {
  ownerAddress: `0x${string}`;
  serverAddress: `0x${string}`;
  publicKey: `0x${string}`;
  serverUrl: string;
  serverId: string | null;
  registered: boolean;
}

interface PersonalServerHealthIdentity {
  address: `0x${string}`;
  publicKey: `0x${string}`;
  serverId: string | null;
}

interface PersonalServerHealthBody {
  status?: string;
  owner?: `0x${string}` | null;
  apiOrigin?: string | null;
  gatewayUrl?: string | null;
  gatewayConfig?: (DataPortabilityGatewayConfig & { url?: string }) | null;
  identity?: PersonalServerHealthIdentity | null;
  registration?: PersonalServerHealthRegistration | null;
  runtime?: unknown;
  checkedAt?: string;
}

export function createPersonalServerRegistrationRequest(params: {
  gatewayConfig: DataPortabilityGatewayConfig;
  ownerAddress: `0x${string}`;
  serverAddress: `0x${string}`;
  publicKey: `0x${string}`;
  serverUrl: string;
}): PersonalServerRegistrationRequest {
  const candidate = {
    ownerAddress: params.ownerAddress,
    serverAddress: params.serverAddress,
    publicKey: params.publicKey,
    serverUrl: params.serverUrl,
  };
  return {
    gatewayConfig: params.gatewayConfig,
    candidate,
    typedData: {
      domain: serverRegistrationDomain(params.gatewayConfig),
      types: SERVER_REGISTRATION_TYPES,
      primaryType: "ServerRegistration",
      message: candidate,
    },
  };
}

export function createPersonalServerInfoFromHealth(params: {
  kind: PersonalServerKind;
  status: PersonalServerStatus;
  health: unknown;
  localUrl?: string | null;
  publicUrl?: string | null;
}): PersonalServerInfo {
  const health = toHealthBody(params.health);
  const publicUrl = params.publicUrl ?? health.apiOrigin ?? null;
  const apiOrigin = publicUrl ?? params.localUrl ?? null;
  const gatewayConfig = stripGatewayUrl(health.gatewayConfig);
  const candidate = health.registration
    ? {
        ownerAddress: health.registration.ownerAddress,
        serverAddress: health.registration.serverAddress,
        publicKey: health.registration.publicKey,
        serverUrl: health.registration.serverUrl,
      }
    : null;

  return {
    kind: params.kind,
    status:
      health.status === "unavailable" && params.status === "ready"
        ? "unavailable"
        : params.status,
    ownerAddress: health.owner ?? health.registration?.ownerAddress ?? null,
    server: health.identity
      ? {
          address: health.identity.address,
          publicKey: health.identity.publicKey,
          serverId: health.identity.serverId,
        }
      : null,
    urls: {
      local: params.localUrl ?? null,
      public: publicUrl,
      apiOrigin,
      registration: health.registration?.serverUrl ?? publicUrl,
    },
    registration: {
      registered: Boolean(health.registration?.registered),
      candidate,
    },
    gatewayUrl: health.gatewayUrl ?? health.gatewayConfig?.url ?? null,
    gatewayConfig,
    checkedAt: health.checkedAt,
    details: health,
  };
}

export async function createOwnerSignedPersonalServerRequest(params: {
  origin: string;
  path: string;
  method: string;
  body?: Uint8Array;
  auth: PersonalServerOwnerAuth;
  headers?: Record<string, string>;
}): Promise<Request> {
  const headers = new Headers(params.headers);
  if ("bearerToken" in params.auth) {
    headers.set("Authorization", `Bearer ${params.auth.bearerToken}`);
  } else {
    headers.set(
      "Authorization",
      await buildWeb3SignedHeader({
        signMessage: params.auth.signMessage,
        aud: params.origin,
        method: params.method,
        uri: params.path,
        body: params.body,
      }),
    );
  }
  return new Request(`${params.origin}${params.path}`, {
    method: params.method,
    headers,
    body: params.body as BodyInit | undefined,
  });
}

export async function submitPersonalServerRegistration(params: {
  gateway: Pick<GatewayClient, "getServer" | "registerServer">;
  request: PersonalServerRegistrationRequest;
  signature: `0x${string}`;
}): Promise<RegisterServerResult> {
  const existing = await params.gateway.getServer(
    params.request.candidate.serverAddress,
  );
  if (existing?.id) {
    return { alreadyRegistered: true, serverId: existing.id };
  }
  return params.gateway.registerServer({
    ...params.request.candidate,
    signature: params.signature,
  });
}

export function requestPath(input: string | URL | Request): string {
  const url =
    input instanceof Request
      ? new URL(input.url)
      : input instanceof URL
        ? input
        : new URL(input, "https://personal-server.local");
  return `${url.pathname}${url.search}`;
}

function toHealthBody(value: unknown): PersonalServerHealthBody {
  return value && typeof value === "object"
    ? (value as PersonalServerHealthBody)
    : {};
}

function stripGatewayUrl(
  config: (DataPortabilityGatewayConfig & { url?: string }) | null | undefined,
): DataPortabilityGatewayConfig | null {
  if (!config) return null;
  return {
    chainId: config.chainId,
    contracts: config.contracts,
  };
}
