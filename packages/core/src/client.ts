import {
  buildWeb3SignedHeader,
  type DataFileEnvelope,
  type DataPortabilityGatewayConfig,
  type GatewayClient,
  type GrantListItem,
  type ServerInfo,
  type RegisterServerParams,
  type RegisterServerResult,
  SERVER_REGISTRATION_TYPES,
  serverRegistrationDomain,
  type Web3SignedSignFn,
} from "@opendatalabs/vana-sdk/browser";
import type { ScopeSummary } from "./storage/index/types.js";
import type { SyncStatus } from "./sync/types.js";

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

export interface PersonalServerListDataOptions {
  scopePrefix?: string;
  limit?: number;
  offset?: number;
  auth?: PersonalServerOwnerAuth;
  headers?: Record<string, string>;
}

export interface PersonalServerListDataResult {
  scopes: ScopeSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface PersonalServerListVersionsOptions {
  limit?: number;
  offset?: number;
  auth?: PersonalServerOwnerAuth;
  headers?: Record<string, string>;
}

export interface PersonalServerDataVersion {
  fileId: string | null;
  schemaId: string | null;
  collectedAt: string;
}

export interface PersonalServerListVersionsResult {
  scope: string;
  versions: PersonalServerDataVersion[];
  total: number;
  limit: number;
  offset: number;
}

export interface PersonalServerReadDataOptions {
  grantId?: string;
  fileId?: string;
  at?: string;
  auth?: PersonalServerOwnerAuth;
  headers?: Record<string, string>;
}

export interface PersonalServerSyncTriggerResult {
  status: "started" | "disabled";
  message?: string;
  fileId?: string;
}

export interface PersonalServerAuthRequestOptions {
  auth?: PersonalServerOwnerAuth;
  headers?: Record<string, string>;
}

export interface PersonalServerCreateGrantOptions extends PersonalServerAuthRequestOptions {
  granteeAddress: `0x${string}`;
  scopes: string[];
  expiresAt?: number;
  nonce?: number;
}

export interface PersonalServerCreateGrantResult {
  grantId?: string;
}

export interface PersonalServerListGrantsResult {
  grants: GrantListItem[];
}

export interface PersonalServerRevokeGrantResult {
  status: "revoked";
  grantId: string;
}

export interface PersonalServerHandle {
  readonly kind: PersonalServerKind;
  ready(options?: PersonalServerReadyOptions): Promise<PersonalServerInfo>;
  info(): Promise<PersonalServerInfo>;
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
  listData(
    options?: PersonalServerListDataOptions,
  ): Promise<PersonalServerListDataResult>;
  listVersions(
    scope: string,
    options?: PersonalServerListVersionsOptions,
  ): Promise<PersonalServerListVersionsResult>;
  readData(
    scope: string,
    options?: PersonalServerReadDataOptions,
  ): Promise<DataFileEnvelope>;
  createGrant(
    options: PersonalServerCreateGrantOptions,
  ): Promise<PersonalServerCreateGrantResult>;
  listGrants(
    options?: PersonalServerAuthRequestOptions,
  ): Promise<PersonalServerListGrantsResult>;
  revokeGrant(
    grantId: string,
    options?: PersonalServerAuthRequestOptions,
  ): Promise<PersonalServerRevokeGrantResult>;
  syncStatus(options?: PersonalServerAuthRequestOptions): Promise<SyncStatus>;
  syncNow(
    options?: PersonalServerAuthRequestOptions,
  ): Promise<PersonalServerSyncTriggerResult>;
  stop(): Promise<void>;
}

export interface PersonalServerClientErrorBody {
  error?: {
    code?: number;
    errorCode?: string;
    message?: string;
    details?: unknown;
  };
  [key: string]: unknown;
}

export class PersonalServerClientError extends Error {
  readonly status: number;
  readonly errorCode?: string;
  readonly details?: unknown;
  readonly body?: unknown;

  constructor(params: {
    message: string;
    status: number;
    errorCode?: string;
    details?: unknown;
    body?: unknown;
  }) {
    super(params.message);
    this.name = "PersonalServerClientError";
    this.status = params.status;
    this.errorCode = params.errorCode;
    this.details = params.details;
    this.body = params.body;
  }
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
  const publicUrl =
    params.publicUrl === undefined
      ? (health.apiOrigin ?? null)
      : params.publicUrl;
  const apiOrigin = publicUrl ?? health.apiOrigin ?? params.localUrl ?? null;
  const gatewayConfig = stripGatewayUrl(health.gatewayConfig);
  const candidate = health.registration
    ? {
        ownerAddress: health.registration.ownerAddress,
        serverAddress: health.registration.serverAddress,
        publicKey: health.registration.publicKey,
        serverUrl: publicUrl ?? health.registration.serverUrl,
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
      registration: publicUrl ?? health.registration?.serverUrl ?? null,
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
        uri: new URL(params.path, params.origin).pathname,
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
    assertRegistrationMatches(existing, params.request.candidate);
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

export function dataListPath(
  options: PersonalServerListDataOptions = {},
): string {
  const params = new URLSearchParams();
  if (options.scopePrefix) params.set("scopePrefix", options.scopePrefix);
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.offset !== undefined)
    params.set("offset", String(options.offset));
  const query = params.toString();
  return query ? `/v1/data?${query}` : "/v1/data";
}

export function dataVersionsPath(
  scope: string,
  options: PersonalServerListVersionsOptions = {},
): string {
  const params = new URLSearchParams();
  if (options.limit !== undefined) params.set("limit", String(options.limit));
  if (options.offset !== undefined)
    params.set("offset", String(options.offset));
  const query = params.toString();
  return `/v1/data/${encodeURIComponent(scope)}/versions${
    query ? `?${query}` : ""
  }`;
}

export function dataReadPath(
  scope: string,
  options: PersonalServerReadDataOptions = {},
): string {
  const params = new URLSearchParams();
  if (options.grantId) params.set("grantId", options.grantId);
  if (options.fileId) params.set("fileId", options.fileId);
  if (options.at) params.set("at", options.at);
  const query = params.toString();
  return `/v1/data/${encodeURIComponent(scope)}${query ? `?${query}` : ""}`;
}

export function grantRevokePath(grantId: string): string {
  return `/v1/grants/${encodeURIComponent(grantId)}`;
}

export async function parsePersonalServerJsonResponse<T>(
  response: Response,
  action: string,
): Promise<T> {
  const body = await readJsonBody(response);
  if (!response.ok) {
    const structured = toClientErrorBody(body);
    throw new PersonalServerClientError({
      status: response.status,
      errorCode: structured?.error?.errorCode,
      details: structured?.error?.details,
      body,
      message:
        structured?.error?.message ??
        `Personal Server ${action} failed: ${response.status}`,
    });
  }
  return body as T;
}

async function readJsonBody(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function toClientErrorBody(
  value: unknown,
): PersonalServerClientErrorBody | null {
  return value && typeof value === "object"
    ? (value as PersonalServerClientErrorBody)
    : null;
}

function assertRegistrationMatches(
  existing: ServerInfo,
  candidate: PersonalServerRegistrationCandidate,
): void {
  if (existing.serverUrl === candidate.serverUrl) return;
  throw new PersonalServerClientError({
    status: 409,
    errorCode: "SERVER_URL_MISMATCH",
    message: `Server ${existing.id} is already registered with URL "${existing.serverUrl}". Cannot change to "${candidate.serverUrl}".`,
    details: {
      serverId: existing.id,
      existingUrl: existing.serverUrl,
      candidateUrl: candidate.serverUrl,
    },
  });
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
