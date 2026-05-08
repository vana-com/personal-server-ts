import {
  createBearerTokenPsLiteAuth,
  createIndexedDbPsLiteRuntime,
  createPsLiteRuntime,
  psLiteRelayPublicUrl,
  savePsLiteConfig,
  startPsLiteRelayClient,
  type PsLiteRelayClient,
  type PsLiteRelayStatus,
  type PsLiteRuntime,
} from "@opendatalabs/personal-server-ts-lite";
import type {
  ServerAccount,
  SignTypedDataParams,
} from "@opendatalabs/personal-server-ts-core/keys";
import type { ServerSigner } from "@opendatalabs/personal-server-ts-core/signing";
import {
  createGatewayClient,
  fileRegistrationDomain,
  grantRegistrationDomain,
  grantRevocationDomain,
  FILE_REGISTRATION_TYPES,
  GRANT_REGISTRATION_TYPES,
  GRANT_REVOCATION_TYPES,
  type DataPortabilityGatewayConfig,
  type FileRegistrationMessage,
  type GrantRegistrationMessage,
  type GrantRevocationMessage,
} from "@opendatalabs/vana-sdk/browser";

const ORIGIN = "https://ps-lite.local";
const OWNER_TOKEN = "ps-lite-owner-token";
const BUILDER_TOKEN = "ps-lite-builder-token";
const CONTROL_PLANE_TOKEN = "ps-lite-control-plane-token";
const SAMPLE_SCOPE = "instagram.profile";
const GATEWAY_SCHEMA_SCOPES = [
  "instagram.profile",
  "linkedin.profile",
  "spotify.profile",
] as const;
const SAMPLE_GRANT_ID = "debug-grant";
const DEFAULT_CONTROL_URL = "wss://control.34.16.49.200.sslip.io:8443";
const DEFAULT_PUBLIC_SUFFIX = "34.16.49.200.sslip.io";
const DEBUG_OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

type StorageMode = "indexeddb";
type AuthMode = "owner" | "builder" | "none" | "bad-builder";

interface UiRequestOptions {
  method?: string;
  body?: unknown;
  auth?: AuthMode;
  headers?: Record<string, string>;
}

interface RelayOptions {
  sessionId?: string;
  controlUrl?: string;
  publicSuffix?: string;
  certIssuerUrl?: string;
}

interface UiResult {
  status: number;
  ok: boolean;
  data: unknown;
}

type DebugRequest = (
  path: string,
  options?: UiRequestOptions,
) => Promise<UiResult>;

let runtime: PsLiteRuntime | undefined;
let storageMode: StorageMode = "indexeddb";
let relayClient: PsLiteRelayClient | undefined;
let relayStatus: PsLiteRelayStatus = "closed";
let relayPublicUrl = "";

function randomSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function createBrowserServerSigner(
  account: Pick<ServerAccount, "signTypedData">,
  gatewayConfig: DataPortabilityGatewayConfig,
): ServerSigner {
  return {
    async signFileRegistration(
      msg: FileRegistrationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: fileRegistrationDomain(gatewayConfig),
        types:
          FILE_REGISTRATION_TYPES as unknown as SignTypedDataParams["types"],
        primaryType: "FileRegistration",
        message: msg as unknown as Record<string, unknown>,
      });
    },

    async signGrantRegistration(
      msg: GrantRegistrationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: grantRegistrationDomain(gatewayConfig),
        types:
          GRANT_REGISTRATION_TYPES as unknown as SignTypedDataParams["types"],
        primaryType: "GrantRegistration",
        message: {
          ...msg,
          fileIds: msg.fileIds.map((id: bigint) => id),
        } as unknown as Record<string, unknown>,
      });
    },

    async signGrantRevocation(
      msg: GrantRevocationMessage,
    ): Promise<`0x${string}`> {
      return account.signTypedData({
        domain: grantRevocationDomain(gatewayConfig),
        types:
          GRANT_REVOCATION_TYPES as unknown as SignTypedDataParams["types"],
        primaryType: "GrantRevocation",
        message: msg as unknown as Record<string, unknown>,
      });
    },
  };
}

function authHeaders(mode: AuthMode): Record<string, string> {
  if (mode === "owner") return { Authorization: `Bearer ${OWNER_TOKEN}` };
  if (mode === "builder") return { Authorization: `Bearer ${BUILDER_TOKEN}` };
  if (mode === "bad-builder") return { Authorization: "Bearer bad-token" };
  return {};
}

function inferAuth(method: string): AuthMode {
  if (method === "POST" || method === "DELETE" || method === "PUT") {
    return "owner";
  }
  return "builder";
}

async function makeRuntime(_mode: StorageMode): Promise<PsLiteRuntime> {
  const browserRuntime = await createIndexedDbPsLiteRuntime({
    dbName: "personal-server-lite-debug",
    storageDbName: "personal-server-lite-debug-storage",
    storageKey: "data-storage-v1",
    ownerSignature: DEBUG_OWNER_SIGNATURE,
    configDefaults: {
      server: { port: 443, origin: ORIGIN },
    },
    auth: createBearerTokenPsLiteAuth({
      ownerToken: OWNER_TOKEN,
      builderToken: BUILDER_TOKEN,
    }),
    active: true,
    gateway: undefined,
    accessToken: CONTROL_PLANE_TOKEN,
  });
  const config = browserRuntime.config;
  const identity = browserRuntime.identity;
  const gatewayConfig = {
    chainId: config.gateway.chainId,
    contracts: config.gateway.contracts,
  };

  const nextRuntime = createPsLiteRuntime({
    storage: browserRuntime.storage,
    auth: createBearerTokenPsLiteAuth({
      ownerToken: OWNER_TOKEN,
      builderToken: BUILDER_TOKEN,
    }),
    active: true,
    config,
    identity: {
      address: identity.account.address,
      publicKey: identity.account.publicKey,
    },
    gateway: createGatewayClient(config.gateway.url),
    serverOwner: identity.account.address,
    serverSigner: createBrowserServerSigner(identity.account, gatewayConfig),
    saveConfig: async (nextConfig) => {
      const saved = await savePsLiteConfig(
        browserRuntime.stateStore,
        nextConfig,
      );
      Object.assign(config, saved);
    },
    stateCapabilities: { config: "indexeddb" },
    tokenStore: browserRuntime.tokenStore,
    accessLogReader: browserRuntime.accessLogStore,
    accessLogWriter: browserRuntime.accessLogStore,
    accessToken: CONTROL_PLANE_TOKEN,
  });
  nextRuntime.activate();
  return nextRuntime;
}

async function ensureRuntime(): Promise<PsLiteRuntime> {
  runtime ??= await makeRuntime(storageMode);
  return runtime;
}

async function parseResponse(response: Response): Promise<UiResult> {
  const text = await response.text();
  let data: unknown = text;
  if (text) {
    try {
      data = JSON.parse(text) as unknown;
    } catch {
      data = text;
    }
  } else {
    data = null;
  }
  return { status: response.status, ok: response.ok, data };
}

async function request(
  path: string,
  options: UiRequestOptions = {},
): Promise<UiResult> {
  const activeRuntime = await ensureRuntime();
  return requestWithRuntime(activeRuntime, path, options);
}

async function requestWithRuntime(
  activeRuntime: PsLiteRuntime,
  path: string,
  options: UiRequestOptions = {},
): Promise<UiResult> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = {
    ...authHeaders(options.auth ?? inferAuth(method)),
    ...options.headers,
  };
  const init: RequestInit = { method, headers };
  if (options.body !== undefined && method !== "GET" && method !== "HEAD") {
    headers["Content-Type"] ??= "application/json";
    init.body =
      typeof options.body === "string"
        ? options.body
        : JSON.stringify(options.body);
  }

  return parseResponse(
    await activeRuntime.fetch(new Request(`${ORIGIN}${path}`, init)),
  );
}

async function reset(nextStorageMode = storageMode): Promise<UiResult> {
  storageMode = nextStorageMode;
  runtime = await makeRuntime(storageMode);
  return status();
}

async function status(): Promise<UiResult> {
  const activeRuntime = await ensureRuntime();
  const health = await parseResponse(
    await activeRuntime.fetch(new Request(`${ORIGIN}/health`)),
  );
  return {
    status: health.status,
    ok: health.ok,
    data: {
      runtime: health.data,
      storageMode,
      relay: {
        status: relayStatus,
        publicUrl: relayPublicUrl || null,
        connected: relayStatus === "connected",
      },
    },
  };
}

async function activate(): Promise<UiResult> {
  const activeRuntime = await ensureRuntime();
  activeRuntime.activate();
  return status();
}

async function deactivate(): Promise<UiResult> {
  const activeRuntime = await ensureRuntime();
  activeRuntime.deactivate();
  return status();
}

async function runStorageSmoke(requestFn: DebugRequest): Promise<UiResult> {
  const schema = await gatewaySchemaSmoke();
  const payload = {
    source: "debug-ui",
    runtime: "browser-ps-lite",
    at: new Date().toISOString(),
  };
  const write = await requestFn(`/v1/data/${SAMPLE_SCOPE}`, {
    method: "POST",
    auth: "owner",
    body: payload,
  });
  const list = await requestFn("/v1/data", { auth: "builder" });
  const versions = await requestFn(`/v1/data/${SAMPLE_SCOPE}/versions`, {
    auth: "builder",
  });
  const read = await requestFn(
    `/v1/data/${SAMPLE_SCOPE}?grantId=${SAMPLE_GRANT_ID}`,
    { auth: "builder" },
  );
  return {
    status: write.ok && list.ok && versions.ok && read.ok ? 200 : 500,
    ok: write.ok && list.ok && versions.ok && read.ok,
    data: { schema, write, list, versions, read },
  };
}

async function storageSmoke(): Promise<UiResult> {
  return runStorageSmoke(request);
}

async function gatewaySchemaSmoke(): Promise<UiResult> {
  const activeRuntime = await ensureRuntime();
  const health = await parseResponse(
    await activeRuntime.fetch(new Request(`${ORIGIN}/health`)),
  );
  const runtimeHealth = health.data as
    | { gatewayUrl?: string | null }
    | null
    | undefined;
  const gatewayUrl = runtimeHealth?.gatewayUrl;
  if (!gatewayUrl) {
    return {
      status: 500,
      ok: false,
      data: { error: "PS Lite gateway URL is not configured" },
    };
  }

  const gateway = createGatewayClient(gatewayUrl);
  for (const scope of GATEWAY_SCHEMA_SCOPES) {
    const schema = await gateway.getSchemaForScope(scope);
    if (schema) {
      return {
        status: 200,
        ok: true,
        data: { scope, gatewayUrl, schema },
      };
    }
  }

  return {
    status: 404,
    ok: false,
    data: {
      gatewayUrl,
      scopes: GATEWAY_SCHEMA_SCOPES,
      error: "No configured debug schema scopes were found in the gateway",
    },
  };
}

async function authSmoke(): Promise<UiResult> {
  const unauthenticatedWrite = await request(`/v1/data/${SAMPLE_SCOPE}`, {
    method: "POST",
    auth: "none",
    body: { shouldFail: true },
  });
  const badBuilderRead = await request(
    `/v1/data/${SAMPLE_SCOPE}?grantId=${SAMPLE_GRANT_ID}`,
    { auth: "bad-builder" },
  );
  const missingGrantRead = await request(`/v1/data/${SAMPLE_SCOPE}`, {
    auth: "builder",
  });
  const ok =
    unauthenticatedWrite.status === 401 &&
    badBuilderRead.status === 401 &&
    missingGrantRead.status === 403;
  return {
    status: ok ? 200 : 500,
    ok,
    data: { unauthenticatedWrite, badBuilderRead, missingGrantRead },
  };
}

async function deleteSmoke(): Promise<UiResult> {
  await request(`/v1/data/${SAMPLE_SCOPE}`, {
    method: "POST",
    auth: "owner",
    body: { source: "delete-smoke" },
  });
  const deleted = await request(`/v1/data/${SAMPLE_SCOPE}`, {
    method: "DELETE",
    auth: "owner",
  });
  const readAfterDelete = await request(
    `/v1/data/${SAMPLE_SCOPE}?grantId=${SAMPLE_GRANT_ID}`,
    { auth: "builder" },
  );
  const ok = deleted.status === 204 && readAfterDelete.status === 404;
  return {
    status: ok ? 200 : 500,
    ok,
    data: { deleted, readAfterDelete },
  };
}

async function authRoutesSmoke(): Promise<UiResult> {
  const init = await request("/auth/device", {
    method: "POST",
    auth: "none",
  });
  const initData = init.data as
    | { login?: string; poll?: { token?: string } }
    | undefined;
  const pollToken = initData?.poll?.token;
  const loginUrl = initData?.login;
  const pending = pollToken
    ? await request(`/auth/device/poll?token=${pollToken}`, { auth: "none" })
    : { status: 500, ok: false, data: "missing poll token" };
  const approve = loginUrl
    ? await request(new URL(loginUrl).pathname + new URL(loginUrl).search, {
        method: "POST",
        auth: "owner",
      })
    : { status: 500, ok: false, data: "missing login url" };
  const oauth = pollToken
    ? await request("/oauth/token", {
        method: "POST",
        auth: "none",
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: pollToken,
        }).toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      })
    : { status: 500, ok: false, data: "missing poll token" };
  const provision = await request("/auth/device/token", {
    method: "POST",
    auth: "none",
    body: { token: "vana_ps_debug_cli_token" },
    headers: {
      Authorization: `Bearer ${CONTROL_PLANE_TOKEN}`,
    },
  });
  const revoke = await request("/auth/device/token", {
    method: "DELETE",
    auth: "none",
    headers: {
      Authorization: "Bearer vana_ps_debug_cli_token",
    },
  });
  const ok =
    init.ok &&
    pending.status === 404 &&
    approve.ok &&
    oauth.ok &&
    provision.status === 201 &&
    revoke.ok;
  return {
    status: ok ? 200 : 500,
    ok,
    data: { init, pending, approve, oauth, provision, revoke },
  };
}

async function connectRelay(options: RelayOptions = {}): Promise<UiResult> {
  relayClient?.close("replaced");
  const sessionId = options.sessionId || randomSessionId();
  const controlUrl = options.controlUrl || DEFAULT_CONTROL_URL;
  const publicSuffix = options.publicSuffix || DEFAULT_PUBLIC_SUFFIX;
  relayPublicUrl = psLiteRelayPublicUrl(sessionId, publicSuffix);
  relayStatus = "connecting";
  relayClient = startPsLiteRelayClient({
    sessionId,
    runtime: await ensureRuntime(),
    controlUrl,
    publicSuffix,
    certIssuerUrl: options.certIssuerUrl || undefined,
    onStatus(nextStatus) {
      relayStatus = nextStatus;
      window.dispatchEvent(new CustomEvent("ps-lite-relay-status"));
    },
    logger(line) {
      window.dispatchEvent(
        new CustomEvent("ps-lite-relay-log", { detail: line }),
      );
    },
  });
  return status();
}

async function disconnectRelay(): Promise<UiResult> {
  relayClient?.close("debug-ui");
  relayClient = undefined;
  relayStatus = "closed";
  return status();
}

const psLiteDebug = {
  activate,
  authRoutesSmoke,
  authSmoke,
  connectRelay,
  deactivate,
  deleteSmoke,
  disconnectRelay,
  gatewaySchemaSmoke,
  request,
  reset,
  status,
  storageSmoke,
};

declare global {
  interface Window {
    psLiteDebug: typeof psLiteDebug;
  }
}

window.psLiteDebug = psLiteDebug;
void ensureRuntime();
