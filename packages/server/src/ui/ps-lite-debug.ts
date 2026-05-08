import {
  createBearerTokenPsLiteAuth,
  createIndexedDbPsLitePersistence,
  createIndexedDbPsLiteStateStore,
  createMemoryPsLiteStorage,
  createPersistentPsLiteStorage,
  createPsLiteRuntime,
  loadOrCreatePsLiteConfig,
  loadOrCreatePsLiteServerIdentity,
  psLiteRelayPublicUrl,
  startPsLiteRelayClient,
  type PsLiteRelayClient,
  type PsLiteRelayStatus,
  type PsLiteRuntime,
} from "@opendatalabs/personal-server-ts-lite";
import type { GatewayClient } from "@opendatalabs/vana-sdk/browser";

const ORIGIN = "https://ps-lite.local";
const OWNER_TOKEN = "ps-lite-owner-token";
const BUILDER_TOKEN = "ps-lite-builder-token";
const CONTROL_PLANE_TOKEN = "ps-lite-control-plane-token";
const SAMPLE_SCOPE = "debug.local.profile";
const SAMPLE_GRANT_ID = "debug-grant";
const DEFAULT_CONTROL_URL = "wss://control.34.16.49.200.sslip.io:8443";
const DEFAULT_PUBLIC_SUFFIX = "34.16.49.200.sslip.io";
const DEBUG_OWNER_SIGNATURE =
  "0xedbb7743cce459345238442dcfb291f234a321d253485eaa58251aa0f28ea8f1410ab988bae2657b689cd24417b41e315efc22ba333024f4a6269c424ded8d361b";

type StorageMode = "indexeddb" | "memory";
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

let runtime: PsLiteRuntime | undefined;
let storageMode: StorageMode = "indexeddb";
let relayClient: PsLiteRelayClient | undefined;
let relayStatus: PsLiteRelayStatus = "closed";
let relayPublicUrl = "";

const mockGateway: GatewayClient = {
  async isRegisteredBuilder() {
    return true;
  },
  async getBuilder(address: string) {
    return {
      id: "debug-builder",
      ownerAddress: address,
      granteeAddress: address,
      publicKey: "0x04",
      appUrl: "https://debug-builder.local",
      addedAt: new Date().toISOString(),
    };
  },
  async getGrant(grantId: string) {
    return {
      id: grantId,
      grantorAddress: "debug-owner",
      granteeId: "debug-builder",
      grant: JSON.stringify({
        scopes: [`${SAMPLE_SCOPE}`],
        expiresAt: 0,
      }),
      fileIds: [],
      status: "confirmed",
      addedAt: new Date().toISOString(),
      revokedAt: null,
      revocationSignature: null,
    };
  },
  async listGrantsByUser() {
    return [];
  },
  async getSchemaForScope(scope: string) {
    return {
      id: "debug-schema",
      ownerAddress: "debug-owner",
      name: scope,
      definitionUrl: "https://schemas.local/debug.schema.json",
      scope,
      addedAt: new Date().toISOString(),
    };
  },
  async getServer() {
    return null;
  },
  async getFile() {
    return null;
  },
  async listFilesSince() {
    return { files: [], nextCursor: null };
  },
  async getSchema() {
    return null;
  },
  async registerFile() {
    return { fileId: "debug-file" };
  },
  async createGrant() {
    return { grantId: SAMPLE_GRANT_ID };
  },
  async revokeGrant() {},
};

function randomSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
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

async function makeRuntime(mode: StorageMode): Promise<PsLiteRuntime> {
  const stateStore = createIndexedDbPsLiteStateStore({
    dbName: "personal-server-lite-debug",
    storeName: "state",
  });
  const config = await loadOrCreatePsLiteConfig(stateStore, {
    server: { port: 443, origin: ORIGIN },
  });
  const identity = await loadOrCreatePsLiteServerIdentity({
    store: stateStore,
    ownerSignature: DEBUG_OWNER_SIGNATURE,
  });
  const storage =
    mode === "indexeddb"
      ? await createPersistentPsLiteStorage(
          { kind: "indexeddb" },
          createIndexedDbPsLitePersistence({
            dbName: "personal-server-lite-debug",
            storeName: "state",
            key: "data-storage-v1",
          }),
        )
      : createMemoryPsLiteStorage();

  const nextRuntime = createPsLiteRuntime({
    storage,
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
    gateway: mockGateway,
    serverOwner: identity.account.address,
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

async function storageSmoke(): Promise<UiResult> {
  const payload = {
    source: "debug-ui",
    runtime: "browser-ps-lite",
    at: new Date().toISOString(),
  };
  const write = await request(`/v1/data/${SAMPLE_SCOPE}`, {
    method: "POST",
    auth: "owner",
    body: payload,
  });
  const list = await request("/v1/data", { auth: "builder" });
  const versions = await request(`/v1/data/${SAMPLE_SCOPE}/versions`, {
    auth: "builder",
  });
  const read = await request(
    `/v1/data/${SAMPLE_SCOPE}?grantId=${SAMPLE_GRANT_ID}`,
    { auth: "builder" },
  );
  return {
    status: write.ok && list.ok && versions.ok && read.ok ? 200 : 500,
    ok: write.ok && list.ok && versions.ok && read.ok,
    data: { write, list, versions, read },
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
