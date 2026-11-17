import {
  createBearerTokenPsLiteAuth,
  PersonalServerClientError,
  startPersonalServer,
  type PersonalServerHandle,
  type PsLiteRelayStatus,
} from "@opendatalabs/personal-server-ts-lite";
import { createGatewayClient } from "@opendatalabs/vana-sdk/browser";

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

interface CreateGrantInput {
  granteeAddress: `0x${string}`;
  scopes: string[];
  expiresAt?: number;
  nonce?: number;
}

interface PsLiteBootstrap {
  ownerSignature: `0x${string}`;
  config?: Record<string, unknown>;
}

type DebugRequest = (
  path: string,
  options?: UiRequestOptions,
) => Promise<UiResult>;

let personalServer: PersonalServerHandle | undefined;
let personalServerStart: Promise<PersonalServerHandle> | undefined;
let storageMode: StorageMode = "indexeddb";
let relayStatus: PsLiteRelayStatus = "closed";
let relayPublicUrl = "";
let activeRelayOptions: RelayOptions | false = {};

function getBootstrap(): PsLiteBootstrap {
  const bootstrap = window.__PS_LITE_BOOTSTRAP__;
  if (
    !bootstrap ||
    typeof bootstrap.ownerSignature !== "string" ||
    !bootstrap.ownerSignature.startsWith("0x")
  ) {
    throw new Error("PS Lite owner signature is not configured");
  }
  return bootstrap;
}

function liteConfigDefaults(bootstrap: PsLiteBootstrap) {
  const config = bootstrap.config ?? {};
  const server =
    config.server && typeof config.server === "object" ? config.server : {};
  const sync =
    config.sync && typeof config.sync === "object" ? config.sync : {};
  return {
    ...config,
    server: { ...server, port: 443, origin: ORIGIN },
    sync: { ...sync, enabled: true, lastProcessedTimestamp: null },
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

function sampleInstagramProfileData(reason = "debug-ui") {
  return {
    username: "vana_debug",
    full_name: "Vana Debug Profile",
    bio: "Schema-shaped sample profile for Personal Server debug UI testing.",
    biography_with_entities: {
      raw_text:
        "Schema-shaped sample profile for Personal Server debug UI testing.",
      entities: [],
    },
    pronouns: ["they/them"],
    bio_links: [
      {
        title: "Vana",
        url: "https://www.vana.org",
        lynx_url: "https://www.vana.org",
      },
    ],
    external_url: "https://www.vana.org",
    external_url_linkshimmed: "https://www.vana.org",
    fb_profile_biolink: null,
    profile_pic_url: "https://www.vana.org/favicon.ico",
    hd_profile_pic_url: "https://www.vana.org/favicon.ico",
    pk: "2605080001",
    id: "2605080001",
    fbid: null,
    eimu_id: null,
    follower_count: 1234,
    following_count: 321,
    media_count: 42,
    highlight_reel_count: 3,
    pinned_channels_list_count: 0,
    is_private: false,
    is_verified: true,
    is_verified_by_mv4b: false,
    is_business: false,
    is_professional_account: true,
    is_supervised_user: false,
    is_supervision_enabled: false,
    is_joined_recently: false,
    is_embeds_disabled: false,
    is_regulated_c18: false,
    hide_like_and_view_counts: false,
    ai_agent_type: null,
    has_clips: true,
    has_channel: false,
    has_guides: false,
    has_ar_effects: false,
    has_chaining: true,
    country_block: false,
    should_show_category: true,
    should_show_public_contacts: false,
    show_account_transparency_details: true,
    transparency_label: null,
    transparency_product: null,
    business: {
      is_business_account: false,
      category_name: "Technology",
      business_category_name: null,
      overall_category_name: null,
      category_enum: null,
      business_contact_method: null,
      business_email: null,
      business_phone_number: null,
      business_address_json: null,
    },
    viewer_relationship: {
      followed_by_viewer: true,
      follows_viewer: false,
      requested_by_viewer: false,
      has_requested_viewer: false,
      blocked_by_viewer: false,
      has_blocked_viewer: false,
      restricted_by_viewer: false,
      is_guardian_of_viewer: false,
      is_supervised_by_viewer: false,
      mutual_followed_by_count: 7,
    },
    collected_at: new Date().toISOString(),
    debug_source: reason,
  };
}

async function makePersonalServer(
  _mode: StorageMode,
  relay: RelayOptions | false = activeRelayOptions,
): Promise<PersonalServerHandle> {
  const bootstrap = getBootstrap();
  const relayConfig =
    relay === false
      ? false
      : {
          ...(relay.sessionId ? { sessionId: relay.sessionId } : {}),
          controlUrl: relay.controlUrl || DEFAULT_CONTROL_URL,
          publicSuffix: relay.publicSuffix || DEFAULT_PUBLIC_SUFFIX,
          certIssuerUrl: relay.certIssuerUrl || undefined,
          onStatus(nextStatus: PsLiteRelayStatus) {
            relayStatus = nextStatus;
            window.dispatchEvent(new CustomEvent("ps-lite-relay-status"));
          },
          logger(line: string) {
            window.dispatchEvent(
              new CustomEvent("ps-lite-relay-log", { detail: line }),
            );
          },
        };
  relayStatus = relayConfig === false ? "closed" : "connecting";
  const ps = await startPersonalServer({
    dbName: "personal-server-lite-debug",
    storageDbName: "personal-server-lite-debug-storage",
    storageKey: "data-storage-v1",
    ownerSignature: bootstrap.ownerSignature,
    configDefaults: liteConfigDefaults(bootstrap),
    auth: createBearerTokenPsLiteAuth({
      ownerToken: OWNER_TOKEN,
      builderToken: BUILDER_TOKEN,
    }),
    active: true,
    gateway: undefined,
    accessToken: CONTROL_PLANE_TOKEN,
    relay: relayConfig,
  });
  relayPublicUrl = (await ps.info()).urls.public ?? "";
  activeRelayOptions = relay;
  return ps;
}

async function ensurePersonalServer(): Promise<PersonalServerHandle> {
  if (personalServer) return personalServer;
  if (!personalServerStart) {
    const start = makePersonalServer(storageMode)
      .then((ps) => {
        personalServer = ps;
        return ps;
      })
      .finally(() => {
        if (personalServerStart === start) {
          personalServerStart = undefined;
        }
      });
    personalServerStart = start;
  }
  return personalServerStart;
}

async function stopPersonalServer(): Promise<void> {
  const active =
    personalServer ?? (await personalServerStart?.catch(() => undefined));
  personalServer = undefined;
  personalServerStart = undefined;
  await active?.stop();
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

function uiResult(data: unknown, status = 200): UiResult {
  return { status, ok: status >= 200 && status < 300, data };
}

function uiError(error: unknown): UiResult {
  if (error instanceof PersonalServerClientError) {
    return {
      status: error.status,
      ok: false,
      data: error.body ?? {
        error: {
          code: error.status,
          errorCode: error.errorCode,
          message: error.message,
          details: error.details,
        },
      },
    };
  }
  const message = error instanceof Error ? error.message : String(error);
  return {
    status: 500,
    ok: false,
    data: { error: { code: 500, message } },
  };
}

async function handleUiCall(call: () => Promise<unknown>): Promise<UiResult> {
  try {
    return uiResult(await call());
  } catch (error) {
    return uiError(error);
  }
}

async function request(
  path: string,
  options: UiRequestOptions = {},
): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return requestWithServer(activeServer, path, options);
}

async function requestWithServer(
  activeServer: PersonalServerHandle,
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

  return parseResponse(await activeServer.fetch(path, init));
}

async function reset(nextStorageMode = storageMode): Promise<UiResult> {
  storageMode = nextStorageMode;
  await stopPersonalServer();
  personalServer = await ensurePersonalServer();
  return status();
}

async function status(): Promise<UiResult> {
  if (!personalServer) {
    return stoppedStatus();
  }
  const activeServer = await ensurePersonalServer();
  const info = await activeServer.info();
  return {
    status: info.status === "error" ? 500 : 200,
    ok: info.status !== "error",
    data: {
      runtime: info.details,
      personalServer: info,
      storageMode,
      relay: {
        status: relayStatus,
        publicUrl: (info.urls.public ?? relayPublicUrl) || null,
        connected: relayStatus === "connected",
      },
    },
  };
}

function stoppedStatus(): UiResult {
  return {
    status: 200,
    ok: true,
    data: {
      runtime: null,
      personalServer: { kind: "lite", status: "stopped" },
      storageMode,
      relay: {
        status: relayStatus,
        publicUrl: null,
        connected: false,
      },
    },
  };
}

async function activate(): Promise<UiResult> {
  await ensurePersonalServer();
  return status();
}

async function deactivate(): Promise<UiResult> {
  await stopPersonalServer();
  relayStatus = "closed";
  return stoppedStatus();
}

async function runStorageSmoke(requestFn: DebugRequest): Promise<UiResult> {
  const schema = await gatewaySchemaSmoke();
  const payload = sampleInstagramProfileData("ps-lite-storage-smoke");
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
  const activeServer = await ensurePersonalServer();
  const info = await activeServer.info();
  const gatewayUrl = info.gatewayUrl;
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
    body: sampleInstagramProfileData("ps-lite-auth-negative"),
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
    body: sampleInstagramProfileData("ps-lite-delete-smoke"),
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

async function postData(scope: string, body: unknown): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.postData(scope, body, { bearerToken: OWNER_TOKEN }),
  );
}

async function listData(options?: {
  scopePrefix?: string;
  limit?: number;
  offset?: number;
}): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.listData({
      ...options,
      auth: { bearerToken: OWNER_TOKEN },
    }),
  );
}

async function listVersions(
  scope: string,
  options?: { limit?: number; offset?: number },
): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.listVersions(scope, {
      ...options,
      auth: { bearerToken: OWNER_TOKEN },
    }),
  );
}

async function readData(
  scope: string,
  options?: { grantId?: string; fileId?: string; at?: string },
): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.readData(scope, {
      ...options,
      auth: { bearerToken: OWNER_TOKEN },
    }),
  );
}

async function syncStatus(): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.syncStatus({ auth: { bearerToken: OWNER_TOKEN } }),
  );
}

async function syncTrigger(): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.syncNow({ auth: { bearerToken: OWNER_TOKEN } }),
  );
}

async function createGrant(input: CreateGrantInput): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.createGrant({
      ...input,
      auth: { bearerToken: OWNER_TOKEN },
    }),
  );
}

async function listGrants(): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.listGrants({ auth: { bearerToken: OWNER_TOKEN } }),
  );
}

async function revokeGrant(grantId: string): Promise<UiResult> {
  const activeServer = await ensurePersonalServer();
  return handleUiCall(() =>
    activeServer.revokeGrant(grantId, { auth: { bearerToken: OWNER_TOKEN } }),
  );
}

async function syncSmoke(): Promise<UiResult> {
  const write = await request(`/v1/data/${SAMPLE_SCOPE}`, {
    method: "POST",
    auth: "owner",
    body: sampleInstagramProfileData("ps-lite-sync-smoke"),
  });
  const trigger = await syncTrigger();
  const status = await syncStatus();
  const syncData = status.data as
    { pendingFiles?: number; errors?: unknown[] } | undefined;
  const ok =
    write.ok &&
    trigger.status === 202 &&
    status.ok &&
    syncData?.pendingFiles === 0 &&
    (syncData.errors?.length ?? 0) === 0;
  return {
    status: ok ? 200 : 500,
    ok,
    data: { write, trigger, status },
  };
}

async function authRoutesSmoke(): Promise<UiResult> {
  const init = await request("/auth/device", {
    method: "POST",
    auth: "none",
  });
  const initData = init.data as
    { login?: string; poll?: { token?: string } } | undefined;
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
  await stopPersonalServer();
  personalServer = await makePersonalServer(storageMode, options);
  return status();
}

async function disconnectRelay(): Promise<UiResult> {
  await stopPersonalServer();
  personalServer = await makePersonalServer(storageMode, false);
  return status();
}

const psLiteDebug = {
  activate,
  authRoutesSmoke,
  authSmoke,
  connectRelay,
  createGrant,
  deactivate,
  deleteSmoke,
  disconnectRelay,
  gatewaySchemaSmoke,
  listData,
  listGrants,
  listVersions,
  postData,
  readData,
  request,
  reset,
  revokeGrant,
  status,
  storageSmoke,
  syncSmoke,
  syncStatus,
  syncTrigger,
};

declare global {
  interface Window {
    psLiteDebug: typeof psLiteDebug;
    __PS_LITE_BOOTSTRAP__: PsLiteBootstrap | null;
  }
}

window.psLiteDebug = psLiteDebug;
