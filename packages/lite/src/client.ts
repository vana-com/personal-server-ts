import {
  createOwnerSignedPersonalServerRequest,
  createPersonalServerInfoFromHealth,
  createPersonalServerRegistrationRequest,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  grantRevokePath,
  parsePersonalServerJsonResponse,
  requestPath,
  submitPersonalServerRegistration,
  type PersonalServerAuthRequestOptions,
  type PersonalServerCreateGrantOptions,
  type PersonalServerCreateGrantResult,
  type PersonalServerHandle,
  type PersonalServerInfo,
  type PersonalServerListDataOptions,
  type PersonalServerListDataResult,
  type PersonalServerListGrantsResult,
  type PersonalServerListVersionsOptions,
  type PersonalServerListVersionsResult,
  type PersonalServerOwnerAuth,
  type PersonalServerPostDataOptions,
  type PersonalServerPrepareRegistrationOptions,
  type PersonalServerReadDataOptions,
  type PersonalServerReadyOptions,
  type PersonalServerRevokeGrantResult,
  type PersonalServerRegistrationRequest,
  type PersonalServerStatus,
  type PersonalServerSubmitRegistrationOptions,
  type PersonalServerSyncTriggerResult,
} from "@opendatalabs/personal-server-ts-core/client";
import type { SyncStatus } from "@opendatalabs/personal-server-ts-core/sync";
import {
  createGatewayClient,
  type DataFileEnvelope,
  type GatewayClient,
  type RegisterServerResult,
} from "@opendatalabs/vana-sdk/browser";
import {
  createIndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntime,
  type IndexedDbPsLiteRuntimeOptions,
} from "./browser-runtime.js";
import {
  psLiteRelayPublicUrl,
  startPsLiteRelayClient,
  type PsLiteRelayClient,
  type PsLiteRelayClientOptions,
  type PsLiteRelayStatus,
} from "./relay.js";
import type { PsLiteRuntime } from "./runtime.js";
import {
  createIndexedDbPsLiteStateStore,
  loadPsLiteRelayState,
  savePsLiteRelayState,
  type PsLiteRelayState,
  type PsLiteStateStore,
} from "./state.js";

const DEFAULT_LITE_ORIGIN = "https://ps-lite.local";

export interface StartPersonalServerLiteRelayOptions extends Omit<
  PsLiteRelayClientOptions,
  "runtime" | "onStatus" | "sessionId"
> {
  sessionId?: string;
  onStatus?: PsLiteRelayClientOptions["onStatus"];
}

export interface StartPersonalServerLiteOptions extends Omit<
  IndexedDbPsLiteRuntimeOptions,
  "ownerSignature" | "active"
> {
  ownerSignature?: `0x${string}`;
  active?: boolean;
  runtime?: PsLiteRuntime;
  localOrigin?: string;
  relay?: false | StartPersonalServerLiteRelayOptions;
  relayStateStore?: PsLiteStateStore;
  gateway?: GatewayClient;
  onStatus?: (status: PersonalServerStatus) => void;
}

export async function startPersonalServer(
  options: StartPersonalServerLiteOptions,
): Promise<PersonalServerHandle> {
  const localOrigin = options.localOrigin ?? DEFAULT_LITE_ORIGIN;
  const relayOptions = options.relay || undefined;
  const relayStateStore = relayOptions
    ? (options.relayStateStore ??
      (options.runtime
        ? undefined
        : createIndexedDbPsLiteStateStore({
            dbName: options.dbName ?? "personal-server-lite",
            storeName: options.stateStoreName ?? "state",
          })))
    : undefined;
  const savedRelayState = relayStateStore
    ? await loadPsLiteRelayState(relayStateStore).catch(() => null)
    : null;
  const resolvedRelayOptions = relayOptions
    ? {
        ...relayOptions,
        sessionId:
          relayOptions.sessionId ??
          savedRelaySessionId(savedRelayState, relayOptions) ??
          randomSessionId(),
      }
    : undefined;
  const initialPublicUrl = resolvedRelayOptions
    ? psLiteRelayPublicUrl(
        resolvedRelayOptions.sessionId,
        resolvedRelayOptions.publicSuffix,
      )
    : null;
  const runtimeOrigin = initialPublicUrl ?? localOrigin;
  const runtimeBundle: IndexedDbPsLiteRuntime | null = options.runtime
    ? null
    : await createIndexedDbPsLiteRuntime({
        ...options,
        ownerSignature: requiredOwnerSignature(options.ownerSignature),
        active: options.active ?? true,
        runtimeOrigin,
        configDefaults: configDefaultsWithOrigin(
          options.configDefaults,
          runtimeOrigin,
        ),
      });
  const runtime = options.runtime ?? runtimeBundle!.runtime;

  if (options.active ?? true) {
    runtime.activate();
  }

  let status: PersonalServerStatus = "ready";
  let relayStatus: PsLiteRelayStatus = "closed";
  let relayClient: PsLiteRelayClient | undefined;
  let publicUrl: string | null = null;
  let lastInfo: PersonalServerInfo | null = null;
  let lastPreparedRegistration: PersonalServerRegistrationRequest | null = null;
  const gateway = options.gateway;

  const setStatus = (nextStatus: PersonalServerStatus): void => {
    status = nextStatus;
    options.onStatus?.(nextStatus);
  };

  if (resolvedRelayOptions) {
    relayStatus = "connecting";
    publicUrl = initialPublicUrl;
    relayClient = startPsLiteRelayClient({
      ...resolvedRelayOptions,
      runtime,
      origin: runtimeOrigin,
      onStatus(nextRelayStatus) {
        relayStatus = nextRelayStatus;
        if (nextRelayStatus === "error") setStatus("error");
        resolvedRelayOptions.onStatus?.(nextRelayStatus);
      },
    });
  }

  async function info(): Promise<PersonalServerInfo> {
    if (status === "stopped" && lastInfo) {
      return { ...lastInfo, status: "stopped" };
    }
    const response = await runtime.fetch(new Request(`${localOrigin}/health`));
    const body = await response.json();
    lastInfo = createPersonalServerInfoFromHealth({
      kind: "lite",
      status,
      health: {
        ...(body as Record<string, unknown>),
        relay: { status: relayStatus, publicUrl },
      },
      localUrl: localOrigin,
      publicUrl,
    });
    return lastInfo;
  }

  async function prepareRegistration(
    prepareOptions: PersonalServerPrepareRegistrationOptions = {},
  ): Promise<PersonalServerRegistrationRequest> {
    const current = await info();
    const serverUrl = prepareOptions.serverUrl ?? current.urls.registration;
    if (!current.ownerAddress || !current.server || !serverUrl) {
      throw new Error("Personal Server identity and URL are required");
    }
    if (!current.gatewayConfig) {
      throw new Error("Personal Server gateway config is required");
    }
    const request = createPersonalServerRegistrationRequest({
      gatewayConfig: current.gatewayConfig,
      ownerAddress: current.ownerAddress,
      serverAddress: current.server.address,
      publicKey: current.server.publicKey,
      serverUrl,
    });
    lastPreparedRegistration = request;
    return request;
  }

  async function submitRegistration(
    submitOptions: PersonalServerSubmitRegistrationOptions,
  ): Promise<RegisterServerResult> {
    const request =
      submitOptions.request ??
      (submitOptions.serverUrl
        ? await prepareRegistration({ serverUrl: submitOptions.serverUrl })
        : (lastPreparedRegistration ?? (await prepareRegistration())));
    const gatewayClient =
      gateway ?? createGatewayClient(requiredGatewayUrl(await info()));
    return submitPersonalServerRegistration({
      gateway: gatewayClient,
      request,
      signature: submitOptions.signature,
    }).then(async (result) => {
      await rememberRegisteredRelay(request.candidate.serverUrl);
      return result;
    });
  }

  async function callFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    const origin = (await info()).urls.apiOrigin ?? localOrigin;
    return runtime.fetch(toRuntimeRequest(input, origin, init));
  }

  async function postData(
    scope: string,
    body: unknown,
    postOptions: PersonalServerPostDataOptions,
  ): Promise<{ scope: string; collectedAt: string; status: string }> {
    const current = await info();
    const origin = requiredApiOrigin(current);
    const path = `/v1/data/${encodeURIComponent(scope)}`;
    const request = await createOwnerRequest({
      origin,
      path,
      method: "POST",
      body,
      authOptions: postOptions,
      headers: {
        "Content-Type": "application/json",
        ...postOptions.headers,
      },
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "data write",
    );
  }

  async function listData(
    listOptions: PersonalServerListDataOptions = {},
  ): Promise<PersonalServerListDataResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: dataListPath(listOptions),
      method: "GET",
      authOptions: listOptions,
      headers: listOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "data list",
    );
  }

  async function listVersions(
    scope: string,
    versionOptions: PersonalServerListVersionsOptions = {},
  ): Promise<PersonalServerListVersionsResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: dataVersionsPath(scope, versionOptions),
      method: "GET",
      authOptions: versionOptions,
      headers: versionOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "data versions list",
    );
  }

  async function readData(
    scope: string,
    readOptions: PersonalServerReadDataOptions = {},
  ): Promise<DataFileEnvelope> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: dataReadPath(scope, readOptions),
      method: "GET",
      authOptions: readOptions,
      headers: readOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "data read",
    );
  }

  async function syncStatus(
    syncOptions: PersonalServerAuthRequestOptions = {},
  ): Promise<SyncStatus> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: "/v1/sync/status",
      method: "GET",
      authOptions: syncOptions,
      headers: syncOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "sync status",
    );
  }

  async function createGrant(
    grantOptions: PersonalServerCreateGrantOptions,
  ): Promise<PersonalServerCreateGrantResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: "/v1/grants",
      method: "POST",
      body: {
        granteeAddress: grantOptions.granteeAddress,
        scopes: grantOptions.scopes,
        ...(grantOptions.expiresAt === undefined
          ? {}
          : { expiresAt: grantOptions.expiresAt }),
        ...(grantOptions.nonce === undefined
          ? {}
          : { nonce: grantOptions.nonce }),
      },
      authOptions: grantOptions,
      headers: {
        "Content-Type": "application/json",
        ...grantOptions.headers,
      },
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "grant create",
    );
  }

  async function listGrants(
    grantOptions: PersonalServerAuthRequestOptions = {},
  ): Promise<PersonalServerListGrantsResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: "/v1/grants",
      method: "GET",
      authOptions: grantOptions,
      headers: grantOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "grant list",
    );
  }

  async function revokeGrant(
    grantId: string,
    grantOptions: PersonalServerAuthRequestOptions = {},
  ): Promise<PersonalServerRevokeGrantResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: grantRevokePath(grantId),
      method: "DELETE",
      authOptions: grantOptions,
      headers: grantOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "grant revoke",
    );
  }

  async function syncNow(
    syncOptions: PersonalServerAuthRequestOptions = {},
  ): Promise<PersonalServerSyncTriggerResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: "/v1/sync/trigger",
      method: "POST",
      authOptions: syncOptions,
      headers: syncOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "sync trigger",
    );
  }

  async function rememberRegisteredRelay(serverUrl: string): Promise<void> {
    if (!resolvedRelayOptions || !relayStateStore) return;
    await savePsLiteRelayState(relayStateStore, {
      sessionId: resolvedRelayOptions.sessionId,
      controlUrl: resolvedRelayOptions.controlUrl,
      publicSuffix: resolvedRelayOptions.publicSuffix,
      publicUrl: serverUrl,
    });
  }

  async function createOwnerRequest(params: {
    origin: string;
    path: string;
    method: string;
    body?: unknown;
    authOptions:
      | PersonalServerAuthRequestOptions
      | PersonalServerPostDataOptions;
    headers?: Record<string, string>;
  }): Promise<Request> {
    const encoded =
      params.body === undefined
        ? undefined
        : new TextEncoder().encode(JSON.stringify(params.body));
    const auth = authFromOptions(params.authOptions);
    if (auth) {
      return createOwnerSignedPersonalServerRequest({
        origin: params.origin,
        path: params.path,
        method: params.method,
        body: encoded,
        auth,
        headers: params.headers,
      });
    }
    return new Request(`${params.origin}${params.path}`, {
      method: params.method,
      body: encoded,
      headers: params.headers,
    });
  }

  async function stop(): Promise<void> {
    if (status === "stopped") return;
    relayClient?.close("personal-server-stop");
    relayClient = undefined;
    runtime.deactivate();
    await runtimeBundle?.syncManager?.stop?.();
    setStatus("stopped");
  }

  return {
    kind: "lite",
    ready: (_options?: PersonalServerReadyOptions) => info(),
    info,
    prepareRegistration,
    submitRegistration,
    fetch: callFetch,
    postData,
    listData,
    listVersions,
    readData,
    createGrant,
    listGrants,
    revokeGrant,
    syncStatus,
    syncNow,
    stop,
  };
}

function savedRelaySessionId(
  state: PsLiteRelayState | null,
  options: StartPersonalServerLiteRelayOptions,
): string | null {
  if (!state?.sessionId) return null;
  if (options.controlUrl && state.controlUrl !== options.controlUrl)
    return null;
  if (options.publicSuffix && state.publicSuffix !== options.publicSuffix) {
    return null;
  }
  return state.sessionId;
}

function randomSessionId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(
    "",
  );
}

function authFromOptions(
  options: PersonalServerAuthRequestOptions | PersonalServerPostDataOptions,
): PersonalServerOwnerAuth | undefined {
  if ("auth" in options && options.auth) return options.auth;
  if ("signMessage" in options) return { signMessage: options.signMessage };
  if ("bearerToken" in options) return { bearerToken: options.bearerToken };
  return undefined;
}

function requiredOwnerSignature(
  ownerSignature: `0x${string}` | undefined,
): `0x${string}` {
  if (!ownerSignature) {
    throw new Error("ownerSignature is required to start PS Lite");
  }
  return ownerSignature;
}

function configDefaultsWithOrigin(
  defaults: StartPersonalServerLiteOptions["configDefaults"],
  origin: string,
): StartPersonalServerLiteOptions["configDefaults"] {
  return {
    ...defaults,
    server: {
      ...defaults?.server,
      origin,
    },
  } as StartPersonalServerLiteOptions["configDefaults"];
}

function requiredGatewayUrl(info: PersonalServerInfo): string {
  if (!info.gatewayUrl) {
    throw new Error("Personal Server gateway URL is required");
  }
  return info.gatewayUrl;
}

function requiredApiOrigin(info: PersonalServerInfo): string {
  if (!info.urls.apiOrigin) {
    throw new Error("Personal Server API origin is required");
  }
  return info.urls.apiOrigin;
}

function toRuntimeRequest(
  input: string | URL | Request,
  origin: string,
  init?: RequestInit,
): Request {
  const url = `${origin}${requestPath(input)}`;
  if (input instanceof Request) {
    const base = new Request(url, input);
    return init ? new Request(base, init) : base;
  }
  return new Request(url, init);
}
