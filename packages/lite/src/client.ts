import {
  accessLogsListPath,
  createOwnerSignedPersonalServerRequest,
  createPersonalServerInfoFromHealth,
  createPersonalServerRegistrationRequest,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  grantRevokePath,
  parsePersonalServerJsonResponse,
  PersonalServerClientError,
  requestPath,
  submitPersonalServerRegistration,
  type PersonalServerAuthRequestOptions,
  type PersonalServerCreateGrantOptions,
  type PersonalServerCreateGrantResult,
  type PersonalServerHandle,
  type PersonalServerInfo,
  type PersonalServerListAccessLogsOptions,
  type PersonalServerListAccessLogsResult,
  type PersonalServerListDataOptions,
  type PersonalServerListDataResult,
  type PersonalServerListGrantsResult,
  type PersonalServerListVersionsOptions,
  type PersonalServerListVersionsResult,
  type PersonalServerOpenScopeUploadOptions,
  type PersonalServerOwnerAuth,
  type PersonalServerPostDataOptions,
  type PersonalServerPrepareRegistrationOptions,
  type PersonalServerReadDataOptions,
  type PersonalServerReadyOptions,
  type PersonalServerRevokeGrantResult,
  type PersonalServerRegistrationRequest,
  type PersonalServerScopeUpload,
  type PersonalServerScopeUploadResult,
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
  createRelayDrainGatedReadFulfillmentReporter,
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

/** Target body size of one scope-upload batch. */
const SCOPE_UPLOAD_BATCH_BYTES = 1024 * 1024;
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
  if (options.persistence && options.runtime) {
    throw new Error(
      "runtime cannot be supplied with a complete persistence bundle",
    );
  }
  if (options.persistence && options.relayStateStore) {
    throw new Error(
      "relayStateStore cannot be supplied with a complete persistence bundle",
    );
  }
  const localOrigin = options.localOrigin ?? DEFAULT_LITE_ORIGIN;
  const relayOptions = options.relay || undefined;
  const relayStateStore = relayOptions
    ? (options.relayStateStore ??
      options.persistence?.state ??
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
  // Late-bound relay handle for the drain-gated fulfillment reporter: the
  // runtime needs the (wrapped) reporter at construction time, but the relay
  // client only starts further down. Until it exists, reports pass through.
  let relayClientForDrain: PsLiteRelayClient | undefined;
  const readFulfillmentReporter =
    options.readFulfillmentReporter && resolvedRelayOptions
      ? createRelayDrainGatedReadFulfillmentReporter(
          options.readFulfillmentReporter,
          () => relayClientForDrain,
        )
      : options.readFulfillmentReporter;
  const runtimeBundle: IndexedDbPsLiteRuntime | null = options.runtime
    ? null
    : await createIndexedDbPsLiteRuntime({
        ...options,
        readFulfillmentReporter,
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
      tlsIdentityStore:
        options.persistence?.relayTlsIdentity ??
        resolvedRelayOptions.tlsIdentityStore,
      onStatus(nextRelayStatus, detail) {
        relayStatus = nextRelayStatus;
        if (nextRelayStatus === "error") setStatus("error");
        resolvedRelayOptions.onStatus?.(nextRelayStatus, detail);
      },
    });
    relayClientForDrain = relayClient;
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
    return runtime.fetch(await toRuntimeRequest(input, origin, init));
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

  async function openScopeUpload(
    scope: string,
    uploadOptions: PersonalServerOpenScopeUploadOptions,
  ): Promise<PersonalServerScopeUpload> {
    const origin = requiredApiOrigin(await info());
    const base = `/v1/data/${encodeURIComponent(scope)}/uploads`;
    const send = async (
      method: string,
      path: string,
      body: unknown,
      what: string,
    ) => {
      const request = await createOwnerRequest({
        origin,
        path,
        method,
        body,
        authOptions: uploadOptions,
        headers: {
          "Content-Type": "application/json",
          ...uploadOptions.headers,
        },
      });
      return parsePersonalServerJsonResponse(await callFetch(request), what);
    };
    const begun = (await send(
      "POST",
      base,
      { data: uploadOptions.data, arrayKey: uploadOptions.arrayKey },
      "scope upload begin",
    )) as { uploadId: string; collectedAt: string; maxBatchBytes: number };
    const path = `${base}/${encodeURIComponent(begun.uploadId)}`;
    // Batches stay at the size Web3Signed owner auth accepts as a body; only
    // a single larger record goes up alone, up to the server's limit.
    const batchBytes = Math.min(begun.maxBatchBytes, SCOPE_UPLOAD_BATCH_BYTES);
    let seq = 0;

    async function appendBatch(items: unknown[]): Promise<void> {
      const body = { items };
      if (
        items.length > 1 &&
        new TextEncoder().encode(JSON.stringify(body)).byteLength > batchBytes
      ) {
        const half = Math.ceil(items.length / 2);
        await appendBatch(items.slice(0, half));
        await appendBatch(items.slice(half));
        return;
      }
      const batchPath = `${path}/batches/${seq}`;
      try {
        await send("PUT", batchPath, body, "scope upload batch");
      } catch (err) {
        // A transport failure may hide a stored batch: resend it under the
        // same number, which the server answers as a replay if it was.
        if (err instanceof PersonalServerClientError) throw err;
        await send("PUT", batchPath, body, "scope upload batch");
      }
      seq += 1;
    }

    return {
      uploadId: begun.uploadId,
      collectedAt: begun.collectedAt,
      maxBatchBytes: begun.maxBatchBytes,
      async append(items) {
        if (items.length > 0) await appendBatch(items);
      },
      async commit(data) {
        return (await send(
          "POST",
          `${path}/commit`,
          { data },
          "scope upload commit",
        )) as PersonalServerScopeUploadResult;
      },
      async abort() {
        const request = await createOwnerRequest({
          origin,
          path,
          method: "DELETE",
          authOptions: uploadOptions,
          headers: uploadOptions.headers,
        });
        const response = await callFetch(request);
        if (
          !response.ok &&
          response.status !== 404 &&
          response.status !== 410
        ) {
          await parsePersonalServerJsonResponse(response, "scope upload abort");
        }
      },
    };
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

  async function listAccessLogs(
    accessLogOptions: PersonalServerListAccessLogsOptions = {},
  ): Promise<PersonalServerListAccessLogsResult> {
    const current = await info();
    const request = await createOwnerRequest({
      origin: requiredApiOrigin(current),
      path: accessLogsListPath(accessLogOptions),
      method: "GET",
      authOptions: accessLogOptions,
      headers: accessLogOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await callFetch(request),
      "access logs list",
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
        ...(grantOptions.grantVersion === undefined
          ? {}
          : { grantVersion: grantOptions.grantVersion }),
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
      PersonalServerAuthRequestOptions | PersonalServerPostDataOptions;
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
    openScopeUpload,
    listData,
    listAccessLogs,
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

async function toRuntimeRequest(
  input: string | URL | Request,
  origin: string,
  init?: RequestInit,
): Promise<Request> {
  const url = `${origin}${requestPath(input)}`;
  if (input instanceof Request) {
    // Rebuild onto the runtime origin with an explicitly buffered body.
    // `new Request(url, request)` treats the request as an init bag and reads
    // its body via the `Request.prototype.body` getter, which Firefox does
    // not implement (no fetch upload streaming) - the body silently drops and
    // every POST reaches the runtime empty ("Request body must be valid
    // JSON"). Buffering via arrayBuffer() works in every engine.
    const buffered =
      input.method === "GET" || input.method === "HEAD"
        ? undefined
        : await input.clone().arrayBuffer();
    const base = new Request(url, {
      method: input.method,
      headers: input.headers,
      body: buffered && buffered.byteLength > 0 ? buffered : undefined,
      signal: input.signal,
    });
    return init ? new Request(base, init) : base;
  }
  return new Request(url, init);
}
