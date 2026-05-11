import {
  createOwnerSignedPersonalServerRequest,
  createPersonalServerInfoFromHealth,
  createPersonalServerRegistrationRequest,
  requestPath,
  submitPersonalServerRegistration,
  type PersonalServerHandle,
  type PersonalServerInfo,
  type PersonalServerOwnerAuth,
  type PersonalServerPostDataOptions,
  type PersonalServerPrepareRegistrationOptions,
  type PersonalServerReadyOptions,
  type PersonalServerRegistrationRequest,
  type PersonalServerStatus,
  type PersonalServerSubmitRegistrationOptions,
} from "@opendatalabs/personal-server-ts-core/client";
import {
  createGatewayClient,
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

const DEFAULT_LITE_ORIGIN = "https://ps-lite.local";

export interface StartPersonalServerLiteRelayOptions extends Omit<
  PsLiteRelayClientOptions,
  "runtime" | "onStatus"
> {
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
  gateway?: GatewayClient;
  onStatus?: (status: PersonalServerStatus) => void;
}

export async function startPersonalServer(
  options: StartPersonalServerLiteOptions,
): Promise<PersonalServerHandle> {
  const localOrigin = options.localOrigin ?? DEFAULT_LITE_ORIGIN;
  const relayOptions = options.relay || undefined;
  const initialPublicUrl = relayOptions
    ? psLiteRelayPublicUrl(relayOptions.sessionId, relayOptions.publicSuffix)
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
  const gateway = options.gateway;

  const setStatus = (nextStatus: PersonalServerStatus): void => {
    status = nextStatus;
    options.onStatus?.(nextStatus);
  };

  if (relayOptions) {
    relayStatus = "connecting";
    publicUrl = initialPublicUrl;
    relayClient = startPsLiteRelayClient({
      ...relayOptions,
      runtime,
      origin: runtimeOrigin,
      onStatus(nextRelayStatus) {
        relayStatus = nextRelayStatus;
        if (nextRelayStatus === "error") setStatus("error");
        relayOptions.onStatus?.(nextRelayStatus);
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
    return createPersonalServerRegistrationRequest({
      gatewayConfig: current.gatewayConfig,
      ownerAddress: current.ownerAddress,
      serverAddress: current.server.address,
      publicKey: current.server.publicKey,
      serverUrl,
    });
  }

  async function submitRegistration(
    submitOptions: PersonalServerSubmitRegistrationOptions,
  ): Promise<RegisterServerResult> {
    const request = await prepareRegistration();
    const gatewayClient =
      gateway ?? createGatewayClient(requiredGatewayUrl(await info()));
    return submitPersonalServerRegistration({
      gateway: gatewayClient,
      request,
      signature: submitOptions.signature,
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
    const encoded = new TextEncoder().encode(JSON.stringify(body));
    const request = await createOwnerSignedPersonalServerRequest({
      origin,
      path,
      method: "POST",
      body: encoded,
      auth: authFromOptions(postOptions),
      headers: {
        "Content-Type": "application/json",
        ...postOptions.headers,
      },
    });
    const response = await callFetch(request);
    if (!response.ok) {
      throw new Error(`Personal Server data write failed: ${response.status}`);
    }
    return (await response.json()) as {
      scope: string;
      collectedAt: string;
      status: string;
    };
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
    stop,
  };
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

function authFromOptions(options: PersonalServerPostDataOptions) {
  if ("signMessage" in options) return { signMessage: options.signMessage };
  return { bearerToken: options.bearerToken } satisfies PersonalServerOwnerAuth;
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
