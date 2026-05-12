import { createAdaptorServer } from "@hono/node-server";
import type { AddressInfo } from "node:net";
import type { ServerConfig } from "@opendatalabs/personal-server-ts-core/schemas";
import {
  createOwnerSignedPersonalServerRequest,
  createPersonalServerInfoFromHealth,
  createPersonalServerRegistrationRequest,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  parsePersonalServerJsonResponse,
  requestPath,
  submitPersonalServerRegistration,
  type PersonalServerAuthRequestOptions,
  type PersonalServerHandle,
  type PersonalServerInfo,
  type PersonalServerListDataOptions,
  type PersonalServerListDataResult,
  type PersonalServerListVersionsOptions,
  type PersonalServerListVersionsResult,
  type PersonalServerOwnerAuth,
  type PersonalServerPostDataOptions,
  type PersonalServerPrepareRegistrationOptions,
  type PersonalServerReadDataOptions,
  type PersonalServerReadyOptions,
  type PersonalServerRegistrationRequest,
  type PersonalServerStatus,
  type PersonalServerSubmitRegistrationOptions,
  type PersonalServerSyncTriggerResult,
} from "@opendatalabs/personal-server-ts-core/client";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/node";
import type { SyncStatus } from "@opendatalabs/personal-server-ts-core/sync";
import type {
  GatewayClient,
  RegisterServerResult,
} from "@opendatalabs/vana-sdk/node";
import { createServer, type CreateServerOptions } from "./bootstrap.js";
import { loadConfig, type LoadConfigOptions } from "./config/index.js";

type NodeFetchHandler = Parameters<typeof createAdaptorServer>[0]["fetch"];
type NodeServer = ReturnType<typeof createAdaptorServer>;

export interface StartPersonalServerNodeOptions
  extends
    Pick<CreateServerOptions, "rootPath" | "dataDir" | "ownerSignature">,
    LoadConfigOptions {
  config?: ServerConfig;
  configDefaults?: Partial<ServerConfig>;
  port?: number;
  hostname?: string;
  localApproval?: boolean;
  startBackgroundServices?: boolean;
  gatewayClient?: GatewayClient;
  onStatus?: (status: PersonalServerStatus) => void;
}

export async function startPersonalServer(
  options: StartPersonalServerNodeOptions = {},
): Promise<PersonalServerHandle> {
  if (options.port === 0) {
    throw new Error("port: 0 is not supported by the public Node handle");
  }
  let status: PersonalServerStatus = "starting";
  let stopped = false;
  let lastInfo: PersonalServerInfo | null = null;
  const setStatus = (nextStatus: PersonalServerStatus): void => {
    status = nextStatus;
    options.onStatus?.(nextStatus);
  };

  const config = prepareConfig(
    options.config ?? (await loadConfig(options)),
    options,
  );
  const context = await createServer(config, {
    rootPath: options.rootPath,
    dataDir: options.dataDir,
    ownerSignature: options.ownerSignature,
    gatewayClient: options.gatewayClient,
  });
  const mainServer = await listenHttpServer({
    fetch: context.app.fetch,
    port: config.server.port,
    hostname: options.hostname,
  });
  const localOrigin = originFromAddress(mainServer.address());

  let localAuthServer: NodeServer | undefined;
  if (
    options.localApproval !== false &&
    context.localApprovalPort &&
    config.server.port !== 0
  ) {
    try {
      localAuthServer = await listenHttpServer({
        fetch: context.app.fetch,
        port: context.localApprovalPort,
        hostname: "127.0.0.1",
      });
      context.setLocalApprovalOrigin(
        originFromAddress(localAuthServer.address()),
      );
    } catch (err) {
      context.logger.warn(
        { err, port: context.localApprovalPort },
        "Loopback auth listener unavailable",
      );
    }
  }

  setStatus("ready");
  const backgroundServices =
    options.startBackgroundServices === false
      ? Promise.resolve()
      : context.startBackgroundServices().catch((err: unknown) => {
          setStatus("error");
          context.logger.warn({ err }, "Background services failed");
        });

  async function info(): Promise<PersonalServerInfo> {
    if (stopped && lastInfo) {
      return { ...lastInfo, status: "stopped" };
    }
    const response = await fetch(`${localOrigin}/health`);
    const body = await response.json();
    lastInfo = createPersonalServerInfoFromHealth({
      kind: "node",
      status,
      health: body,
      localUrl: localOrigin,
      publicUrl: context.tunnelUrl ?? null,
    });
    return lastInfo;
  }

  async function ready(
    readyOptions: PersonalServerReadyOptions = {},
  ): Promise<PersonalServerInfo> {
    if (readyOptions.publicUrl) {
      await backgroundServices;
    }
    return info();
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
    return submitPersonalServerRegistration({
      gateway: context.gatewayClient,
      request: await prepareRegistration(),
      signature: submitOptions.signature,
    });
  }

  async function callFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    return fetch(toLocalRequest(input, localOrigin, init));
  }

  async function postData(
    scope: string,
    body: unknown,
    postOptions: PersonalServerPostDataOptions,
  ): Promise<{ scope: string; collectedAt: string; status: string }> {
    const path = `/v1/data/${encodeURIComponent(scope)}`;
    const request = await createOwnerRequest({
      path,
      method: "POST",
      body,
      authOptions: postOptions,
      headers: {
        "Content-Type": "application/json",
        ...postOptions.headers,
      },
    });
    const response = await callFetch(request);
    return parsePersonalServerJsonResponse(response, "data write");
  }

  async function listData(
    listOptions: PersonalServerListDataOptions = {},
  ): Promise<PersonalServerListDataResult> {
    const path = dataListPath(listOptions);
    const request = await createOwnerRequest({
      path,
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
    const path = dataVersionsPath(scope, versionOptions);
    const request = await createOwnerRequest({
      path,
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
    const path = dataReadPath(scope, readOptions);
    const request = await createOwnerRequest({
      path,
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
    const request = await createOwnerRequest({
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

  async function syncNow(
    syncOptions: PersonalServerAuthRequestOptions = {},
  ): Promise<PersonalServerSyncTriggerResult> {
    const request = await createOwnerRequest({
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

  async function createOwnerRequest(params: {
    path: string;
    method: string;
    body?: unknown;
    authOptions:
      | PersonalServerAuthRequestOptions
      | PersonalServerPostDataOptions;
    headers?: Record<string, string>;
  }): Promise<Request> {
    const current = await info();
    const origin = current.urls.apiOrigin;
    if (!origin) throw new Error("Personal Server API origin is required");
    const encoded =
      params.body === undefined
        ? undefined
        : new TextEncoder().encode(JSON.stringify(params.body));
    const auth = authFromOptions(params.authOptions);
    if (auth) {
      return createOwnerSignedPersonalServerRequest({
        origin,
        path: params.path,
        method: params.method,
        body: encoded,
        auth,
        headers: params.headers,
      });
    }
    return new Request(`${origin}${params.path}`, {
      method: params.method,
      body: encoded,
      headers: params.headers,
    });
  }

  async function stop(): Promise<void> {
    if (stopped) return;
    if (!lastInfo) {
      lastInfo = await info();
    }
    stopped = true;
    setStatus("stopped");
    await Promise.all([
      closeServer(mainServer),
      localAuthServer ? closeServer(localAuthServer) : Promise.resolve(),
    ]);
    await context.cleanup();
  }

  return {
    kind: "node",
    ready,
    info,
    prepareRegistration,
    submitRegistration,
    fetch: callFetch,
    postData,
    listData,
    listVersions,
    readData,
    syncStatus,
    syncNow,
    stop,
  };
}

function authFromOptions(
  options: PersonalServerAuthRequestOptions | PersonalServerPostDataOptions,
): PersonalServerOwnerAuth | undefined {
  if ("auth" in options && options.auth) return options.auth;
  if ("signMessage" in options) return { signMessage: options.signMessage };
  if ("bearerToken" in options) return { bearerToken: options.bearerToken };
  return undefined;
}

async function listenHttpServer(params: {
  fetch: NodeFetchHandler;
  port: number;
  hostname?: string;
}): Promise<NodeServer> {
  const server = createAdaptorServer({ fetch: params.fetch });
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("error", onError);
      reject(error);
    };
    server.once("error", onError);
    server.listen(params.port, params.hostname, () => {
      server.off("error", onError);
      resolve();
    });
  });
  return server;
}

function closeServer(server: NodeServer): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((err?: Error) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function prepareConfig(
  input: ServerConfig,
  options: StartPersonalServerNodeOptions,
): ServerConfig {
  const config = mergeConfig(input, options.configDefaults);
  if (options.port !== undefined) {
    config.server = {
      ...config.server,
      port: options.port,
      origin: `http://localhost:${options.port}`,
    };
  }
  return config;
}

function mergeConfig(
  input: ServerConfig,
  defaults: Partial<ServerConfig> | undefined,
): ServerConfig {
  if (!defaults) return structuredClone(input);
  return {
    ...input,
    ...defaults,
    server: { ...input.server, ...defaults.server },
    logging: { ...input.logging, ...defaults.logging },
    storage: {
      ...input.storage,
      ...defaults.storage,
      config: {
        ...input.storage.config,
        ...defaults.storage?.config,
      },
    },
    gateway: {
      ...input.gateway,
      ...defaults.gateway,
      contracts: {
        ...input.gateway.contracts,
        ...defaults.gateway?.contracts,
      },
    },
    devUi: { ...input.devUi, ...defaults.devUi },
    sync: { ...input.sync, ...defaults.sync },
    tunnel: { ...input.tunnel, ...defaults.tunnel },
  };
}

function originFromAddress(address: string | AddressInfo | null): string {
  if (!address || typeof address === "string") {
    throw new Error("Could not resolve bound server address");
  }
  return `http://127.0.0.1:${address.port}`;
}

function toLocalRequest(
  input: string | URL | Request,
  localOrigin: string,
  init?: RequestInit,
): Request {
  const url = `${localOrigin}${requestPath(input)}`;
  if (input instanceof Request) {
    const base = new Request(url, input);
    return init ? new Request(base, init) : base;
  }
  return new Request(url, init);
}
