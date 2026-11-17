import {
  accessLogsListPath,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  parsePersonalServerJsonResponse,
  type PersonalServerAuthRequestOptions,
  type PersonalServerListAccessLogsOptions,
  type PersonalServerListAccessLogsResult,
  type PersonalServerListDataOptions,
  type PersonalServerListDataResult,
  type PersonalServerListVersionsOptions,
  type PersonalServerListVersionsResult,
  type PersonalServerOwnerAuth,
  type PersonalServerReadDataOptions,
  type PersonalServerSyncTriggerResult,
} from "@opendatalabs/personal-server-ts-core/client";
import type { SyncStatus } from "@opendatalabs/personal-server-ts-core/sync";
import type { DataFileEnvelope } from "@opendatalabs/vana-sdk/browser";
import { createOwnerRequest } from "./owner-request.js";

export interface PersonalServerClientOptions {
  /**
   * How a request reaches the Personal Server: a runtime's `fetch`, or a
   * network `fetch` aimed at a sidecar or a relay.
   */
  fetch: (request: Request) => Promise<Response>;
  /**
   * Where requests go. A function when it can change, as a relay URL does once
   * the relay connects; it is read on every call.
   */
  origin: string | (() => string);
  /** The default owner auth. A call's own `auth` replaces it. */
  auth?: PersonalServerOwnerAuth;
}

/**
 * The typed read calls of a Personal Server, over one `fetch`. The Lite handle
 * builds its calls from this, so a host that holds only a `fetch` and an auth
 * (not a handle) makes the same requests and parses the same responses.
 */
export interface PersonalServerClient {
  listData(
    options?: PersonalServerListDataOptions,
  ): Promise<PersonalServerListDataResult>;
  listAccessLogs(
    options?: PersonalServerListAccessLogsOptions,
  ): Promise<PersonalServerListAccessLogsResult>;
  listVersions(
    scope: string,
    options?: PersonalServerListVersionsOptions,
  ): Promise<PersonalServerListVersionsResult>;
  readData(
    scope: string,
    options?: PersonalServerReadDataOptions,
  ): Promise<DataFileEnvelope>;
  syncStatus(options?: PersonalServerAuthRequestOptions): Promise<SyncStatus>;
  syncNow(
    options?: PersonalServerAuthRequestOptions,
  ): Promise<PersonalServerSyncTriggerResult>;
}

export function createPersonalServerClient(
  options: PersonalServerClientOptions,
): PersonalServerClient {
  const originNow = (): string =>
    typeof options.origin === "function" ? options.origin() : options.origin;

  async function call<T>(
    action: string,
    path: string,
    method: "GET" | "POST",
    callOptions: PersonalServerAuthRequestOptions,
  ): Promise<T> {
    const request = await createOwnerRequest({
      origin: originNow(),
      path,
      method,
      authOptions: {
        ...callOptions,
        auth: callOptions.auth ?? options.auth,
      },
      headers: callOptions.headers,
    });
    return parsePersonalServerJsonResponse(
      await options.fetch(request),
      action,
    );
  }

  return {
    listData: (listOptions = {}) =>
      call("data list", dataListPath(listOptions), "GET", listOptions),
    listAccessLogs: (logOptions = {}) =>
      call(
        "access logs list",
        accessLogsListPath(logOptions),
        "GET",
        logOptions,
      ),
    listVersions: (scope, versionOptions = {}) =>
      call(
        "data versions list",
        dataVersionsPath(scope, versionOptions),
        "GET",
        versionOptions,
      ),
    readData: (scope, readOptions = {}) =>
      call("data read", dataReadPath(scope, readOptions), "GET", readOptions),
    syncStatus: (syncOptions = {}) =>
      call("sync status", "/v1/sync/status", "GET", syncOptions),
    syncNow: (syncOptions = {}) =>
      call("sync trigger", "/v1/sync/trigger", "POST", syncOptions),
  };
}
