import {
  accessLogsListPath,
  dataListPath,
  dataReadPath,
  dataVersionsPath,
  parsePersonalServerJsonResponse,
  PersonalServerReadInterrupted,
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

/**
 * How many times a data read is made when its body keeps stopping before the
 * end (a read of a whole stream while an apply replaces the stream's head).
 *
 * A stopped read means another head was committed while the body was read.
 * The next read queues behind the apply still running, so it starts from that
 * apply's result and stops again only if one more apply of the same stream
 * lands during the new read. Nothing bounds how often a stream's head moves,
 * so no number can be derived from the data. The bound is a fixed three (two
 * retries) for this reason: one retry covers the usual case of one apply
 * overlapping the read, the second covers a second apply in quick succession,
 * and a read stopped three times in a row is a stream that changes faster than
 * a body of it can be read. A fourth try would again spend a whole body for
 * the same odds, so the caller gets the typed error and decides when to ask
 * again. The bound also holds for any other interruption, such as a dropped
 * connection.
 */
const READ_ATTEMPTS = 3;

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
    readData: async (scope, readOptions = {}) => {
      for (let attempt = 1; ; attempt += 1) {
        try {
          return await call<DataFileEnvelope>(
            "data read",
            dataReadPath(scope, readOptions),
            "GET",
            readOptions,
          );
        } catch (error) {
          if (
            !(error instanceof PersonalServerReadInterrupted) ||
            attempt >= READ_ATTEMPTS
          ) {
            throw error;
          }
        }
      }
    },
    syncStatus: (syncOptions = {}) =>
      call("sync status", "/v1/sync/status", "GET", syncOptions),
    syncNow: (syncOptions = {}) =>
      call("sync trigger", "/v1/sync/trigger", "POST", syncOptions),
  };
}
