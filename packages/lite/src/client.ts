import {
  leavesUnconfirmed,
  type CycleReport,
  type FailedStream,
  type PublicationReceipt,
  type SeedIntake,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createPersonalServerInfoFromHealth,
  createPersonalServerRegistrationRequest,
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
  type PersonalServerListGrantsResult,
  type PersonalServerOpenScopeUploadOptions,
  type PersonalServerPostDataOptions,
  type PersonalServerPrepareRegistrationOptions,
  type PersonalServerReadyOptions,
  type PersonalServerRevokeGrantResult,
  type PersonalServerRegistrationRequest,
  type PersonalServerScopeUpload,
  type PersonalServerScopeUploadResult,
  type PersonalServerStatus,
  type PersonalServerSubmitRegistrationOptions,
} from "@opendatalabs/personal-server-ts-core/client";
import type {
  RunIntake,
  RunPublicationStatus,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import {
  prepareScopeUploadBatches,
  type PreparedScopeUploadBatch,
} from "@opendatalabs/personal-server-ts-core/api";
import {
  createGatewayClient,
  type GatewayClient,
  type RegisterServerResult,
} from "@opendatalabs/vana-sdk/browser";
import { createOwnerRequest } from "./owner-request.js";
import { createPersonalServerClient } from "./personal-server-client.js";
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
  /** Pull switched owner data before advertising. Incoming relay and cycle
   * publication stay closed until registration is confirmed. Built runtimes only. */
  ownerReadBeforeRegistration?: boolean;
  ownerSignature?: `0x${string}`;
  active?: boolean;
  runtime?: PsLiteRuntime;
  localOrigin?: string;
  relay?: false | StartPersonalServerLiteRelayOptions;
  relayStateStore?: PsLiteStateStore;
  gateway?: GatewayClient;
  onStatus?: (status: PersonalServerStatus) => void;
}

/** What one connection's publication did in a `publish()` pass. */
export type PersonalServerLiteConnectionPublication = {
  /** The connection's control scope (`controlScope(connector, ns)`). */
  readonly connectionId: string;
  readonly outcome: "published" | "noop" | "failed";
  /** Why the connection failed; set with `outcome: "failed"`. */
  readonly error?: string;
  /** `update_required`: this build cannot read the connection's log. `degraded`: a load stopped on `failedStreams`. */
  readonly status?: "update_required" | "degraded";
  readonly failedStreams?: readonly FailedStream[];
  readonly publications: readonly PublicationReceipt[];
};

export type PersonalServerLitePublicationResult = {
  readonly outcome: "published" | "noop";
  /** The receipts of the connections the caller owns (every connection when it names none). */
  readonly publications: readonly PublicationReceipt[];
  /** Every connection the pass took, the caller's own and the others. */
  readonly connections: readonly PersonalServerLiteConnectionPublication[];
  /** A failure of the pass that belongs to no connection (the listing, saving controls, a purge). It never rejects. */
  readonly cycleError?: string;
};

export type PersonalServerLitePublishOptions = {
  /**
   * The connections (`controlScope(connector, ns)`) whose publication the
   * caller awaits. `publish()` rejects only for these: another connection's
   * failure is in `connections` and nothing more. Without it, or with an empty
   * list, every connection is the caller's own.
   */
  readonly connections?: readonly string[];
};

/** The Lite handle: the shared handle plus the host's run-intake door. */
export type PersonalServerLiteHandle = PersonalServerHandle & {
  /** True only when this handle admits verified owner pulls before registration. */
  readonly ownerReadBeforeRegistration: boolean;
  /** Local identity/status only: never looks up server registration. */
  localInfo(): Promise<PersonalServerInfo>;
  /** In-process run intake; `null` unless the host built a run intake. */
  readonly streamSyncIntake: RunIntake | null;
  /** One-time retained-snapshot intake, with the runtime's Account admission. */
  readonly streamSyncSeed: SeedIntake | null;
  /** Await a database publication cycle. Rejects if a stream of the caller's
   * own connections (`options.connections`; all of them when none are named)
   * cannot confirm publication. Another connection's failure does not reject:
   * read it from `connections`.
   * A stream of a deleted connection (outcome `purged`) is settled, not
   * unconfirmed: it neither rejects nor appears in the receipts.
   * Receipts cover individual streams, not every stream of a connection.
   * A noop contains no new coverage. Unavailable or stopped runtimes reject.
   */
  publish(
    options?: PersonalServerLitePublishOptions,
  ): Promise<PersonalServerLitePublicationResult>;
  /** Whether an ended run is saved, from durable local state. Use it when a
   * `publish()` reply was lost; it does not collect or publish anything.
   * Errors as `streamSyncIntake.publicationStatus` does.
   */
  publicationStatus(runId: string): Promise<RunPublicationStatus>;
  /**
   * The built runtime's change announcements, for a host that shows the data
   * (see `IndexedDbPsLiteRuntime`). Absent over a supplied runtime: its
   * storage is the caller's. A host without them can only re-read on a timer.
   */
  readonly subscribeViewChanges?: IndexedDbPsLiteRuntime["subscribeViewChanges"];
  readonly subscribeSyncStatus?: IndexedDbPsLiteRuntime["subscribeSyncStatus"];
};

export async function startPersonalServer(
  options: StartPersonalServerLiteOptions,
): Promise<PersonalServerLiteHandle> {
  if (options.ownerReadBeforeRegistration && options.runtime) {
    throw new Error("Early owner reads require a verified built runtime");
  }
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
  let registrationConfirmed = false;
  const earlyOwnerReads = options.ownerReadBeforeRegistration === true;
  const runtimeBundle: IndexedDbPsLiteRuntime | null = options.runtime
    ? null
    : await createIndexedDbPsLiteRuntime({
        ...options,
        ...(earlyOwnerReads && {
          registrationReady: () => registrationConfirmed,
        }),
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

  let stopping = false;
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

  publicUrl = initialPublicUrl;
  function startRelay(): void {
    if (
      !resolvedRelayOptions ||
      relayClient ||
      status === "stopped" ||
      stopping
    )
      return;
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
  function confirmRegistration(): void {
    if (registrationConfirmed || stopping || status === "stopped") return;
    registrationConfirmed = true;
    startRelay();
    // A pull may already be running. Trigger coalesces the publication pass
    // behind it, without delaying the registration receipt on historical data.
    if (earlyOwnerReads)
      void runtimeBundle?.syncManager?.trigger().catch(() => {});
  }
  if (!earlyOwnerReads) startRelay();

  async function readInfo(lookup: boolean): Promise<PersonalServerInfo> {
    if (status === "stopped" && lastInfo) {
      return { ...lastInfo, status: "stopped" };
    }
    const response = await runtime.fetch(
      new Request(`${localOrigin}/health${lookup ? "" : "?registration=skip"}`),
    );
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
    if (lastInfo.registration.registered) confirmRegistration();
    return lastInfo;
  }
  const info = () => readInfo(true);

  /**
   * Where API calls go: the relay URL once there is one, else the local
   * runtime. It is the `urls.apiOrigin` that `info()` reports, without the
   * `/health` request behind `info()`, which looks this server up at the
   * gateway. A call that needs only the origin must not pay that lookup: the
   * handle's calls each did, twice.
   */
  function apiOrigin(): string {
    return publicUrl ?? localOrigin;
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
      confirmRegistration();
      return result;
    });
  }

  async function callFetch(
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> {
    return runtime.fetch(await toRuntimeRequest(input, apiOrigin(), init));
  }

  async function postData(
    scope: string,
    body: unknown,
    postOptions: PersonalServerPostDataOptions,
  ): Promise<{ scope: string; collectedAt: string; status: string }> {
    const origin = apiOrigin();
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
    const origin = apiOrigin();
    const base = `/v1/data/${encodeURIComponent(scope)}/uploads`;
    // Every request below is already addressed to `origin`, so each goes
    // straight to the runtime. `callFetch` would ask `info()` for the origin
    // again, and that is a `/health` request that looks the server up at the
    // gateway: once per batch of a large upload.
    const fetchOpened = (request: Request) => runtime.fetch(request);
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
      return parsePersonalServerJsonResponse(await fetchOpened(request), what);
    };
    const begun = (await send(
      "POST",
      base,
      { data: uploadOptions.data, arrayKey: uploadOptions.arrayKey },
      "scope upload begin",
    )) as { uploadId: string; collectedAt: string; maxBatchBytes: number };
    const maxBatchBytes = begun?.maxBatchBytes;
    if (
      typeof maxBatchBytes !== "number" ||
      !Number.isFinite(maxBatchBytes) ||
      maxBatchBytes <= 0
    ) {
      throw new Error(
        "Invalid scope upload begin response: expected a positive maxBatchBytes",
      );
    }
    const path = `${base}/${encodeURIComponent(begun.uploadId)}`;
    // Batches stay at the size Web3Signed owner auth accepts as a body; only
    // a single larger record goes up alone, up to the server's limit.
    const batchBytes = Math.min(maxBatchBytes, SCOPE_UPLOAD_BATCH_BYTES);
    let seq = 0;
    // Set when an append fails: the server may hold some of its batches, and
    // the handle does not know which, so it takes no more appends or commits.
    let failed = false;
    const failedUpload = () =>
      new PersonalServerClientError({
        message:
          "An earlier append to this upload failed, so the server may hold part of it. Abort the upload and start over.",
        status: 409,
        errorCode: "UPLOAD_FAILED",
      });

    async function sendBatch(items: unknown[]): Promise<void> {
      const body = { items };
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

    async function sendPreparedBatch(
      batch: PreparedScopeUploadBatch,
    ): Promise<void> {
      const batchPath = `${path}/batches/${seq}`;
      const sendPrepared = async () => {
        const request = await createOwnerRequest({
          origin,
          path: batchPath,
          method: "PUT",
          body: { bodySha256: batch.bodySha256 },
          authOptions: uploadOptions,
          headers: {
            "Content-Type": "application/json",
            ...uploadOptions.headers,
          },
        });
        return parsePersonalServerJsonResponse(
          await runtime.appendScopeUpload!(request, batch),
          "scope upload batch",
        );
      };
      try {
        await sendPrepared();
      } catch (err) {
        if (err instanceof PersonalServerClientError) throw err;
        // Retain the immutable batch, not the source objects: a lost reply
        // must replay the very same bytes without serializing them again.
        await sendPrepared();
      }
      seq += 1;
    }

    /** Group items into batches by their own encoded size, one at a time. */
    async function appendItems(items: unknown[]): Promise<void> {
      if (runtime.appendScopeUpload) {
        for await (const batch of prepareScopeUploadBatches(
          items,
          batchBytes,
        )) {
          await sendPreparedBatch(batch);
        }
        return;
      }
      const encoder = new TextEncoder();
      const frameBytes = encoder.encode('{"items":[]}').byteLength;
      let batch: unknown[] = [];
      let bytes = frameBytes;
      for (const item of items) {
        const itemBytes =
          encoder.encode(JSON.stringify(item) ?? "null").byteLength + 1;
        if (batch.length > 0 && bytes + itemBytes > batchBytes) {
          await sendBatch(batch);
          batch = [];
          bytes = frameBytes;
        }
        batch.push(item);
        bytes += itemBytes;
      }
      if (batch.length > 0) await sendBatch(batch);
    }

    return {
      uploadId: begun.uploadId,
      collectedAt: begun.collectedAt,
      maxBatchBytes: begun.maxBatchBytes,
      async append(items) {
        if (failed) throw failedUpload();
        try {
          await appendItems(items);
        } catch (err) {
          failed = true;
          throw err;
        }
      },
      async commit(data) {
        // A partial append must not become a version: it would publish a
        // prefix of the records as if it were the whole scope.
        if (failed) throw failedUpload();
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
        const response = await fetchOpened(request);
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

  // The read calls are the factory's, over this handle's `fetch` and origin.
  const client = createPersonalServerClient({
    fetch: (request) => callFetch(request),
    origin: apiOrigin,
  });
  const listData = client.listData;

  const listAccessLogs = client.listAccessLogs;

  const listVersions = client.listVersions;

  const readData = client.readData;

  const syncStatus = client.syncStatus;

  async function createGrant(
    grantOptions: PersonalServerCreateGrantOptions,
  ): Promise<PersonalServerCreateGrantResult> {
    const request = await createOwnerRequest({
      origin: apiOrigin(),
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
    const request = await createOwnerRequest({
      origin: apiOrigin(),
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
    const request = await createOwnerRequest({
      origin: apiOrigin(),
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

  const syncNow = client.syncNow;

  async function rememberRegisteredRelay(serverUrl: string): Promise<void> {
    if (!resolvedRelayOptions || !relayStateStore) return;
    await savePsLiteRelayState(relayStateStore, {
      sessionId: resolvedRelayOptions.sessionId,
      controlUrl: resolvedRelayOptions.controlUrl,
      publicSuffix: resolvedRelayOptions.publicSuffix,
      publicUrl: serverUrl,
    });
  }

  const publishing = new Set<Promise<PersonalServerLitePublicationResult>>();
  const seedPort = runtime.streamSyncSeed;
  const streamSyncSeed: SeedIntake | null = seedPort
    ? {
        async status(connector) {
          if (stopping || status === "stopped")
            throw new Error("Stream seed intake is unavailable");
          return seedPort.status(connector);
        },
        async put(connector, stream, body) {
          if (stopping || status === "stopped")
            throw new Error("Stream seed intake is unavailable");
          return seedPort.put(connector, stream, body);
        },
      }
    : null;
  function publish(
    options: PersonalServerLitePublishOptions = {},
  ): Promise<PersonalServerLitePublicationResult> {
    if (stopping)
      return Promise.reject(new Error("Stream publication is unavailable"));
    const operation = publishCycle(options);
    publishing.add(operation);
    void operation.finally(() => publishing.delete(operation)).catch(() => {});
    return operation;
  }

  async function publishCycle(
    options: PersonalServerLitePublishOptions,
  ): Promise<PersonalServerLitePublicationResult> {
    if (
      (earlyOwnerReads && !registrationConfirmed) ||
      status === "stopped" ||
      !runtimeBundle?.getLocalSync
    )
      throw new Error("Stream publication is unavailable");
    // An empty list names no connection: it is no scope, as when omitted.
    const awaited = options.connections?.length
      ? options.connections
      : undefined;
    const report = await (await runtimeBundle.getLocalSync()).publish(awaited);
    const connections = report.connections.map(connectionPublication);
    const own = awaited ? new Set(awaited) : null;
    const mine = connections.filter(
      (connection) => own === null || own.has(connection.connectionId),
    );
    // A connection the caller does not own never rejects its publication.
    const failed = mine.find((connection) => connection.error !== undefined);
    if (failed) throw new Error(failed.error);
    const publications = mine.flatMap((connection) => connection.publications);
    return {
      outcome: publications.length ? "published" : "noop",
      publications,
      connections,
      ...(report.cycleError !== undefined
        ? { cycleError: report.cycleError }
        : {}),
    };
  }

  async function publicationStatus(
    runId: string,
  ): Promise<RunPublicationStatus> {
    const intake = runtimeBundle?.streamSyncIntake;
    if (stopping || status === "stopped" || !intake)
      throw new Error("Stream publication is unavailable");
    return intake.publicationStatus(runId);
  }

  async function stop(): Promise<void> {
    if (status === "stopped") return;
    stopping = true;
    relayClient?.close("personal-server-stop");
    relayClient = undefined;
    runtime.deactivate();
    // The importer writes through the stores; stop it before they wind down.
    await runtimeBundle?.importWaker?.stop();
    await runtimeBundle?.syncManager?.stop?.();
    await Promise.allSettled([...publishing]);
    await runtimeBundle?.closeStreamSync?.();
    setStatus("stopped");
  }

  // Only a runtime this function built has passed the door. A supplied
  // runtime's storage is the caller's, so its handle reports no status.
  const replicationStatus = runtimeBundle?.replication;
  return {
    kind: "lite",
    ownerReadBeforeRegistration: earlyOwnerReads,
    localInfo: () => readInfo(false),
    ...(replicationStatus && {
      replication: { status: () => replicationStatus },
    }),
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
    ...(runtimeBundle && {
      subscribeViewChanges: runtimeBundle.subscribeViewChanges,
      subscribeSyncStatus: runtimeBundle.subscribeSyncStatus,
    }),
    streamSyncIntake: runtimeBundle?.streamSyncIntake ?? null,
    streamSyncSeed,
    publish,
    publicationStatus,
    stop,
  };
}

/** One connection's pass: its error, or the first stream it left unconfirmed, as a failure. */
function connectionPublication(
  connection: CycleReport["connections"][number],
): PersonalServerLiteConnectionPublication {
  const unconfirmed = connection.published.find((result) =>
    leavesUnconfirmed(result.outcome),
  );
  const error =
    connection.error ??
    (unconfirmed
      ? `Stream publication ${unconfirmed.outcome}: ${connection.connectionId}/${unconfirmed.stream}`
      : undefined);
  const publications = connection.published.flatMap((result) =>
    result.publication ? [result.publication] : [],
  );
  return {
    connectionId: connection.connectionId,
    outcome:
      error !== undefined
        ? "failed"
        : publications.length > 0
          ? "published"
          : "noop",
    ...(error !== undefined ? { error } : {}),
    ...(connection.status ? { status: connection.status } : {}),
    ...(connection.failedStreams
      ? { failedStreams: connection.failedStreams }
      : {}),
    publications,
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
