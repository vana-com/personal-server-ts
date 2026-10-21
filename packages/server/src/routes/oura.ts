import {
  createBodyLimit,
  DATA_INGEST_MAX_SIZE,
} from "../middleware/body-limit.js";
import { Hono } from "hono";
import { handleOuraCollectionRequirementsRequest } from "@opendatalabs/personal-server-ts-core/api";
import {
  importOuraBrowserRecords,
  type OuraBrowserImportInput,
  type OuraBrowserImportResult,
} from "@opendatalabs/personal-server-ts-core/oura";
import { createRecordDataValidator } from "../pdpp/record-schema.js";
import type { AppDeps } from "../app.js";
import { createServerApiAuth } from "../api-auth.js";
import { createNodeDataStorage } from "../storage/node-data-storage.js";
import { cacheRequestBodyBytes } from "@opendatalabs/personal-server-ts-core/auth";

type OuraRouteDeps = Pick<
  AppDeps,
  | "dataStorage"
  | "indexManager"
  | "hierarchyOptions"
  | "serverOrigin"
  | "serverOwner"
  | "gateway"
  | "devToken"
  | "accessToken"
  | "tokenStore"
  | "legacyScopeView"
  | "pdpp"
  | "pdppConnections"
  | "config"
  | "syncManager"
  | "scopeDeletions"
  | "additions"
  | "derivativeCompute"
>;
const SCOPES = ["oura.sleep", "oura.readiness", "oura.activity"];

export function ouraRoutes(deps: OuraRouteDeps): Hono {
  const app = new Hono();
  app.use("*", createBodyLimit(DATA_INGEST_MAX_SIZE));
  const storage = deps.dataStorage ?? createNodeDataStorage(deps);
  const auth = createServerApiAuth({
    ...deps,
    dataStorage: storage,
    pdppOwnerBearer: deps.pdpp
      ? {
          auth: deps.pdpp.auth,
          configuredMethods: deps.pdpp.configuredMethods,
          ownerSubjectId: deps.serverOwner,
          instancesForSubject: deps.pdpp.instancesForSubject,
          instancesForSource: deps.pdpp.instancesForSource,
        }
      : undefined,
  });
  app.all("/requirements", (c) =>
    handleOuraCollectionRequirementsRequest(c.req.raw, {
      storage,
      auth: {
        // Desktop's source owner token may plan collection before a connection
        // exists. Authorize exactly the Oura namespace, never generic owner APIs.
        authorizeOwner: async (request) => {
          for (const scope of SCOPES) {
            await auth.authorizeOwnerScope({ request, scope });
          }
        },
      },
      legacyScopeView: deps.legacyScopeView,
      retainedCanonicalRecords: () =>
        deps.pdpp?.bindingStore.readSnapshot(
          () => retainedCanonicalHistory(deps)?.records,
        ),
    }),
  );
  app.all("/", async (c) => {
    if (c.req.method !== "POST") {
      await auth.authorizeOwner(c.req.raw);
      return c.json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }
    // Existing WRITE authorization for every affected scope. The GET bridge
    // alone is not a write credential, and no write-session store is wired.
    for (const scope of SCOPES) {
      await auth.authorizeWrite({ request: c.req.raw, scope });
    }
    let body: OuraBrowserImportInput & { native?: NativeOuraPublication };
    try {
      body = JSON.parse(
        new TextDecoder().decode(
          await cacheRequestBodyBytes(c.req.raw, DATA_INGEST_MAX_SIZE),
        ),
      );
    } catch {
      return c.json({ error: "INVALID_BODY" }, 400);
    }
    if (body?.native !== undefined) {
      const token = /^Bearer\s+(.+)$/i.exec(
        c.req.header("authorization") ?? "",
      )?.[1];
      const context = token
        ? await deps.pdpp?.auth.resolveToken(token)
        : undefined;
      if (
        context?.active &&
        ((context.sourceId !== undefined &&
          context.sourceId !== body.native?.sourceId) ||
          (context.instanceIds !== undefined &&
            !context.instanceIds.includes(body.native?.instance)))
      )
        return c.json({ ok: false, reason: "native_authority_mismatch" }, 403);
      if (!validNativePublication(deps, body.native))
        return c.json({ ok: false, reason: "native_binding_mismatch" }, 409);
    } else {
      await auth.authorizeOwner(c.req.raw);
    }
    if (
      deps.config?.pdpp.optInMethods.includes("oura-browser") &&
      SCOPES.some((scope) => {
        const head = storage.findEntry({ scope });
        return (
          head &&
          head.producer !== "pdpp-projector" &&
          head.producer !== "pdpp-import-projection"
        );
      })
    )
      return c.json({ ok: false, reason: "method_opt_in" }, 409);
    // One snapshot binds repair constraints and the epoch checked by the writer.
    const preflight = deps.pdpp?.bindingStore.readSnapshot(() => ({
      epoch: canonicalEpoch(deps),
      history: retainedCanonicalHistory(deps),
    }));
    const expectedCanonicalEpoch = preflight?.epoch ?? "disabled";
    const result = await importOuraBrowserRecords(storage, body, {
      legacyScopeView: deps.legacyScopeView,
      retainedCanonicalHistory: preflight?.history,
      artifactBoundNativeCompletion: body.native !== undefined,
      scopeDeletions: deps.scopeDeletions,
      syncManager: deps.syncManager,
      additions: deps.additions,
      onDataWritten: deps.derivativeCompute
        ? (event) =>
            deps.derivativeCompute?.scheduler.markSourceChanged(event.scope, {
              lineageSources: event.lineageSources,
            })
        : undefined,
      beforeCommit: (input) =>
        commitCanonicalBatch(deps, input, () => {
          if (canonicalEpoch(deps) !== expectedCanonicalEpoch)
            return { ok: false as const, reason: "canonical_history_changed" };
          if (
            body.native !== undefined &&
            !validNativePublication(deps, body.native)
          )
            return { ok: false as const, reason: "native_binding_mismatch" };
        }),
    });
    return c.json(result, result.ok ? 200 : 409);
  });
  return app;
}

function retainedCanonicalHistory(deps: OuraRouteDeps) {
  if (!deps.pdpp) return;
  const store = deps.pdpp.bindingStore;
  const sources = [...(deps.pdppConnections?.connectionMethods ?? [])]
    .filter(([, methods]) => methods.includes("oura-browser"))
    .map(([source]) => source);
  if (sources.length !== 1) return;
  const connections = store
    .listConnections(sources[0]!)
    .filter((connection) => connection.deletedAt === null);
  if (connections.length !== 1) return;
  const connection = connections[0]!;
  const configured = deps.pdpp.configuredMethods.get(connection.instance);
  if (
    connection.method !== "oura-browser" ||
    configured?.length !== 1 ||
    configured[0] !== "oura-browser"
  )
    return;
  const rows = SCOPES.flatMap((scope) => {
    const stream = scope.slice("oura.".length);
    return store
      .listRetainedRecordData(connection.instance, stream)
      .map((row) => ({ ...row, stream }));
  });
  const times = [
    ...rows.map((row) => row.emittedAt),
    ...store
      .listStreamCompletions(connection.instance)
      .map((receipt) => receipt.sourceCollectedAt),
  ];
  if (!times.length) return;
  return {
    records: rows.map(({ stream, data }) => ({ stream, data })),
    collectedAt: new Date(
      times.reduce((latest, time) => Math.max(latest, Date.parse(time)), 0),
    ).toISOString(),
  };
}

/** Synchronous snapshot before history reads and again immediately before P7. */
function canonicalEpoch(deps: OuraRouteDeps): string {
  if (!deps.pdpp) return "disabled";
  const store = deps.pdpp.bindingStore;
  return store.readSnapshot(() => {
    const sources = [...(deps.pdppConnections?.connectionMethods ?? [])]
      .filter(([, methods]) => methods.includes("oura-browser"))
      .map(([source]) => source);
    const connections = sources.flatMap((source) =>
      store.listConnections(source),
    );
    const instances = connections.map((connection) => connection.instance);
    return JSON.stringify({
      connections,
      horizon: store.listRecords("sleep", {
        instanceIds: instances,
        limit: 1,
        order: "asc",
      }).horizon,
      receipts: instances.map((instance) =>
        store.listStreamCompletions(instance),
      ),
      configured: instances.map((instance) =>
        deps.pdpp!.configuredMethods.get(instance),
      ),
    });
  });
}

interface NativeOuraPublication {
  sourceId: string;
  instance: string;
  method: string;
  generation: number;
  artifactDigest: string;
}

function validNativePublication(
  deps: OuraRouteDeps,
  native: NativeOuraPublication,
): boolean {
  if (
    !native ||
    typeof native !== "object" ||
    native.sourceId !== "https://registry.pdpp.dev/sources/oura" ||
    native.method !== "oura-browser" ||
    native.artifactDigest !==
      "sha256:45d044af6e263a5121033df51f7ad5eaed1e19f1263cffe95ae63737259888c5" ||
    typeof native.instance !== "string" ||
    !Number.isSafeInteger(native.generation)
  )
    return false;
  const binding = deps.pdpp?.bindingStore
    .listConnections(native.sourceId)
    .find(
      (entry) => entry.instance === native.instance && entry.deletedAt === null,
    );
  return (
    binding?.method === native.method &&
    binding.generation === native.generation &&
    deps.pdpp?.configuredMethods.get(native.instance)?.length === 1 &&
    deps.pdpp.configuredMethods.get(native.instance)?.[0] === native.method
  );
}

/** Use the real bound P7 writer and validator, never a projection-file authority shortcut. */
async function commitCanonicalBatch(
  deps: OuraRouteDeps,
  input: OuraBrowserImportInput,
  validateCurrent?: () => Extract<
    OuraBrowserImportResult,
    { ok: false }
  > | void,
): Promise<Extract<OuraBrowserImportResult, { ok: false }> | void> {
  if (!deps.pdpp) {
    if (SCOPES.some((scope) => deps.legacyScopeView?.ownsScope(scope)))
      return { ok: false, reason: "canonical_store_unavailable" };
    return;
  }
  const sources = [...(deps.pdppConnections?.connectionMethods ?? [])]
    .filter(([, methods]) => methods.includes("oura-browser"))
    .map(([source]) => source);
  if (sources.length !== 1 || !deps.serverOwner)
    return { ok: false, reason: "canonical_method_unavailable" };
  const sourceId = sources[0]!;
  const pdpp = deps.pdpp;
  const serverOwner = deps.serverOwner;
  const store = pdpp.bindingStore;
  const refused = store.writeTransaction<Extract<
    OuraBrowserImportResult,
    { ok: false }
  > | void>(() => {
    const changed = validateCurrent?.();
    if (changed) return changed;
    const connections = store
      .listConnections(sourceId)
      .filter((connection) => connection.deletedAt === null);
    if (connections.length > 1)
      return { ok: false, reason: "ambiguous_connection" };
    let connection = connections[0];
    if (!connection) {
      // Existing PS account-1 naming, not an upstream Oura account identity.
      const instance = `${sourceId.split("/").at(-1)}:${serverOwner.toLowerCase()}`;
      connection = store.registerConnection({
        instance,
        sourceId,
        method: "oura-browser",
        label: "Personal",
      });
      pdpp.configuredMethods.set(instance, ["oura-browser"]);
    }
    const configured = pdpp.configuredMethods.get(connection.instance);
    if (
      connection.method !== "oura-browser" ||
      configured?.length !== 1 ||
      configured[0] !== "oura-browser"
    )
      return { ok: false, reason: "canonical_method_conflict" };
    const validateData = createRecordDataValidator(pdpp.declarations);
    const batch = SCOPES.map((scope) => {
      const stream = scope.slice("oura.".length);
      const declaration = pdpp.declarations.forInstance(
        connection!.instance,
        stream,
      );
      if (!declaration || declaration.semantics !== "mutable_state")
        throw new Error("Oura declaration unavailable");
      return {
        instance: connection!.instance,
        stream,
        method: "oura-browser",
        generation: connection!.generation,
        primaryKey: declaration.primaryKey,
        validateData,
        emittedAt: input.collectedAt,
        sourceCollectedAt: input.collectedAt,
        envelopes: input.records
          .filter((record) => record.stream === stream)
          .map(({ data }) => ({
            instance: connection!.instance,
            stream,
            key: String(data.id),
            data,
            emitted_at: input.collectedAt,
          })),
      };
    });
    try {
      store.replaceStreams(batch);
    } catch {
      return { ok: false, reason: "canonical_batch_rejected" };
    }
  });
  if (refused) return refused;
  for (const scope of SCOPES) {
    const served = await deps.legacyScopeView?.readLatest(scope);
    if (served?.kind !== "canonical")
      return { ok: false, reason: "canonical_view_unavailable", scope };
  }
}
