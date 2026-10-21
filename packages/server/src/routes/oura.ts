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
    }),
  );
  app.all("/", async (c) => {
    await auth.authorizeOwner(c.req.raw);
    if (c.req.method !== "POST")
      return c.json({ error: "METHOD_NOT_ALLOWED" }, 405);
    let body: OuraBrowserImportInput;
    try {
      body = JSON.parse(
        new TextDecoder().decode(
          await cacheRequestBodyBytes(c.req.raw, DATA_INGEST_MAX_SIZE),
        ),
      );
    } catch {
      return c.json({ error: "INVALID_BODY" }, 400);
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
    const result = await importOuraBrowserRecords(storage, body, {
      legacyScopeView: deps.legacyScopeView,
      scopeDeletions: deps.scopeDeletions,
      syncManager: deps.syncManager,
      additions: deps.additions,
      onDataWritten: deps.derivativeCompute
        ? (event) =>
            deps.derivativeCompute?.scheduler.markSourceChanged(event.scope, {
              lineageSources: event.lineageSources,
            })
        : undefined,
      beforeCommit: (input) => commitCanonicalBatch(deps, input),
    });
    return c.json(result, result.ok ? 200 : 409);
  });
  return app;
}

/** Use the real bound P7 writer and validator, never a projection-file authority shortcut. */
async function commitCanonicalBatch(
  deps: OuraRouteDeps,
  input: OuraBrowserImportInput,
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
  const store = deps.pdpp.bindingStore;
  const connections = store
    .listConnections(sourceId)
    .filter((connection) => connection.deletedAt === null);
  if (connections.length > 1)
    return { ok: false, reason: "ambiguous_connection" };
  let connection = connections[0];
  if (!connection) {
    // Existing PS account-1 naming, not an upstream Oura account identity.
    const instance = `${sourceId.split("/").at(-1)}:${deps.serverOwner.toLowerCase()}`;
    connection = store.registerConnection({
      instance,
      sourceId,
      method: "oura-browser",
      label: "Personal",
    });
    deps.pdpp.configuredMethods.set(instance, ["oura-browser"]);
  }
  const configured = deps.pdpp.configuredMethods.get(connection.instance);
  if (
    connection.method !== "oura-browser" ||
    configured?.length !== 1 ||
    configured[0] !== "oura-browser"
  )
    return { ok: false, reason: "canonical_method_conflict" };
  const validateData = createRecordDataValidator(deps.pdpp.declarations);
  const batch = SCOPES.map((scope) => {
    const stream = scope.slice("oura.".length);
    const declaration = deps.pdpp!.declarations.forInstance(
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
  for (const scope of SCOPES) {
    const served = await deps.legacyScopeView?.readLatest(scope);
    if (served?.kind !== "canonical")
      return { ok: false, reason: "canonical_view_unavailable", scope };
  }
}
