import {
  deriveOuraCollectionRequirements,
  OURA_LEGACY_SCOPES,
  OURA_LEGACY_TAKEOVER_CONTRACT,
  type OuraCollectionRequirements,
} from "../contracts/oura-collection-requirements.js";
import type { DataStoragePort } from "../ports/index.js";
import type { LegacyScopeViewPort } from "../storage/legacy-scope-view.js";
import type { PersonalServerApiAuthPort } from "./index.js";

export { OURA_LEGACY_TAKEOVER_CONTRACT } from "../contracts/oura-collection-requirements.js";

/** Retained file heads and the current canonical projections both constrain future runs. */
export async function readOuraCollectionRequirements(
  storage: DataStoragePort,
  view?: LegacyScopeViewPort,
): Promise<OuraCollectionRequirements> {
  const histories: { scope: string; data: unknown }[] = [];
  const heads = OURA_LEGACY_SCOPES.map((scope) => storage.findEntry({ scope }));
  for (const [index, scope] of OURA_LEGACY_SCOPES.entries()) {
    const head = heads[index];
    if (head) {
      const envelope = await (
        storage.readStoredEnvelope ?? storage.readEnvelope
      ).call(storage, scope, head.collectedAt);
      if (envelope.scope !== scope)
        throw new Error("Stored Oura scope mismatch");
      histories.push({ scope, data: envelope.data });
    }
    if (view) {
      const current = await view.readLatest(scope);
      if (current.kind === "canonical")
        histories.push({ scope, data: current.envelope.data });
      else if (
        current.kind === "refused" &&
        !(
          !head &&
          ["no_connection", "no_synced_data"].includes(current.refusal.reason)
        )
      ) {
        throw new Error("Current Oura view unavailable");
      }
    }
  }
  if (
    heads.some(
      (head, index) =>
        storage.findEntry({ scope: OURA_LEGACY_SCOPES[index]! })?.path !==
        head?.path,
    )
  ) {
    throw new Error("Oura heads changed during requirements read");
  }
  return deriveOuraCollectionRequirements(histories);
}

export async function handleOuraCollectionRequirementsRequest(
  request: Request,
  deps: {
    storage: DataStoragePort;
    auth: Pick<PersonalServerApiAuthPort, "authorizeOwner">;
    legacyScopeView?: LegacyScopeViewPort;
  },
): Promise<Response> {
  await deps.auth.authorizeOwner(request);
  const headers = {
    "content-type": "application/json",
    "cache-control": "no-store",
  };
  if (request.method !== "GET")
    return Response.json(
      { error: "METHOD_NOT_ALLOWED" },
      { status: 405, headers },
    );
  try {
    const result = await readOuraCollectionRequirements(
      deps.storage,
      deps.legacyScopeView,
    );
    return result.ok
      ? Response.json(
          { ...result, contract: OURA_LEGACY_TAKEOVER_CONTRACT },
          { headers },
        )
      : Response.json(
          {
            error: "OURA_HISTORY_INVALID",
            reason: result.reason,
            scope: result.scope,
          },
          { status: 409, headers },
        );
  } catch {
    return Response.json(
      { error: "OURA_HISTORY_UNAVAILABLE" },
      { status: 503, headers },
    );
  }
}
