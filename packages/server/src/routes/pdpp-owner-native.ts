import { Hono } from "hono";
import {
  resolveSelection,
  validateSelectionRequest,
  type DeclarationSnapshot,
  type OwnerChoices,
  type SelectionRequest,
  type StreamGrant,
} from "@opendatalabs/personal-server-ts-core/pdpp";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { PdppInstanceBinding } from "../storage/pdpp-records-sqlite-store.js";
import { isCompletionTime } from "../storage/pdpp-stream-completion.js";
import { resolveRetainedSourceId } from "../pdpp/source-id-compat.js";

export interface PdppOwnerNativeStore {
  listConnections(sourceId: string): PdppInstanceBinding[];
  listStreams(instanceIds: string[]): Array<{
    stream: string;
    recordCount: number;
    lastUpdated: string | null;
  }>;
  assessStreamCompletion(input: {
    instance: string;
    stream: string;
    sourceId: string;
    primaryKey: string[];
  }): {
    status: "current" | "missing" | "invalid" | "unknown";
    receipt: {
      instance: string;
      stream: string;
      method: string;
      generation: number;
      sourceCollectedAt: string;
      writeSeq: number;
      liveCount: number;
      snapshotSha256: string;
      collectionTimeBasis: "host_run_finished";
    } | null;
  };
  firstAddedCoverage(instanceIds: string[]): Array<{
    instance: string;
    trackedSince: string;
  }>;
  listFirstAdded(
    instanceIds: string[],
    since: string,
    until: string,
  ): Array<{ instance: string; stream: string; added: number }>;
}

export interface PdppOwnerNativeRouteDeps {
  auth: PdppAuthorizationService;
  ownerSubjectId: string;
  sourceIds: Set<string>;
  declarations: DeclarationSnapshot[];
  store: PdppOwnerNativeStore;
}

type OwnerScope = {
  subjectId: string;
  sourceId: string;
  instanceIds?: string[];
};

function jsonError(code: string, message: string, status: number): Response {
  return Response.json({ error: { code, message } }, { status });
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function pdppOwnerNativeRoutes(deps: PdppOwnerNativeRouteDeps): Hono {
  const app = new Hono();

  async function owner(request: Request): Promise<OwnerScope | Response> {
    const token = request.headers
      .get("authorization")
      ?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token)
      return jsonError("authentication_error", "Owner token required", 401);
    const context = await deps.auth.resolveToken(token);
    if (
      !context.active ||
      context.tokenKind !== "owner" ||
      !context.subjectId ||
      !context.sourceId ||
      context.subjectId.toLowerCase() !== deps.ownerSubjectId.toLowerCase()
    ) {
      return jsonError("authentication_error", "Owner token required", 401);
    }
    return {
      subjectId: context.subjectId,
      sourceId: context.sourceId,
      ...(context.instanceIds && { instanceIds: context.instanceIds }),
    };
  }

  function scopeSource(
    scope: OwnerScope,
    requested: unknown,
  ): { sourceId: string; snapshot: DeclarationSnapshot } | Response {
    const sourceId =
      typeof requested === "string"
        ? resolveRetainedSourceId(requested, deps.sourceIds)
        : undefined;
    const snapshot = deps.declarations.find(
      (candidate) => candidate.source_id === sourceId,
    );
    if (!sourceId || !snapshot) {
      return jsonError("not_found", "Source declaration not found", 404);
    }
    if (scope.sourceId !== sourceId) {
      return jsonError(
        "access_denied",
        "Owner token has a different source scope",
        403,
      );
    }
    return { sourceId, snapshot };
  }

  function visibleConnections(scope: OwnerScope, sourceId: string) {
    return deps.store
      .listConnections(sourceId)
      .filter(
        (binding) =>
          scope.instanceIds === undefined ||
          scope.instanceIds.includes(binding.instance),
      );
  }

  app.post("/pdpp/v1/selection-status", async (c) => {
    const scope = await owner(c.req.raw);
    if (scope instanceof Response) return scope;
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonError("invalid_request", "Body must be JSON", 400);
    }
    if (!isObject(body) || !isObject(body.selection)) {
      return jsonError("invalid_request", "selection must be an object", 400);
    }
    const selection = body.selection as unknown as SelectionRequest;
    const requestedSourceId = isObject(selection.source)
      ? selection.source.id
      : undefined;
    const sourceId =
      typeof requestedSourceId === "string"
        ? resolveRetainedSourceId(requestedSourceId, deps.sourceIds)
        : undefined;
    if (sourceId && scope.sourceId !== sourceId) {
      return jsonError(
        "access_denied",
        "Owner token has a different source scope",
        403,
      );
    }
    const snapshot = deps.declarations.find(
      (candidate) => candidate.source_id === (sourceId ?? scope.sourceId),
    );
    if (!snapshot) {
      return jsonError("not_found", "Source declaration not found", 404);
    }
    const responseSourceId = sourceId ?? scope.sourceId;
    const unresolved = (
      status: "unknown" | "choice_required",
      code: string,
      stream?: string,
    ) =>
      c.json({
        source_id: responseSourceId,
        source_declaration: {
          version: snapshot.version,
          digest: snapshot.digest,
        },
        status,
        resolved: null,
        streams: [],
        reasons: [{ code, ...(stream && { stream }) }],
      });
    if (!sourceId) return unresolved("unknown", "unknown_source");
    const expected = body.expected_declaration;
    if (
      !isObject(expected) ||
      expected.version !== snapshot.version ||
      expected.digest !== snapshot.digest
    ) {
      return jsonError(
        "declaration_changed",
        "Expected declaration is no longer current",
        409,
      );
    }

    const connections = visibleConnections(scope, sourceId);
    if (
      Array.isArray(selection.streams) &&
      selection.streams.some(
        (stream) =>
          Array.isArray(stream.instance_ids) &&
          stream.instance_ids.some(
            (instance) =>
              typeof instance === "string" &&
              !connections.some((binding) => binding.instance === instance),
          ),
      )
    ) {
      return jsonError(
        "access_denied",
        "Selection exceeds the owner token instance scope",
        403,
      );
    }
    if (
      (body.instance_choices !== undefined &&
        !isObject(body.instance_choices)) ||
      (body.owner_choices !== undefined && !isObject(body.owner_choices)) ||
      (body.requirements !== undefined && !isObject(body.requirements))
    ) {
      return unresolved("unknown", "invalid_evaluation_options");
    }
    const instanceChoices = isObject(body.instance_choices)
      ? body.instance_choices
      : {};
    if (
      Object.values(instanceChoices).some(
        (instance) =>
          typeof instance === "string" &&
          !connections.some((binding) => binding.instance === instance),
      )
    ) {
      return jsonError(
        "access_denied",
        "Selection exceeds the owner token instance scope",
        403,
      );
    }
    const inventory = {
      eligibleFor(stream: string) {
        const eligible = connections.map((binding) => binding.instance);
        const choice = instanceChoices[stream];
        return typeof choice === "string"
          ? eligible.includes(choice)
            ? [choice]
            : []
          : eligible;
      },
    };
    const validation = validateSelectionRequest(selection, snapshot);
    if (!validation.ok) return unresolved("unknown", validation.failure.code);

    const resolution = resolveSelection(
      selection,
      snapshot,
      inventory,
      isObject(body.owner_choices)
        ? (body.owner_choices as OwnerChoices)
        : undefined,
    );
    if (!resolution.ok) {
      return unresolved(
        resolution.failure.code === "instance_choice_required"
          ? "choice_required"
          : "unknown",
        resolution.failure.code,
        resolution.failure.stream,
      );
    }

    const requirements = isObject(body.requirements) ? body.requirements : {};
    let notReady = false;
    let unknown = false;
    const reasons: { code: string; stream?: string; instance_id?: string }[] =
      [];
    const resolvedNames = new Set(
      resolution.streams.map((stream) => stream.name),
    );
    for (const name of Object.keys(requirements)) {
      if (!resolvedNames.has(name)) {
        unknown = true;
        reasons.push({ code: "requirement_not_in_selection", stream: name });
      }
    }
    const streams = resolution.streams.flatMap((grant) =>
      grant.instance_ids.map((instanceId) => {
        const listing = deps.store
          .listStreams([instanceId])
          .find((item) => item.stream === grant.name);
        const declared = snapshot.streams.find(
          (item) => item.name === grant.name,
        );
        const assessment = declared
          ? deps.store.assessStreamCompletion({
              instance: instanceId,
              stream: grant.name,
              sourceId,
              primaryKey: declared.primary_key,
            })
          : { status: "unknown" as const, receipt: null };
        const exactCount =
          listing?.recordCount ??
          (assessment.status === "current"
            ? (assessment.receipt?.liveCount ?? null)
            : null);
        const rawRequirement = requirements[grant.name];
        const requirement = isObject(rawRequirement) ? rawRequirement : {};
        const minRecords = requirement.min_records;
        const collectedSince = requirement.source_collected_since;
        const requireComplete = requirement.require_complete;
        let stateUnknown =
          exactCount === null ||
          (rawRequirement !== undefined && !isObject(rawRequirement)) ||
          assessment.status === "invalid" ||
          assessment.status === "unknown";
        if (stateUnknown) {
          unknown = true;
          reasons.push({
            code: "evidence_unknown",
            stream: grant.name,
            instance_id: instanceId,
          });
        }
        if (
          (minRecords !== undefined &&
            (typeof minRecords !== "number" ||
              !Number.isSafeInteger(minRecords) ||
              minRecords < 0)) ||
          (collectedSince !== undefined && !isCompletionTime(collectedSince)) ||
          (requireComplete !== undefined &&
            typeof requireComplete !== "boolean")
        ) {
          stateUnknown = true;
          unknown = true;
          reasons.push({
            code: "invalid_requirement",
            stream: grant.name,
            instance_id: instanceId,
          });
        }
        if (minRecords !== undefined && typeof minRecords === "number") {
          if (exactCount === null) stateUnknown = true;
          else if (exactCount < minRecords) {
            notReady = true;
            reasons.push({
              code: "minimum_records_not_met",
              stream: grant.name,
              instance_id: instanceId,
            });
          }
        }
        if (requireComplete === true || collectedSince !== undefined) {
          if (assessment.status === "missing") {
            notReady = true;
            reasons.push({
              code: "completion_missing",
              stream: grant.name,
              instance_id: instanceId,
            });
          } else if (assessment.status !== "current" || !assessment.receipt) {
            stateUnknown = true;
            reasons.push({
              code: "completion_unknown",
              stream: grant.name,
              instance_id: instanceId,
            });
          } else if (
            typeof collectedSince === "string" &&
            assessment.receipt.sourceCollectedAt < collectedSince
          ) {
            notReady = true;
            reasons.push({
              code: "completion_too_old",
              stream: grant.name,
              instance_id: instanceId,
            });
          }
        }
        if (stateUnknown) {
          unknown = true;
          reasons.push({
            code: "count_unknown",
            stream: grant.name,
            instance_id: instanceId,
          });
        }
        return {
          name: grant.name,
          instance_ids: [instanceId],
          record_count: exactCount,
          count_exact: exactCount !== null,
          completion_status: assessment.status,
        };
      }),
    );
    const status = unknown ? "unknown" : notReady ? "not_ready" : "ready";
    const resolved: StreamGrant[] = resolution.streams;
    return c.json({
      source_id: sourceId,
      source_declaration: {
        version: snapshot.version,
        digest: snapshot.digest,
      },
      status,
      resolved,
      streams,
      reasons,
    });
  });

  app.get("/pdpp/v1/metrics/additions", async (c) => {
    const scope = await owner(c.req.raw);
    if (scope instanceof Response) return scope;
    const scopedSource = scopeSource(scope, c.req.query("source_id"));
    if (scopedSource instanceof Response) return scopedSource;
    const { sourceId, snapshot } = scopedSource;
    const since = c.req.query("since");
    const until = c.req.query("until");
    if (
      !isCompletionTime(since) ||
      !isCompletionTime(until) ||
      since >= until
    ) {
      return jsonError(
        "invalid_request",
        "since and until must be valid UTC timestamps with since < until",
        400,
      );
    }
    const requestedInstance = c.req.query("instance_id");
    const connections = visibleConnections(scope, sourceId);
    const visible = requestedInstance
      ? connections.filter((binding) => binding.instance === requestedInstance)
      : connections;
    if (requestedInstance && visible.length === 0) {
      return jsonError(
        "access_denied",
        "Owner token is not scoped to this connection",
        403,
      );
    }
    const instanceIds = visible.map((binding) => binding.instance);
    const coverageRows = deps.store.firstAddedCoverage(instanceIds);
    const trackedSince =
      coverageRows.length === instanceIds.length && coverageRows.length > 0
        ? (coverageRows
            .map((row) => row.trackedSince)
            .sort()
            .at(-1) ?? null)
        : null;
    const unavailable = trackedSince === null;
    const partial = !unavailable && trackedSince > since;
    const rows =
      unavailable || partial
        ? []
        : deps.store.listFirstAdded(instanceIds, since, until);
    const counts = new Map<string, number>();
    for (const row of rows) {
      const key = `${row.stream}\u0000${row.instance}`;
      counts.set(key, row.added);
    }
    const streams = visible.flatMap((binding) =>
      snapshot.streams.map((declared) => ({
        name: declared.name,
        instance_id: binding.instance,
        added:
          unavailable || partial
            ? null
            : (counts.get(`${declared.name}\u0000${binding.instance}`) ?? 0),
      })),
    );
    const total =
      unavailable || partial || streams.some((stream) => stream.added === null)
        ? null
        : streams.reduce((sum, stream) => sum + (stream.added ?? 0), 0);
    return c.json({
      source_id: sourceId,
      since,
      until,
      as_of: new Date().toISOString(),
      coverage: unavailable ? "unavailable" : partial ? "partial" : "complete",
      tracked_since: trackedSince,
      streams,
      added: total,
    });
  });

  return app;
}
