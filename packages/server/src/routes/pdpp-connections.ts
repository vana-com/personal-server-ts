import { Hono } from "hono";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  PdppBindingError,
  type PdppInstanceBinding,
} from "../storage/pdpp-records-sqlite-store.js";
import { resolveRetainedSourceId } from "../pdpp/source-id-compat.js";

interface PdppConnectionStore {
  listConnections(sourceId: string): PdppInstanceBinding[];
  getInstanceBinding(instance: string): PdppInstanceBinding;
  registerConnection(input: {
    instance: string;
    sourceId: string;
    method: string;
    label: string;
  }): PdppInstanceBinding;
  deleteConnection(instance: string): PdppInstanceBinding;
}

export interface PdppConnectionRouteDeps {
  store: PdppConnectionStore;
  auth: PdppAuthorizationService;
  ownerSubjectId: string;
  /** Known method ids keyed by source id. */
  configuredMethods: Map<string, string[]>;
  /** Retained source ids this server can serve. */
  sourceIds: Set<string>;
}

function jsonError(code: string, message: string, status: number): Response {
  return Response.json({ error: { code, message } }, { status });
}

const CONNECTION_ID =
  /^conn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function isConnectionId(id: string, owner: string, sourceId?: string): boolean {
  return (
    CONNECTION_ID.test(id) ||
    (sourceId !== undefined &&
      id ===
        `${sourceId.split("/").filter(Boolean).pop() ?? sourceId}:${owner.toLowerCase()}`)
  );
}

function connectionJson(
  binding: PdppInstanceBinding,
  sourceId = binding.sourceId,
) {
  return {
    connection_id: binding.instance,
    source_id: sourceId,
    method_id: binding.method,
    label: binding.label,
  };
}

export function pdppConnectionRoutes(deps: PdppConnectionRouteDeps): Hono {
  const app = new Hono();

  async function owner(
    request: Request,
  ): Promise<{ subjectId: string; sourceId: string } | Response> {
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
    return { subjectId: context.subjectId, sourceId: context.sourceId };
  }

  app.get("/pdpp/capabilities", (c) =>
    c.json({ capabilities: ["connections_v1"] }),
  );

  app.get("/pdpp/connections", async (c) => {
    const requestedSourceId = c.req.query("source_id");
    const sourceId = requestedSourceId
      ? resolveRetainedSourceId(requestedSourceId, deps.sourceIds)
      : undefined;
    if (!requestedSourceId || !sourceId) {
      return jsonError("not_found", "Source declaration not found", 404);
    }
    const ownerScope = await owner(c.req.raw);
    if (ownerScope instanceof Response) return ownerScope;
    if (ownerScope.sourceId !== sourceId) {
      return jsonError(
        "access_denied",
        "Owner token has a different source scope",
        403,
      );
    }
    return c.json({
      connections: deps.store
        .listConnections(sourceId)
        .map((connection) => connectionJson(connection, requestedSourceId)),
    });
  });

  app.put("/pdpp/connections/:connectionId", async (c) => {
    const connectionId = c.req.param("connectionId");
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return jsonError("invalid_request", "Body must be JSON", 400);
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return jsonError("invalid_request", "Body must be an object", 400);
    }
    const input = body as Record<string, unknown>;
    const requestedSourceId = input.source_id;
    const sourceId =
      typeof requestedSourceId === "string"
        ? resolveRetainedSourceId(requestedSourceId, deps.sourceIds)
        : undefined;
    if (
      !sourceId ||
      typeof input.method_id !== "string" ||
      typeof input.label !== "string"
    ) {
      return jsonError(
        "invalid_request",
        "source_id, method_id and label are required",
        400,
      );
    }
    const ownerScope = await owner(c.req.raw);
    if (ownerScope instanceof Response) return ownerScope;
    if (ownerScope.sourceId !== sourceId) {
      return jsonError(
        "access_denied",
        "Owner token has a different source scope",
        403,
      );
    }
    if (!isConnectionId(connectionId, ownerScope.subjectId, sourceId)) {
      return jsonError(
        "connection_id_invalid",
        "Connection id is invalid",
        400,
      );
    }
    const configured = deps.configuredMethods.get(sourceId) ?? [];
    if (configured.length !== 1 || configured[0] !== input.method_id) {
      return jsonError(
        "method_inactive",
        "Method is not active for this source",
        409,
      );
    }
    try {
      const binding = deps.store.registerConnection({
        instance: connectionId,
        sourceId,
        method: input.method_id,
        label: input.label,
      });
      deps.configuredMethods.set(connectionId, [input.method_id]);
      return c.json(connectionJson(binding), 200);
    } catch (error) {
      if (error instanceof PdppBindingError) {
        const status = error.reason === "connection_id_invalid" ? 400 : 409;
        return jsonError(error.reason, error.reason, status);
      }
      throw error;
    }
  });

  app.delete("/pdpp/connections/:connectionId", async (c) => {
    const connectionId = c.req.param("connectionId");
    const ownerScope = await owner(c.req.raw);
    if (ownerScope instanceof Response) return ownerScope;
    const current = deps.store.getInstanceBinding(connectionId);
    if (
      !current.sourceId ||
      !deps.sourceIds.has(current.sourceId) ||
      !isConnectionId(connectionId, ownerScope.subjectId, current.sourceId)
    ) {
      return jsonError("not_found", "Connection not found", 404);
    }
    if (ownerScope.sourceId !== current.sourceId) {
      return jsonError(
        "access_denied",
        "Owner token has a different source scope",
        403,
      );
    }
    if (current.deletedAt !== null) return c.json(connectionJson(current), 200);
    try {
      return c.json(
        connectionJson(deps.store.deleteConnection(connectionId)),
        200,
      );
    } catch (error) {
      if (error instanceof PdppBindingError) {
        return jsonError(error.reason, error.reason, 409);
      }
      throw error;
    }
  });

  return app;
}
