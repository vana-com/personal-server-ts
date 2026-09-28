import { Hono } from "hono";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  PdppBindingError,
  type PdppInstanceBinding,
} from "../storage/pdpp-records-sqlite-store.js";

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
  /** Known method ids keyed by the source's legacy account-1 handle. */
  configuredMethods: Map<string, string[]>;
  /** Retained source ids this server can serve. */
  sourceIds: Set<string>;
}

function jsonError(code: string, message: string, status: number): Response {
  return Response.json({ error: { code, message } }, { status });
}

const CONNECTION_ID =
  /^conn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function legacyIdFor(owner: string, sourceId: string): string {
  const connector = sourceId.split("/").filter(Boolean).pop() ?? sourceId;
  return `${connector}:${owner.toLowerCase()}`;
}

function isConnectionId(id: string, owner: string, sourceId?: string): boolean {
  return (
    CONNECTION_ID.test(id) ||
    (sourceId !== undefined && id === legacyIdFor(owner, sourceId))
  );
}

function connectionJson(binding: PdppInstanceBinding) {
  return {
    connection_id: binding.instance,
    source_id: binding.sourceId,
    method_id: binding.method,
    label: binding.label,
  };
}

export function pdppConnectionRoutes(deps: PdppConnectionRouteDeps): Hono {
  const app = new Hono();

  async function owner(request: Request): Promise<string | Response> {
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
      context.subjectId.toLowerCase() !== deps.ownerSubjectId.toLowerCase()
    ) {
      return jsonError("authentication_error", "Owner token required", 401);
    }
    return context.subjectId;
  }

  app.get("/pdpp/capabilities", (c) =>
    c.json({ capabilities: ["connections_v1"] }),
  );

  app.get("/pdpp/connections", async (c) => {
    const subject = await owner(c.req.raw);
    if (subject instanceof Response) return subject;
    const sourceId = c.req.query("source_id");
    if (!sourceId || !deps.sourceIds.has(sourceId)) {
      return jsonError("not_found", "Source declaration not found", 404);
    }
    return c.json({
      connections: deps.store.listConnections(sourceId).map(connectionJson),
    });
  });

  app.put("/pdpp/connections/:connectionId", async (c) => {
    const subject = await owner(c.req.raw);
    if (subject instanceof Response) return subject;
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
    if (
      typeof input.source_id !== "string" ||
      typeof input.method_id !== "string" ||
      typeof input.label !== "string" ||
      !deps.sourceIds.has(input.source_id)
    ) {
      return jsonError(
        "invalid_request",
        "source_id, method_id and label are required",
        400,
      );
    }
    if (!isConnectionId(connectionId, subject, input.source_id)) {
      return jsonError(
        "connection_id_invalid",
        "Connection id is invalid",
        400,
      );
    }
    const configured =
      deps.configuredMethods.get(legacyIdFor(subject, input.source_id)) ?? [];
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
        sourceId: input.source_id,
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
    const subject = await owner(c.req.raw);
    if (subject instanceof Response) return subject;
    const connectionId = c.req.param("connectionId");
    const current = deps.store.getInstanceBinding(connectionId);
    if (
      !current.sourceId ||
      !deps.sourceIds.has(current.sourceId) ||
      !isConnectionId(connectionId, subject, current.sourceId)
    ) {
      return jsonError("not_found", "Connection not found", 404);
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
