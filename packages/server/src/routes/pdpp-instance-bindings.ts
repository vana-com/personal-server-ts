import { Hono } from "hono";
import { randomUUID } from "node:crypto";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import type { PdppInstanceBinding } from "../storage/pdpp-records-sqlite-store.js";

interface InstanceBindingStore {
  getInstanceBinding(instance: string): PdppInstanceBinding;
}

export interface PdppInstanceBindingRouteDeps {
  store: InstanceBindingStore;
  auth: PdppAuthorizationService;
  ownerSubjectId: string;
  instancesForSubject(subjectId: string): string[];
  instancesForSource?(subjectId: string, sourceId: string): string[];
  configuredMethods: Map<string, string[]>;
}

function errorResponse(
  code: string,
  message: string,
  status: 400 | 401 | 404 | 409 | 503,
) {
  return Response.json(
    { error: { code, message }, request_id: `req_${randomUUID()}` },
    { status },
  );
}

export function pdppInstanceBindingRoutes(
  deps: PdppInstanceBindingRouteDeps,
): Hono {
  const app = new Hono();

  async function ownerContext(request: Request) {
    const token = request.headers
      .get("authorization")
      ?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token)
      return {
        error: errorResponse(
          "authentication_error",
          "Missing access token",
          401,
        ),
      };
    const context = await deps.auth.resolveToken(token);
    if (
      !context.active ||
      context.tokenKind !== "owner" ||
      !context.subjectId ||
      context.subjectId.toLowerCase() !== deps.ownerSubjectId.toLowerCase()
    ) {
      return {
        error: errorResponse(
          "authentication_error",
          "Owner token required",
          401,
        ),
      };
    }
    return {
      subjectId: context.subjectId,
      instanceIds: context.instanceIds,
      sourceId: context.sourceId,
    };
  }

  function scopedOwnedInstances(owner: {
    subjectId: string;
    instanceIds?: string[];
    sourceId?: string;
  }): string[] {
    if (owner.sourceId) {
      const current =
        deps.instancesForSource?.(owner.subjectId, owner.sourceId) ?? [];
      if (!owner.instanceIds) return current;
      return owner.instanceIds.filter((instance) => current.includes(instance));
    }
    const current = deps.instancesForSubject(owner.subjectId);
    if (!owner.instanceIds) return [];
    return owner.instanceIds.filter((instance) => current.includes(instance));
  }

  function canAccessInstance(
    instance: string,
    owner: { subjectId: string; instanceIds?: string[]; sourceId?: string },
  ): boolean {
    return scopedOwnedInstances(owner).includes(instance);
  }

  function configuredActiveMethod(instance: string): string | null {
    const methods = deps.configuredMethods.get(instance) ?? [];
    return methods.length === 1 ? methods[0] : null;
  }

  app.get("/pdpp/instances/:instance/binding", async (c) => {
    const owner = await ownerContext(c.req.raw);
    if ("error" in owner) return owner.error;
    const instance = c.req.param("instance");
    if (!canAccessInstance(instance, owner)) {
      return errorResponse(
        "authentication_error",
        "Instance is not owned",
        401,
      );
    }
    const binding = deps.store.getInstanceBinding(instance);
    return c.json({
      method: binding.method,
      generation: binding.generation,
      empty: binding.empty === true,
      configured_active_method: configuredActiveMethod(instance),
    });
  });

  return app;
}
