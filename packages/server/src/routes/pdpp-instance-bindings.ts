import { Hono } from "hono";
import { randomUUID } from "node:crypto";
import type { PdppAuthorizationService } from "@opendatalabs/personal-server-ts-core/ports/pdpp-auth";
import {
  PdppBindingError,
  type PdppInstanceBinding,
} from "../storage/pdpp-records-sqlite-store.js";

interface InstanceBindingStore {
  getInstanceBinding(instance: string): PdppInstanceBinding;
  resetInstanceBinding(input: {
    instance: string;
    expectedMethod: string | null;
    expectedGeneration: number;
    nextMethod: string | null;
  }): { binding: PdppInstanceBinding; alreadyReset: boolean };
}

export interface PdppInstanceBindingRouteDeps {
  store: InstanceBindingStore;
  auth: PdppAuthorizationService;
  ownerSubjectId: string;
  instancesForSubject(subjectId: string): string[];
  configuredMethods: Map<string, string[]>;
}

function errorResponse(
  code: string,
  message: string,
  status: 400 | 401 | 404 | 409,
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
    return { subjectId: context.subjectId };
  }

  function ownInstance(instance: string, subjectId: string): boolean {
    return deps.instancesForSubject(subjectId).includes(instance);
  }

  function configuredActiveMethod(instance: string): string | null {
    const methods = deps.configuredMethods.get(instance) ?? [];
    return methods.length === 1 ? methods[0] : null;
  }

  app.get("/pdpp/instances/:instance/binding", async (c) => {
    const owner = await ownerContext(c.req.raw);
    if ("error" in owner) return owner.error;
    const instance = c.req.param("instance");
    if (!ownInstance(instance, owner.subjectId)) {
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

  app.post("/pdpp/instances/:instance/reset", async (c) => {
    const owner = await ownerContext(c.req.raw);
    if ("error" in owner) return owner.error;
    const instance = c.req.param("instance");
    if (!ownInstance(instance, owner.subjectId)) {
      return errorResponse(
        "authentication_error",
        "Instance is not owned",
        401,
      );
    }
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return errorResponse("invalid_request", "Reset body must be JSON", 400);
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return errorResponse(
        "invalid_request",
        "Reset body must be an object",
        400,
      );
    }
    const input = body as Record<string, unknown>;
    if (
      !(
        typeof input.expected_method === "string" ||
        input.expected_method === null
      ) ||
      !Number.isSafeInteger(input.expected_generation) ||
      typeof input.expected_generation !== "number" ||
      input.expected_generation < 1 ||
      !(typeof input.next_method === "string" || input.next_method === null)
    ) {
      return errorResponse("invalid_request", "Reset fields are invalid", 400);
    }
    // A reset may name a method that is not configured yet: the switch
    // flow resets to B before it writes B to the config (design §4.5,
    // step 2 before step 4). It may not name an empty method: a binding of
    // "" refuses every write (method_required) until the next reset.
    if (typeof input.next_method === "string" && !input.next_method.trim()) {
      return errorResponse(
        "invalid_request",
        "next_method must be null or a non-empty method id",
        400,
      );
    }
    try {
      const result = deps.store.resetInstanceBinding({
        instance,
        expectedMethod: input.expected_method as string | null,
        expectedGeneration: input.expected_generation as number,
        nextMethod: input.next_method as string | null,
      });
      return c.json({
        method: result.binding.method,
        generation: result.binding.generation,
        reset_clock: result.binding.resetClock,
        ...(result.alreadyReset && { status: "already_reset" }),
      });
    } catch (err) {
      if (err instanceof PdppBindingError) {
        return errorResponse(err.reason, err.reason, 409);
      }
      throw err;
    }
  });

  return app;
}
