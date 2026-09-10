import { timingSafeEqual } from "node:crypto";
import type { FleetController } from "./placement.js";
import type { FleetOwner, FleetScope } from "./contracts.js";
/** Controller identity plus its signed-bundle window, reported on admin status
 * so an operator can see the deployment a directory decision was made under. */
export interface FleetStatusConfig {
  issuedAt: string | null;
  expiresAt: string | null;
  composeHash: string;
  appId: string;
  instanceId: string;
}
export interface FleetControlHttpOptions {
  controller: FleetController;
  credential: string;
  role: "gateway" | "admin";
  config?: FleetStatusConfig;
  active?: () => Promise<boolean>;
  identity(body: unknown): Promise<unknown>;
  seal(body: unknown): Promise<unknown>;
  admit(body: unknown): Promise<unknown>;
  prepareRollback(body: unknown): Promise<unknown>;
  migrate(body: unknown): Promise<unknown>;
  activate(): Promise<unknown>;
  quiesce(): Promise<unknown>;
}
function authorized(request: Request, credential: string): boolean {
  const supplied = Buffer.from(request.headers.get("authorization") ?? "");
  const expected = Buffer.from(`Bearer ${credential}`);
  return (
    supplied.length === expected.length && timingSafeEqual(supplied, expected)
  );
}
class FleetBodyLimitError extends Error {}
async function boundedBody(request: Request): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) return "{}";
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.length;
      if (size > 256 * 1024) {
        await reader.cancel();
        throw new FleetBodyLimitError();
      }
      chunks.push(part.value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}
/** Mount on a dedicated listener. Public MCP never imports this route tree. */
export function createFleetControlHttp(
  options: FleetControlHttpOptions,
): (request: Request) => Promise<Response> {
  if (options.credential.length < 32)
    throw new Error(
      "Fleet service credential must contain at least 32 characters",
    );
  return async (request) => {
    if (!authorized(request, options.credential))
      return Response.json({ error: "unauthorized" }, { status: 401 });
    if (request.method !== "POST") return new Response(null, { status: 404 });
    try {
      const text = await boundedBody(request);
      if (Buffer.byteLength(text) > 256 * 1024)
        return new Response(null, { status: 413 });
      const body = JSON.parse(text) as Record<string, unknown>;
      const path = new URL(request.url).pathname;
      if (options.role === "gateway") {
        if (options.active && !(await options.active()))
          return Response.json(
            { error: "fleet_migration_pending" },
            { status: 503 },
          );
        if (path === "/fleet/v1/ensure" || path === "/fleet/v1/readiness") {
          const owner = body.owner as FleetOwner,
            scopes = body.scopes as FleetScope[];
          if (
            !owner ||
            !Array.isArray(scopes) ||
            scopes.length > 64 ||
            scopes.some(
              (s) =>
                !s ||
                typeof s.scope !== "string" ||
                (s.minimumVersion !== undefined &&
                  (!Number.isSafeInteger(s.minimumVersion) ||
                    s.minimumVersion < 0)),
            )
          )
            return Response.json({ error: "invalid_request" }, { status: 400 });
          if (path.endsWith("/ensure"))
            return Response.json({
              assignment: await options.controller.ensure(owner, scopes),
              readiness: await options.controller.readiness(owner, scopes),
            });
          return Response.json({
            assignment: options.controller.assignment(owner),
            readiness: await options.controller.readiness(owner, scopes),
          });
        }
        if (path === "/fleet/v1/identity")
          return Response.json(await options.identity(body));
        if (path === "/fleet/v1/seal")
          return Response.json(await options.seal(body));
      } else {
        if (path === "/fleet/v1/activate")
          return Response.json(await options.activate());
        if (path === "/fleet/v1/quiesce")
          return Response.json(await options.quiesce());
        if (path === "/fleet/v1/admit")
          return Response.json(await options.admit(body));
        if (path === "/fleet/v1/drain") {
          if (typeof body.nodeId !== "string") throw new Error("Invalid node");
          await options.controller.drain(body.nodeId);
          return Response.json({ success: true });
        }
        if (path === "/fleet/v1/prepare-rollback")
          return Response.json(await options.prepareRollback(body));
        if (path === "/fleet/v1/migrate")
          return Response.json(await options.migrate(body));
        if (path === "/fleet/v1/status")
          return Response.json({
            controllerTerm: 1,
            paused: options.controller.paused(),
            config: options.config ?? null,
            nodes: options.controller.nodeStatus(),
            placements: options.controller.snapshot(),
          });
      }
      return new Response(null, { status: 404 });
    } catch (error) {
      if (error instanceof FleetBodyLimitError)
        return new Response(null, { status: 413 });
      return Response.json(
        { error: "fleet_request_unavailable" },
        { status: 503 },
      );
    }
  };
}
