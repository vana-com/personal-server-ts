import { timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import { ScopeSchema } from "@opendatalabs/vana-sdk/protocol/scopes";
import { createBodyLimit } from "../middleware/body-limit.js";

/** Sandbox-local endpoint. Never mounted on a full PS or a public router. */
export function enclaveFleetRoutes(deps: {
  accessToken: string;
  hydrate(scopes: string[]): Promise<void>;
  observe(
    scope: string,
  ):
    | { dataVersion: number | null; ready: boolean }
    | Promise<{ dataVersion: number | null; ready: boolean }>;
}): Hono {
  const app = new Hono();
  app.use("*", createBodyLimit(16 * 1024));
  app.post("/readiness", async (c) => {
    const received = Buffer.from(c.req.header("authorization") ?? "");
    const expected = Buffer.from(`Bearer ${deps.accessToken}`);
    if (
      received.length !== expected.length ||
      !timingSafeEqual(received, expected)
    )
      return c.json({ error: "authorization required" }, 401);
    const body = (await c.req.json().catch(() => null)) as {
      scopes?: Array<{ scope: string; minimumVersion?: number }>;
      hydrate?: boolean;
    } | null;
    if (
      !body ||
      !Array.isArray(body.scopes) ||
      body.scopes.length > 32 ||
      body.scopes.some(
        (s) =>
          !s ||
          !ScopeSchema.safeParse(s.scope).success ||
          (s.minimumVersion !== undefined &&
            (!Number.isSafeInteger(s.minimumVersion) || s.minimumVersion < 1)),
      )
    ) {
      return c.json({ error: "invalid scopes" }, 400);
    }
    if (body.hydrate) await deps.hydrate(body.scopes.map((s) => s.scope));
    return c.json(
      await Promise.all(
        body.scopes.map(async (s) => {
          const observed = await deps.observe(s.scope);
          return {
            scope: s.scope,
            dataVersion: observed.dataVersion,
            state:
              observed.ready &&
              observed.dataVersion !== null &&
              observed.dataVersion >= (s.minimumVersion ?? 1)
                ? "ready"
                : "pending",
            observedAt: new Date().toISOString(),
          };
        }),
      ),
    );
  });
  return app;
}
