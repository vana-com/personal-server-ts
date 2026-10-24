import { Hono } from "hono";
import { z } from "zod";
import { ProtocolError } from "@opendatalabs/personal-server-ts-core/errors";
import type { PersonalServerApiAuthPort } from "@opendatalabs/personal-server-ts-core/api";
import type { createLegacyPublicationPolicy } from "../storage/legacy-publication-policy.js";
import { createBodyLimit, DEFAULT_MAX_SIZE } from "../middleware/body-limit.js";

const epoch = z.number().int().nonnegative().safe();
const stopSchema = z
  .object({ expectedEpoch: epoch, ownerOptIn: z.literal(true) })
  .strict();
const rollbackSchema = z.object({ expectedEpoch: epoch }).strict();
export function legacyPublicationPolicyRoutes(deps: {
  policy: ReturnType<typeof createLegacyPublicationPolicy>;
  auth: Pick<PersonalServerApiAuthPort, "authorizeOwner">;
}): Hono {
  const app = new Hono();
  app.use("*", createBodyLimit(DEFAULT_MAX_SIZE));
  app.use("*", async (c, next) => {
    await deps.auth.authorizeOwner(c.req.raw);
    await next();
  });
  app.get("/:scope", (c) =>
    c.json({
      policy: deps.policy.read(c.req.param("scope")),
      capabilities: deps.policy.capabilities(),
      canonical: deps.policy.canonicalCoverage(c.req.param("scope")),
    }),
  );
  app.post("/:scope/:action", async (c) => {
    const action = c.req.param("action");
    if (action !== "stop" && action !== "rollback") return c.notFound();
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw new ProtocolError(
        400,
        "INVALID_BODY",
        "A JSON transition request is required",
      );
    }
    const parsed = (action === "stop" ? stopSchema : rollbackSchema).safeParse(
      body,
    );
    if (!parsed.success)
      throw new ProtocolError(
        400,
        "INVALID_BODY",
        "Supply the current expectedEpoch and explicit ownerOptIn for stop; evidence cannot be supplied by callers",
      );
    const scope = c.req.param("scope");
    const policy =
      action === "stop"
        ? await deps.policy.stop(
            scope,
            parsed.data as z.infer<typeof stopSchema>,
          )
        : await deps.policy.rollback(scope, parsed.data);
    return c.json({ policy });
  });
  return app;
}
