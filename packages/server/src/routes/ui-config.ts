import { readFile, writeFile } from "node:fs/promises";
import { Hono } from "hono";
import type { MiddlewareHandler } from "hono";
import {
  configReadErrorContract,
  configWriteErrorContract,
  validateServerConfigContract,
} from "@opendatalabs/personal-server-ts-core/contracts";

export interface UiConfigRouteDeps {
  devToken: string;
  configPath: string;
}

export function uiConfigRoutes(deps: UiConfigRouteDeps): Hono {
  const app = new Hono();

  const requireDevToken: MiddlewareHandler = async (c, next) => {
    const authHeader = c.req.header("authorization");
    if (authHeader !== `Bearer ${deps.devToken}`) {
      return c.json(
        {
          error: {
            code: 401,
            errorCode: "UNAUTHORIZED",
            message: "Invalid dev token",
          },
        },
        401,
      );
    }
    await next();
  };

  // GET /ui/api/config — read config from disk
  app.get("/config", requireDevToken, async (c) => {
    try {
      const contents = await readFile(deps.configPath, "utf-8");
      const config = JSON.parse(contents);
      return c.json(config);
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        const result = configReadErrorContract("not-found");
        return c.json(result.body, 404);
      }
      const result = configReadErrorContract("read");
      return c.json(result.body, 500);
    }
  });

  // PUT /ui/api/config — validate and write config to disk
  app.put("/config", requireDevToken, async (c) => {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json(
        {
          error: {
            code: 400,
            errorCode: "INVALID_BODY",
            message: "Invalid JSON body",
          },
        },
        400,
      );
    }

    const result = validateServerConfigContract(body);
    if (!result.ok) return c.json(result.body, 400);

    try {
      await writeFile(
        deps.configPath,
        JSON.stringify((result.body as { config: unknown }).config, null, 2) +
          "\n",
      );
      return c.json(result.body);
    } catch {
      const writeError = configWriteErrorContract();
      return c.json(writeError.body, 500);
    }
  });

  return app;
}
