import { readFile, writeFile } from "node:fs/promises";
import { Hono } from "hono";
import { MissingAuthError } from "@opendatalabs/personal-server-ts-core/errors";
import { handlePersonalServerConfigRequest } from "@opendatalabs/personal-server-ts-core/api";

export interface UiConfigRouteDeps {
  devToken: string;
  configPath: string;
}

export function uiConfigRoutes(deps: UiConfigRouteDeps): Hono {
  const app = new Hono();

  app.all("/config", (c) =>
    handlePersonalServerConfigRequest(c.req.raw, {
      auth: {
        async authorizeOwner(request) {
          if (
            request.headers.get("authorization") !== `Bearer ${deps.devToken}`
          ) {
            throw new MissingAuthError();
          }
        },
      },
      async readConfig() {
        return JSON.parse(await readFile(deps.configPath, "utf-8")) as unknown;
      },
      async writeConfig(config) {
        await writeFile(
          deps.configPath,
          `${JSON.stringify(config, null, 2)}\n`,
        );
      },
    }),
  );

  return app;
}
