import { serve } from "@hono/node-server";
import { join } from "node:path";
import { ServerConfigSchema } from "../../../packages/core/src/schemas/server-config.js";
import { createServer } from "../../../packages/server/src/bootstrap.js";

const rootPath = process.env.PS_E2E_ROOT_PATH;
const port = Number(process.env.PS_E2E_PORT);
const ownerSignature = process.env.PS_E2E_OWNER_SIGNATURE as
  `0x${string}` | undefined;

if (!rootPath || !Number.isSafeInteger(port) || !ownerSignature) {
  throw new Error("Missing child server environment");
}

process.env.VANA_MASTER_KEY_SIGNATURE = ownerSignature;
const config = ServerConfigSchema.parse({
  server: { port, origin: `http://127.0.0.1:${port}` },
  gateway: { url: "http://127.0.0.1:9999" },
  logging: { level: "fatal" },
});
const context = await createServer(config, {
  serverDir: rootPath,
  dataDir: join(rootPath, "data"),
  ownerSignature,
});
const server = serve({
  fetch: context.app.fetch,
  port,
  hostname: "127.0.0.1",
});
server.once("listening", () => {
  process.send?.({
    type: "ready",
    url: `http://127.0.0.1:${port}`,
    devToken: context.devToken,
  });
});

process.on("SIGTERM", () => {
  server.close(async () => {
    await context.cleanup();
    process.exit(0);
  });
});
