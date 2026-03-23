import { createAdaptorServer } from "@hono/node-server";
import type { AddressInfo } from "node:net";
import { createRequire } from "node:module";
import { loadConfig } from "@opendatalabs/personal-server-ts-core/config";
import { createServer } from "./bootstrap.js";
import { verifyTunnelUrl } from "./tunnel/index.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };

const DRAIN_TIMEOUT_MS = 5_000;
type NodeFetchHandler = Parameters<typeof createAdaptorServer>[0]["fetch"];
type NodeServer = ReturnType<typeof createAdaptorServer>;

async function listenHttpServer(params: {
  fetch: NodeFetchHandler;
  port: number;
  hostname?: string;
  onListening?: (info: AddressInfo) => void;
}): Promise<NodeServer> {
  const server = createAdaptorServer({ fetch: params.fetch });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      server.off("error", onError);
      reject(error);
    };

    server.once("error", onError);
    server.listen(params.port, params.hostname, () => {
      server.off("error", onError);
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("Could not resolve bound server address"));
        return;
      }

      params.onListening?.(address);
      resolve();
    });
  });

  return server;
}

async function main(): Promise<void> {
  const rootPath = process.env.PERSONAL_SERVER_ROOT_PATH;
  const config = await loadConfig({ rootPath });
  const context = await createServer(config, { rootPath });
  const { app, logger, devToken } = context;

  const server = await listenHttpServer({
    fetch: app.fetch,
    port: config.server.port,
    onListening: (info) => {
      logger.info({ port: info.port, version: pkg.version }, "Server started");

      if (devToken) {
        logger.info(
          { url: `http://localhost:${info.port}/ui` },
          "Dev UI available",
        );
        logger.info({ devToken }, "Dev token (ephemeral)");
      }
    },
  });

  let localAuthServer: NodeServer | undefined;
  if (context.localApprovalPort) {
    try {
      localAuthServer = await listenHttpServer({
        fetch: app.fetch,
        port: context.localApprovalPort,
        hostname: "127.0.0.1",
        onListening: (info) => {
          const localApprovalOrigin = `http://127.0.0.1:${info.port}`;
          context.setLocalApprovalOrigin(localApprovalOrigin);
          logger.info(
            { localApprovalOrigin },
            "Loopback auth listener started",
          );
        },
      });
    } catch (err) {
      logger.warn(
        { err, port: context.localApprovalPort },
        "Loopback auth listener unavailable — public approval flow will require owner wallet auth",
      );
    }
  }

  // Fire-and-forget: gateway check + tunnel connect (slow operations)
  // HTTP server is already listening so POST /v1/data/:scope works immediately
  context.startBackgroundServices().then(() => {
    // Verify tunnel URL is reachable now that both HTTP server and tunnel are up
    const { tunnelManager, tunnelUrl } = context;
    if (
      tunnelUrl &&
      tunnelManager &&
      tunnelManager.getStatus().status !== "error"
    ) {
      logger.info({ tunnelUrl }, "Verifying tunnel URL is reachable...");
      verifyTunnelUrl(tunnelUrl).then((result) => {
        tunnelManager.setVerified(result.reachable, result.error);
        if (result.reachable) {
          logger.info(
            { tunnelUrl, attempts: result.attempts },
            "Tunnel URL verified",
          );
        } else {
          logger.warn(
            { tunnelUrl, attempts: result.attempts, error: result.error },
            "Tunnel URL not reachable — server running in local-only mode",
          );
        }
      });
    }
  });

  function shutdown(signal: string): void {
    logger.info({ signal }, "Shutdown signal received, draining connections");

    let pending = localAuthServer ? 2 : 1;
    const finish = () => {
      pending -= 1;
      if (pending === 0) {
        logger.info("Server stopped");
        process.exit(0);
      }
    };

    server.close(finish);
    if (localAuthServer) {
      localAuthServer.close(finish);
    }

    // Force exit after drain timeout
    setTimeout(() => {
      logger.warn("Drain timeout exceeded, forcing exit");
      process.exit(1);
    }, DRAIN_TIMEOUT_MS).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  console.error("Failed to start server:", err);
  process.exit(1);
});
