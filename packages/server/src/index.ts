import { createRequire } from "node:module";
import { loadConfig } from "./config/index.js";
import { createServer } from "./bootstrap.js";
import { verifyTunnelUrl } from "./tunnel/index.js";
import { runEnclaveMain } from "./enclave-main.js";
import { listenHttpServer, type NodeServer } from "./listen.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string };

const DRAIN_TIMEOUT_MS = 5_000;
async function main(): Promise<void> {
  if (process.env.ENCLAVE_MODE === "true") {
    await runEnclaveMain();
    return;
  }

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
      context.isServerRegistered() &&
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
