import { createAdaptorServer } from "@hono/node-server";
import type { AddressInfo } from "node:net";

export type NodeFetchHandler = Parameters<
  typeof createAdaptorServer
>[0]["fetch"];
export type NodeServer = ReturnType<typeof createAdaptorServer>;

export async function listenHttpServer(params: {
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
