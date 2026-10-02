import { fork, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { resolve } from "node:path";

export interface ChildTestServer {
  url: string;
  devToken: string;
  pid: number;
  kill: () => Promise<void>;
  stop: () => Promise<void>;
}

export async function startChildTestServer(options: {
  rootPath: string;
  ownerSignature: string;
}): Promise<ChildTestServer> {
  const port = await availablePort();
  const child = fork(
    resolve(process.cwd(), "tests/e2e/helpers/child-server-entry.ts"),
    [],
    {
      execArgv: ["--import", "tsx"],
      env: {
        ...process.env,
        PS_E2E_ROOT_PATH: options.rootPath,
        PS_E2E_PORT: String(port),
        PS_E2E_OWNER_SIGNATURE: options.ownerSignature,
      },
      stdio: ["ignore", "ignore", "inherit", "ipc"],
    },
  );
  let ready: { url: string; devToken: string };
  try {
    ready = await waitForReady(child);
  } catch (error) {
    child.kill("SIGKILL");
    await waitForExit(child);
    throw error;
  }
  const pid = child.pid;
  if (!pid) throw new Error("Child server has no pid");
  return {
    url: ready.url,
    devToken: ready.devToken,
    pid,
    kill: async () => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGKILL");
      await waitForExit(child);
    },
    stop: async () => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      await waitForExit(child);
    },
  };
}

function waitForReady(
  child: ChildProcess,
): Promise<{ url: string; devToken: string }> {
  return new Promise((resolveReady, rejectReady) => {
    const timeout = setTimeout(() => {
      cleanup();
      rejectReady(new Error("Child server did not become ready"));
    }, 15_000);
    const cleanup = () => {
      clearTimeout(timeout);
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const onMessage = (message: unknown) => {
      if (
        message &&
        typeof message === "object" &&
        (message as { type?: unknown }).type === "ready" &&
        typeof (message as { url?: unknown }).url === "string" &&
        typeof (message as { devToken?: unknown }).devToken === "string"
      ) {
        cleanup();
        resolveReady(message as { url: string; devToken: string });
      }
    };
    const onError = (error: Error) => {
      cleanup();
      rejectReady(error);
    };
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      rejectReady(new Error(`Child server exited early: ${code ?? signal}`));
    };
    child.on("message", onMessage);
    child.on("error", onError);
    child.on("exit", onExit);
  });
}

function waitForExit(child: ChildProcess): Promise<void> {
  return new Promise((resolveExit, rejectExit) => {
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) {
      resolveExit();
      return;
    }
    const timeout = setTimeout(() => {
      child.off("exit", onExit);
      child.off("close", onExit);
      rejectExit(new Error("Child server did not exit"));
    }, 15_000);
    const onExit = () => {
      clearTimeout(timeout);
      resolveExit();
    };
    child.once("exit", onExit);
    child.once("close", onExit);
  });
}

async function availablePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolveListen) =>
    server.listen(0, "127.0.0.1", resolveListen),
  );
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Could not reserve a port");
  }
  const port = address.port;
  await new Promise<void>((resolveClose, rejectClose) =>
    server.close((error) => (error ? rejectClose(error) : resolveClose())),
  );
  return port;
}
