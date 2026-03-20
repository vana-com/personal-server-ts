import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  ServerConfigSchema,
  type ServerConfig,
} from "../schemas/server-config.js";
import { resolveRootPath } from "./paths.js";

/**
 * Apply environment-variable overrides to the raw config object.
 *
 * Supported env vars (all optional):
 *   SERVER_PORT          — server.port (integer)
 *   SERVER_ORIGIN        — server.origin (URL)
 *   TUNNEL_ENABLED       — tunnel.enabled (boolean: "true"/"false")
 *   DEV_UI_ENABLED       — devUi.enabled (boolean: "true"/"false")
 */
function applyEnvOverrides(obj: Record<string, unknown>): void {
  const { SERVER_PORT, SERVER_ORIGIN, TUNNEL_ENABLED, DEV_UI_ENABLED } =
    process.env;

  if (SERVER_PORT !== undefined || SERVER_ORIGIN !== undefined) {
    const server = (obj.server as Record<string, unknown> | undefined) ?? {};
    if (SERVER_PORT !== undefined) server.port = Number(SERVER_PORT);
    if (SERVER_ORIGIN !== undefined) server.origin = SERVER_ORIGIN;
    obj.server = server;
  }

  if (TUNNEL_ENABLED !== undefined) {
    const tunnel = (obj.tunnel as Record<string, unknown> | undefined) ?? {};
    tunnel.enabled = TUNNEL_ENABLED === "true";
    obj.tunnel = tunnel;
  }

  if (DEV_UI_ENABLED !== undefined) {
    const devUi = (obj.devUi as Record<string, unknown> | undefined) ?? {};
    devUi.enabled = DEV_UI_ENABLED === "true";
    obj.devUi = devUi;
  }
}

export interface LoadConfigOptions {
  configPath?: string;
  rootPath?: string;
}

export async function loadConfig(
  options?: LoadConfigOptions,
): Promise<ServerConfig> {
  const configPath =
    options?.configPath ??
    join(resolveRootPath(options?.rootPath), "config.json");

  let raw: string | undefined;
  try {
    raw = await readFile(configPath, "utf-8");
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      "code" in err &&
      (err as NodeJS.ErrnoException).code === "ENOENT"
    ) {
      // File doesn't exist — will use empty object for defaults
    } else {
      throw err;
    }
  }

  const parsed = raw !== undefined ? JSON.parse(raw) : {};

  // Allow env vars to override config-file values (useful for cloud / Docker deployments)
  applyEnvOverrides(parsed);

  const config = ServerConfigSchema.parse(parsed);

  // Write back so that defaults are visible and editable in config.json
  const serialized = JSON.stringify(config, null, 2) + "\n";
  if (serialized !== raw) {
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, serialized);
  }

  return config;
}

export async function saveConfig(
  config: ServerConfig,
  options?: LoadConfigOptions,
): Promise<void> {
  const configPath =
    options?.configPath ??
    join(resolveRootPath(options?.rootPath), "config.json");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}
