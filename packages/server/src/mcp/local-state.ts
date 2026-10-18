import { createHash } from "node:crypto";
import { rename } from "node:fs/promises";
import type { Logger } from "../logger/index.js";
import { openMcpDurableState, type McpDurableState } from "./durable-state.js";

const KEY_LABEL = "vana.mcp.local-state.v1";

/**
 * MCP connections and OAuth authorizations for a standard (non-enclave) Node
 * Personal Server, sealed to disk so a restart keeps every approved MCP client
 * (such as a claude.ai connector) signed in. Without it they lived in memory
 * and every client had to reconnect after the server restarted.
 *
 * The file is encrypted with a key derived from the owner's master key, so
 * only this owner's server can read it. A file that no longer decrypts (the
 * owner changed, or it was damaged) is moved aside and the server starts with
 * no connections instead of failing to boot.
 */
export async function openLocalMcpState(options: {
  path: string;
  masterKey: Uint8Array;
  logger?: Pick<Logger, "warn">;
}): Promise<McpDurableState> {
  const key = createHash("sha256")
    .update(KEY_LABEL)
    .update(options.masterKey)
    .digest();
  try {
    return await openMcpDurableState({ path: options.path, key });
  } catch (error) {
    const aside = `${options.path}.unreadable-${Date.now()}`;
    await rename(options.path, aside);
    options.logger?.warn(
      { err: error, movedTo: aside },
      "MCP state could not be read; starting with no MCP connections",
    );
    return openMcpDurableState({ path: options.path, key });
  }
}
