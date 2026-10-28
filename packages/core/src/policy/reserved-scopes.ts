import { isReplicaScope } from "../replication/namespace.js";
/** Private runtime state is never authorized by delegated grants or MCP. */
export function isSystemScope(scope: string): boolean {
  return scope.startsWith("vana.system.") || isReplicaScope(scope);
}

/**
 * Agent memory, written by the `remember` MCP tool as full snapshots of a
 * `{ records }` list. MCP clients may only be granted writes here, memory tools
 * only act here, and sync publishes only the newest snapshot of these scopes.
 */
export const MEMORY_SCOPE_PREFIX = "memory.";

export function isMemoryScope(scope: string): boolean {
  return (
    scope.startsWith(MEMORY_SCOPE_PREFIX) &&
    scope.length > MEMORY_SCOPE_PREFIX.length
  );
}
