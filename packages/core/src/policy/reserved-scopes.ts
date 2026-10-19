/** Private runtime state is never authorized by delegated grants or MCP. */
export function isSystemScope(scope: string): boolean {
  return scope.startsWith("vana.system.");
}
