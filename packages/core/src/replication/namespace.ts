/** Dedicated SDK-compatible source name; never a legacy source or permission. */
export const REPLICA_SCOPE_PREFIX = "pdpp_replica_v1";
export function isReplicaScope(scope: string): boolean {
  return (
    scope === REPLICA_SCOPE_PREFIX ||
    scope.startsWith(`${REPLICA_SCOPE_PREFIX}.`)
  );
}
