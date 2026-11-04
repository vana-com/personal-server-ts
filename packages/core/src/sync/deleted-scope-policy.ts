export type DeletedScopeServingPolicy = "erase-held" | "erase-and-stop";

/** Change this line to require a gateway re-add before a deleted scope serves. */
export const DELETED_SCOPE_SERVING_POLICY: DeletedScopeServingPolicy =
  "erase-held";

/** One policy choice shared by reads, listings and every deletion-aware reader. */
export function deletedScopeNeedsGatewayReadd(
  policy: DeletedScopeServingPolicy = DELETED_SCOPE_SERVING_POLICY,
): boolean {
  return policy === "erase-and-stop";
}
