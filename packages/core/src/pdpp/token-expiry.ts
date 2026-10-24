/** Client-token persistence and resolution share this finite-expiration invariant. */
export function hasFiniteExpiration(
  expiresAt: string | null | undefined,
): expiresAt is string {
  return (
    typeof expiresAt === "string" && Number.isFinite(Date.parse(expiresAt))
  );
}
