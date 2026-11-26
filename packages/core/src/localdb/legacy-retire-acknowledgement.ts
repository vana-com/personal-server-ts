/** Stored acknowledgement values that permit a retirement pass to continue. */
export function isLegacyRetireAcknowledgement(
  value: unknown,
): value is "not-sent" | "unconfirmed" | "accepted" {
  return (
    value === "not-sent" || value === "unconfirmed" || value === "accepted"
  );
}
