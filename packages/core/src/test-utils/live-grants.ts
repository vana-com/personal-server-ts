/**
 * An explicit always-live verifier for tests whose point is not grant
 * liveness. The server requires one; omitting it is a compile error.
 */
export const alwaysLive =
  (connection: { grants: ReadonlyArray<{ grantId: string }> }) =>
  async (): Promise<string[]> =>
    connection.grants.map((grant) => grant.grantId);
