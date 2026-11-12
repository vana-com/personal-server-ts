/**
 * Explicit verifiers for tests whose point is not grant liveness. The server
 * requires one; omitting it is a compile error. Each answers with the
 * connection's own stored scopes, as a gateway that never narrowed them would.
 */
type Grants = ReadonlyArray<{ grantId: string; scopes: string[] }>;

export const alwaysLive =
  (connection: { grants: Grants }) =>
  async (): Promise<Array<{ grantId: string; scopes: string[] }>> =>
    connection.grants.map(({ grantId, scopes }) => ({ grantId, scopes }));

/** Only the named grant ids are live. */
export const liveOnly =
  (connection: { grants: Grants }, ids: readonly string[]) =>
  async (): Promise<Array<{ grantId: string; scopes: string[] }>> =>
    connection.grants
      .filter((grant) => ids.includes(grant.grantId))
      .map(({ grantId, scopes }) => ({ grantId, scopes }));
