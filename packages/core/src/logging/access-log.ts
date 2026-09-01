export interface AccessLogEntry {
  logId: string;
  grantId: string;
  builder: string;
  /**
   * "read"    - a builder read served under a grant.
   * "write"   - a builder write served under a write grant.
   * "delete"  - the owner durably deleted a scope (grantId "owner", builder =
   *             owner address).
   * "lineage" - a lineage view served (GET /v1/data/:scope/lineage); the
   *             graph discloses which scopes derive from which, so it is
   *             logged like a read.
   */
  action: "read" | "write" | "delete" | "lineage";
  scope: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
}

export interface AccessLogWriter {
  write(entry: AccessLogEntry): Promise<void>;
}
