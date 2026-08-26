export interface AccessLogEntry {
  logId: string;
  grantId: string;
  builder: string;
  /**
   * "read"   - a builder read served under a grant.
   * "write"  - a builder write served under a write grant.
   * "delete" - the owner durably deleted a scope (grantId "owner", builder =
   *            owner address).
   */
  action: "read" | "write" | "delete";
  scope: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
}

export interface AccessLogWriter {
  write(entry: AccessLogEntry): Promise<void>;
}
