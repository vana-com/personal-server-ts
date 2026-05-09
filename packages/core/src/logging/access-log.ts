export interface AccessLogEntry {
  logId: string;
  grantId: string;
  builder: string;
  action: "read";
  scope: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
}

export interface AccessLogWriter {
  write(entry: AccessLogEntry): Promise<void>;
}
