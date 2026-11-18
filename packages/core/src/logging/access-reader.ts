import type { AccessLogEntry } from "./access-log.js";

export interface AccessLogReadResult {
  logs: AccessLogEntry[];
  /** Legacy adapters return totals; cursor adapters omit the full-table count. */
  total?: number;
  nextCursor?: string | null;
  limit: number;
  offset: number;
}

export interface AccessLogReader {
  read(options?: {
    limit?: number;
    offset?: number;
    cursor?: string;
  }): Promise<AccessLogReadResult>;
}
