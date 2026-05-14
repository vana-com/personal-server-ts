import type { AccessLogEntry } from "./access-log.js";

export interface AccessLogReadResult {
  logs: AccessLogEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface AccessLogReader {
  read(options?: {
    limit?: number;
    offset?: number;
  }): Promise<AccessLogReadResult>;
}
