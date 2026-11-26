import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AccessLogEntry } from "./access-log.js";

const ACCESS_LOG_ACTIONS = {
  read: true,
  write: true,
  delete: true,
  lineage: true,
} satisfies Record<AccessLogEntry["action"], true>;

/**
 * Row-shape guard: a log line is valid JSON but not necessarily an
 * AccessLogEntry (e.g. the single line `null`). Trusting the parsed
 * value as-is lets a wrong-shape row reach the timestamp sort, where
 * reading `.timestamp` throws a TypeError. Skip such rows, exactly
 * like malformed JSON lines.
 */
function isAccessLogEntry(value: unknown): value is AccessLogEntry {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const row = value as Record<string, unknown>;
  for (const field of [
    "logId",
    "grantId",
    "builder",
    "scope",
    "timestamp",
  ] as const) {
    if (typeof row[field] !== "string") {
      return false;
    }
  }
  if (
    typeof row.action !== "string" ||
    !Object.hasOwn(ACCESS_LOG_ACTIONS, row.action)
  ) {
    return false;
  }
  // ipAddress and userAgent are optional: the writer omits them when the
  // request carried no metadata. Validate the type only when present.
  for (const field of ["ipAddress", "userAgent"] as const) {
    if (row[field] !== undefined && typeof row[field] !== "string") {
      return false;
    }
  }
  // A timestamp string alone is not enough: it must parse to a real date.
  return !Number.isNaN(new Date(row.timestamp as string).getTime());
}

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

/**
 * Reads all access-*.log files from logsDir, merges entries,
 * sorts by timestamp DESC, and paginates.
 */
export function createAccessLogReader(logsDir: string): AccessLogReader {
  return {
    async read(options?: {
      limit?: number;
      offset?: number;
    }): Promise<AccessLogReadResult> {
      const limit = options?.limit ?? 50;
      const offset = options?.offset ?? 0;

      let filenames: string[];
      try {
        filenames = await readdir(logsDir);
      } catch {
        // Directory doesn't exist — return empty result
        return { logs: [], total: 0, limit, offset };
      }

      const logFiles = filenames.filter(
        (f) => f.startsWith("access-") && f.endsWith(".log"),
      );

      const allEntries: AccessLogEntry[] = [];

      for (const filename of logFiles) {
        const filepath = join(logsDir, filename);
        const content = await readFile(filepath, "utf-8");
        const lines = content
          .split("\n")
          .filter((line) => line.trim().length > 0);

        for (const line of lines) {
          try {
            const entry: unknown = JSON.parse(line);
            if (isAccessLogEntry(entry)) {
              allEntries.push(entry);
            }
          } catch {
            // Skip malformed lines
          }
        }
      }

      // Sort by timestamp DESC (newest first)
      allEntries.sort((a, b) => {
        const ta = new Date(a.timestamp).getTime();
        const tb = new Date(b.timestamp).getTime();
        return tb - ta;
      });

      const total = allEntries.length;
      const paginated = allEntries.slice(offset, offset + limit);

      return { logs: paginated, total, limit, offset };
    },
  };
}
