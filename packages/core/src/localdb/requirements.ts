import type { LocalSyncDeps } from "./deps.js";
import type { RecordQuery } from "./query.js";

/** Answer of `GET /v1/streams/requirements?connection=`. */
export type RequirementsAnswer =
  | {
      readonly ok: true;
      /** Smallest declared date value (YYYY-MM-DD) over the connection; `null` when none is declared. */
      readonly since: string | null;
    }
  | { readonly ok: false; readonly reason: "malformed_day" };

/**
 * Manifest data port: for a connection, stream name to the name of the
 * date-valued record field that its manifest declares as `history.since_field`.
 * Empty until the manifest carries the field. The Personal Server names no
 * connector; the manifest is the only source.
 */
export interface SinceFieldSource {
  sinceFields(connectionId: string): Promise<Readonly<Record<string, string>>>;
}

/**
 * r5.2 4.1: generic history requirements. Pages `records` through the query
 * port (JSON1 is not available; one page at a time, within the memory gate),
 * takes the minimum declared day, caches by the connection's head versions.
 * No declared field: `{ ok: true, since: null }`.
 */
export interface LocalRequirements {
  requirements(connectionId: string): Promise<RequirementsAnswer>;
}

export function createLocalRequirements(
  deps: LocalSyncDeps,
  options: {
    readonly query: RecordQuery;
    readonly source: SinceFieldSource;
  },
): LocalRequirements {
  const cache = new Map<
    string,
    { readonly key: string; readonly answer: RequirementsAnswer }
  >();

  return {
    async requirements(connectionId) {
      const fields = Object.entries(
        await options.source.sinceFields(connectionId),
      ).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
      const heads = await deps.db.query<{
        stream: string;
        head_version: number;
      }>(
        "SELECT stream, head_version FROM stream_state WHERE connection_id = ? ORDER BY stream",
        [connectionId],
      );
      // A declaration may change without changing a stream's stored head.
      const key = JSON.stringify([fields, heads]);
      const cached = cache.get(connectionId);
      if (cached?.key === key) return cached.answer;

      const remember = (answer: RequirementsAnswer): RequirementsAnswer => {
        cache.set(connectionId, { key, answer });
        return answer;
      };
      let since: string | null = null;
      for (const [stream, field] of fields) {
        let cursor: string | undefined;
        do {
          const page = await options.query.listRecords({
            connectionId,
            stream,
            ...(cursor === undefined ? {} : { cursor }),
            limit: 100,
          });
          for (const record of page.records) {
            let body: unknown;
            try {
              body = JSON.parse(record.body);
            } catch {
              return remember({ ok: false, reason: "malformed_day" });
            }
            if (
              body === null ||
              typeof body !== "object" ||
              !Object.prototype.hasOwnProperty.call(body, field)
            ) {
              continue;
            }
            const day = (body as Record<string, unknown>)[field];
            if (!isCalendarDay(day)) {
              return remember({ ok: false, reason: "malformed_day" });
            }
            if (since === null || day < since) since = day;
          }
          cursor = page.nextCursor ?? undefined;
        } while (cursor !== undefined);
      }
      return remember({ ok: true, since });
    },
  };
}

function isCalendarDay(value: unknown): value is string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  if (year === 0 || month < 1 || month > 12 || day < 1) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1]!;
}
