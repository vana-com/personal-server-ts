// A SqlDriver that refuses what the phone's SQL bridge refuses, so a test can
// show that a write path stays inside the frame without a phone.
//
// The rules are those of the bridge, which lives in the Unity Surfaces repo
// (`apps/mobile-shell/ps_bundle/src/phone-sql-driver.js` and
// `lib/ps/ps_sql_handler.dart`); the numbers are copied from there:
//   - a request is its JSON, and over 4 MiB it is refused;
//   - a text or blob value over 1 MiB is staged ahead of the statement and the
//     statement carries a handle; a request stages at most 8 values and at most
//     64 MiB in all; a blob that is not staged travels as base64;
//   - a reply over 4 MiB is refused.
import type { SqlDriver } from "../../../core/src/localdb/index.js";

export const SQL_FRAME_BYTES = 4 * 1024 * 1024;
export const SQL_STAGE_OVER_BYTES = 1024 * 1024;
export const SQL_MAX_STAGES = 8;
export const SQL_MAX_STAGED_BYTES = 64 * 1024 * 1024;

const utf8 = (text: string) => Buffer.byteLength(text, "utf8");

export interface FrameLog {
  /** The largest request frame, in bytes, that was let through. */
  largestRequest: number;
  /** The largest reply frame, in bytes, that was let through. */
  largestReply: number;
  /** The most values one request staged. */
  mostStaged: number;
}

export function frameLimited(
  inner: SqlDriver,
): SqlDriver & { frames: FrameLog } {
  const frames: FrameLog = {
    largestRequest: 0,
    largestReply: 0,
    mostStaged: 0,
  };
  const encode = (value: unknown, staged: { n: number; bytes: number }) => {
    if (value === null || typeof value === "number") return value;
    if (typeof value === "bigint") return Number(value);
    if (typeof value === "string") {
      if (value.length * 3 <= SQL_STAGE_OVER_BYTES) return value;
      const bytes = utf8(value);
      if (bytes <= SQL_STAGE_OVER_BYTES) return value;
      staged.n += 1;
      staged.bytes += bytes;
      return { $: "s", id: `stage-${staged.n}` };
    }
    if (value instanceof Uint8Array) {
      if (value.length > SQL_STAGE_OVER_BYTES) {
        staged.n += 1;
        staged.bytes += value.length;
        return { $: "s", id: `stage-${staged.n}` };
      }
      return { $: "b", v: Buffer.from(value).toString("base64") };
    }
    throw new TypeError("unsupported SQL value");
  };
  const send = (
    statements: readonly { sql: string; params?: readonly unknown[] }[],
  ) => {
    const staged = { n: 0, bytes: 0 };
    const request = statements.map(({ sql, params }) => ({
      sql,
      params: (params ?? []).map((value) => encode(value, staged)),
    }));
    if (staged.n > SQL_MAX_STAGES || staged.bytes > SQL_MAX_STAGED_BYTES)
      throw new Error(
        `psSql staging is full (${staged.n} values, ${staged.bytes} bytes)`,
      );
    const bytes = utf8(JSON.stringify(request));
    if (bytes > SQL_FRAME_BYTES)
      throw new RangeError(
        `psSql request exceeds 4 MiB (${bytes} bytes); send fewer statements`,
      );
    frames.largestRequest = Math.max(frames.largestRequest, bytes);
    frames.mostStaged = Math.max(frames.mostStaged, staged.n);
  };
  const reply = (rows: readonly Record<string, unknown>[]) => {
    const bytes = utf8(
      JSON.stringify(
        rows.map((row) =>
          Object.fromEntries(
            Object.entries(row).map(([column, value]) => [
              column,
              value instanceof Uint8Array
                ? { $: "b", v: Buffer.from(value).toString("base64") }
                : typeof value === "bigint"
                  ? Number(value)
                  : value,
            ]),
          ),
        ),
      ),
    );
    if (bytes > SQL_FRAME_BYTES)
      throw new RangeError(`psSql reply exceeds 4 MiB (${bytes} bytes)`);
    frames.largestReply = Math.max(frames.largestReply, bytes);
  };
  return {
    ...inner,
    frames,
    query: async (sql, params) => {
      send([{ sql, params }]);
      const rows = await inner.query(sql, params);
      reply(rows as Record<string, unknown>[]);
      return rows;
    },
    batch: async (statements) => {
      send(statements);
      return inner.batch(statements);
    },
  } as SqlDriver & { frames: FrameLog };
}
