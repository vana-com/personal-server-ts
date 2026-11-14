import { spawn } from "node:child_process";
import type {
  SqlDriver,
  SqlStatement,
  SqlValue,
} from "@opendatalabs/personal-server-ts-core/localdb";

const DONE = "<<done>>";
const literal = (v: SqlValue): string =>
  v === null
    ? "NULL"
    : v instanceof Uint8Array
      ? `X'${Buffer.from(v).toString("hex")}'`
      : typeof v === "string"
        ? `'${v.replaceAll("'", "''")}'`
        : String(v);
const inline = (sql: string, params: readonly SqlValue[] = []) => {
  let i = 0;
  return sql.replaceAll("?", () => literal(params[i++] ?? null));
};
const cell = (s: string): SqlValue =>
  s === "" ? null : /^-?\d+$/.test(s) ? Number(s) : s;

/**
 * Fallback driver for the SQLite 3.22.0 conformance row (SPECS A.2):
 * better-sqlite3 does not compile against 3.22.0, so the suite's SQL runs
 * through a 3.22.0 `sqlite3` shell kept open per database, so that TEMP
 * tables last across calls. Test use only: values come back as numbers or text, tab-separated.
 */
export function openSqlite3Cli(cli: string, file: string): SqlDriver {
  const child = spawn("sh", ["-c", `exec "$0" "$1" 2>&1`, cli, file]);
  let out = "";
  let wake: (() => void) | undefined;
  child.stdout.on("data", (d: Buffer) => {
    out += d.toString();
    wake?.();
  });
  let chain: Promise<unknown> = Promise.resolve();
  const exchange = (script: string): Promise<string[]> => {
    const run = async () => {
      child.stdin.write(`${script}\nSELECT '${DONE}';\n`);
      while (!out.includes(`${DONE}\n`)) {
        await new Promise<void>((r) => (wake = r));
      }
      const lines = out.slice(0, out.indexOf(`${DONE}\n`)).split("\n");
      out = out.slice(out.indexOf(`${DONE}\n`) + DONE.length + 1);
      return lines.filter((l) => l !== "");
    };
    const result = chain.then(run);
    chain = result.catch(() => undefined);
    return result;
  };
  const failure = (lines: string[]) =>
    lines.find((l) => /^(Error|Parse error|Runtime error)/.test(l));
  return {
    info: { sqliteVersion: "3.22.0", host: "node", persistent: true },
    async query<R extends Record<string, SqlValue>>(
      sql: string,
      params?: readonly SqlValue[],
    ) {
      const lines = await exchange(
        `.separator "\t"\n.headers on\n${inline(sql, params).replace(/;?\s*$/, ";")}\n.headers off`,
      );
      const error = failure(lines);
      if (error) throw new Error(error);
      const [head, ...rows] = lines;
      const names = head?.split("\t") ?? [];
      return rows.map(
        (r) =>
          Object.fromEntries(
            r.split("\t").map((c, i) => [names[i], cell(c)]),
          ) as R,
      );
    },
    async batch(statements: readonly SqlStatement[]) {
      const script = statements
        .map(
          (s) =>
            `${inline(s.sql, s.params).replace(/;?\s*$/, ";")}\nSELECT 'ch:'||changes();`,
        )
        .join("\n");
      // The shell keeps going after an error, so commit only if none was seen.
      const lines = await exchange(`BEGIN IMMEDIATE;\n${script}`);
      const error = failure(lines);
      await exchange(error ? "ROLLBACK;" : "COMMIT;");
      if (error) throw new Error(error);
      return {
        changes: lines
          .filter((l) => l.startsWith("ch:"))
          .map((l) => Number(l.slice(3))),
      };
    },
    async close() {
      child.stdin.end();
      await new Promise((r) => child.once("close", r));
    },
  };
}
