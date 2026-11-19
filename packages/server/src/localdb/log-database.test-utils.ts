import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";

/** Log publication owns durable workspace rows. Keep fixtures on a real file
 * and remove their database, WAL and directory when the driver closes. */
export async function openLogTestDatabase() {
  const directory = await mkdtemp(join(process.cwd(), ".log-database-"));
  const driver = openBetterSqlite3(join(directory, "db"));
  await driver.query("PRAGMA journal_mode=WAL");
  await driver.query("PRAGMA synchronous=NORMAL");
  return {
    ...driver,
    async close() {
      try {
        await driver.close();
      } finally {
        await rm(directory, { recursive: true, force: true });
      }
    },
  };
}
