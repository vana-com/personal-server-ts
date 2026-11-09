import type { SqlDriver } from "./driver.js";
import { MIGRATIONS } from "./schema.js";

/** The file was written by a newer build. The host shows its generic update message. */
export class LocalDbTooNew extends Error {
  constructor(
    readonly found: number,
    readonly supported: number,
  ) {
    super(
      `local database version ${found} is newer than supported ${supported}`,
    );
    this.name = "LocalDbTooNew";
  }
}

/** Runs each missing migration as one batch that ends with its `user_version`. */
export async function migrate(driver: SqlDriver): Promise<void> {
  const [row] = await driver.query<{ user_version: number }>(
    "PRAGMA user_version",
  );
  const current = Number(row?.user_version ?? 0);
  if (current > MIGRATIONS.length) {
    throw new LocalDbTooNew(current, MIGRATIONS.length);
  }
  for (let n = current; n < MIGRATIONS.length; n += 1) {
    await driver.batch([
      ...MIGRATIONS[n]!.map((sql) => ({ sql })),
      { sql: `PRAGMA user_version = ${n + 1}` },
    ]);
  }
}
