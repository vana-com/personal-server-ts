import type { SqlDriver } from "./driver.js";
import { migrate } from "./migrate.js";
import { TEMP_TABLES } from "./merge.js";

export interface LocalDbIdentity {
  readonly owner: string;
  readonly network: string;
  /** Written once, when the file is created. */
  readonly deviceId: string;
}

/** The file belongs to another owner or network. */
export class LocalDbIdentityMismatch extends Error {
  constructor(what: string) {
    super(`local database belongs to another ${what}`);
    this.name = "LocalDbIdentityMismatch";
  }
}

/**
 * Sets the connection pragmas, migrates, creates the TEMP tables and checks
 * (or, on a new file, records) the owner and network. Web uses TRUNCATE
 * journaling; the other hosts use WAL.
 */
export async function openLocalDb(
  driver: SqlDriver,
  identity: LocalDbIdentity,
): Promise<SqlDriver> {
  const journal = driver.info.host === "web" ? "TRUNCATE" : "WAL";
  await driver.query("PRAGMA recursive_triggers = OFF");
  await driver.query("PRAGMA synchronous = NORMAL");
  await driver.query(`PRAGMA journal_mode = ${journal}`);
  await migrate(driver);
  await driver.batch([
    ...TEMP_TABLES.map((sql) => ({ sql })),
    {
      sql: "INSERT OR IGNORE INTO db_meta (id, owner, network, device_id, created_at) VALUES (1, ?, ?, ?, ?)",
      params: [
        identity.owner.toLowerCase(),
        identity.network,
        identity.deviceId,
        Date.now(),
      ],
    },
  ]);
  const [meta] = await driver.query<{ owner: string; network: string }>(
    "SELECT owner, network FROM db_meta WHERE id = 1",
  );
  if (meta?.owner !== identity.owner.toLowerCase()) {
    throw new LocalDbIdentityMismatch("owner");
  }
  if (meta.network !== identity.network) {
    throw new LocalDbIdentityMismatch("network");
  }
  return driver;
}
