import type { SqlDriver } from "./driver.js";
import { migrate } from "./migrate.js";
import { TEMP_TABLES } from "./merge.js";
import type { ViewChangeRecorder, ViewLogger } from "./view-changes.js";

export interface LocalDbIdentity {
  readonly owner: string;
  readonly network: string;
  /** Written once, when the file is created. */
  readonly deviceId: string;
}

export interface OpenLocalDbOptions {
  /**
   * The host's view-change recorder. Every host that serves a reader attaches
   * it here, so each commit through the returned driver reaches the
   * recorder's subscribers. A host with no reader passes nothing.
   */
  readonly viewChanges?: {
    readonly recorder: ViewChangeRecorder;
    readonly logger: ViewLogger;
  };
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
 *
 * With `options.viewChanges` the returned driver is the recorder's: the host
 * uses it for every write, and the recorder starts a new baseline per open.
 */
export async function openLocalDb(
  driver: SqlDriver,
  identity: LocalDbIdentity,
  options: OpenLocalDbOptions = {},
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
  const views = options.viewChanges;
  return views ? views.recorder.attach(driver, views.logger) : driver;
}
