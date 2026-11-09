import type { SqlDriver } from "@opendatalabs/personal-server-ts-core/localdb";

/**
 * Lite's database port (PS-2, B.3/B.4). The host (Web Worker, phone `psSql`
 * bridge, or a test) supplies one factory; Lite opens the database through it
 * with `openLocalDb` and runs `createLocalSync` on the result. Lite owns no
 * SQL driver of its own. `persistent: false` = memory mode (DB6).
 */
export type LiteSqlDriverFactory = (request: {
  /** `localDatabaseName(owner, network)`. */
  readonly name: string;
  readonly owner: string;
  readonly network: string;
}) => Promise<SqlDriver>;

export interface LiteLocalDbOptions {
  readonly openDriver: LiteSqlDriverFactory;
}

/**
 * Opens the host's driver and the shared database for one owner and network;
 * `null` when the host cannot hold the database (the caller then treats stream
 * sync as unavailable in this process).
 */
export async function openLiteLocalDb(
  options: LiteLocalDbOptions,
  identity: {
    readonly owner: string;
    readonly network: string;
    readonly deviceId: string;
  },
): Promise<SqlDriver | null> {
  void options;
  void identity;
  throw new Error("PS-2: not built");
}
