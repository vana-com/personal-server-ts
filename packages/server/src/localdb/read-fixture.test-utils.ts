/** Real SQLite apply/resolver fixture for HTTP and paid MCP journeys. */
import { afterEach } from "vitest";
import {
  openLocalDb,
  connectionQueue,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";
import { createServerLocalSync } from "./sync.js";
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
export async function databaseReadFixture(connector: string) {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys, connector);
  const owner = `0x${"11".repeat(20)}` as const;
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner,
    network: "test",
    deviceId: "read-journey",
  });
  drivers.push(db);
  let op = 0;
  const local = createServerLocalSync(
    {
      db,
      queue: connectionQueue(),
      ownerAddress: owner,
      registry: remote.registry,
      blobs: remote.storage,
      keys,
      signer: { signAddData: async () => "0x00" },
      logger: { info() {}, warn() {} },
      now: () => 100,
      newOp: () => String(++op),
    },
    {
      resolveArtifact: () => undefined,
      declaredStreams: () => [],
      olderVersionReads: () => true,
    },
  );
  return { remote, local };
}
export type DatabaseReadFixture = Awaited<
  ReturnType<typeof databaseReadFixture>
>;
