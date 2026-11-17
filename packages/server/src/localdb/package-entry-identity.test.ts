import { afterEach, expect, it, vi } from "vitest";
import {
  applyConnection,
  connectionQueue,
  openLocalDb,
  syncBeforeBegin,
  type LocalSyncDeps,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  RegistryUnavailableBeforeWriteError,
  RegistryUnavailableError,
} from "@opendatalabs/personal-server-ts-core/stream-sync";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { remoteFixture } from "./apply-fixture.js";

// The server imports the core package through its entries. The registry
// classifies unavailability with `instanceof`, so an error thrown by a
// registry built from one entry must be the class apply and bootstrap, built
// from another entry, test for. Two copies of the class would make every
// "offline" decision silently false.
const drivers: SqlDriver[] = [];
afterEach(async () => {
  for (const db of drivers.splice(0)) await db.close();
});
it("an unavailable error thrown from the stream-sync entry is the class apply and bootstrap test for", async () => {
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: "0xabc",
    network: "test",
    deviceId: "entry",
  });
  drivers.push(db);
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys);
  const unavailable = new RegistryUnavailableError("registry listing: 503");
  const deps: LocalSyncDeps = {
    db,
    keys,
    blobs: remote.storage,
    registry: {
      ...remote.registry,
      read: async () => {
        throw unavailable;
      },
      listStreamRows: async () => {
        throw unavailable;
      },
    },
    queue: connectionQueue(),
    ownerAddress: "0xabc",
    signer: { signAddData: async () => "0x00" },
    logger: { info: vi.fn(), warn: vi.fn() },
    now: () => 1000,
    newOp: () => "entry-1",
  };
  await db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,'fixture-source','',1,'active',1)",
      params: [remote.control],
    },
  ]);
  const error = await applyConnection(deps, remote.control).catch(
    (e: unknown) => e,
  );
  expect(error).toBeInstanceOf(RegistryUnavailableBeforeWriteError);
  expect((error as Error).cause).toBe(unavailable);
  // Bootstrap, from the same entry, takes it as offline.
  expect(await syncBeforeBegin(deps, "fixture-source")).toMatchObject({
    unreachable: true,
  });
});
