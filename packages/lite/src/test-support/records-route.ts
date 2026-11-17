/**
 * A switched owner's store on the Lite runtime, built from a remote registry
 * fixture: what a device holds after it synced another device's connection.
 * Shared by the records-route tests.
 */
import {
  createModeAuthority,
  createMemoryModeRecordStore,
} from "@opendatalabs/personal-server-ts-core/sync/account-mode";
import {
  connectionQueue,
  openLocalDb,
  type LocalSync,
  type SqlDriver,
} from "@opendatalabs/personal-server-ts-core/localdb";
import {
  createTestWallet,
  buildWeb3SignedHeader,
} from "@opendatalabs/personal-server-ts-core/test-utils";
import { createPsLiteRuntime, createWeb3SignedPsLiteAuth } from "../runtime.js";
import {
  createMemoryPsLiteStorage,
  createMemoryPsLiteTokenStore,
} from "./memory.js";
import { openBetterSqlite3 } from "../../../server/src/localdb/better-sqlite3-driver.js";
import { remoteFixture } from "../../../server/src/localdb/apply-fixture.test-utils.js";
import { createServerLocalSync } from "../../../server/src/localdb/sync.js";

export const ORIGIN = "https://ps-lite.local";
export const owner = createTestWallet(7);
export const CONNECTOR = "meta";
const drivers: SqlDriver[] = [];

/** Close every store opened since the last call (an `afterEach` hook). */
export async function closeStores(): Promise<void> {
  for (const db of drivers.splice(0)) await db.close();
}

export type RemoteFixture = Awaited<ReturnType<typeof remoteFixture>>;

/**
 * A device that has synced `setup`'s registry state. The host names no
 * streams: what the device has is what it synced.
 */
export async function syncedStore(
  setup: (remote: RemoteFixture) => Promise<void>,
): Promise<{ local: LocalSync; remote: RemoteFixture; db: SqlDriver }> {
  const keys = {
    namespaceHmac: async () => new Uint8Array(32),
    encrypt: async (_s: string, b: Uint8Array) => b,
    encryptPart: async (_s: string, b: Uint8Array) => b,
    decrypt: async (_s: string, b: Uint8Array) => b,
  };
  const remote = await remoteFixture(keys, CONNECTOR);
  await setup(remote);
  const db = await openLocalDb(openBetterSqlite3(":memory:"), {
    owner: owner.address,
    network: "test",
    deviceId: "lite-records",
  });
  drivers.push(db);
  let op = 0;
  const local = createServerLocalSync(
    {
      db,
      queue: connectionQueue(),
      ownerAddress: owner.address,
      registry: remote.registry,
      blobs: remote.storage,
      keys,
      signer: { signAddData: async () => "0x00" },
      logger: { info() {}, warn() {} },
      now: () => 100,
      newOp: () => String(++op),
    },
    {
      resolveArtifact: () => null,
    },
  );
  await local.apply();
  return { local, remote, db };
}

export async function liteRuntime(local: LocalSync) {
  const authority = createModeAuthority({
    store: createMemoryModeRecordStore(),
  });
  await authority.ready;
  await authority.submitEvidence({ owner: owner.address, state: "on" });
  const accessLogSink = {
    async write() {},
    async read() {
      return { logs: [], total: 0, limit: 50, offset: 0 };
    },
  };
  return createPsLiteRuntime({
    accountModeAuthority: authority,
    active: true,
    storage: createMemoryPsLiteStorage(),
    accessLogReader: accessLogSink,
    accessLogWriter: accessLogSink,
    tokenStore: createMemoryPsLiteTokenStore(),
    saveConfig: async () => {},
    stateCapabilities: { config: "memory" },
    serverOwner: owner.address,
    localSync: async () => local,
    auth: createWeb3SignedPsLiteAuth({
      origin: ORIGIN,
      ownerAddress: owner.address,
    }),
  });
}

export async function liteGet(
  runtime: Awaited<ReturnType<typeof liteRuntime>>,
  pathAndQuery: string,
): Promise<Response> {
  const auth = await buildWeb3SignedHeader({
    wallet: owner,
    aud: ORIGIN,
    method: "GET",
    uri: pathAndQuery.split("?")[0]!,
  });
  return runtime.fetch(
    new Request(`${ORIGIN}${pathAndQuery}`, {
      headers: { Authorization: auth },
    }),
  );
}
