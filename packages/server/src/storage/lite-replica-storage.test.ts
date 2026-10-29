import { afterEach, expect, it } from "vitest";
import {
  LiteReplicaTransferError,
  type LiteReplicaObjectTransfers,
} from "@opendatalabs/personal-server-ts-lite";
import {
  createLiteReplicaStorage,
  reclaimLiteTransientBytes,
} from "../../../lite/src/replication-storage.js";
import { createSqliteLiteReplicaPersistence } from "./lite-replica-sqlite.test-utils.js";

/**
 * The Lite storage adapter's transient bytes when a step stops waiting for
 * its native transfer: the engine rejects the attempt on abort, but the
 * native call settles later.
 */

const opened: { close(): void }[] = [];
afterEach(() => {
  for (const store of opened.splice(0)) store.close();
});

it("cancels a native upload with its step and keeps its bytes from the next step's reclaim", async () => {
  const native = createSqliteLiteReplicaPersistence();
  opened.push(native);
  const persistence = native.port;
  let seen: AbortSignal | undefined;
  let settle!: () => void;
  const settled = new Promise<void>((resolve) => (settle = resolve));
  const read: number[] = [];
  const transfers = {
    async upload(request, call) {
      seen = call.signal;
      // The native side stops after the cancel arrives, reading the bytes
      // it was streaming until then.
      await settled;
      let length = 0;
      for await (const part of persistence.readBytes(request.bytesId))
        length += part.length;
      read.push(length);
      throw new LiteReplicaTransferError("cancelled", "upload cancelled");
    },
  } as Pick<LiteReplicaObjectTransfers, "upload"> as LiteReplicaObjectTransfers;
  const inUse = new Set<string>();
  const storage = createLiteReplicaStorage({
    persistence,
    transfers,
    urlForKey: (key) => `https://storage.test/${key}`,
    inUse,
  });
  const inventory = () =>
    native.db
      .prepare(
        `SELECT (SELECT count(*) FROM lite_bytes) AS bytes,
                (SELECT count(*) FROM pdpp_lite_replica_transient) AS transient`,
      )
      .get();

  const step = new AbortController();
  const upload = storage.upload("k", new Uint8Array(4096).fill(7), step.signal);
  while (!seen) await new Promise((resolve) => setImmediate(resolve));
  // A pause or the step deadline reaches the native transfer.
  step.abort();
  expect(seen.aborted).toBe(true);

  // The next step starts before the native call settles.
  expect(
    await persistence.transaction((tx) => reclaimLiteTransientBytes(tx, inUse)),
  ).toBe(0);
  expect(inventory()).toEqual({ bytes: 1, transient: 1 });

  settle();
  await expect(upload).rejects.toThrow("upload cancelled");
  expect(read).toEqual([4096]);
  // The transfer released its own bytes when it settled.
  expect(inventory()).toEqual({ bytes: 0, transient: 0 });
  expect(inUse.size).toBe(0);
});
