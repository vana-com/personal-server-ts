/**
 * Cursor fences (oracle design §4). Every case takes real continuation
 * tokens from a first page, asserts each token exists, applies one event,
 * and resumes. Events that change what a reader may see on the connection
 * expire every token; events that change nothing visible keep every token
 * valid, and a kept token continues after the first page.
 *
 * Node: owner and grant `listRecords` and `changesSince`, one row per page.
 * Lite: owner and grant `readConnectionPage` over more than one scan page.
 */
import { afterEach, describe, expect, it } from "vitest";
import type { ReplicaOperation } from "@opendatalabs/personal-server-ts-core/replication/envelope";
import { CursorExpiredError } from "@opendatalabs/personal-server-ts-core/storage/pdpp-records";
import { BINDINGS } from "./generator.test-utils.js";
import {
  liteDriver,
  liteMemoryPersistence,
  liteSqlitePersistence,
  METHOD,
  nodeDriver,
  OWNER,
  SOURCE,
  type LiteDriver,
  type NodeDriver,
  type ReplicaPortDriver,
} from "./ports.test-utils.js";

const ROWS = 120; // more than one 100-entry Lite scan page
const base = (connection: string, generation = 1) => ({
  owner: OWNER,
  sourceId: SOURCE,
  connectionId: connection,
  methodId: METHOD,
  generation,
});
const rev = (counter: number, operationId: string) => ({
  counter,
  writerId: "w-remote",
  operationId,
});
const key = (i: number) => `k${String(i).padStart(3, "0")}`;
const put = (
  connection: string,
  i: number,
  text: string,
  counter: number,
  generation = 1,
) =>
  ({
    ...base(connection, generation),
    kind: "upsert",
    declaration: BINDINGS.m,
    recordKey: key(i),
    emittedAt: "2026-10-20T00:00:00Z",
    data: { id: key(i), text },
    blobs: [],
    revision: rev(counter, `put-${connection}-${generation}-${i}-${counter}`),
  }) as const satisfies ReplicaOperation;
const seed: ReplicaOperation[] = [
  {
    ...base("c1"),
    generation: 1,
    kind: "connection-register",
    revision: rev(1, "register-c1"),
  },
  {
    ...base("c2"),
    generation: 1,
    kind: "connection-register",
    revision: rev(1, "register-c2"),
  },
  ...Array.from({ length: ROWS }, (_, i) => put("c1", i, "seed", 2)),
  put("c2", 0, "seed", 2),
];

interface Fence {
  label: string;
  /** Resolves to the first record key of the resumed page; rejects when expired. */
  resume(): Promise<string | undefined>;
  first: string;
}
interface Port<D extends ReplicaPortDriver> {
  open(): Promise<D>;
  fences(driver: D): Promise<Fence[]>;
  expired(error: unknown): boolean;
}

const nodePort: Port<NodeDriver> = {
  open: async () =>
    nodeDriver({
      durable: true,
      declarations: [BINDINGS.m, BINDINGS.a],
      provisioned: ["c1", "c2"],
    }),
  async fences(driver) {
    const out: Fence[] = [];
    for (const reader of ["owner", "grant"] as const) {
      const read = () => driver.receiver.readStore({ reader });
      const list = { instanceIds: ["c1"], limit: 1, order: "asc" as const };
      const listed = read().listRecords("messages", list);
      const changes = { instanceIds: ["c1"], limit: 1 };
      const changed = read().changesSince("messages", changes);
      out.push(
        {
          label: `${reader} listRecords`,
          first: listed.data[0].recordKey,
          token: listed.nextCursor,
          resume: async () =>
            read().listRecords("messages", {
              ...list,
              cursor: listed.nextCursor,
            }).data[0]?.recordKey,
        } as Fence & { token?: string },
        {
          label: `${reader} changesSince`,
          first: changed.data[0].recordKey,
          token: changed.nextCursor,
          resume: async () =>
            read().changesSince("messages", {
              ...changes,
              cursor: changed.nextCursor,
            }).data[0]?.recordKey,
        } as Fence & { token?: string },
      );
    }
    for (const fence of out as (Fence & { token?: string })[])
      expect(fence.token, fence.label).toEqual(expect.any(String));
    return out;
  },
  expired: (error) => error instanceof CursorExpiredError,
};
const litePort = (sqlite: boolean): Port<LiteDriver> => ({
  open: () =>
    liteDriver({
      name: sqlite ? "lite-sqlite" : "lite-memory",
      persistence: sqlite ? liteSqlitePersistence() : liteMemoryPersistence(),
      declarations: [BINDINGS.m, BINDINGS.a],
      provisioned: ["c1", "c2"],
    }),
  async fences(driver) {
    const out: Fence[] = [];
    for (const reader of ["owner", "grant"] as const) {
      const page = await driver.store.readConnectionPage("c1", undefined, {
        reader,
      });
      expect(page.after, reader).toEqual(expect.any(String));
      expect(page.rows.length, reader).toBeLessThan(ROWS);
      out.push({
        label: `${reader} readConnectionPage`,
        first: page.rows[0].recordKey,
        resume: async () =>
          (await driver.store.readConnectionPage("c1", page.after, { reader }))
            .rows[0]?.recordKey,
      });
    }
    return out;
  },
  expired: (error) =>
    error instanceof Error &&
    error.message === "canonical connection cursor expired",
});

interface Event {
  name: string;
  expires: boolean;
  run(driver: ReplicaPortDriver): Promise<unknown>;
}
const events: Event[] = [
  {
    name: "terminal quarantine",
    expires: true,
    run: (d) => d.quarantineConnection("c1"),
  },
  {
    name: "key conflict",
    expires: true,
    // The same revision id with different content on one key.
    run: (d) =>
      d.importBatch(
        "conflict",
        [{ ...put("c1", 5, "seed", 2), data: { id: key(5), text: "forked" } }],
        [],
      ),
  },
  {
    name: "valid reset",
    expires: true,
    run: (d) =>
      d.importBatch(
        "reset",
        [
          {
            ...base("c1", 2),
            kind: "connection-reset",
            previousGeneration: 1,
            revision: rev(50, "reset-c1"),
          },
        ],
        [],
      ),
  },
  { name: "unchanged retry", expires: false, run: (d) => d.retry() },
  {
    name: "unrelated connection",
    expires: false,
    run: (d) => d.importBatch("unrelated", [put("c2", 1, "other", 3)], []),
  },
  { name: "reopen", expires: false, run: (d) => d.reopen() },
  {
    name: "duplicate evidence",
    expires: false,
    run: (d) => d.importBatch("seed", seed, []),
  },
  {
    name: "duplicate evidence after reopen",
    expires: false,
    run: async (d) => {
      await d.reopen();
      await d.importBatch("seed", seed, []);
    },
  },
];

const opened: ReplicaPortDriver[] = [];
afterEach(() => {
  for (const driver of opened.splice(0)) driver.close();
});

function fenceSuite<D extends ReplicaPortDriver>(name: string, port: Port<D>) {
  describe(`${name} cursor fences`, () => {
    for (const event of events) {
      it(`${event.name} ${event.expires ? "expires" : "keeps"} tokens`, async () => {
        const driver = await port.open();
        opened.push(driver);
        await driver.importBatch("seed", seed, []);
        const fences = await port.fences(driver);
        expect(fences.length).toBeGreaterThan(1);
        await event.run(driver);
        for (const fence of fences) {
          const resumed = await fence.resume().then(
            (first) => ({ first }),
            (error: unknown) => ({ error }),
          );
          if (event.expires) {
            expect(
              "error" in resumed && port.expired(resumed.error),
              fence.label,
            ).toBe(true);
          } else {
            if ("error" in resumed)
              throw new Error(`${fence.label}: ${String(resumed.error)}`);
            expect(resumed.first, fence.label).toEqual(expect.any(String));
            expect(resumed.first, fence.label).not.toBe(fence.first);
          }
        }
      });
    }
  });
}

fenceSuite("node", nodePort);
fenceSuite("lite-memory", litePort(false));
fenceSuite("lite-sqlite", litePort(true));
