// The prepass of a progressive first load reads every segment that removes a
// key before the first batch applies, so a key a later segment deletes is never
// shown. It must not cost a second download of those segments when their
// batches come, and it must not start every download at once on a long tail.
import { afterEach, expect, it } from "vitest";
import { applyConnection } from "../../../core/src/localdb/index.js";
import { PARTS_IN_FLIGHT } from "../../../core/src/stream-sync/storage-retry.js";
import {
  CONNECTION_ID,
  CONNECTOR,
  closeWorldDrivers,
  sName,
  world,
} from "./log-world.test-utils.js";

afterEach(closeWorldDrivers);

const STREAM = sName(0);
const SEGMENT = /\/s-[0-9a-f]+$/;
const REMOVING = PARTS_IN_FLIGHT + 8;
const PREPASS_WAIT_MS = 3_000;

function readiness() {
  let signal!: () => void;
  const ready = new Promise<void>((resolve) => {
    signal = resolve;
  });
  return { ready, signal };
}

async function beforeDeadline<T>(work: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () =>
            reject(
              new Error(
                `Timed out after ${PREPASS_WAIT_MS} ms waiting for ${label}`,
              ),
            ),
          PREPASS_WAIT_MS,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function waitForPrepass(
  ready: Promise<void>,
  applying: Promise<unknown>,
  label: string,
): Promise<void> {
  return beforeDeadline(
    Promise.race([
      ready,
      applying.then(
        () => {
          throw new Error(`Restore settled before ${label}`);
        },
        (cause: unknown) => {
          throw new Error(`Restore failed before ${label}`, { cause });
        },
      ),
    ]),
    label,
  );
}

async function deletionHeavyLog(w: Awaited<ReturnType<typeof world>>) {
  const a = await w.device("a");
  const ids = Array.from({ length: REMOVING }, (_, i) => `k${i}`);
  await a.run(
    "r0",
    ids.map((id) => ({ stream: STREAM, id })),
    { observedAt: 1000 },
  );
  await a.cycle();
  for (const [i, id] of ids.entries()) {
    await a.run("d" + i, [{ stream: STREAM, id, remove: true }], {
      full: false,
      covered: [STREAM],
      observedAt: 1100 + i,
    });
    await a.cycle();
  }
}

it("reads each removing segment from storage once, and not all of them at once", async () => {
  const w = await world({ streams: 1 });
  await deletionHeavyLog(w);

  let waiting = 0;
  let widest = 0;
  const windowFull = readiness();
  let open = false;
  let head: string | undefined;
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const b = await w.device("b", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    beforeGet: async (key) => {
      if (open || !SEGMENT.test(key)) return;
      // The first segment read is the head, which the prepass waits for.
      head ??= key;
      if (key === head) return;
      widest = Math.max(widest, ++waiting);
      if (waiting >= PARTS_IN_FLIGHT) windowFull.signal();
      try {
        await gate;
      } finally {
        waiting--;
      }
    },
  });
  await b.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  const applying = applyConnection(b.deps, CONNECTION_ID);
  let started: number;
  try {
    await waitForPrepass(
      windowFull.ready,
      applying,
      "the full download window",
    );
    // Give an incorrectly larger window a chance to start another download.
    const turns = async () => {
      for (let turn = 0; turn < 10; turn++)
        await new Promise((resolve) => setTimeout(resolve));
    };
    await waitForPrepass(turns(), applying, "the in-flight concurrency check");
    started = widest;
  } finally {
    open = true;
    release();
  }
  await beforeDeadline(applying, "restore completion");

  expect(started).toBe(PARTS_IN_FLIGHT);
  const perSegment = new Map<string, number>();
  for (const key of b.gets)
    if (SEGMENT.test(key)) perSegment.set(key, (perSegment.get(key) ?? 0) + 1);
  expect([...perSegment.values()].filter((n) => n > 1)).toEqual([]);
  // The ciphertext kept on disk for the batches is gone when the load ends.
  const [kept] = await b.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM log_spool",
  );
  expect(kept!.n).toBe(0);
});

it("ends the prepass downloads before it discards the spool when the load fails", async () => {
  const w = await world({ streams: 1 });
  await deletionHeavyLog(w);

  let waiting = 0;
  const windowFull = readiness();
  const failureInjected = readiness();
  const spoolDiscarded = readiness();
  let head: string | undefined;
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  const b = await w.device("b", {
    progressiveFirstLoad: true,
    keyedFirstLoad: false,
    beforeGet: async (key) => {
      if (!SEGMENT.test(key)) return;
      head ??= key;
      if (key === head) return;
      waiting++;
      if (waiting >= PARTS_IN_FLIGHT) windowFull.signal();
      try {
        await gate;
      } finally {
        waiting--;
      }
    },
  });
  await b.db.batch([
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,generation,control_state,control_version) VALUES (?,?,'',1,'active',1)",
      params: [CONNECTION_ID, CONNECTOR],
    },
  ]);
  // The load's first write after the prepass starts fails, once every worker
  // of the prepass has a download in flight.
  const batch = b.db.batch.bind(b.db);
  let failedAfterGets = -1;
  let inFlightAtDiscard: number | undefined;
  b.db.batch = (async (statements: Parameters<typeof batch>[0]) => {
    if (
      failedAfterGets < 0 &&
      statements.some((s) => /stream_partial/.test(s.sql))
    ) {
      await waitForPrepass(
        windowFull.ready,
        applying,
        "failed restore's download window",
      );
      failedAfterGets = b.gets.length;
      failureInjected.signal();
      throw new Error("setup_failed");
    }
    const discarding =
      failedAfterGets >= 0 &&
      statements.some((s) => /\bDELETE\s+FROM\s+log_spool\b/i.test(s.sql));
    if (discarding) inFlightAtDiscard = waiting;
    const result = await batch(statements);
    if (discarding) spoolDiscarded.signal();
    return result;
  }) as typeof b.db.batch;

  // Start on the next microtask: the batch wrapper can then race applying.
  const applying = Promise.resolve()
    .then(() => applyConnection(b.deps, CONNECTION_ID))
    .then(
      () => "applied",
      (error: Error) => error.message,
    );
  try {
    await waitForPrepass(
      failureInjected.ready,
      applying,
      "the injected setup failure",
    );
  } finally {
    release();
  }
  await waitForPrepass(spoolDiscarded.ready, applying, "the spool discard");
  expect(await beforeDeadline(applying, "failed restore completion")).toBe(
    "setup_failed",
  );
  expect(inFlightAtDiscard).toBe(0);
  expect(b.gets.length).toBe(failedAfterGets);
  const [kept] = await b.db.query<{ n: number }>(
    "SELECT COUNT(*) AS n FROM log_spool",
  );
  expect(kept!.n).toBe(0);
});
