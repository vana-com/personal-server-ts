// SIGKILL of a process between the durable commits of a compaction's outputs:
// seal, output receipt, upload receipt, ready, sent, settle, cleanup. The child
// (log-output-crash.harness.ts) runs the real producer, upload loop and settle
// on a file database and stops before or after the commit; the parent reopens
// the file, checks what survived and finishes the work the way a restart does.
import { expect, it } from "vitest";
import { fork } from "node:child_process";
import { once } from "node:events";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBetterSqlite3 } from "./better-sqlite3-driver.js";
import { migrate } from "../../../core/src/localdb/migrate.js";
import {
  outputProducer,
  sealOutputs,
  sendOutputs,
  uploadOutputs,
  type OutputSet,
} from "../../../core/dist/localdb/log-output.js";
import {
  runtimeAdmission,
  setWorkspaceAuthority,
  type SentObservation,
} from "../../../core/dist/localdb/workspace.js";
import { settleAbandonedOutputs } from "../../../core/dist/localdb/log-output.js";
import { openLocalDb } from "../../../core/dist/localdb/open.js";
import { openLogWorkspace } from "../../../core/dist/localdb/workspace-consumer.js";
import type { LocalSyncDeps } from "../../../core/dist/localdb/deps.js";

const OPERATION = "out-job";
const NAMES = ["a", "b", "c"];
const TARGETS = [
  "output-seal",
  "output-receipt",
  "upload-receipt",
  "ready",
  "sent",
  "settle",
  "cleanup",
] as const;
type Target = (typeof TARGETS)[number];
const LANDED: SentObservation = { kind: "head", version: 2, head: "0xnew" };
const OLD_HEAD: SentObservation = { kind: "head", version: 1, head: "0xold" };
const COMPETING: SentObservation = {
  kind: "head",
  version: 2,
  head: "0xother",
};

async function killedAt(edge: "before" | "after", target: Target) {
  const dir = await mkdtemp(join(tmpdir(), "log-output-crash-")),
    path = join(dir, "db");
  const db = openBetterSqlite3(path);
  await db.query("PRAGMA journal_mode=WAL");
  await db.query("PRAGMA synchronous=NORMAL");
  await migrate(db);
  await db.batch([
    {
      sql: "INSERT INTO db_meta(id,owner,network,device_id,created_at) VALUES(1,'o','test','d',0)",
    },
    {
      sql: "INSERT INTO connections(connection_id,connector,ns,control_state) VALUES('c','test','','active')",
    },
  ]);
  await db.close();
  const child = fork(
    new URL("./log-output-crash.harness.ts", import.meta.url),
    [path, edge, target],
    {
      execArgv: ["--import", "tsx"],
      stdio: ["ignore", "ignore", "pipe", "ipc"],
    },
  );
  let stderr = "";
  child.stderr?.on("data", (chunk) => {
    stderr = (stderr + String(chunk)).slice(-8000);
  });
  const timer = setTimeout(() => child.kill("SIGKILL"), 20000);
  try {
    await Promise.race([
      once(child, "message"),
      once(child, "exit").then(([code, signal]) => {
        throw new Error(
          `child exited before the boundary code=${code} signal=${signal}: ${stderr}`,
        );
      }),
    ]);
    const exit = once(child, "exit");
    await new Promise((resolve) => setTimeout(resolve, 100));
    child.kill("SIGKILL");
    const [code, signal] = await exit;
    expect({ code, signal }).toEqual({ code: null, signal: "SIGKILL" });
  } finally {
    clearTimeout(timer);
    child.kill("SIGKILL");
  }
  return { dir, path, remote: join(dir, "remote.log") };
}

async function remoteLines(file: string) {
  const text = await readFile(file, "utf8").catch(() => "");
  return text
    .split("\n")
    .filter(Boolean)
    .map((l) => l.split(" ") as [string, string]);
}
const count = async (
  db: ReturnType<typeof openBetterSqlite3>,
  table: string,
  where = "",
) =>
  Number(
    (
      await db.query<{ n: number }>(
        `SELECT COUNT(*) AS n FROM ${table} WHERE operation=? ${where}`,
        [OPERATION],
      )
    )[0]!.n,
  );
const phaseOf = async (db: ReturnType<typeof openBetterSqlite3>) =>
  (
    await db.query<{ phase: string }>(
      "SELECT phase FROM workspaces WHERE operation=?",
      [OPERATION],
    )
  )[0]?.phase;

/** What a restarted process does with the workspace it finds, step by step. */
async function resume(
  path: string,
  remote: string,
  observation: SentObservation,
) {
  const { appendFile } = await import("node:fs/promises");
  const { createHash } = await import("node:crypto");
  const db = openBetterSqlite3(path);
  const deps = { db } as unknown as LocalSyncDeps;
  try {
    const [meta] = await db.query<{
      owner: string;
      device_id: string;
      created_at: number;
    }>("SELECT owner,device_id,created_at FROM db_meta WHERE id=1");
    const binding = {
      owner: meta!.owner,
      databaseIncarnation: JSON.stringify([meta!.device_id, meta!.created_at]),
      connection: "c",
      generation: 1,
      keyCheck: "key",
      operation: OPERATION,
      expectedHead: "0xold",
      codecVersion: 1,
    };
    await setWorkspaceAuthority(db, binding);
    for (let step = 0; step < 12; step++) {
      const phase = await phaseOf(db);
      if (phase === "clean" || phase === undefined) return;
      try {
        if (phase === "sent" || phase === "finished" || phase === "aborted") {
          // A restart does not reopen a workspace that is sent or over: it
          // settles it from the registry's head and the log, as the cycle does.
          const registry = {
            read: async () => ({
              found: true,
              version: String(observation.version),
              dataHash: observation.head,
            }),
          };
          await settleAbandonedOutputs(
            { db, registry } as unknown as LocalSyncDeps,
            "c",
            "scope",
            observation === LANDED ? [{ position: 2, dataHash: "0xnew" }] : [],
            new Set(),
          );
          if (observation === OLD_HEAD) return;
          continue;
        }
        const ws = await openLogWorkspace(db, binding);
        const outputs: OutputSet = { ws, count: NAMES.length };
        if (phase === "collect") {
          const lease = await ws.acquire(128 * 1024 * 1024);
          const producer = outputProducer(deps, ws, lease);
          // Encrypting again gives other bytes: staged names keep their first.
          for (const name of NAMES) await producer.put(name, randomBytes(96));
          await ws.transition("collect", "folded");
          await lease.release();
          await runtimeAdmission.finish(db, OPERATION);
        } else if (phase === "folded") await sealOutputs(ws);
        else if (phase === "sealed")
          await uploadOutputs(deps, outputs, async (name, bytes) => {
            await appendFile(
              remote,
              `${name} ${createHash("sha256").update(bytes).digest("hex")}\n`,
            );
          });
        else if (phase === "ready")
          await sendOutputs(outputs, 2, "0xold", "0xnew");
      } catch (error) {
        throw new Error(`resume step ${step} in phase ${phase}: ${error}`);
      }
    }
  } finally {
    await db.close();
  }
}

const EXPECTED_AT_KILL: Record<
  string,
  {
    phase: string;
    outputs: number;
    uploads: number;
    remote: number;
    sent: number;
    sealedValues?: number;
  }
> = {
  "before output-seal": {
    phase: "collect",
    outputs: 0,
    uploads: 0,
    remote: 0,
    sent: 0,
    sealedValues: 0,
  },
  "after output-seal": {
    phase: "collect",
    outputs: 0,
    uploads: 0,
    remote: 0,
    sent: 0,
    sealedValues: 1,
  },
  "before output-receipt": {
    phase: "collect",
    outputs: 0,
    uploads: 0,
    remote: 0,
    sent: 0,
  },
  "after output-receipt": {
    phase: "collect",
    outputs: 1,
    uploads: 0,
    remote: 0,
    sent: 0,
  },
  "before upload-receipt": {
    phase: "sealed",
    outputs: 3,
    uploads: 0,
    remote: 1,
    sent: 0,
  },
  "after upload-receipt": {
    phase: "sealed",
    outputs: 3,
    uploads: 1,
    remote: 1,
    sent: 0,
  },
  "before ready": {
    phase: "sealed",
    outputs: 3,
    uploads: 3,
    remote: 3,
    sent: 0,
  },
  "after ready": { phase: "ready", outputs: 3, uploads: 3, remote: 3, sent: 0 },
  "before sent": { phase: "ready", outputs: 3, uploads: 3, remote: 3, sent: 0 },
  "after sent": { phase: "sent", outputs: 3, uploads: 3, remote: 3, sent: 1 },
  "before settle": {
    phase: "sent",
    outputs: 3,
    uploads: 3,
    remote: 3,
    sent: 1,
  },
  "after settle": {
    phase: "finished",
    outputs: 3,
    uploads: 3,
    remote: 3,
    sent: 1,
  },
  "before cleanup": {
    phase: "finished",
    outputs: 3,
    uploads: 3,
    remote: 3,
    sent: 1,
  },
  "after cleanup": {
    phase: "finished",
    outputs: 3,
    uploads: 3,
    remote: 3,
    sent: 0,
  },
};

it.each(
  TARGETS.flatMap((target) =>
    (["before", "after"] as const).map((edge) => ({ target, edge })),
  ),
)(
  "SIGKILL $edge $target: what survived is a complete prefix, and a restart ends in clean with each object put from its one sealed value",
  async ({ edge, target }) => {
    const { dir, path, remote } = await killedAt(edge, target);
    try {
      const db = openBetterSqlite3(path);
      const want = EXPECTED_AT_KILL[`${edge} ${target}`]!;
      expect({
        phase: await phaseOf(db),
        outputs: await count(db, "workspace_cells", "AND relation='outputs'"),
        uploads: await count(db, "workspace_cells", "AND relation='uploads'"),
        remote: (await remoteLines(remote)).length,
        sent: await count(db, "workspace_sent"),
      }).toEqual({
        phase: want.phase,
        outputs: want.outputs,
        uploads: want.uploads,
        remote: want.remote,
        sent: want.sent,
      });
      if (want.sealedValues !== undefined)
        expect(await count(db, "body_values", "AND sealed=1")).toBe(
          want.sealedValues,
        );
      await db.close();
      // The registry took the request, wherever the process stopped.
      await resume(path, remote, LANDED);
      const after = openBetterSqlite3(path);
      try {
        expect(await phaseOf(after)).toBe("clean");
        for (const table of [
          "workspace_cells",
          "workspace_sent",
          "body_values",
          "workspace_receipts",
        ])
          expect(await count(after, table), table).toBe(0);
      } finally {
        await after.close();
      }
      const lines = await remoteLines(remote);
      // Every object reached the store, and a name put twice (a receipt lost)
      // was put from the same sealed bytes: never encrypted again.
      expect(new Set(lines.map(([name]) => name))).toEqual(new Set(NAMES));
      for (const name of NAMES) {
        const hashes = lines.filter(([n]) => n === name).map(([, h]) => h);
        expect(new Set(hashes).size, name).toBe(1);
        expect(hashes.length, name).toBeLessThanOrEqual(2);
      }
      expect(lines.length).toBe(
        NAMES.length +
          (edge === "before" && target === "upload-receipt" ? 1 : 0),
      );
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
  60000,
);

it("an old registry head is no verdict: a restart keeps the sent workspace and its objects; a competing head ends it; the candidate's own head finishes it, once", async () => {
  const { dir, path, remote } = await killedAt("after", "sent");
  try {
    await resume(path, remote, OLD_HEAD);
    let db = openBetterSqlite3(path);
    expect(await phaseOf(db)).toBe("sent");
    expect(await count(db, "workspace_cells")).toBeGreaterThan(0);
    expect(await count(db, "workspace_sent")).toBe(1);
    await db.close();
    // The same reading again changes nothing, however often it is made.
    await resume(path, remote, OLD_HEAD);
    db = openBetterSqlite3(path);
    expect(await phaseOf(db)).toBe("sent");
    await db.close();
    await resume(path, remote, COMPETING);
    db = openBetterSqlite3(path);
    expect(await phaseOf(db)).toBe("clean");
    expect(await count(db, "workspace_cells")).toBe(0);
    await db.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);

it("a candidate settled finished is not settled again, and a later competing reading cannot revive or abort it", async () => {
  const { dir, path, remote } = await killedAt("after", "settle");
  try {
    let db = openBetterSqlite3(path);
    expect(await phaseOf(db)).toBe("finished");
    await db.close();
    // A competing reading after acceptance (the log moved on) is not an abort:
    // a finished workspace is only paged away.
    await resume(path, remote, COMPETING);
    db = openBetterSqlite3(path);
    expect(await phaseOf(db)).toBe("clean");
    await db.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);

const OWNER = { owner: "o", network: "test", deviceId: "d" };
const rowsOf = async (db: ReturnType<typeof openBetterSqlite3>, sql: string) =>
  Number(
    (await db.query<{ n: number }>(`SELECT COUNT(*) AS n FROM ${sql}`))[0]!.n,
  );

it.each([
  ["after", "output-receipt", "collect"],
  ["after", "upload-receipt", "sealed"],
  ["after", "ready", "ready"],
] as const)(
  "a restart reclaims what a dead process left: after SIGKILL %s %s (%s), opening the database pages the workspace and its sealed values away",
  async (edge, target, phase) => {
    const { dir, path } = await killedAt(edge, target);
    try {
      let db = openBetterSqlite3(path);
      expect(await phaseOf(db)).toBe(phase);
      expect(await rowsOf(db, "body_values")).toBeGreaterThan(0);
      await db.close();
      // One process owns the file (the driver's process lock), so a workspace
      // that is not over belongs to a process that is gone.
      db = openBetterSqlite3(path);
      await openLocalDb(db, OWNER);
      for (const table of [
        "workspace_cells",
        "workspace_stage",
        "workspace_receipts",
        "workspace_attempts",
        "workspace_sent",
        "body_values",
        "body_value_chunks",
        "workspace_jobs",
      ])
        expect(await rowsOf(db, table), table).toBe(0);
      expect(await phaseOf(db)).toBe("clean");
      await db.close();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  },
  60000,
);

it("a restart keeps a sent workspace and its objects: only the registry's head ends it", async () => {
  const { dir, path } = await killedAt("after", "sent");
  try {
    const db = openBetterSqlite3(path);
    await openLocalDb(db, OWNER);
    expect(await phaseOf(db)).toBe("sent");
    expect(await rowsOf(db, "workspace_sent")).toBe(1);
    expect(await rowsOf(db, "workspace_cells")).toBeGreaterThan(0);
    expect(await rowsOf(db, "body_values")).toBeGreaterThan(0);
    await db.close();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}, 60000);
