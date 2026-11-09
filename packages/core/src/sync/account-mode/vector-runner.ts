/**
 * Runs the shared JSON vectors (`vectors.json`) against the real module: the
 * authority, a record store with fault hooks, and the reducer.
 *
 * The vector format is host-neutral JSON. A host adapter (Rust, Dart, Web) runs
 * the same files: it turns each `accountResult` into the evidence it would send
 * and feeds the real module, then compares the decisions.
 *
 * Event ops
 *   fetchStart       the host starts asking the Account (clock, requestId)
 *   accountResult    the host's answer for a fetch (rawFixture + evidence)
 *   admit / read     ask for the mode
 *   commit           a durable write asks to commit (sink legacy|stream|importSeed)
 *   clock            move time forward
 *   pauseDurableSave / completeDurableSave / failDurableSave   record store faults
 *   importDone       the host finished importing the owner's legacy data
 *   quarantineRecord the store cannot read the owner's record and sets it
 *                    aside, keeping a tombstone (history unknown) in its place
 *   crash            restart every runtime from the durable records
 *                    (clockTrusted:false, discardPausedSaves:true)
 *   wipeDataDb       the legacy data store is emptied; mode records are not
 * Any event may carry `runtime` (default "R1") and `clock`.
 *
 * Expectations are checked right after the event named by `after`:
 *   decision/code/status/importRequired  against that event's decision, or the
 *                                        event named by `of`
 *   httpStatus                           the status a route answers with for that
 *                                        decision: a refusal's status, else 200
 *   legacyMutations                      legacy writes allowed so far
 *   durable                              {alias: null | {field: value}}; a boolean
 *                                        field the store leaves out is false
 */

import {
  createModeAuthorityWithImporter,
  type ImportSeedCapability,
  type ModeAuthority,
} from "./authority.js";
import { createMemoryModeRecordStore } from "./memory-record-store.js";
import {
  OFF_TTL_MS,
  type ModeDecision,
  type ModeState,
} from "./mode-machine.js";

export interface VectorClock {
  boot?: string;
  monoMs: number;
  wallMs?: number;
}

export interface VectorEvent {
  id: string;
  op: string;
  runtime?: string;
  clock?: VectorClock;
  owner?: string;
  authOwner?: string;
  requestId?: string;
  rawFixture?: string;
  evidence?: { owner: string; state: ModeState };
  operationId?: string;
  sink?: "legacy" | "stream" | "importSeed";
  fail?: boolean;
  clockTrusted?: boolean;
  discardPausedSaves?: boolean;
}

export interface VectorExpectation {
  after: string;
  of?: string;
  decision?: "streams" | "legacy" | "refuse";
  code?: string;
  status?: number;
  httpStatus?: number;
  importRequired?: boolean;
  legacyMutations?: number;
  durable?: Record<string, null | Record<string, unknown>>;
}

export interface Vector {
  version: 1;
  id: string;
  description?: string;
  policy: { offTtlMs: number };
  owners: Record<string, string>;
  initial: { legacyFiles?: string[]; runtimes?: string[] };
  events: VectorEvent[];
  expect: VectorExpectation[];
}

/** What a raw Account response looks like to the module. */
const RAW_STATUS: Record<string, number | null> = {
  "explicit-off": 200,
  "explicit-on": 200,
  "http-500": 500,
  "http-401": 401,
  "http-503": 503,
  timeout: null,
  malformed: 200,
};

const WALL_BASE = 1_700_000_000_000;

const NO_SEED = {
  ok: false,
  decision: { kind: "refuse", code: "ACCOUNT_MODE_UNKNOWN", status: 503 },
} as const;

function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

async function settleSome(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await flush();
}

export async function runVector(vector: Vector): Promise<string[]> {
  const failures: string[] = [];
  const fail = (message: string) => failures.push(`${vector.id}: ${message}`);

  if (vector.version !== 1) fail(`unsupported version ${vector.version}`);
  if (vector.policy.offTtlMs !== OFF_TTL_MS) {
    fail(`vector policy offTtlMs ${vector.policy.offTtlMs} != ${OFF_TTL_MS}`);
  }
  const ids = new Set<string>();
  for (const event of vector.events) {
    if (ids.has(event.id)) fail(`duplicate event id ${event.id}`);
    ids.add(event.id);
  }
  for (const exp of vector.expect) {
    if (!ids.has(exp.after))
      fail(`expectation after unknown event ${exp.after}`);
    if (exp.of !== undefined && !ids.has(exp.of)) {
      fail(`expectation of unknown event ${exp.of}`);
    }
  }
  if (failures.length > 0) return failures;

  const address = (alias: string): string => {
    if (alias === "") return "";
    return (vector.owners[alias] ?? alias).toLowerCase();
  };

  let mono = 0;
  let wall = WALL_BASE;
  let boots = 0;
  const store = createMemoryModeRecordStore();
  const legacyFiles = new Set(
    (vector.initial.legacyFiles ?? []).map((alias) => address(alias)),
  );
  let legacyMutations = 0;
  const clock = { mono: () => mono, wall: () => wall };

  const seeds = new Map<string, ImportSeedCapability>();
  const makeRuntime = (name: string, clockTrusted: boolean): ModeAuthority => {
    boots += 1;
    const { authority, importSeed } = createModeAuthorityWithImporter({
      store,
      bootId: `boot-${boots}`,
      clockTrusted,
      clock,
      hasLegacyFiles: (owner) => legacyFiles.has(owner),
    });
    seeds.set(name, importSeed);
    return authority;
  };

  const runtimeNames = vector.initial.runtimes ?? ["R1"];
  let runtimes = new Map<string, ModeAuthority>();
  const boot = async (clockTrusted: boolean) => {
    runtimes = new Map(
      runtimeNames.map((name) => [name, makeRuntime(name, clockTrusted)]),
    );
    // A runtime the store refuses never becomes ready; that is a result.
    await Promise.all(
      [...runtimes.values()].map((r) => r.ready.catch(() => undefined)),
    );
  };
  await boot(true);

  const requests = new Map<string, { wall: number }>();
  const decisions = new Map<string, ModeDecision | "pending">();
  const track = async (id: string, promise: Promise<ModeDecision>) => {
    decisions.set(id, "pending");
    void promise.then(
      (decision) => decisions.set(id, decision),
      (error) => fail(`event ${id} threw: ${String(error)}`),
    );
    await settleSome();
  };

  for (const event of vector.events) {
    if (event.clock) {
      mono = event.clock.monoMs;
      wall = event.clock.wallMs ?? WALL_BASE + event.clock.monoMs;
    }
    const runtime = runtimes.get(event.runtime ?? runtimeNames[0]);
    if (!runtime) {
      fail(`event ${event.id}: unknown runtime ${event.runtime}`);
      continue;
    }

    switch (event.op) {
      case "fetchStart":
        requests.set(event.requestId ?? "", { wall });
        break;
      case "clock":
        break;
      case "accountResult": {
        const fixture = event.rawFixture ?? "";
        if (!(fixture in RAW_STATUS)) {
          fail(`event ${event.id}: unknown rawFixture ${fixture}`);
          break;
        }
        const started = requests.get(event.requestId ?? "");
        await track(
          event.id,
          runtime.submitEvidence({
            owner: address(event.evidence?.owner ?? ""),
            authOwner: address(event.authOwner ?? ""),
            state: event.evidence?.state ?? "unknown",
            fetchStartedAt: started ? started.wall : Number.NaN,
            rawStatus: RAW_STATUS[fixture],
          }),
        );
        break;
      }
      case "admit":
        decisions.set(
          event.id,
          runtime.admit(address(event.owner ?? ""), event.operationId ?? ""),
        );
        break;
      case "read":
        decisions.set(event.id, runtime.read(address(event.owner ?? "")));
        break;
      case "commit": {
        const owner = address(event.owner ?? "");
        const operationId = event.operationId ?? "";
        if (event.sink === "stream" || event.sink === "importSeed") {
          const seal = (
            event.sink === "stream"
              ? runtime.commitStream(owner, operationId, () => undefined)
              : (seeds
                  .get(event.runtime ?? runtimeNames[0])
                  ?.commitImportSeed(owner, operationId, () => undefined) ??
                Promise.resolve(NO_SEED))
          ).then((result): ModeDecision =>
            result.ok
              ? { kind: "streams", importRequired: result.importRequired }
              : result.decision,
          );
          await track(event.id, seal);
          break;
        }
        await track(
          event.id,
          runtime
            .commitLegacy(owner, operationId, () => {
              legacyMutations += 1;
              // A legacy write leaves legacy data behind for a later import.
              legacyFiles.add(owner);
            })
            .then((result): ModeDecision =>
              result.ok ? { kind: "legacy" } : result.decision,
            ),
        );
        break;
      }
      case "pauseDurableSave":
        store.pauseSaves();
        break;
      case "completeDurableSave":
        store.releaseSaves();
        await settleSome();
        break;
      case "failDurableSave":
        store.failSaves(event.fail !== false);
        break;
      case "importDone":
        await track(event.id, runtime.importDone(address(event.owner ?? "")));
        break;
      case "crash":
        if (event.discardPausedSaves) store.abandonHeldSaves();
        // Every runtime dies, and with it the ownership of the store.
        store.dropLease();
        await boot(event.clockTrusted !== false);
        break;
      case "quarantineRecord":
        store.quarantine(address(event.owner ?? ""));
        break;
      case "wipeDataDb":
        legacyFiles.clear();
        break;
      default:
        fail(`event ${event.id}: unknown op ${event.op}`);
    }

    for (const exp of vector.expect.filter((e) => e.after === event.id)) {
      checkExpectation(exp);
    }
  }

  function checkExpectation(exp: VectorExpectation): void {
    const label = `after ${exp.after}`;
    if (
      exp.decision !== undefined ||
      exp.code !== undefined ||
      exp.status !== undefined ||
      exp.httpStatus !== undefined ||
      exp.importRequired !== undefined
    ) {
      const got = decisions.get(exp.of ?? exp.after);
      if (got === undefined || got === "pending") {
        fail(
          `${label}: no decision (${got === "pending" ? "still pending" : "none"})`,
        );
      } else {
        if (exp.decision !== undefined && got.kind !== exp.decision) {
          fail(`${label}: decision ${got.kind}, expected ${exp.decision}`);
        }
        if (exp.code !== undefined) {
          const code = got.kind === "refuse" ? got.code : undefined;
          if (code !== exp.code)
            fail(`${label}: code ${code}, expected ${exp.code}`);
        }
        if (exp.status !== undefined) {
          const status = got.kind === "refuse" ? got.status : undefined;
          if (status !== exp.status) {
            fail(`${label}: status ${status}, expected ${exp.status}`);
          }
        }
        if (exp.httpStatus !== undefined) {
          const http = got.kind === "refuse" ? got.status : 200;
          if (http !== exp.httpStatus) {
            fail(`${label}: httpStatus ${http}, expected ${exp.httpStatus}`);
          }
        }
        if (exp.importRequired !== undefined) {
          const got2 = got.kind === "streams" ? got.importRequired : undefined;
          if (got2 !== exp.importRequired) {
            fail(
              `${label}: importRequired ${got2}, expected ${exp.importRequired}`,
            );
          }
        }
      }
    }
    if (
      exp.legacyMutations !== undefined &&
      legacyMutations !== exp.legacyMutations
    ) {
      fail(
        `${label}: legacyMutations ${legacyMutations}, expected ${exp.legacyMutations}`,
      );
    }
    for (const [alias, want] of Object.entries(exp.durable ?? {})) {
      const record = store.durable.get(address(alias));
      if (want === null) {
        if (record !== undefined) fail(`${label}: durable ${alias} present`);
        continue;
      }
      if (record === undefined) {
        fail(`${label}: durable ${alias} missing`);
        continue;
      }
      for (const [field, value] of Object.entries(want)) {
        // A boolean the store leaves out (historyUnknown) is false.
        const fields = record as unknown as Record<string, unknown>;
        const got =
          field in fields
            ? fields[field]
            : typeof value === "boolean"
              ? false
              : undefined;
        if (got !== value) {
          fail(`${label}: durable ${alias}.${field} is not ${String(value)}`);
        }
      }
    }
  }

  return failures;
}
