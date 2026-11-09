import { readFileSync } from "node:fs";
import { Ajv2020 } from "ajv2020/dist/2020.js";
import { describe, expect, it, vi } from "vitest";
import {
  OFF_TTL_MS,
  createModeRecord,
  fromDurable,
  reduceAccountMode,
  toDurable,
  type AccountModeRecord,
  type ModeClock,
  type ModeDecision,
  type ModeEvent,
} from "./mode-machine.js";
import { runVector, type Vector } from "./vector-runner.js";

const clock: ModeClock = { nowMono: 100, nowWall: 1000, bootId: "boot-1" };
const evidence = (
  state: "on" | "off" | "unknown",
  extra: Partial<Extract<ModeEvent, { type: "evidence" }>> = {},
): ModeEvent => ({
  type: "evidence",
  owner: "A",
  authOwner: "A",
  state,
  fetchStartMono: 100,
  rawStatus: 200,
  ...extra,
});
const read: ModeEvent = { type: "read", owner: "A" };
const commit: ModeEvent = {
  type: "commit",
  owner: "A",
  operationId: "same-operation",
  sink: "legacy",
};
const unknown: ModeDecision = {
  kind: "refuse",
  code: "ACCOUNT_MODE_UNKNOWN",
  status: 503,
};

const vectors: Vector[] = JSON.parse(
  readFileSync(new URL("./vectors.json", import.meta.url), "utf8"),
);

describe("the shared vectors, run through the module", () => {
  it("has the vectors every host runs", () => {
    expect(vectors.length).toBeGreaterThanOrEqual(18);
    expect(new Set(vectors.map((v) => v.id)).size).toBe(vectors.length);
  });
  for (const vector of vectors) {
    it(vector.id, async () => {
      expect(await runVector(vector)).toEqual([]);
    });
  }
});

/** Apply an event and, when the policy asks for a save, report it as done. */
function accept(
  record: AccountModeRecord | null,
  event: ModeEvent,
  at: ModeClock = clock,
): AccountModeRecord | null {
  const result = reduceAccountMode(record, event, at);
  if (!result.persist) return result.record;
  return reduceAccountMode(
    result.record,
    { type: "saveComplete", owner: result.record?.owner ?? "" },
    at,
  ).record;
}

describe("the vectors file other hosts copy", () => {
  const read = (name: string) =>
    JSON.parse(readFileSync(new URL(name, import.meta.url), "utf8"));
  const schema = read("./vectors.schema.json");

  it("is valid against its JSON schema", () => {
    const validate = new Ajv2020({
      allErrors: true,
      strict: true,
      strictRequired: false,
    }).compile(schema);
    expect(
      validate(read("./vectors.json")),
      JSON.stringify(validate.errors),
    ).toBe(true);
  });

  it("is checked by a schema that rejects what a host cannot run", () => {
    const validate = new Ajv2020({
      strict: true,
      strictRequired: false,
    }).compile(schema);
    const [first] = vectors;
    for (const broken of [
      { ...first, version: 2 },
      { ...first, extra: true },
      { ...first, policy: { offTtlMs: 1 } },
      { ...first, events: [{ id: "x", op: "teleport" }] },
      { ...first, events: [{ id: "x", op: "commit", owner: "A" }] },
      { ...first, expect: [{ after: "x", decision: "maybe" }] },
    ]) {
      expect(validate([broken])).toBe(false);
    }
  });

  it("names only owners it defines", () => {
    for (const vector of vectors) {
      const known = new Set(Object.keys(vector.owners));
      const used = [
        ...(vector.initial.legacyFiles ?? []),
        ...vector.events.flatMap((e) =>
          [e.owner, e.authOwner, e.evidence?.owner].filter(
            (alias): alias is string => alias !== undefined && alias !== "",
          ),
        ),
        ...vector.expect.flatMap((e) => Object.keys(e.durable ?? {})),
      ];
      for (const alias of used) {
        expect(known.has(alias), `${vector.id}: ${alias}`).toBe(true);
      }
    }
  });

  it("is built into the package and exported under a stable path", () => {
    const pkg = read("../../../package.json");
    expect(pkg.files).toContain("dist");
    expect(pkg.exports["./account-mode/vectors.json"]).toBe(
      "./dist/sync/account-mode/vectors.json",
    );
    expect(pkg.exports["./account-mode/vectors.schema.json"]).toBe(
      "./dist/sync/account-mode/vectors.schema.json",
    );
    const tsconfig = readFileSync(
      new URL("../../../tsconfig.json", import.meta.url),
      "utf8",
    );
    expect(tsconfig).toContain("src/sync/account-mode/vectors.json");
    expect(tsconfig).toContain("src/sync/account-mode/vectors.schema.json");
  });
});

describe("the policy is a pure function", () => {
  it("reads neither an ambient clock nor storage", () => {
    const now = vi.spyOn(Date, "now").mockImplementation(() => {
      throw Error("ambient clock");
    });
    let result;
    try {
      result = reduceAccountMode(null, evidence("off"), clock);
    } finally {
      now.mockRestore();
    }
    expect(result?.persist).toBe(true);
    const source = readFileSync(
      new URL("./mode-machine.ts", import.meta.url),
      "utf8",
    )
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/^\s*\/\/.*$/gm, "");
    expect(source).not.toMatch(
      /\b(?:Date|performance|process|fetch)\b|^import\s/m,
    );
  });

  it("does not change its inputs and answers the same twice", () => {
    const off = accept(null, evidence("off"));
    Object.freeze(off);
    Object.freeze(clock);
    const event = evidence("on", { legacyFiles: true });
    Object.freeze(event);
    expect(reduceAccountMode(off, event, clock)).toEqual(
      reduceAccountMode(off, event, clock),
    );
  });
});

describe("named safety mutants and boundary cases", () => {
  it("UNKNOWN_AS_OFF: an answer that is not a usable Off never mints or ends one", () => {
    const failed = [
      evidence("unknown", { rawStatus: null }),
      evidence("unknown"),
      evidence("off", { rawStatus: 500 }),
      evidence("off", { rawStatus: null }),
      evidence("off", { rawStatus: 300 }),
      evidence("off", { fetchStartMono: null }),
    ];
    for (const event of failed) {
      expect(reduceAccountMode(null, event, clock)).toEqual({
        record: null,
        decision: unknown,
        persist: false,
      });
    }
    const off = accept(null, evidence("off"));
    expect(reduceAccountMode(off, read, clock).decision.kind).toBe("legacy");
    for (const event of failed) {
      const result = reduceAccountMode(off, event, clock);
      expect(result.record).toEqual(off);
      expect(result.persist).toBe(false);
      expect(result.decision.kind).toBe("legacy");
    }
  });

  it("OFF_AFTER_ON_LOWERS: a later Off and an outage do not lower a saved On", () => {
    let record = accept(null, evidence("on"));
    for (const event of [
      evidence("off"),
      evidence("unknown", { rawStatus: null }),
    ]) {
      record = reduceAccountMode(record, event, clock).record;
      expect(record?.switched).toBe(true);
      expect(reduceAccountMode(record, read, clock).decision.kind).toBe(
        "streams",
      );
    }
  });

  it("OWNERLESS_READ_ANSWERS: a missing or foreign owner changes nothing", () => {
    const off = accept(null, evidence("off"));
    for (const owner of [undefined, "", "B"]) {
      const result = reduceAccountMode(
        off,
        { type: "read", owner } as ModeEvent,
        clock,
      );
      expect(result).toEqual({
        record: off,
        decision: unknown,
        persist: false,
      });
    }
  });

  it("owners are compared lowercased", () => {
    const on = accept(
      null,
      evidence("on", { owner: "0xAB", authOwner: "0xab" }),
    );
    expect(on?.owner).toBe("0xab");
    expect(
      reduceAccountMode(on, { type: "read", owner: "0xaB" }, clock).decision
        .kind,
    ).toBe("streams");
  });

  it("ADMISSION_ONLY_CHECK: a legacy commit after a saved On is refused", () => {
    const off = accept(null, evidence("off"));
    const admission = reduceAccountMode(
      off,
      { type: "admit", owner: "A", operationId: "same-operation" },
      clock,
    );
    expect(admission.decision.kind).toBe("legacy");
    const on = accept(off, evidence("on"));
    expect(reduceAccountMode(on, commit, clock).decision).toEqual({
      kind: "refuse",
      code: "LEGACY_REFUSED_SWITCHED",
      status: 426,
    });
  });

  it("LATCH_USED_BEFORE_SAVE: a pending or failed On serves neither sink", () => {
    let record = reduceAccountMode(null, evidence("on"), clock).record;
    for (const event of [
      read,
      commit,
      { ...commit, sink: "stream" } as ModeEvent,
    ]) {
      expect(reduceAccountMode(record, event, clock).decision).toEqual(unknown);
    }
    record = reduceAccountMode(
      record,
      { type: "saveFailed", owner: "A" },
      clock,
    ).record;
    expect(reduceAccountMode(record, read, clock).decision).toEqual(unknown);
    expect(record?.switched).toBe(true);
    // A later On answer asks for the save again.
    expect(reduceAccountMode(record, evidence("on"), clock).persist).toBe(true);
  });

  it("OFF_USED_BEFORE_SAVE: an Off serves nothing until its save completes", () => {
    const pending = reduceAccountMode(null, evidence("off"), clock);
    expect(pending.persist).toBe(true);
    expect(pending.decision).toEqual(unknown);
    for (const event of [read, commit]) {
      expect(reduceAccountMode(pending.record, event, clock).decision).toEqual(
        unknown,
      );
    }
    const failed = reduceAccountMode(
      pending.record,
      { type: "saveFailed", owner: "A" },
      clock,
    );
    expect(failed.decision).toEqual(unknown);
    expect(reduceAccountMode(failed.record, read, clock).decision).toEqual(
      unknown,
    );
    // A later Off asks for the save again, and then serves.
    expect(
      reduceAccountMode(failed.record, evidence("off"), clock).persist,
    ).toBe(true);
    const saved = reduceAccountMode(
      pending.record,
      { type: "saveComplete", owner: "A" },
      clock,
    );
    expect(saved.decision.kind).toBe("legacy");
  });

  it("OFF_NEVER_EXPIRES: the deadline itself is expired", () => {
    const off = accept(null, evidence("off"), { ...clock, nowMono: 1000 });
    expect(
      reduceAccountMode(off, read, { ...clock, nowMono: 100 + OFF_TTL_MS - 1 })
        .decision.kind,
    ).toBe("legacy");
    expect(
      reduceAccountMode(off, read, { ...clock, nowMono: 100 + OFF_TTL_MS })
        .decision,
    ).toEqual(unknown);
    expect(
      reduceAccountMode(off, read, { ...clock, nowMono: 99 }).decision,
    ).toEqual(unknown);
    expect(
      reduceAccountMode(off, read, { ...clock, bootId: "boot-2" }).decision,
    ).toEqual(unknown);
  });

  it("EXPIRY_LOWERS_LATCH: expiry and an untrusted reboot keep a saved On", () => {
    const on = accept(null, evidence("on"));
    const reboot = reduceAccountMode(
      on,
      { type: "boot", owner: "A", bootId: "boot-2", clockTrusted: false },
      { ...clock, bootId: "boot-2", nowMono: 0 },
    );
    expect(reboot.record?.switched).toBe(true);
    expect(
      reduceAccountMode(reboot.record, read, {
        ...clock,
        bootId: "boot-2",
        nowMono: OFF_TTL_MS * 2,
      }).decision.kind,
    ).toBe("streams");
  });

  it("an untrusted reboot expires an Off; a trusted one on the same boot keeps it", () => {
    const off = accept(null, evidence("off"));
    const same = reduceAccountMode(
      off,
      { type: "boot", owner: "A", bootId: "boot-1", clockTrusted: true },
      clock,
    );
    expect(same.decision.kind).toBe("legacy");
    const untrusted = reduceAccountMode(
      off,
      { type: "boot", owner: "A", bootId: "boot-1", clockTrusted: false },
      clock,
    );
    expect(untrusted.decision).toEqual(unknown);
    expect(untrusted.record?.cleanOffAt).toBe(off?.cleanOffAt);
  });

  it("NEVER_SEEN_OWNER_ADMITS: first access is unknown and creates nothing", () => {
    for (const event of [commit, read]) {
      expect(reduceAccountMode(null, event, clock)).toEqual({
        record: null,
        decision: unknown,
        persist: false,
      });
    }
    const off = accept(null, evidence("off"));
    expect(reduceAccountMode(off, commit, clock).decision.kind).toBe("legacy");
  });

  it("MISMATCHED_AUTH_OWNER_OFF: another account cannot mint or erase this Off", () => {
    const off = accept(null, evidence("off"));
    for (const record of [null, off]) {
      expect(
        reduceAccountMode(record, evidence("off", { authOwner: "B" }), clock),
      ).toEqual({ record, decision: unknown, persist: false });
    }
  });

  it("saves importPending with the first On, and keeps it until importDone", () => {
    const off = accept(null, evidence("off"));
    const on = reduceAccountMode(
      off,
      evidence("on", { legacyFiles: true }),
      clock,
    );
    expect(on.persist).toBe(true);
    expect(on.decision).toEqual(unknown);
    // The flag is in the record that is written, not only in the answer.
    expect(toDurable(on.record!).importPending).toBe(true);
    const saved = reduceAccountMode(
      on.record,
      { type: "saveComplete", owner: "A" },
      clock,
    );
    expect(saved.decision).toEqual({ kind: "streams", importRequired: true });
    // Every later answer still says an import is owed.
    const later = reduceAccountMode(saved.record, read, clock);
    expect(later.decision).toEqual({ kind: "streams", importRequired: true });
    const again = reduceAccountMode(
      later.record,
      evidence("on", { legacyFiles: false }),
      clock,
    );
    expect(again.persist).toBe(false);
    expect(again.decision).toEqual({ kind: "streams", importRequired: true });
    // A restart reads the same flag back from the disk.
    const restarted = fromDurable("a", toDurable(saved.record!));
    expect(
      reduceAccountMode(restarted, { ...read, owner: "a" }, clock).decision,
    ).toEqual({ kind: "streams", importRequired: true });
  });

  it("STREAM_WRITE_BEFORE_IMPORT_DONE: a stream commit is refused until the import is done", () => {
    const pending = accept(null, evidence("on", { legacyFiles: true }));
    const streamCommit = { ...commit, sink: "stream" } as ModeEvent;
    expect(reduceAccountMode(pending, streamCommit, clock).decision).toEqual({
      kind: "refuse",
      code: "IMPORT_PENDING",
      status: 503,
    });
    const done = reduceAccountMode(
      pending,
      { type: "importDone", owner: "A" },
      clock,
    );
    expect(done.persist).toBe(true);
    expect(toDurable(done.record!).importPending).toBe(false);
    // Save before use: nothing is served as clean until the save completes.
    expect(done.decision).toEqual(unknown);
    expect(
      reduceAccountMode(done.record, streamCommit, clock).decision,
    ).toEqual(unknown);
    const saved = reduceAccountMode(
      done.record,
      { type: "saveComplete", owner: "A" },
      clock,
    );
    expect(saved.decision).toEqual({ kind: "streams", importRequired: false });
    expect(
      reduceAccountMode(saved.record, streamCommit, clock).decision,
    ).toEqual({ kind: "streams", importRequired: false });
    // A failed save of the clean record keeps the owner unknown, and a later
    // importDone asks for the save again.
    const failed = reduceAccountMode(
      done.record,
      { type: "saveFailed", owner: "A" },
      clock,
    );
    expect(failed.decision).toEqual(unknown);
    expect(
      reduceAccountMode(
        failed.record,
        { type: "importDone", owner: "A" },
        clock,
      ).persist,
    ).toBe(true);
  });

  it("admits an import seed publish while pending, and only that", () => {
    const pending = accept(null, evidence("on", { legacyFiles: true }));
    const seed = { ...commit, sink: "importSeed" } as ModeEvent;
    // ORDINARY_WRITE_PASSES_WHILE_PENDING: the ordinary stream commit stays refused.
    expect(
      reduceAccountMode(pending, { ...commit, sink: "stream" }, clock).decision,
    ).toEqual({ kind: "refuse", code: "IMPORT_PENDING", status: 503 });
    // IMPORT_SEED_REFUSED_WHILE_PENDING
    expect(reduceAccountMode(pending, seed, clock).decision).toEqual({
      kind: "streams",
      importRequired: true,
    });
    // It changes nothing: no save, same record.
    const again = reduceAccountMode(pending, seed, clock);
    expect(again.persist).toBe(false);
    expect(again.record).toEqual(pending);
  });

  it("does not admit an import seed publish for an unsaved On or an Off", () => {
    const seed = { ...commit, sink: "importSeed" } as ModeEvent;
    const unsavedOn = reduceAccountMode(
      null,
      evidence("on", { legacyFiles: true }),
      clock,
    );
    expect(reduceAccountMode(unsavedOn.record, seed, clock).decision).toEqual(
      unknown,
    );
    const off = reduceAccountMode(null, evidence("off"), clock);
    expect(reduceAccountMode(off.record, seed, clock).decision.kind).not.toBe(
      "streams",
    );
  });

  it("importDone changes nothing for an owner that has no pending import", () => {
    const done = { type: "importDone", owner: "A" } as ModeEvent;
    expect(reduceAccountMode(null, done, clock)).toEqual({
      record: null,
      decision: unknown,
      persist: false,
    });
    const off = accept(null, evidence("off"));
    expect(reduceAccountMode(off, done, clock).persist).toBe(false);
    const clean = accept(null, evidence("on"));
    const result = reduceAccountMode(clean, done, clock);
    expect(result.persist).toBe(false);
    expect(result.decision).toEqual({ kind: "streams", importRequired: false });
  });

  it("owes no import when the probe finds no legacy files", () => {
    const on = reduceAccountMode(null, evidence("on"), clock);
    const saved = reduceAccountMode(
      on.record,
      { type: "saveComplete", owner: "A" },
      clock,
    );
    expect(saved.decision).toEqual({ kind: "streams", importRequired: false });
    expect(toDurable(on.record!).importPending).toBe(false);
  });

  it("rejects future and expired Off timestamps and an invalid status", () => {
    for (const event of [
      evidence("off", { fetchStartMono: 101 }),
      evidence("off", { fetchStartMono: null }),
      evidence("off", { rawStatus: null }),
      evidence("off", { rawStatus: 300 }),
    ])
      expect(reduceAccountMode(null, event, clock).decision).toEqual(unknown);
    expect(
      reduceAccountMode(null, evidence("off"), {
        ...clock,
        nowMono: 100 + OFF_TTL_MS,
      }).decision,
    ).toEqual(unknown);
  });

  it("does not extend freshness when an older response arrives late", () => {
    const newer = accept(null, evidence("off", { fetchStartMono: 150 }), {
      ...clock,
      nowMono: 200,
    });
    const older = reduceAccountMode(
      newer,
      evidence("off", { fetchStartMono: 100 }),
      { ...clock, nowMono: 300 },
    );
    expect(older.record?.offFetchStartMono).toBe(150);
    expect(older.persist).toBe(false);
  });
});

describe("the durable projection", () => {
  it("round-trips, and a record read from disk counts as saved", () => {
    const on = accept(null, evidence("on", { legacyFiles: true }))!;
    const back = fromDurable("a", toDurable(on));
    expect(back).toMatchObject({
      owner: "a",
      switched: true,
      switchedAt: on.switchedAt,
      persistence: "saved",
      importPending: true,
    });
    expect(Object.keys(toDurable(on)).sort()).toEqual([
      "bootId",
      "cleanOffAt",
      "importPending",
      "offFetchStartMono",
      "switched",
      "switchedAt",
    ]);
  });

  it("refuses to make a record without an owner", () => {
    expect(() => createModeRecord("", "boot-1")).toThrow("needs an owner");
  });
});
