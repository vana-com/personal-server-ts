import { describe, expect, it, vi } from "vitest";
import {
  runStateMigrations,
  type StateMigration,
  type StateMigrationContext,
  type StateMigrationsState,
} from "./state-migrations.js";

// The framework operates on a StateMigrationContext; these tests exercise the
// registry/tracking logic with stub migrations, so the db handle is unused.
const ctx = {
  db: {} as never,
  storageRoot: "/tmp/unused",
} as StateMigrationContext;

function oneShot(
  id: string,
  run: () => void,
  check = () => true,
): StateMigration {
  return {
    id,
    description: id,
    check,
    run: () => {
      run();
      return { changed: true };
    },
  };
}

let clock = 0;
const now = () => `2026-07-14T00:00:${String(clock++).padStart(2, "0")}Z`;

describe("runStateMigrations", () => {
  it("tolerates a malformed prior ledger (non-array applied/log) instead of bricking boot", () => {
    // A corrupt / hand-edited state.json parses to valid JSON with wrong types.
    const malformed = {
      applied: {},
      log: {},
    } as unknown as StateMigrationsState;
    const run = vi.fn();
    const state = runStateMigrations(ctx, malformed, {
      migrations: [oneShot("m1", run)],
      now,
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(state.applied).toEqual(["m1"]);
    expect(Array.isArray(state.log)).toBe(true);
    expect(state.log).toHaveLength(1);
  });

  it("runs a pending one-shot migration once and records it as applied", () => {
    const run = vi.fn();
    const state = runStateMigrations(ctx, undefined, {
      migrations: [oneShot("m1", run)],
      now,
    });
    expect(run).toHaveBeenCalledTimes(1);
    expect(state.applied).toContain("m1");
    expect(state.log).toHaveLength(1);
    expect(state.log[0]).toMatchObject({ id: "m1", changed: true });
  });

  it("does not re-run a one-shot migration already recorded as applied", () => {
    const run = vi.fn();
    const state = runStateMigrations(
      ctx,
      { applied: ["m1"], log: [] },
      { migrations: [oneShot("m1", run)], now },
    );
    expect(run).not.toHaveBeenCalled();
    expect(state.applied).toEqual(["m1"]);
  });

  it("marks a one-shot as applied even when its check() is false, so it is not re-checked", () => {
    const run = vi.fn();
    const state = runStateMigrations(ctx, undefined, {
      migrations: [oneShot("m1", run, () => false)],
      now,
    });
    expect(run).not.toHaveBeenCalled();
    expect(state.applied).toContain("m1");
    expect(state.log).toHaveLength(0);
  });

  it("re-evaluates an everyBoot migration on every run and never marks it applied", () => {
    const run = vi.fn();
    const migration: StateMigration = {
      id: "heal",
      description: "heal",
      everyBoot: true,
      check: () => true,
      run: () => {
        run();
        return { changed: true, detail: "did work" };
      },
    };
    let state = runStateMigrations(ctx, undefined, {
      migrations: [migration],
      now,
    });
    state = runStateMigrations(ctx, state, { migrations: [migration], now });
    expect(run).toHaveBeenCalledTimes(2);
    expect(state.applied).not.toContain("heal");
    expect(state.log).toHaveLength(2);
  });

  it("does not mark a migration applied when it throws, so it retries next boot", () => {
    const boom = (): StateMigration => ({
      id: "explode",
      description: "explode",
      check: () => true,
      run: () => {
        throw new Error("kaboom");
      },
    });
    const logger = { info: vi.fn(), warn: vi.fn() };
    const state = runStateMigrations({ ...ctx, logger }, undefined, {
      migrations: [boom()],
      now,
    });
    expect(state.applied).not.toContain("explode");
    expect(logger.warn).toHaveBeenCalled();
  });

  it("does not mark a migration applied when its check() throws", () => {
    const migration: StateMigration = {
      id: "bad-check",
      description: "bad-check",
      check: () => {
        throw new Error("check failed");
      },
      run: () => ({ changed: false }),
    };
    const state = runStateMigrations(ctx, undefined, {
      migrations: [migration],
      now,
    });
    expect(state.applied).not.toContain("bad-check");
  });

  it("caps the run log at maxLog entries", () => {
    const migration: StateMigration = {
      id: "heal",
      description: "heal",
      everyBoot: true,
      check: () => true,
      run: () => ({ changed: true }),
    };
    let state = { applied: [] as string[], log: [] };
    for (let i = 0; i < 10; i++) {
      state = runStateMigrations(ctx, state, {
        migrations: [migration],
        now,
        maxLog: 3,
      });
    }
    expect(state.log).toHaveLength(3);
  });
});
