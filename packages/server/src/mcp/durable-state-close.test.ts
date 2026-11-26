import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createMcpConnection } from "@opendatalabs/personal-server-ts-core/mcp";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import { openMcpDurableState } from "./durable-state.js";

const OWNER = "0x1111111111111111111111111111111111111111";
const CLOSED = "MCP state is closed";
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function seeded() {
  const directory = await mkdtemp(join(tmpdir(), "mcp-state-close-"));
  directories.push(directory);
  const path = join(directory, "state.sealed");
  const key = randomBytes(32);
  const state = await openMcpDurableState({ path, key });
  const created = await createMcpConnection(
    { displayName: "Claude" },
    { store: state.connections, publicOrigin: "https://ps.example" },
  );
  await state.bindOwner(created.connectionId, { owner: OWNER, chainId: 14800 });
  await state.connections.update(created.connectionId, { status: "approved" });
  return { directory, path, key, state, id: created.connectionId };
}

/** An empty state, the only kind a snapshot can be imported into. */
async function emptyTarget() {
  const directory = await mkdtemp(join(tmpdir(), "mcp-state-close-"));
  directories.push(directory);
  const path = join(directory, "state.sealed");
  const key = randomBytes(32);
  return {
    directory,
    path,
    key,
    state: await openMcpDurableState({ path, key }),
  };
}

/** A snapshot another state exported, for importSnapshot. */
async function snapshot(migrationId: string): Promise<Uint8Array> {
  const source = await seeded();
  return source.state.fenceAndExport(migrationId, "target");
}

const identity = {
  userPsId: userPsId(14800, OWNER),
  epoch: 2,
  enclaveAddress: OWNER,
  enclavePublicKey: "0x04",
  sealedEnvelope: {
    v: 1 as const,
    iv: "iv",
    ciphertext: "ciphertext",
    tag: "tag",
    wrappedContentKey: { iv: "iv", ciphertext: "key", tag: "tag" },
  },
};

type Seeded = Awaited<ReturnType<typeof seeded>>;
const entryPoints: Record<
  string,
  (s: Seeded, snap: Uint8Array) => Promise<unknown>
> = {
  mutate: (s) =>
    s.state.connections.update(s.id, { lastUsedAt: "2026-01-01T00:00:00Z" }),
  exclusive: (s) => s.state.exclusive(async () => "ran"),
  fenceAndExport: (s) => s.state.fenceAndExport("m-fence", "target"),
  importSnapshot: (s, snap) => s.state.importSnapshot(snap, "m-import"),
  prepareRollback: (s) =>
    s.state.prepareRollback("m-prepare", async () => ({
      identity,
      generation: 1,
    })),
  activateRollback: (s) =>
    s.state.activateRollback({
      migrationId: "m",
      digest: "d",
      owners: 0,
      connections: 0,
    }),
};

describe("MCP durable state close", () => {
  describe.each(Object.keys(entryPoints))("%s", (name) => {
    it("is refused after close and leaves the storage untouched", async () => {
      const s = await seeded();
      const snap = await snapshot("m-import");
      await s.state.close();
      const before = {
        files: await readdir(s.directory),
        bytes: await readFile(s.path),
      };
      await expect(entryPoints[name]!(s, snap)).rejects.toThrow(CLOSED);
      expect(await readdir(s.directory)).toEqual(before.files);
      expect((await readFile(s.path)).equals(before.bytes)).toBe(true);
    });
  });

  it("lands a write that was admitted before close", async () => {
    const s = await seeded();
    const started = entryPoints.mutate!(s, new Uint8Array());
    const closing = s.state.close();
    await expect(started).resolves.not.toBeNull();
    await closing;
    const reopened = await openMcpDurableState({ path: s.path, key: s.key });
    expect((await reopened.connections.getById(s.id))?.lastUsedAt).toBe(
      "2026-01-01T00:00:00Z",
    );
  });

  it("completes a fence admitted before close", async () => {
    const s = await seeded();
    const started = s.state.fenceAndExport("m-fence", "target");
    const closing = s.state.close();
    await expect(started).resolves.toBeInstanceOf(Uint8Array);
    await closing;
    const reopened = await openMcpDurableState({ path: s.path, key: s.key });
    expect((await reopened.migrationStatus()).fenced).toBe(true);
  });

  it("completes an import admitted before close", async () => {
    const target = await emptyTarget();
    const snap = await snapshot("m-import");
    const started = target.state.importSnapshot(snap, "m-import");
    const closing = target.state.close();
    await expect(started).resolves.toMatchObject({ connections: 1 });
    await closing;
    const reopened = await openMcpDurableState({
      path: target.path,
      key: target.key,
    });
    expect(await reopened.connections.list()).toHaveLength(1);
  });

  it("does not refuse a rollback preparation admitted before close", async () => {
    const target = await emptyTarget();
    await target.state.importSnapshot(await snapshot("m-prepare"), "m-prepare");
    const started = target.state.prepareRollback("m-prepare", async () => ({
      identity,
      generation: 1,
    }));
    const closing = target.state.close();
    await expect(started).resolves.toMatchObject({ migrationId: "m-prepare" });
    await closing;
    const reopened = await openMcpDurableState({
      path: target.path,
      key: target.key,
    });
    expect(await reopened.getIdentity(identity.userPsId)).toEqual(identity);
  });

  it("does not refuse an activation admitted before close", async () => {
    const s = await seeded();
    const started = entryPoints.activateRollback!(s, new Uint8Array());
    const closing = s.state.close();
    // The call is admitted; this receipt has no preparation, so the state
    // rejects it for that reason and not because it is closed.
    await expect(started).rejects.not.toThrow(CLOSED);
    await closing;
  });

  it("finishes every write of an exclusive operation admitted before close, and refuses the rest", async () => {
    const s = await seeded();
    const events: string[] = [];
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    let entered!: () => void;
    const running = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const operation = s.state.exclusive(async () => {
      entered();
      await gate;
      await s.state.connections.update(s.id, { lastUsedAt: "first" });
      await s.state.connections.update(s.id, { lastUsedAt: "second" });
      events.push("operation done");
    });
    await running;
    const closing = s.state.close().then(() => events.push("close done"));
    // Outside the operation, a write and a new operation are both refused.
    await expect(
      s.state.connections.update(s.id, { lastUsedAt: "outside" }),
    ).rejects.toThrow(CLOSED);
    await expect(s.state.exclusive(async () => "late")).rejects.toThrow(CLOSED);

    open();
    await operation;
    await closing;
    expect(events).toEqual(["operation done", "close done"]);
    const reopened = await openMcpDurableState({ path: s.path, key: s.key });
    expect((await reopened.connections.getById(s.id))?.lastUsedAt).toBe(
      "second",
    );
  });

  it("refuses a write a detached continuation starts after its operation returned", async () => {
    const s = await seeded();
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    let detached!: Promise<unknown>;
    await s.state.exclusive(async () => {
      // Started inside the operation, never awaited by it.
      detached = gate.then(() =>
        s.state.connections.update(s.id, { lastUsedAt: "detached" }),
      );
      detached.catch(() => undefined);
    });
    await s.state.close();
    const bytes = await readFile(s.path);
    const files = await readdir(s.directory);

    open();
    await expect(detached).rejects.toThrow(CLOSED);
    expect(await readdir(s.directory)).toEqual(files);
    expect((await readFile(s.path)).equals(bytes)).toBe(true);
  });

  it("revokes an operation's writes when its callback throws", async () => {
    const s = await seeded();
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    let detached!: Promise<unknown>;
    await expect(
      s.state.exclusive(async () => {
        detached = gate.then(() =>
          s.state.connections.update(s.id, { lastUsedAt: "after-throw" }),
        );
        detached.catch(() => undefined);
        throw new Error("callback failed");
      }),
    ).rejects.toThrow("callback failed");
    await s.state.close();
    const bytes = await readFile(s.path);

    open();
    await expect(detached).rejects.toThrow(CLOSED);
    expect((await readFile(s.path)).equals(bytes)).toBe(true);
  });

  it("rejects a close made from inside an admitted operation, then closes from outside", async () => {
    const s = await seeded();
    await expect(
      s.state.exclusive(async () => {
        await s.state.close();
      }),
    ).rejects.toThrow("cannot be closed from inside");
    // The refused call did not close the state: a write still lands.
    await s.state.connections.update(s.id, { lastUsedAt: "after-refusal" });
    await s.state.close();
    await expect(
      s.state.connections.update(s.id, { lastUsedAt: "late" }),
    ).rejects.toThrow(CLOSED);
  });

  it("rejects a close made from inside an admitted operation while a close is in progress", async () => {
    const s = await seeded();
    let entered!: () => void;
    const running = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const inside = s.state.exclusive(async () => {
      entered();
      await gate;
      await s.state.close();
    });
    inside.catch(() => undefined);
    await running;
    const outside = s.state.close();
    open();
    await expect(inside).rejects.toThrow("cannot be closed from inside");
    await outside;
  });

  it("rejects a close made from a rollback resolver, then drains from outside", async () => {
    const target = await emptyTarget();
    await target.state.importSnapshot(
      await snapshot("m-resolver"),
      "m-resolver",
    );
    await expect(
      target.state.prepareRollback("m-resolver", async () => {
        await target.state.close();
        return { identity, generation: 1 };
      }),
    ).rejects.toThrow("cannot be closed from inside");
    // The refused close left the state open and the lifecycle usable.
    await target.state.connections.update(
      (await target.state.connections.list())[0]!.id,
      { lastUsedAt: "after-refusal" },
    );
    await target.state.close();
    await expect(
      target.state.connections.update("any", { lastUsedAt: "late" }),
    ).rejects.toThrow(CLOSED);
  });

  it("rejects a close made from a rollback resolver while a close is in progress", async () => {
    const target = await emptyTarget();
    await target.state.importSnapshot(
      await snapshot("m-resolver"),
      "m-resolver",
    );
    let entered!: () => void;
    const running = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let open!: () => void;
    const gate = new Promise<void>((resolve) => {
      open = resolve;
    });
    const inside = target.state.prepareRollback("m-resolver", async () => {
      entered();
      await gate;
      await target.state.close();
      return { identity, generation: 1 };
    });
    inside.catch(() => undefined);
    await running;
    const outside = target.state.close();
    open();
    await expect(inside).rejects.toThrow("cannot be closed from inside");
    await outside;
  });

  it("drains a later inert operation even if an earlier operation failed", async () => {
    const { state } = await emptyTarget();
    const calls: string[] = [];
    const failed = state.exclusive(async () => {
      calls.push("failed");
      throw new Error("fixture failure");
    });
    const rejected = expect(failed).rejects.toThrow("fixture failure");
    const following = state.exclusive(async () => {
      calls.push("finished");
      return "fixture result";
    });

    await state.close();
    expect(calls).toEqual(["failed", "finished"]);
    await rejected;
    await expect(following).resolves.toBe("fixture result");
  });

  it("closes an idle fixture without adding filesystem entries", async () => {
    const { state, directory } = await emptyTarget();
    const before = (await readdir(directory)).sort();

    await state.close();

    expect((await readdir(directory)).sort()).toEqual(before);
  });

  it("returns one promise for repeated closes", async () => {
    const s = await seeded();
    const first = s.state.close();
    expect(s.state.close()).toBe(first);
    await first;
  });

  it("settles queued callbacks in order before shutdown completes", async () => {
    const { state } = await emptyTarget();
    const events: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });

    const first = state.exclusive(async () => {
      await gate;
      events.push("first");
    });
    const second = state.exclusive(async () => {
      events.push("second");
    });
    const closing = state.close().then(() => events.push("closed"));

    release();
    await Promise.all([first, second, closing]);
    expect(events).toEqual(["first", "second", "closed"]);
  });

  it("does not delay a separate instance closing while a callback drains", async () => {
    const { state: first } = await emptyTarget();
    const { state: second } = await emptyTarget();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = first.exclusive(async () => {
      await gate;
    });
    let firstClosed = false;
    const closing = first.close().then(() => {
      firstClosed = true;
    });

    try {
      await second.close();
      expect(firstClosed).toBe(false);
    } finally {
      release();
      await Promise.all([pending, closing]);
    }
    expect(firstClosed).toBe(true);
  });

  it("keeps the final connection readable without exposing a mutable reference after close", async () => {
    const s = await seeded();
    await s.state.close();
    const before = await readFile(s.path);
    const record = await s.state.connections.getById(s.id);
    if (!record) throw new Error("fixture connection missing");
    Object.assign(record, { lastUsedAt: "2026-01-02T00:00:00Z" });
    expect((await s.state.connections.getById(s.id))?.lastUsedAt).not.toBe(
      record.lastUsedAt,
    );
    expect(await readFile(s.path)).toEqual(before);
  });

  it("exposes an admitted identity write to a read started after close begins", async () => {
    const s = await emptyTarget();
    const saving = s.state.rememberIdentity(identity);
    const closing = s.state.close();
    await expect(s.state.getIdentity(identity.userPsId)).resolves.toEqual(
      identity,
    );
    await Promise.all([saving, closing]);
    const reopened = await openMcpDurableState({ path: s.path, key: s.key });
    try {
      await expect(reopened.getIdentity(identity.userPsId)).resolves.toEqual(
        identity,
      );
    } finally {
      await reopened.close();
    }
  });
});
