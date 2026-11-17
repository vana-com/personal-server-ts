import { describe, expect, it } from "vitest";
import { runShutdown, type ClosableServer } from "./shutdown.js";

/** A server whose `close` callback fires when the test says its requests ended. */
function fakeServer(events: string[], name: string) {
  let finish: () => void = () => {};
  const server: ClosableServer = {
    close(onClosed) {
      events.push(`${name} stops accepting`);
      finish = () => {
        events.push(`${name} drained`);
        onClosed();
      };
    },
  };
  return { server, drain: () => finish() };
}

const quietLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 10));

function setup(cleanup?: () => Promise<void>) {
  const events: string[] = [];
  const main = fakeServer(events, "main");
  const local = fakeServer(events, "local");
  const exits: number[] = [];
  const done = (extra: { drainTimeoutMs?: number } = {}) =>
    runShutdown({
      servers: [main.server, local.server],
      cleanup:
        cleanup ??
        (async () => {
          events.push("cleanup");
        }),
      logger: quietLogger,
      exit: (code) => {
        events.push(`exit ${code}`);
        exits.push(code);
      },
      drainTimeoutMs: extra.drainTimeoutMs ?? 5_000,
      cleanupTimeoutMs: 5_000,
    });
  return { events, main, local, exits, done };
}

describe("runShutdown", () => {
  it("runs cleanup only after every server has drained, then exits 0", async () => {
    const { events, main, local, done } = setup();
    const finished = done();
    await tick();
    expect(events).toEqual(["main stops accepting", "local stops accepting"]);

    main.drain();
    await tick();
    expect(events).not.toContain("cleanup");

    local.drain();
    await finished;

    expect(events.slice(2)).toEqual([
      "main drained",
      "local drained",
      "cleanup",
      "exit 0",
    ]);
  });

  it("awaits cleanup before it exits", async () => {
    let release: () => void = () => {};
    const { events, main, local, done } = setup(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    const finished = done();
    main.drain();
    local.drain();
    await tick();
    expect(events.some((event) => event.startsWith("exit"))).toBe(false);

    release();
    await finished;

    expect(events.at(-1)).toBe("exit 0");
  });

  it("exits 1 when cleanup fails", async () => {
    const { main, local, exits, done } = setup(async () => {
      throw new Error("boom");
    });
    const finished = done();
    main.drain();
    local.drain();
    await finished;

    expect(exits).toEqual([1]);
  });

  it("exits 1 without cleanup when a server does not drain in time", async () => {
    const { events, exits, done } = setup();

    await done({ drainTimeoutMs: 30 });

    expect(exits).toEqual([1]);
    expect(events).not.toContain("cleanup");
  });
});
