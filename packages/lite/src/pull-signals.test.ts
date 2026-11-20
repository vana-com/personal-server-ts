import { describe, expect, it, vi } from "vitest";
import { startPullSignals, startVisibilityPause } from "./pull-signals.js";

function target(visibilityState?: string) {
  const et = new EventTarget() as EventTarget & { visibilityState?: string };
  if (visibilityState) et.visibilityState = visibilityState;
  return et;
}

describe("startPullSignals", () => {
  it("pulls when the page becomes visible, not when it is hidden", () => {
    const doc = target("hidden");
    const onSignal = vi.fn();
    startPullSignals(onSignal, { document: doc, window: target() });

    doc.dispatchEvent(new Event("visibilitychange"));
    expect(onSignal).not.toHaveBeenCalled();

    doc.visibilityState = "visible";
    doc.dispatchEvent(new Event("visibilitychange"));
    expect(onSignal).toHaveBeenCalledTimes(1);
  });

  it("pulls when the window gains focus and when the network returns", () => {
    const win = target();
    const onSignal = vi.fn();
    startPullSignals(onSignal, { document: target("visible"), window: win });

    win.dispatchEvent(new Event("focus"));
    win.dispatchEvent(new Event("online"));
    expect(onSignal).toHaveBeenCalledTimes(2);
  });

  it("stops listening when stopped", () => {
    const doc = target("visible");
    const win = target();
    const onSignal = vi.fn();
    const stop = startPullSignals(onSignal, { document: doc, window: win });
    stop();

    doc.dispatchEvent(new Event("visibilitychange"));
    win.dispatchEvent(new Event("focus"));
    win.dispatchEvent(new Event("online"));
    expect(onSignal).not.toHaveBeenCalled();
  });

  it("does nothing where there is no page (a worker, Node)", () => {
    const onSignal = vi.fn();
    const stop = startPullSignals(onSignal, {});
    expect(() => stop()).not.toThrow();
    expect(onSignal).not.toHaveBeenCalled();
  });

  it("a thrown handler never breaks the page's event dispatch", () => {
    const win = target();
    startPullSignals(
      () => {
        throw new Error("boom");
      },
      { window: win },
    );
    expect(() => win.dispatchEvent(new Event("focus"))).not.toThrow();
  });
});

describe("startVisibilityPause", () => {
  it("never resumes when a synchronous active notification precedes a failed subscription", () => {
    const manager = { pause: vi.fn(), resume: vi.fn() };
    const onActive = vi.fn();
    let notify = () => {};
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => true,
        subscribe: (callback) => {
          notify = callback;
          callback();
          throw new Error("subscription failed");
        },
      },
      onActive,
    });
    expect(manager.resume).not.toHaveBeenCalled();
    expect(manager.pause).toHaveBeenCalledTimes(1);
    notify();
    stop();
    expect(manager.resume).not.toHaveBeenCalled();
    expect(manager.pause).toHaveBeenCalledTimes(1);
    expect(onActive).not.toHaveBeenCalled();
  });

  it("ignores a queued notification delivered after disposal", () => {
    const manager = { pause: vi.fn(), resume: vi.fn() };
    let active = false;
    let notify = () => {};
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => active,
        subscribe: (callback) => {
          notify = callback;
          return () => {};
        },
      },
    });
    manager.pause.mockClear();
    const queued = notify;
    active = true;
    stop();
    queued();
    expect(manager.pause).not.toHaveBeenCalled();
    expect(manager.resume).not.toHaveBeenCalled();
  });

  it("does not resume when activity reading disposes the subscription", () => {
    const manager = { pause: vi.fn(), resume: vi.fn() };
    const onActive = vi.fn();
    let stop = () => {};
    let notify = () => {};
    let reenter = false;
    const unsubscribe = vi.fn();
    stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => {
          if (reenter) stop();
          return reenter;
        },
        subscribe: (callback) => {
          notify = callback;
          return unsubscribe;
        },
      },
      onActive,
    });
    manager.pause.mockClear();
    reenter = true;
    notify();
    stop();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
    expect(manager.resume).not.toHaveBeenCalled();
    expect(manager.pause).not.toHaveBeenCalled();
    expect(onActive).not.toHaveBeenCalled();
  });

  it("retries a failed resume and pulls once after it succeeds", () => {
    let active = false;
    let notify = () => {};
    const manager = {
      pause: vi.fn(),
      resume: vi.fn().mockImplementationOnce(() => {
        throw new Error("resume failed");
      }),
    };
    const onActive = vi.fn();
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => active,
        subscribe: (callback) => {
          notify = callback;
          return () => {};
        },
      },
      onActive,
    });
    active = true;
    notify();
    expect(onActive).not.toHaveBeenCalled();
    notify();
    notify();
    expect(manager.resume).toHaveBeenCalledTimes(2);
    expect(onActive).toHaveBeenCalledTimes(1);
    stop();
  });

  it("retries a failed pause on the next inactive notification", () => {
    let active = true;
    let notify = () => {};
    const manager = {
      pause: vi.fn().mockImplementationOnce(() => {
        throw new Error("pause failed");
      }),
      resume: vi.fn(),
    };
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => active,
        subscribe: (callback) => {
          notify = callback;
          return () => {};
        },
      },
    });
    active = false;
    notify();
    notify();
    notify();
    expect(manager.pause).toHaveBeenCalledTimes(2);
    expect(manager.resume).toHaveBeenCalledTimes(1);
    stop();
  });

  it("does not resume again when the pull callback throws", () => {
    let active = false;
    let notify = () => {};
    const manager = { pause: vi.fn(), resume: vi.fn() };
    const onActive = vi.fn(() => {
      throw new Error("pull failed");
    });
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => active,
        subscribe: (callback) => {
          notify = callback;
          return () => {};
        },
      },
      onActive,
    });
    active = true;
    notify();
    notify();
    expect(manager.resume).toHaveBeenCalledTimes(1);
    expect(onActive).toHaveBeenCalledTimes(1);
    stop();
  });

  it("recovers an unreadable activity only after a notification", () => {
    let readable = false;
    let notify = () => {};
    const order: string[] = [];
    const manager = {
      pause: vi.fn(() => order.push("pause")),
      resume: vi.fn(() => order.push("resume")),
    };
    const onActive = vi.fn(() => order.push("pull"));
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive: () => {
          if (!readable) throw new Error("read failed");
          return true;
        },
        subscribe: (callback) => {
          notify = callback;
          return () => {};
        },
      },
      onActive,
    });
    readable = true;
    expect(order).toEqual(["pause"]);
    notify();
    notify();
    expect(order).toEqual(["pause", "resume", "pull"]);
    stop();
  });

  it("unsubscribes once when unsubscribe re-enters disposal", () => {
    let stop = () => {};
    let calls = 0;
    const unsubscribe = vi.fn(() => {
      if (++calls === 1) stop();
    });
    stop = startVisibilityPause(
      {},
      {
        activity: { isActive: () => true, subscribe: () => unsubscribe },
      },
    );
    stop();
    expect(unsubscribe).toHaveBeenCalledTimes(1);
  });

  it("applies the latest state after synchronous subscription notifications", () => {
    const manager = { pause: vi.fn(), resume: vi.fn() };
    let active = false;
    let inSubscribe = true;
    const isActive = vi.fn(() => {
      expect(inSubscribe).toBe(false);
      return active;
    });
    const stop = startVisibilityPause(manager, {
      activity: {
        isActive,
        subscribe: (callback) => {
          callback();
          active = true;
          callback();
          inSubscribe = false;
          return () => {};
        },
      },
    });
    expect(isActive).toHaveBeenCalledTimes(1);
    expect(manager.resume).toHaveBeenCalledTimes(1);
    expect(manager.pause).not.toHaveBeenCalled();
    stop();
  });

  it("pauses on hide, resumes on show, and ignores a repeat of the same state", () => {
    const doc = target("visible");
    const manager = { pause: vi.fn(), resume: vi.fn() };
    startVisibilityPause(manager, { document: doc });
    expect(manager.pause).not.toHaveBeenCalled();

    doc.visibilityState = "hidden";
    doc.dispatchEvent(new Event("visibilitychange"));
    expect(manager.pause).toHaveBeenCalledTimes(1);
    doc.visibilityState = "visible";
    doc.dispatchEvent(new Event("visibilitychange"));
    expect(manager.resume).toHaveBeenCalledTimes(1);
  });

  it("a page that starts hidden pauses at once", () => {
    const manager = { pause: vi.fn(), resume: vi.fn() };
    startVisibilityPause(manager, { document: target("hidden") });
    expect(manager.pause).toHaveBeenCalledTimes(1);
  });

  it("resumes before a pull signal registered after it reads the manager", () => {
    const doc = target("hidden");
    const order: string[] = [];
    startVisibilityPause(
      { pause: () => order.push("pause"), resume: () => order.push("resume") },
      { document: doc },
    );
    startPullSignals(() => order.push("pull"), {
      document: doc,
      window: target(),
    });
    doc.visibilityState = "visible";
    doc.dispatchEvent(new Event("visibilitychange"));
    expect(order).toEqual(["pause", "resume", "pull"]);
  });

  it("stops listening when stopped, and does nothing without a page", () => {
    const doc = target("visible");
    const manager = { pause: vi.fn(), resume: vi.fn() };
    const stop = startVisibilityPause(manager, { document: doc });
    stop();
    doc.visibilityState = "hidden";
    doc.dispatchEvent(new Event("visibilitychange"));
    expect(manager.pause).not.toHaveBeenCalled();
    expect(() => startVisibilityPause(manager, {})()).not.toThrow();
  });
});
