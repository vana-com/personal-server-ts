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
