import { describe, expect, it, vi } from "vitest";
import { startPullSignals } from "./pull-signals.js";

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
