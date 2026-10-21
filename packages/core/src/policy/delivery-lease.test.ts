import { afterEach, describe, expect, it, vi } from "vitest";
import {
  allDeliveryLeases,
  collectDeliveryLeases,
  deliver,
  DELIVERY_FRESHNESS_ATTEMPTS,
  DeliveryNotFreshError,
  leasedStream,
  localLease,
  REMOTE_GRANT_REVERIFY_AFTER_MS,
  remoteEvidence,
  type DeliveryLease,
} from "./delivery-lease.js";

afterEach(() => {
  vi.useRealTimers();
});

const live = localLease(() => undefined);
const ended = localLease(() => {
  throw new Error("ended");
});

describe("deliver", () => {
  it("checks locally and releases in the same tick, with no remote call while evidence is fresh", async () => {
    const order: string[] = [];
    const reverify = vi.fn(async () => "again");
    const evidence = remoteEvidence("first", reverify);
    const lease: DeliveryLease = {
      evidence: () => [evidence],
      assertLocal() {
        order.push("local");
        void Promise.resolve().then(() => order.push("microtask"));
      },
    };
    await deliver(lease, () => order.push("release"));
    await Promise.resolve();
    expect(order).toEqual(["local", "release", "microtask"]);
    expect(reverify).not.toHaveBeenCalled();
  });

  it("refreshes stale evidence before the local check", async () => {
    let now = 0;
    const evidence = remoteEvidence("first", async () => "second", {
      now: () => now,
    });
    let seen: string | undefined;
    const lease: DeliveryLease = {
      evidence: () => [evidence],
      assertLocal: () => {
        seen = evidence.current;
      },
    };
    now = REMOTE_GRANT_REVERIFY_AFTER_MS;
    await deliver(lease, () => undefined, { now: () => now });
    expect(seen).toBe("second");
  });

  it("never releases when the local check refuses", async () => {
    const release = vi.fn();
    await expect(deliver(ended, release)).rejects.toThrow("ended");
    expect(release).not.toHaveBeenCalled();
  });

  it("refreshes again any evidence that aged while another piece was refreshed", async () => {
    let now = 0;
    const clock = () => now;
    const a = vi.fn(async () => "a");
    // B's refresh is slow: it takes 60 s, so A's fresh answer is old again.
    let bCalls = 0;
    const b = vi.fn(async () => {
      bCalls += 1;
      if (bCalls === 1) now += 60_000;
      return "b";
    });
    const evidenceA = remoteEvidence("a0", a, { now: clock });
    const evidenceB = remoteEvidence("b0", b, { now: clock });
    const lease: DeliveryLease = {
      evidence: () => [evidenceA, evidenceB],
      assertLocal: () => undefined,
    };
    now = REMOTE_GRANT_REVERIFY_AFTER_MS + 1;
    await deliver(lease, () => undefined, { now: clock });
    // Round 1 refreshed both (B took 60 s); round 2 refreshed both again,
    // because each answer is dated from when its check started.
    expect(a).toHaveBeenCalledTimes(2);
    expect(b).toHaveBeenCalledTimes(2);
    expect(now - evidenceA.verifiedAt).toBeLessThan(
      REMOTE_GRANT_REVERIFY_AFTER_MS,
    );
  });

  it("fails closed when evidence cannot be made fresh", async () => {
    let now = 0;
    // Every check takes longer than the window.
    const evidence = remoteEvidence(
      "x",
      async () => {
        now += REMOTE_GRANT_REVERIFY_AFTER_MS;
        return "x";
      },
      { now: () => now },
    );
    now = REMOTE_GRANT_REVERIFY_AFTER_MS;
    const release = vi.fn();
    await expect(
      deliver(
        { evidence: () => [evidence], assertLocal: () => undefined },
        release,
        { now: () => now },
      ),
    ).rejects.toBeInstanceOf(DeliveryNotFreshError);
    expect(release).not.toHaveBeenCalled();
    expect(DELIVERY_FRESHNESS_ATTEMPTS).toBeGreaterThan(0);
  });
});

describe("leasedStream", () => {
  function source(parts: number): ReadableStream<Uint8Array> {
    let sent = 0;
    return new ReadableStream({
      pull(controller) {
        if (sent === parts) return controller.close();
        sent += 1;
        controller.enqueue(new Uint8Array([sent]));
      },
    });
  }

  it("releases every part while the lease holds", async () => {
    const parts: number[] = [];
    const reader = leasedStream(live, source(3)).getReader();
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      parts.push(next.value[0]!);
    }
    expect(parts).toEqual([1, 2, 3]);
  });

  it("errors before the next part once the lease refuses", async () => {
    let isEnded = false;
    const lease = localLease(() => {
      if (isEnded) throw new Error("ended");
    });
    const reader = leasedStream(lease, source(3)).getReader();
    expect((await reader.read()).value?.[0]).toBe(1);
    isEnded = true;
    await expect(reader.read()).rejects.toThrow("ended");
  });
});

describe("lease composition", () => {
  it("allDeliveryLeases holds only while every lease holds", async () => {
    await expect(
      deliver(allDeliveryLeases(live, undefined), () => "ok"),
    ).resolves.toBe("ok");
    await expect(
      deliver(allDeliveryLeases(live, ended), () => "ok"),
    ).rejects.toThrow("ended");
  });

  it("a collector checks every lease added to it", async () => {
    const collected = collectDeliveryLeases();
    collected.add(live);
    await expect(deliver(collected, () => "ok")).resolves.toBe("ok");
    collected.add(ended);
    expect(collected.size).toBe(2);
    await expect(deliver(collected, () => "ok")).rejects.toThrow("ended");
  });
});
