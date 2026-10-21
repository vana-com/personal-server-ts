import { describe, expect, it, vi } from "vitest";
import {
  allDeliveryLeases,
  collectDeliveryLeases,
  deliver,
  leasedStream,
  REMOTE_GRANT_REVERIFY_AFTER_MS,
  remoteEvidence,
  type DeliveryLease,
} from "./delivery-lease.js";

const live: DeliveryLease = {
  refresh: async () => undefined,
  assertLocal: () => undefined,
};

describe("remoteEvidence", () => {
  it("trusts the admitting verification for 30 s, then fetches new evidence", async () => {
    let now = 1_000;
    const reverify = vi.fn(async () => "second");
    const evidence = remoteEvidence("first", reverify, { now: () => now });

    now += REMOTE_GRANT_REVERIFY_AFTER_MS - 1;
    await evidence.refresh();
    expect(reverify).not.toHaveBeenCalled();
    expect(evidence.current).toBe("first");

    now += 1;
    await evidence.refresh();
    expect(reverify).toHaveBeenCalledTimes(1);
    expect(evidence.current).toBe("second");

    // A success restarts the window.
    now += REMOTE_GRANT_REVERIFY_AFTER_MS - 1;
    await evidence.refresh();
    expect(reverify).toHaveBeenCalledTimes(1);
  });

  it("propagates a refusal and keeps asking until one succeeds", async () => {
    let now = 0;
    const reverify = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("revoked"))
      .mockResolvedValue("ok");
    const evidence = remoteEvidence("first", reverify, { now: () => now });
    now = REMOTE_GRANT_REVERIFY_AFTER_MS;
    await expect(evidence.refresh()).rejects.toThrow("revoked");
    await evidence.refresh();
    expect(reverify).toHaveBeenCalledTimes(2);
  });
});

describe("deliver", () => {
  it("runs the remote half, then the local half, then the release, with no await between the last two", async () => {
    const order: string[] = [];
    let localPassed = false;
    const lease: DeliveryLease = {
      async refresh() {
        await Promise.resolve();
        order.push("remote");
      },
      assertLocal() {
        order.push("local");
        localPassed = true;
        // Anything scheduled now runs only after the release.
        void Promise.resolve().then(() => order.push("microtask"));
      },
    };
    const released = await deliver(lease, () => {
      expect(localPassed).toBe(true);
      order.push("release");
      return 7;
    });
    expect(released).toBe(7);
    await Promise.resolve();
    expect(order).toEqual(["remote", "local", "release", "microtask"]);
  });

  it("never releases when the local half refuses after the remote half", async () => {
    let revoked = false;
    const lease: DeliveryLease = {
      async refresh() {
        // The local state changes while the remote check is in flight.
        revoked = true;
      },
      assertLocal() {
        if (revoked) throw new Error("revoked");
      },
    };
    const release = vi.fn();
    await expect(deliver(lease, release)).rejects.toThrow("revoked");
    expect(release).not.toHaveBeenCalled();
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
    for await (const chunk of leasedStream(
      live,
      source(3),
    ) as unknown as AsyncIterable<Uint8Array>) {
      parts.push(chunk[0]!);
    }
    expect(parts).toEqual([1, 2, 3]);
  });

  it("errors before the next part once the lease refuses", async () => {
    let ended = false;
    const lease: DeliveryLease = {
      refresh: async () => undefined,
      assertLocal() {
        if (ended) throw new Error("ended");
      },
    };
    const reader = leasedStream(lease, source(3)).getReader();
    expect((await reader.read()).value?.[0]).toBe(1);
    ended = true;
    await expect(reader.read()).rejects.toThrow("ended");
  });
});

describe("lease composition", () => {
  const ended: DeliveryLease = {
    refresh: async () => undefined,
    assertLocal() {
      throw new Error("ended");
    },
  };

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
