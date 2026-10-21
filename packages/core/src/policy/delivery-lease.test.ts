import { describe, expect, it, vi } from "vitest";
import {
  allDeliveryLeases,
  REMOTE_GRANT_REVERIFY_AFTER_MS,
  remoteReverification,
} from "./delivery-lease.js";

describe("remoteReverification", () => {
  it("trusts the admitting verification for 30 s, then asks again", async () => {
    let now = 1_000;
    const reverify = vi.fn(async () => undefined);
    const check = remoteReverification(reverify, { now: () => now });

    now += REMOTE_GRANT_REVERIFY_AFTER_MS - 1;
    await check();
    expect(reverify).not.toHaveBeenCalled();

    now += 1;
    await check();
    expect(reverify).toHaveBeenCalledTimes(1);

    // A success restarts the window.
    now += REMOTE_GRANT_REVERIFY_AFTER_MS - 1;
    await check();
    expect(reverify).toHaveBeenCalledTimes(1);
  });

  it("propagates a refusal and keeps asking until one succeeds", async () => {
    let now = 0;
    const reverify = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error("revoked"))
      .mockResolvedValue(undefined);
    const check = remoteReverification(reverify, { now: () => now });
    now = REMOTE_GRANT_REVERIFY_AFTER_MS;
    await expect(check()).rejects.toThrow("revoked");
    await check();
    expect(reverify).toHaveBeenCalledTimes(2);
  });
});

describe("allDeliveryLeases", () => {
  it("holds only while every lease holds", async () => {
    const live = { assertDeliverable: async () => undefined };
    const ended = {
      assertDeliverable: async () => {
        throw new Error("ended");
      },
    };
    await expect(
      allDeliveryLeases(live, undefined).assertDeliverable(),
    ).resolves.toBeUndefined();
    await expect(
      allDeliveryLeases(live, ended).assertDeliverable(),
    ).rejects.toThrow("ended");
  });
});
