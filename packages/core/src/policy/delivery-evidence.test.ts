/**
 * What a lease's evidence carries, and how its age is measured.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { authorizeDataList } from "./data-read.js";
import {
  deliver,
  REMOTE_GRANT_REVERIFY_AFTER_MS,
  remoteEvidence,
} from "./delivery-lease.js";

afterEach(() => {
  vi.useRealTimers();
});

const owner = "0x0000000000000000000000000000000000000001" as const;
const builder = "0x0000000000000000000000000000000000000002" as const;

describe("a listing's evidence", () => {
  it("carries each grant's expiry, checked at release inside the 30 s window", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-21T19:00:00Z"));
    const grant = {
      id: "g",
      grantorAddress: owner,
      granteeId: builder,
      scopes: ["test.records"],
      revokedAt: null,
      expiresAt: "2026-10-21T19:00:05Z",
    };
    const getGrant = vi.fn(async () => grant);
    const { lease } = await authorizeDataList(
      { signer: builder, grantId: "g", serverOwner: owner },
      {
        authSessionVerifier: { getBuilder: async () => ({ id: builder }) },
        grantVerifier: { getGrant },
      } as never,
    );
    // 10 s later: the grant has expired; the evidence is still fresh.
    vi.setSystemTime(new Date("2026-10-21T19:00:10Z"));
    const release = vi.fn(() => "private-list");
    await expect(deliver(lease, release)).rejects.toMatchObject({
      errorCode: "GRANT_EXPIRED",
    });
    expect(release).not.toHaveBeenCalled();
    expect(getGrant).toHaveBeenCalledTimes(1);
  });
});

describe("evidence age", () => {
  it("does not make old evidence fresh when the wall clock moves backwards", async () => {
    let wall = 100_000;
    let refreshes = 0;
    const evidence = remoteEvidence(
      "old",
      async () => {
        refreshes += 1;
        return "new";
      },
      { now: () => wall },
    );
    wall = 40_000;
    await deliver(
      { evidence: () => [evidence], assertLocal: () => undefined },
      () => undefined,
      { now: () => wall },
    );
    expect(refreshes).toBeGreaterThan(0);
  });

  it("counts the monotonic clock too: a wall clock set back cannot hide age", async () => {
    vi.useFakeTimers({ toFake: ["Date", "performance"] });
    const evidence = remoteEvidence("old", async () => "new");
    // Monotonic time passes the bound while the wall clock is set back.
    vi.advanceTimersByTime(REMOTE_GRANT_REVERIFY_AFTER_MS + 1);
    vi.setSystemTime(Date.now() - 3_600_000);
    await deliver(
      { evidence: () => [evidence], assertLocal: () => undefined },
      () => undefined,
    );
    expect(evidence.current).toBe("new");
  });
});
