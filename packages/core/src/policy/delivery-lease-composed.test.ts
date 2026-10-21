/**
 * Composed leases: every piece of remote evidence must be fresh at the moment
 * of the release, not only the piece refreshed last. Uses only `deliver`,
 * `allDeliveryLeases` and `authorizeDataRead`.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { allDeliveryLeases, deliver } from "./delivery-lease.js";
import { authorizeDataRead } from "./data-read.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("composed grant leases", () => {
  it("refuses grant A revoked remotely while grant B's slow re-check runs", async () => {
    const owner = "0x0000000000000000000000000000000000000001" as const;
    const builder = "0x0000000000000000000000000000000000000002" as const;
    const scope = "test.records";
    vi.useFakeTimers({ toFake: ["Date"] });
    let revoked = false;
    let bCalls = 0;
    const input = {
      signer: builder,
      grantId: "g",
      requestedScope: scope,
      serverOwner: owner,
    };
    const grant = {
      id: "g",
      grantorAddress: owner,
      granteeId: builder,
      scopes: [scope],
      revokedAt: null,
      expiresAt: null,
    };
    const ports = (getGrant: () => Promise<unknown>) => ({
      authSessionVerifier: { getBuilder: async () => ({ id: builder }) },
      grantVerifier: { getGrant },
    });
    const a = await authorizeDataRead(
      input,
      ports(async () => ({
        ...grant,
        revokedAt: revoked ? "2026-10-21T00:00:00Z" : null,
      })) as never,
    );
    const b = await authorizeDataRead(
      input,
      ports(async () => {
        bCalls += 1;
        if (bCalls === 2) {
          // While B is re-checked (60 s), A is revoked on the gateway.
          revoked = true;
          vi.setSystemTime(Date.now() + 60_000);
        }
        return grant;
      }) as never,
    );
    vi.setSystemTime(Date.now() + 31_000);
    const release = vi.fn();
    await expect(
      deliver(allDeliveryLeases(a.lease, b.lease), release),
    ).rejects.toMatchObject({ errorCode: "GRANT_REVOKED" });
    expect(release).not.toHaveBeenCalled();
  });
});
