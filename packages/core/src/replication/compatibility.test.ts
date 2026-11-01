import { describe, expect, it } from "vitest";
import { verifyMessage } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { retryFromError } from "./outcome.js";
import {
  assertReplicaPublicationCompatible,
  createGatewayReplicaCompatibility,
  ReplicaPublicationBlockedError,
  type ReplicaCompatibilityRoster,
} from "./compatibility.js";

const capable = (address: string) => ({
  address,
  name: `Server ${address.slice(-2)}`,
  registrationId: `0x${"a".repeat(64)}`,
  revokedAt: null,
  readerFormats: ["fragments-v2"],
  capabilityValid: true,
});
const roster = (
  ...devices: ReturnType<typeof capable>[]
): ReplicaCompatibilityRoster => ({
  complete: true,
  epoch: 7,
  devices,
});

describe("replica publication compatibility", () => {
  it("advertises a signed declaration, checks the full roster, then asks the gateway to persist the reader floor", async () => {
    const requests: { url: string; init?: RequestInit }[] = [];
    const account = privateKeyToAccount(`0x${"1".repeat(64)}`);
    const signer = {
      address: account.address,
      signMessage: (message: string) => account.signMessage({ message }),
    };
    const check = createGatewayReplicaCompatibility({
      gatewayUrl: "https://gateway.test/",
      chainId: 14800,
      owner: "0x0000000000000000000000000000000000000009",
      signer,
      bootId: "boot-1",
      now: () => Date.parse("2026-11-01T12:00:00Z"),
      fetch: async (url, init) => {
        requests.push({ url: String(url), init });
        if (init?.method === "POST" && url.endsWith("replica-capabilities")) {
          const body = JSON.parse(String(init.body)) as Record<
            string,
            string | string[]
          >;
          const { signature, ...statement } = body;
          expect(
            await verifyMessage({
              address: signer.address,
              message: `vana.replica-reader-capability.v1\n${JSON.stringify(statement)}`,
              signature: signature as `0x${string}`,
            }),
          ).toBe(true);
          return Response.json({ success: true });
        }
        if (init?.method === "POST") {
          const body = JSON.parse(String(init.body)) as Record<string, string>;
          const { signature, ...statement } = body;
          expect(
            await verifyMessage({
              address: signer.address,
              message: `vana.replica-publication-authorization.v1\n${JSON.stringify(statement)}`,
              signature: signature as `0x${string}`,
            }),
          ).toBe(true);
          return Response.json({
            success: true,
            epoch: "8",
            minimumReaderFormats: ["fragments-v2"],
          });
        }
        if (url.includes("replica-capabilities"))
          return Response.json({
            owner: "0x0000000000000000000000000000000000000009",
            server: signer.address,
            registrationId: `0x${"a".repeat(64)}`,
            revision: "4",
            challenge: `0x${"b".repeat(64)}`,
            expiresAt: "2026-11-01T12:02:00Z",
            gatewayOrigin: "https://gateway.test",
            chainId: "14800",
          });
        return Response.json({
          complete: true,
          owner: "0x0000000000000000000000000000000000000009",
          epoch: "7",
          minimumReaderFormats: [],
          devices: [
            {
              address: signer.address,
              name: null,
              registrationId: `0x${"a".repeat(64)}`,
              revokedAt: null,
              readerFormats: ["fragments-slash-v1", "fragments-v2"],
              capabilityValid: true,
            },
          ],
        });
      },
    });
    const answer = await check();
    expect(answer).toMatchObject({
      epoch: 8,
      minimumReaderFormats: ["fragments-v2"],
    });
    expect(requests).toHaveLength(4);
    expect(JSON.parse(String(requests[1]!.init?.body))).toMatchObject({
      bootId: "boot-1",
      revision: "5",
      challenge: `0x${"b".repeat(64)}`,
      gatewayOrigin: "https://gateway.test",
      chainId: "14800",
    });
    expect(JSON.parse(String(requests[3]!.init?.body))).toMatchObject({
      expectedEpoch: "7",
      writeFormat: "fragments-v2",
    });
  });

  it("blocks unknown active readers, including offline devices, by name", () => {
    const old = { ...capable("0x0002"), readerFormats: [], online: false };
    expect(() =>
      assertReplicaPublicationCompatible(roster(capable("0x0001"), old)),
    ).toThrowError(ReplicaPublicationBlockedError);
    try {
      assertReplicaPublicationCompatible(roster(old));
    } catch (error) {
      expect(error).toMatchObject({
        blockers: [
          {
            address: "0x0002",
            name: "Server 02",
            reason: "reader_format_unsupported",
          },
        ],
      });
      expect(retryFromError(error, "publish_failed")).toMatchObject({
        problem: "publication_blocked",
        cause: { blockers: [{ address: "0x0002", name: "Server 02" }] },
      });
    }
  });

  it("allows publication when every active reader supports the format", () => {
    expect(
      assertReplicaPublicationCompatible(
        roster(capable("0x0001"), capable("0x0002")),
      ),
    ).toEqual({ epoch: 7, format: "fragments-v2" });
  });

  it("fails closed on incomplete rosters and releases a blocker only after revocation", () => {
    expect(() =>
      assertReplicaPublicationCompatible({
        complete: false,
        epoch: 7,
        devices: [],
      }),
    ).toThrowError("replica_roster_incomplete");
    const removed = { ...capable("0x0002"), revokedAt: "2026-11-01T00:00:00Z" };
    expect(
      assertReplicaPublicationCompatible(roster(capable("0x0001"), removed)),
    ).toEqual({ epoch: 7, format: "fragments-v2" });
  });
});
