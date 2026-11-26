import { describe, expect, it, vi } from "vitest";
import { createLegacyRetireRemote } from "./legacy-retire-remote.js";
import {
  createLegacyGatewayFake,
  FAKE_CHAIN_ID,
  FAKE_GATEWAY,
  FAKE_STORAGE,
} from "../test-utils/legacy-gateway-fake.js";
import { legacyHeadFrom } from "./legacy-delete.js";
const owner = `0x${"11".repeat(20)}` as const;
async function fixture() {
  const fake = createLegacyGatewayFake({ owner, cutover: "v3" });
  fake.seed("github.events", 2);
  let ready = true;
  const check = () => {
    if (!ready) throw Error("revoked");
  };
  const options = {
    gatewayUrl: FAKE_GATEWAY,
    dataPointFeed: fake.feed,
    serverOwner: owner,
    signer: fake.signer,
    storage: {
      endpoint: FAKE_STORAGE,
      chainId: FAKE_CHAIN_ID,
      signMessage: async () => `0x${"ab".repeat(65)}` as `0x${string}`,
    },
    fetch: fake.fetch,
  };
  const head = await legacyHeadFrom(fake.feed, owner)("github.events");
  if (head.state !== "live") throw Error("fixture");
  return {
    fake,
    options,
    head,
    check,
    revoke: () => {
      ready = false;
    },
  };
}
describe("retirement transport authority", () => {
  for (const echo of [undefined, "9"])
    it(`rejects a success with echo ${echo}`, async () => {
      const f = await fixture();
      f.options.fetch = vi.fn(
        async () =>
          new Response(JSON.stringify({ data: { expectedVersion: echo } }), {
            status: 200,
          }),
      ) as typeof fetch;
      await expect(
        createLegacyRetireRemote(f.options).tombstone(
          "github.events",
          f.head,
          f.check,
        ),
      ).rejects.toThrow("pin + 1");
    });
  it("reports not sent when a foreign tombstone wins preflight", async () => {
    const f = await fixture();
    f.fake.foreignTombstone("github.events");
    await expect(
      createLegacyRetireRemote(f.options).tombstone(
        "github.events",
        f.head,
        f.check,
      ),
    ).resolves.toBe("not-sent");
    expect(f.fake.requests).toEqual([]);
  });
  it("revokes during tombstone signing before any HTTP request", async () => {
    const f = await fixture();
    f.options.signer = {
      signAddData: async () => {
        f.revoke();
        return "0x00";
      },
    };
    await expect(
      createLegacyRetireRemote(f.options).tombstone(
        "github.events",
        f.head,
        f.check,
      ),
    ).resolves.toBe("not-sent");
    expect(f.fake.requests).toEqual([]);
  });
  it("revokes during blob signing before any HTTP request", async () => {
    const f = await fixture();
    f.options.storage.signMessage = async () => {
      f.revoke();
      return `0x${"ab".repeat(65)}`;
    };
    await expect(
      createLegacyRetireRemote(f.options).eraseBlob(
        "github.events",
        "1",
        f.check,
      ),
    ).rejects.toThrow("revoked");
    expect(f.fake.requests).toEqual([]);
  });
});
