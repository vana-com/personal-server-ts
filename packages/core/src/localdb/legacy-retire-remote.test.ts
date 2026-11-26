import { describe, expect, it, vi } from "vitest";
import { LegacyTombstoneUnacknowledged } from "./legacy-retire-pipeline.js";
import { createLegacyRetireRemote } from "./legacy-retire-remote.js";
import {
  createLegacyGatewayFake,
  FAKE_CHAIN_ID,
  FAKE_GATEWAY,
  FAKE_STORAGE,
} from "../test-utils/legacy-gateway-fake.js";
import { legacyHeadFrom } from "./legacy-delete.js";
import { GATEWAY_ALREADY_DELETED_CODES } from "../sync/gateway-refusal.js";
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

it("reports not applied for the exact already-deleted 409 after sending DELETE", async () => {
  const f = await fixture();
  f.fake.state.race = "already-deleted";
  await expect(
    createLegacyRetireRemote(f.options).tombstone(
      "github.events",
      f.head,
      f.check,
    ),
  ).resolves.toBe("not-applied");
  expect(f.fake.requests.filter((r) => r.method === "DELETE")).toHaveLength(1);
});

it.each(GATEWAY_ALREADY_DELETED_CODES)(
  "reports not applied for the 409 code %s the shared already-deleted list admits",
  async (code) => {
    const f = await fixture();
    f.options.fetch = async () =>
      new Response(JSON.stringify({ code }), { status: 409 });
    await expect(
      createLegacyRetireRemote(f.options).tombstone(
        "github.events",
        f.head,
        f.check,
      ),
    ).resolves.toBe("not-applied");
  },
);

it.each([
  [400, "owner_stream_head_already_deleted"],
  [409, "other_conflict"],
  [409, "owner_stream_head_already_deleted_extra"],
])("does not classify HTTP %s code %s as not applied", async (status, code) => {
  const f = await fixture();
  f.options.fetch = async () =>
    new Response(JSON.stringify({ code }), { status });
  await expect(
    createLegacyRetireRemote(f.options).tombstone(
      "github.events",
      f.head,
      f.check,
    ),
  ).rejects.toThrow();
});

it("propagates an aborted reply body without classifying it as malformed", async () => {
  const f = await fixture();
  const abort = new DOMException("reply body aborted", "AbortError");
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.error(abort);
      },
    }),
    { status: 200 },
  );
  const text = vi.spyOn(response, "text");
  f.options.fetch = async () => response;
  const attempt = createLegacyRetireRemote(f.options).tombstone(
    "github.events",
    f.head,
    f.check,
  );
  await expect(attempt).rejects.not.toBeInstanceOf(
    LegacyTombstoneUnacknowledged,
  );
  await expect(attempt).rejects.toBe(abort);
  expect(text).toHaveBeenCalledOnce();
});
