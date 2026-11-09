import { streamScope } from "@opendatalabs/personal-server-ts-stream-sync";
import { describe, expect, it } from "vitest";
import { ask, body, Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";
import { eligible } from "../../../stream-sync/src/eligible.js";

describe("one-store per-stream eligibility", () => {
  it.each([true, false])(
    "mid-publish keeps the last complete head (owner=%s), including restart",
    async (isOwnerView) => {
      const f = new Fixture(await testOwnerKey(masterKey(4)));
      const ns = await f.key.ns("meta", "account-1");
      await f.activate("meta", ns);
      for (const stream of ["posts", "post_likes"]) {
        await f.publish({
          connector: "meta",
          ns,
          stream,
          generation: 1,
          complete: true,
          records:
            stream === "posts"
              ? [{ id: "complete", media_url: "complete.png" }]
              : [
                  {
                    id: "like",
                    liker_ordinal: 0,
                    post_id: "complete",
                    user_id: "u1",
                    username: "reader",
                  },
                ],
        });
      }
      let service = await f.service();
      await f.sync(service);
      await f.publish({
        connector: "meta",
        ns,
        stream: "posts",
        generation: 1,
        complete: false,
        records: [{ id: "partial" }],
      });
      await f.sync(service);
      for (let restart = 0; restart < 2; restart++) {
        const decision = await service.resolve(
          ask("instagram.posts", { streamOnly: true, isOwnerView }),
        );
        expect(decision.kind).toBe("view");
        const result = await body(decision);
        expect(result.data.posts).toMatchObject([
          { img_url: "complete.png", who_liked: [{ username: "reader" }] },
        ]);
        expect(
          await service.listScopes({ streamOnly: true, isOwnerView }),
        ).toContainEqual(expect.objectContaining({ scope: "instagram.posts" }));
        service = await f.service();
      }
    },
  );

  it.each([true, false])(
    "never-complete stream keeps the alias unreadable (owner=%s)",
    async (isOwnerView) => {
      const f = new Fixture(await testOwnerKey(masterKey(4)));
      const ns = await f.key.ns("meta", "account-1");
      await f.activate("meta", ns);
      await f.publish({
        connector: "meta",
        ns,
        stream: "posts",
        generation: 1,
        complete: true,
        records: [],
      });
      await f.publish({
        connector: "meta",
        ns,
        stream: "post_likes",
        generation: 1,
        complete: false,
        records: [],
      });
      const service = await f.service();
      await f.sync(service);
      expect(
        await service.resolve(
          ask("instagram.posts", { streamOnly: true, isOwnerView }),
        ),
      ).toMatchObject({ kind: "unavailable", reason: "no_data" });
      const connections = service.connectionViews("meta", undefined, true);
      expect(
        eligible({
          connections,
          target: { kind: "logical", streams: ["posts", "post_likes"] },
          legacyFile: false,
        }),
      ).toEqual({ kind: "unavailable", reason: "no_data" });
      expect(
        await service.listScopes({ streamOnly: true, isOwnerView }),
      ).not.toContainEqual(
        expect.objectContaining({ scope: "instagram.posts" }),
      );
    },
  );
});

it("does not resurrect the retained complete head after a tombstone is replaced by an incomplete publish", async () => {
  const f = new Fixture(await testOwnerKey(masterKey(4)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    complete: true,
    records: [{ id: "deleted" }],
  });
  const service = await f.service();
  await f.sync(service);
  const scope = streamScope("acme", ns, "items");
  f.rows.set(scope, {
    scope,
    ...(await f.key.control()).tombstone,
    expectedVersion: "2",
    addedAt: null,
    deletedAt: new Date().toISOString(),
  });
  await f.sync(service);
  expect(
    await service.resolve(ask("pdpp.acme.items", { streamOnly: true })),
  ).toMatchObject({ kind: "unavailable", reason: "deleted" });
  await f.publish({
    connector: "acme",
    ns,
    stream: "items",
    generation: 1,
    complete: false,
    records: [{ id: "partial" }],
  });
  await f.sync(service);
  for (const reader of [service, await f.service()]) {
    expect(
      await reader.resolve(ask("pdpp.acme.items", { streamOnly: true })),
    ).toMatchObject({ kind: "unavailable", reason: "no_data" });
    expect(
      await reader.listScopes({ streamOnly: true, isOwnerView: true }),
    ).toEqual([]);
  }
});
