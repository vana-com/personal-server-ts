/**
 * `viewCoverage` answers "do the stream views cover this legacy scope, and up
 * to when": the question a legacy delete asks.
 */

import { describe, expect, it } from "vitest";
import {
  alternateLegacyBindingsForScope,
  LEGACY_SCOPE_BINDINGS,
} from "../legacy-projection/index.js";
import { Fixture, masterKey } from "./service-fixture.js";
import { testOwnerKey } from "./testing.js";

const OBSERVED = Date.parse("2026-11-03T00:00:00Z");

async function setup(seed: number) {
  const f = new Fixture(await testOwnerKey(await masterKey(seed)));
  const ns = await f.key.ns("acme", "account-1");
  await f.activate("acme", ns);
  return { f, ns };
}

describe("viewCoverage", () => {
  it("covers a complete live view, through the head's observation time", async () => {
    const { f, ns } = await setup(901);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: true,
      observedAt: OBSERVED,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "covered",
      throughMs: OBSERVED,
    });
  });

  it("skips an incomplete view", async () => {
    const { f, ns } = await setup(902);
    await f.publish({
      connector: "acme",
      ns,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: false,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "skip",
      reason: "incomplete",
    });
  });

  it("skips an unknown connector, a physical name and an unlisted mirror", async () => {
    const { f } = await setup(903);
    const service = await f.service();
    expect(service.viewCoverage("pdpp.acme.items").kind).toBe("skip");
    await f.sync(service);
    expect(service.viewCoverage("pdpp.other.items").kind).toBe("skip");
    expect(service.viewCoverage("pdpp.acme~0123456789abcdef.items").kind).toBe(
      "skip",
    );
  });

  it("does not count another owner's head: a connection under a foreign key is not a view", async () => {
    const f = new Fixture(await testOwnerKey(await masterKey(904)));
    const other = await testOwnerKey(await masterKey(905));
    const otherNs = await other.ns("acme", "account-1");
    await f.activate("acme", otherNs, other);
    await f.publish({
      connector: "acme",
      ns: otherNs,
      stream: "items",
      generation: 1,
      records: [{ id: "a" }],
      complete: true,
      key: other,
    });
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items").kind).toBe("skip");
  });

  it("is ambiguous when the connector has two active connections", async () => {
    const { f, ns } = await setup(906);
    const second = await f.key.ns("acme", "account-2");
    await f.activate("acme", second);
    for (const n of [ns, second]) {
      await f.publish({
        connector: "acme",
        ns: n,
        stream: "items",
        generation: 1,
        records: [{ id: n }],
        complete: true,
      });
    }
    const service = await f.service();
    await f.sync(service);
    expect(service.viewCoverage("pdpp.acme.items")).toEqual({
      kind: "skip",
      reason: "ambiguous",
    });
  });

  describe("a scope with an alternate binding has more than one target", () => {
    // A scope whose alternate binding is read from another connector.
    const scope = "oura.sleep";
    const original = LEGACY_SCOPE_BINDINGS.get(scope)!;
    const originalConnector = original.pdppSource.slice(
      original.pdppSource.lastIndexOf("/") + 1,
    );
    const [profileKey, alternate] = [
      ...alternateLegacyBindingsForScope(scope),
    ][0]!;

    async function publishTarget(
      f: Fixture,
      connector: string,
      streams: readonly string[],
      complete = true,
    ) {
      const ns = await f.key.ns(connector, "account-1");
      await f.activate(connector, ns);
      for (const stream of streams) {
        await f.publish({
          connector,
          ns,
          stream,
          generation: 1,
          records: [{ id: "a" }],
          complete,
          observedAt: OBSERVED,
        });
      }
    }

    it("covers only when EVERY target is complete", async () => {
      expect(profileKey).not.toBe(originalConnector);
      const f = new Fixture(await testOwnerKey(await masterKey(910)));
      await publishTarget(f, originalConnector, original.pdppStreams);
      // The alternate target is known but its head is incomplete.
      await publishTarget(f, profileKey, alternate.pdppStreams, false);
      const service = await f.service();
      await f.sync(service);
      expect(service.viewCoverage(scope).kind).toBe("skip");

      const ns = await f.key.ns(profileKey, "account-1");
      for (const stream of alternate.pdppStreams) {
        await f.publish({
          connector: profileKey,
          ns,
          stream,
          generation: 1,
          records: [{ id: "b" }],
          complete: true,
          observedAt: OBSERVED,
        });
      }
      await f.sync(service);
      expect(service.viewCoverage(scope)).toEqual({
        kind: "covered",
        throughMs: OBSERVED,
      });
    });
  });
});
