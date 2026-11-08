import { describe, expect, it, vi } from "vitest";
import * as names from "@opendatalabs/personal-server-ts-stream-sync";
import {
  logicalStreamScopeParts,
  streamReadScope,
  isPhysicalScope,
} from "../stream-sync-read/routing.js";
import { isPhysicalScope as writerIsPhysicalScope } from "./scope-routing.js";
import { manifestArtifact } from "./artifacts.js";
import { RunIntakeError, StreamSyncIntake } from "./intake.js";

describe("stream-sync names at intake and read boundaries", () => {
  it("uses the shared parser and one physical predicate, without a second grammar", () => {
    expect(logicalStreamScopeParts).toBe(names.parseLogicalStreamScope);
    expect(isPhysicalScope).toBe(names.isPhysicalScope);
    expect(writerIsPhysicalScope).toBe(names.isPhysicalScope);
  });

  it("maps a physical dotted stream without changing its connector identity", () => {
    expect(streamReadScope("pdpp.a~.b.s")).toBe("pdpp.a.b.s");
    expect(logicalStreamScopeParts(streamReadScope("pdpp.a~.b.s")!)).toEqual({
      connector: "a",
      stream: "b.s",
    });
    expect(streamReadScope("pdpp.a.b~.s")).toBeNull();
    for (const name of [
      "pdpp.a~",
      "pdpp.a~0123456789abcdef.s",
      "pdpp.a.b/c",
      "pdpp.a.b\\c",
      "pdpp.a.b c",
      "pdpp.a.b\nc",
    ]) {
      expect(streamReadScope(name)).toBeNull();
    }
    for (const name of ["pdpp.a~.s", "pdpp.a~", "x~y", "pdpp.a.b~.s"]) {
      expect(isPhysicalScope(name)).toBe(true);
      expect(writerIsPhysicalScope(name)).toBe(true);
    }
    expect(isPhysicalScope("pdpp.a.b.s")).toBe(false);
  });

  it("refuses a dotted connector as invalid_request before any writer or artifact access", async () => {
    const writerAccess: string[] = [];
    // Every possible writer entry is guarded, including binding and controls.
    // Therefore neither its spool nor outbox can be reached by a rejected begin.
    const writer = new Proxy(
      {},
      {
        get(_target, key) {
          writerAccess.push(String(key));
          throw new Error(`unexpected writer access: ${String(key)}`);
        },
      },
    ) as ConstructorParameters<typeof StreamSyncIntake>[0]["writer"];
    const resolveArtifact = vi.fn(() => null);
    const deleting = vi.fn(() => false);
    const intake = new StreamSyncIntake({ writer, resolveArtifact, deleting });
    for (const connector of ["a.b", ".a", "a."]) {
      const error = await intake
        .begin("dotted-name", {
          connector,
          artifactDigest: "verified-fixture",
          owner: { address: `0x${"1".repeat(40)}`, leaseId: null },
        })
        .catch((error: unknown) => error);
      expect(error).toBeInstanceOf(RunIntakeError);
      expect(error).toMatchObject({ code: "invalid_request", status: 400 });
    }
    expect(writerAccess).toEqual([]);
    expect(resolveArtifact).not.toHaveBeenCalled();
    expect(deleting).not.toHaveBeenCalled();
  });

  it("validates manifest connector names with the same builder and preserves dotted streams", () => {
    const document = (connector: string) =>
      JSON.stringify({
        connector_key: connector,
        version: "1",
        streams: [
          { name: "b.s", primary_key: ["id"], semantics: "mutable_state" },
        ],
      });
    expect(manifestArtifact(document("a.b"))).toBeNull();
    expect(manifestArtifact(document("a-_09"))?.declarations).toMatchObject({
      connector: "a-_09",
      streams: [{ name: "b.s" }],
    });
  });

  it("a refused begin leaves its run id free for a valid connector and dotted stream", async () => {
    const address = `0x${"1".repeat(40)}`;
    const beginRun = vi.fn(async () => ({
      collectionMode: "incremental",
      state: null,
      keyCheck: "fixture-key",
    }));
    const writer = {
      binding: async () => ({ owner: address, keyCheck: "fixture-key" }),
      hasControls: () => true,
      beginRun,
      stuck: async () => false,
    } as unknown as ConstructorParameters<typeof StreamSyncIntake>[0]["writer"];
    const intake = new StreamSyncIntake({
      writer,
      resolveArtifact: () => ({
        connector: "a-_09",
        version: "1",
        streams: [
          { name: "b.s", semantics: "mutable_state", primaryKey: ["id"] },
        ],
      }),
    });
    const request = {
      connector: "a.b",
      artifactDigest: "verified-fixture",
      owner: { address, leaseId: null },
    };
    const refused = await intake
      .begin("reuse", request)
      .catch((error: unknown) => error);
    expect(refused).toMatchObject({ code: "invalid_request", status: 400 });
    expect(beginRun).not.toHaveBeenCalled();
    const accepted = await intake.begin("reuse", {
      ...request,
      connector: "a-_09",
    });
    expect(accepted).toMatchObject({
      status: "collecting",
      streams: [{ name: "b.s" }],
    });
    expect(beginRun.mock.calls.length).toBe(1);
  });
});
