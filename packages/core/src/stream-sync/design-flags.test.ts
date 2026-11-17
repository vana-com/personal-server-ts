import { describe, expect, it } from "vitest";
import {
  STREAM_SYNC_DESIGN_FLAGS,
  STREAM_SYNC_FLAGS_ENV,
  streamSyncFlagsOn,
} from "./design-flags.js";

describe("the stream-sync design flags: one table", () => {
  it("names each flag once, with its own environment variable", () => {
    const names = STREAM_SYNC_DESIGN_FLAGS.map((flag) => flag.name);
    const envs = STREAM_SYNC_DESIGN_FLAGS.map((flag) => flag.env);
    expect(new Set(names).size).toBe(names.length);
    expect(new Set(envs).size).toBe(envs.length);
    expect(names).toEqual(["publishWhileCollecting", "progressiveFirstLoad"]);
  });

  it("is all off with no list and no environment", () => {
    expect(streamSyncFlagsOn(undefined)).toEqual({
      publishWhileCollecting: false,
      progressiveFirstLoad: false,
    });
  });

  it("turns on the flags a comma list names, ignoring blanks, spaces and unknown names", () => {
    expect(
      streamSyncFlagsOn(
        " publishWhileCollecting , nonsense,,progressiveFirstLoad ",
      ),
    ).toEqual({
      publishWhileCollecting: true,
      progressiveFirstLoad: true,
    });
  });

  it("does not find a name on the object prototype", () => {
    expect(streamSyncFlagsOn("constructor,__proto__,toString")).toEqual({
      publishWhileCollecting: false,
      progressiveFirstLoad: false,
    });
  });

  it("reads the list variable and each flag's own variable from an environment", () => {
    expect(
      streamSyncFlagsOn(undefined, {
        [STREAM_SYNC_FLAGS_ENV]: "progressiveFirstLoad",
      }),
    ).toMatchObject({
      progressiveFirstLoad: true,
      publishWhileCollecting: false,
    });
    for (const flag of STREAM_SYNC_DESIGN_FLAGS) {
      expect(
        streamSyncFlagsOn(undefined, { [flag.env]: "true" })[flag.name],
      ).toBe(true);
      // Only the exact word "true" turns a per-flag variable on.
      expect(streamSyncFlagsOn(undefined, { [flag.env]: "1" })[flag.name]).toBe(
        false,
      );
    }
  });

  it("joins the list option and the environment", () => {
    expect(
      streamSyncFlagsOn("progressiveFirstLoad", {
        PS_PUBLISH_WHILE_COLLECTING: "true",
      }),
    ).toMatchObject({
      progressiveFirstLoad: true,
      publishWhileCollecting: true,
    });
  });

  it("accepts the name of the removed logProtocol flag and its variable, and ignores both", () => {
    // The connection log is the only protocol: a host that still passes the old
    // name is not refused, and the name turns nothing on.
    const off = {
      publishWhileCollecting: false,
      progressiveFirstLoad: false,
    };
    expect(streamSyncFlagsOn("logProtocol")).toEqual(off);
    expect(
      streamSyncFlagsOn(undefined, {
        [STREAM_SYNC_FLAGS_ENV]: "logProtocol",
        PS_STREAM_SYNC_LOG_PROTOCOL: "true",
      }),
    ).toEqual(off);
  });
});
