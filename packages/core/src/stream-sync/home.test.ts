import { describe, expect, it } from "vitest";
import {
  bindStreamSyncHome,
  createMemoryStreamSyncFiles,
  streamSyncHomeId,
  streamSyncNetwork,
} from "./index.js";

const A = "0x1C5A77d9FA7eF466951B2F01F724BCa3A5820b63";
const B = "0x2000000000000000000000000000000000000002";

describe("stream-sync home", () => {
  it("names a home by owner and network only, without raw values", () => {
    const net = streamSyncNetwork({ chainId: 14800, url: "https://g.test/x" });
    expect(net).toBe("vana:14800:https://g.test");
    const id = streamSyncHomeId({ ownerAddress: A, network: net });
    expect(id).toMatch(/^[0-9a-f]{32}$/);
    expect(
      streamSyncHomeId({ ownerAddress: A.toLowerCase(), network: net }),
    ).toBe(id);
    expect(streamSyncHomeId({ ownerAddress: B, network: net })).not.toBe(id);
    expect(
      streamSyncHomeId({
        ownerAddress: A,
        network: streamSyncNetwork({ chainId: 1480, url: "https://g.test" }),
      }),
    ).not.toBe(id);
  });

  it("asks the host for files by the home id", () => {
    const asked: string[] = [];
    const home = bindStreamSyncHome({
      ownerAddress: A as `0x${string}`,
      network: "n",
      open: (id) => {
        asked.push(id);
        return createMemoryStreamSyncFiles();
      },
    });
    expect(asked).toEqual([home.id]);
  });
});
