import { describe, expect, it } from "vitest";
import { InvalidArgumentError } from "./errors.js";
import { controlHashes, deriveKeyCheck, deriveNs } from "./namespace.js";
import { keccak256, nodePorts, testHmac } from "./test-support/ports.js";

describe("namespace", () => {
  it("separates accounts and connectors, and is stable", async () => {
    const a = await deriveNs(testHmac, "chatgpt", "u1");
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(await deriveNs(testHmac, "chatgpt", "u1")).toBe(a);
    expect(await deriveNs(testHmac, "chatgpt", "u2")).not.toBe(a);
    expect(await deriveNs(testHmac, "spotify", "u1")).not.toBe(a);
  });

  it("does not collide on connector/account boundary shifts", async () => {
    // canonicalJson([c, accountId]) keeps the boundary, unlike c + accountId.
    expect(await deriveNs(testHmac, "ab", "c")).not.toBe(
      await deriveNs(testHmac, "a", "bc"),
    );
  });

  it("depends on the key", async () => {
    const other = nodePorts.namespaceHmac(new Uint8Array(32).fill(9));
    expect(await deriveKeyCheck(other)).not.toBe(
      await deriveKeyCheck(testHmac),
    );
    expect(await deriveNs(other, "c", "u")).not.toBe(
      await deriveNs(testHmac, "c", "u"),
    );
  });

  it("binds ACTIVE_DATA to the key check", async () => {
    const one = await controlHashes(keccak256, "0000000000000000");
    const two = await controlHashes(keccak256, "0000000000000001");
    expect(one.activeData).not.toBe(two.activeData);
    expect(one.activeMetadata).toBe(two.activeMetadata);
    expect(one.tombstoneData).toBe(
      "0x30c45ee72fe56d1927701316925ab7ceacd3b6f9267061735d59396f075c6222",
    );
  });

  it("rejects bad inputs", async () => {
    await expect(deriveNs(testHmac, "c", "")).rejects.toThrow(
      InvalidArgumentError,
    );
    await expect(
      deriveNs(async () => new Uint8Array(4), "c", "u"),
    ).rejects.toThrow(InvalidArgumentError);
    await expect(controlHashes(keccak256, "XYZ")).rejects.toThrow(
      InvalidArgumentError,
    );
  });
});
