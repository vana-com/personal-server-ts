import { describe, expect, it, vi } from "vitest";
import { hexToBytes } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { userPsId } from "@opendatalabs/vana-sdk/protocol/identity";
import { createFakeDstackClient } from "../dstack/fake.js";
import { deriveEnclaveIdentity } from "../identity/wallet.js";
import { seal } from "../sealing/envelope.js";
import { MASTER_KEY_MESSAGE } from "../agent/seal.js";
import { resolveMcpRollbackIdentity } from "./rollback.js";

async function fixture(epoch = 2) {
  const account = privateKeyToAccount(`0x${"12".repeat(32)}`);
  const binding = { owner: account.address, chainId: 14800 };
  const id = userPsId(binding.chainId, binding.owner);
  const client = createFakeDstackClient({ appId: "a".repeat(40) });
  const derived = await deriveEnclaveIdentity(client, id, epoch);
  const signature = hexToBytes(
    await account.signMessage({ message: MASTER_KEY_MESSAGE }),
  );
  const identity = {
    userPsId: id,
    epoch,
    enclaveAddress: derived.address,
    enclavePublicKey: derived.publicKey,
    sealedEnvelope: await seal(client, id, epoch, signature),
  };
  signature.fill(0);
  const live = {
    state: "sealed",
    sealed: true,
    identity: {
      userPsId: id,
      epoch,
      ownerAddress: binding.owner,
      chainId: binding.chainId,
      address: derived.address,
      publicKey: derived.publicKey,
    },
  };
  const material = {
    owner: { chainId: binding.chainId, userPsId: id, identityEpoch: epoch },
    generation: 4,
    identity,
  };
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockImplementationOnce(async () => Response.json(live))
    .mockImplementationOnce(async () => Response.json(material));
  const deps = {
    client,
    chainId: binding.chainId,
    gatewayUrl: "https://gateway.example",
    nodeId: "recovery-node",
    nodeSecret: "node-secret",
    fetch,
  };
  return { binding, live, material, deps, identity, account };
}

describe("MCP rollback identity hydration", () => {
  it("recovers a fresh owner's latest sealed epoch without a cached identity or SDK prewarm", async () => {
    const f = await fixture();
    await expect(
      resolveMcpRollbackIdentity(f.binding, f.deps),
    ).resolves.toEqual({
      identity: f.identity,
      generation: 4,
    });
    const [url, init] = f.deps.fetch.mock.calls[1]!;
    expect(String(url)).toBe(
      "https://gateway.example/v1/fleet?action=recovery-envelope",
    );
    expect(init).toMatchObject({
      method: "POST",
      redirect: "error",
      headers: {
        "X-Node-Id": "recovery-node",
        Authorization: "Bearer node-secret",
      },
    });
    expect(JSON.parse(String(init?.body))).toEqual({ owner: f.material.owner });
  });

  it.each(["owner", "epoch", "chain", "generation", "address", "publicKey"])(
    "rejects a recovery response with a mismatched %s before key derivation",
    async (field) => {
      const f = await fixture();
      const derive = vi.spyOn(f.deps.client, "deriveKey");
      if (field === "owner") f.material.owner.userPsId = `0x${"00".repeat(32)}`;
      if (field === "epoch") f.material.identity.epoch = 1;
      if (field === "chain") f.material.owner.chainId = 1;
      if (field === "generation") f.material.generation = -1;
      if (field === "address")
        f.material.identity.enclaveAddress = f.account.address;
      if (field === "publicKey")
        f.material.identity.enclavePublicKey = f.account.publicKey;
      await expect(
        resolveMcpRollbackIdentity(f.binding, f.deps),
      ).rejects.toThrow("identity");
      expect(derive).not.toHaveBeenCalled();
    },
  );

  it.each(["retired", "owner", "epoch", "chain"])(
    "refuses a public identity with invalid %s before requesting recovery material",
    async (field) => {
      const f = await fixture();
      if (field === "retired") f.live.state = "retired";
      if (field === "owner")
        f.live.identity.ownerAddress = `0x${"00".repeat(20)}`;
      if (field === "epoch") f.live.identity.epoch = 0;
      if (field === "chain") f.live.identity.chainId = 1;
      await expect(
        resolveMcpRollbackIdentity(f.binding, f.deps),
      ).rejects.toThrow("identity");
      expect(f.deps.fetch).toHaveBeenCalledTimes(1);
    },
  );

  it.each([401, 403, 409])(
    "fails closed on recovery denial %s",
    async (status) => {
      const f = await fixture();
      f.deps.fetch
        .mockReset()
        .mockResolvedValueOnce(Response.json(f.live))
        .mockResolvedValueOnce(Response.json({ error: "denied" }, { status }));
      await expect(
        resolveMcpRollbackIdentity(f.binding, f.deps),
      ).rejects.toThrow("identity");
    },
  );

  it("rejects an envelope sealed for an older epoch", async () => {
    const f = await fixture();
    const old = await fixture(1);
    f.material.identity.sealedEnvelope = old.identity.sealedEnvelope;
    await expect(resolveMcpRollbackIdentity(f.binding, f.deps)).rejects.toThrow(
      "authentication failed",
    );
  });

  it("rejects a decryptable envelope containing another owner's signature", async () => {
    const f = await fixture();
    const other = privateKeyToAccount(`0x${"34".repeat(32)}`);
    const signature = hexToBytes(
      await other.signMessage({ message: MASTER_KEY_MESSAGE }),
    );
    f.material.identity.sealedEnvelope = await seal(
      f.deps.client,
      f.identity.userPsId,
      f.identity.epoch,
      signature,
    );
    signature.fill(0);
    await expect(resolveMcpRollbackIdentity(f.binding, f.deps)).rejects.toThrow(
      "identity",
    );
  });

  it("rejects a different app's keys even when Gateway material is internally consistent", async () => {
    const f = await fixture();
    f.deps.client = createFakeDstackClient({ appId: "b".repeat(40) });
    await expect(resolveMcpRollbackIdentity(f.binding, f.deps)).rejects.toThrow(
      "identity",
    );
  });

  it("bounds the response body and cancels an oversized stream", async () => {
    const f = await fixture();
    const cancel = vi.fn();
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(16 * 1024 + 1));
      },
      cancel,
    });
    f.deps.fetch.mockReset().mockResolvedValueOnce(new Response(stream));
    await expect(resolveMcpRollbackIdentity(f.binding, f.deps)).rejects.toThrow(
      "identity",
    );
    expect(cancel).toHaveBeenCalledOnce();
  });
});
