import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { DSTACK_KEY_BYTES, type DstackClient } from "../dstack/client.js";
import { createFakeDstackClient } from "../dstack/fake.js";
import { FIRST_EPOCH, userPsId } from "../identity/paths.js";
import {
  SEALED_ENVELOPE_VERSION,
  UnsealError,
  seal,
  sealingAad,
  unseal,
} from "./envelope.js";

const APP = "0000000000000000000000000000000000000001";
const OTHER_APP = "0000000000000000000000000000000000000002";
const OWNER = "0x1234567890AbcdEF1234567890aBcdef12345678" as const;
const USER_A = userPsId(14800, OWNER);
const USER_B = userPsId(14800, "0x0000000000000000000000000000000000000001");
const SIGNATURE_BYTES = 65;
const NEXT_EPOCH = FIRST_EPOCH + 1;

function captureKeys(base: DstackClient): {
  client: DstackClient;
  keys: Uint8Array[];
} {
  const keys: Uint8Array[] = [];
  const client: DstackClient = {
    ...base,
    deriveKey: async (path, purpose) => {
      const derived = await base.deriveKey(path, purpose);
      keys.push(derived.key);
      return derived;
    },
  };

  return { client, keys };
}

describe("seal / unseal", () => {
  it("round-trips on a second node with the same appId", async () => {
    const secret = new Uint8Array(randomBytes(SIGNATURE_BYTES));
    const nodeA = createFakeDstackClient({ appId: APP, instanceId: "a" });
    const nodeB = createFakeDstackClient({ appId: APP, instanceId: "b" });

    const envelope = await seal(nodeA, USER_A, FIRST_EPOCH, secret);
    const opened = await unseal(nodeB, USER_A, FIRST_EPOCH, envelope);

    expect(envelope.v).toBe(SEALED_ENVELOPE_VERSION);
    expect(Buffer.from(opened)).toEqual(Buffer.from(secret));
  });

  it("uses distinct IVs for content and key wrap", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const envelope = await seal(
      client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );

    expect(envelope.iv).not.toBe(envelope.wrappedContentKey.iv);
  });

  it("fails when presented for another user (AAD mismatch)", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const envelope = await seal(
      client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );

    await expect(
      unseal(client, USER_B, FIRST_EPOCH, envelope),
    ).rejects.toBeInstanceOf(UnsealError);
  });

  it("wrong epoch fails", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const envelope = await seal(
      client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );

    await expect(
      unseal(client, USER_A, NEXT_EPOCH, envelope),
    ).rejects.toBeInstanceOf(UnsealError);
  });

  it("fails under a different appId", async () => {
    const envelope = await seal(
      createFakeDstackClient({ appId: APP }),
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );

    await expect(
      unseal(
        createFakeDstackClient({ appId: OTHER_APP }),
        USER_A,
        FIRST_EPOCH,
        envelope,
      ),
    ).rejects.toBeInstanceOf(UnsealError);
  });

  it("fails on a tampered ciphertext byte", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const envelope = await seal(
      client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );
    const bytes = Buffer.from(envelope.ciphertext, "base64");
    bytes[0] ^= 1;

    await expect(
      unseal(client, USER_A, FIRST_EPOCH, {
        ...envelope,
        ciphertext: bytes.toString("base64"),
      }),
    ).rejects.toBeInstanceOf(UnsealError);
  });

  it("fails on a tampered wrapped key", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const envelope = await seal(
      client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );
    const bytes = Buffer.from(envelope.wrappedContentKey.tag, "base64");
    bytes[0] ^= 1;

    await expect(
      unseal(client, USER_A, FIRST_EPOCH, {
        ...envelope,
        wrappedContentKey: {
          ...envelope.wrappedContentKey,
          tag: bytes.toString("base64"),
        },
      }),
    ).rejects.toBeInstanceOf(UnsealError);
  });

  it("zeros derived sealing keys after seal and failed unseal", async () => {
    const captured = captureKeys(createFakeDstackClient({ appId: APP }));
    const envelope = await seal(
      captured.client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );
    const tag = Buffer.from(envelope.wrappedContentKey.tag, "base64");
    tag[0] ^= 1;

    expect(captured.keys[0]).toEqual(new Uint8Array(DSTACK_KEY_BYTES));
    await expect(
      unseal(captured.client, USER_A, FIRST_EPOCH, {
        ...envelope,
        wrappedContentKey: {
          ...envelope.wrappedContentKey,
          tag: tag.toString("base64"),
        },
      }),
    ).rejects.toBeInstanceOf(UnsealError);
    expect(captured.keys[1]).toEqual(new Uint8Array(DSTACK_KEY_BYTES));
  });

  it("rejects an unknown version", async () => {
    const client = createFakeDstackClient({ appId: APP });
    const envelope = await seal(
      client,
      USER_A,
      FIRST_EPOCH,
      new Uint8Array(SIGNATURE_BYTES),
    );

    await expect(
      unseal(client, USER_A, FIRST_EPOCH, {
        ...envelope,
        v: 2 as unknown as 1,
      }),
    ).rejects.toBeInstanceOf(UnsealError);
  });
});

describe("sealingAad", () => {
  it("encodes userPsId/epoch as UTF-8", () => {
    expect(sealingAad(USER_A, FIRST_EPOCH)).toEqual(
      Buffer.from(`${USER_A}/${FIRST_EPOCH}`, "utf8"),
    );
  });
});
