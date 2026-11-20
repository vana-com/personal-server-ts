import { deriveMasterKey } from "@opendatalabs/vana-sdk/browser";
import { describe, expect, it } from "vitest";
import { createStreamSyncKeyPorts } from "./crypto.js";

// Anvil account #0 over "vana-master-key-v1": low s, v = 27.
const SIGNATURE =
  "0x1f5c9b3bafc291e8ea7aa4e0c5700a109e68aa2431fdbea08b49f9bf91b5c7db2aaa192de5cdf866e5f9f5f39502a66bd696a1399a537eac8ffb826c00e4e1d51b" as const;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const r = SIGNATURE.slice(2, 66);
const s = BigInt("0x" + SIGNATURE.slice(66, 130));
const V01 = `0x${r}${SIGNATURE.slice(66, 130)}00` as const;
const HIGH_S = `0x${r}${(N - s).toString(16).padStart(64, "0")}1c` as const;

const message = new TextEncoder().encode("key-check");
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("createStreamSyncKeyPorts", () => {
  it("gives one K_ns for every encoding of the owner signature", async () => {
    const [a, b, c] = await Promise.all(
      [SIGNATURE, V01, HIGH_S].map((sig) =>
        createStreamSyncKeyPorts(sig).namespaceHmac(message),
      ),
    );
    expect(hex(b!)).toBe(hex(a!));
    expect(hex(c!)).toBe(hex(a!));
  });

  it("decrypts a part written under another encoding", async () => {
    const clear = new TextEncoder().encode("part bytes");
    const scope = "pdpp.c~.s";
    const cipher = await createStreamSyncKeyPorts(HIGH_S).encrypt(scope, clear);
    const back = await createStreamSyncKeyPorts(V01).decrypt(scope, cipher);
    expect(hex(back)).toBe(hex(clear));
  });

  it("opens both part encodings and scopes the STREAM key per scope", async () => {
    const keys = createStreamSyncKeyPorts(SIGNATURE);
    const clear = new Uint8Array(200_000).map((_, i) => i % 251);
    const stream = await keys.encryptPart("pdpp.c~.s", clear);
    expect(stream[0]).toBe(0x56);
    expect(hex(await keys.decrypt("pdpp.c~.s", stream))).toBe(hex(clear));
    const pgp = await keys.encrypt("pdpp.c~.s", clear);
    expect(hex(await keys.decrypt("pdpp.c~.s", pgp))).toBe(hex(clear));
    await expect(keys.decrypt("pdpp.c~.other", stream)).rejects.toThrow();
  });

  it("leaves the legacy master key on the raw signature bytes", () => {
    // Legacy keys are out of scope for normalization: encodings still differ.
    expect(hex(deriveMasterKey(HIGH_S))).not.toBe(
      hex(deriveMasterKey(SIGNATURE)),
    );
  });
});
