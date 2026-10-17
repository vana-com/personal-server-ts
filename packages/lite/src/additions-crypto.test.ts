import { describe, expect, it } from "vitest";
import { createMessage, encrypt, enums } from "openpgp";
import {
  decryptWithPassword,
  encryptWithPassword,
} from "@opendatalabs/vana-sdk/browser";
import { AdditionsBudget } from "@opendatalabs/personal-server-ts-core/additions";
import { decryptBoundedAdditions } from "./additions-crypto.js";

describe("installed SDK-compatible bounded worker crypto", () => {
  it("decrypts SDK binary envelopes and preserves SDK-readable output", async () => {
    const plaintext = new TextEncoder().encode(
      '{"scope":"test.profile","data":{"name":"test"}}',
    );
    const encrypted = await encryptWithPassword(plaintext, "disposable");
    expect(
      await decryptBoundedAdditions(
        encrypted,
        "disposable",
        new AdditionsBudget(100_000),
      ),
    ).toEqual(plaintext);
    expect(await decryptWithPassword(encrypted, "disposable")).toEqual(
      plaintext,
    );
    await expect(
      decryptBoundedAdditions(
        encrypted,
        "disposable",
        new AdditionsBudget(encrypted.length * 4 - 1),
      ),
    ).rejects.toThrow("budget");
  });

  it("rejects compressed tag-8 packets before the decoder can expand historical data", async () => {
    const encrypted = await encrypt({
      message: await createMessage({
        binary: new Uint8Array(4 * 1024 * 1024).fill(65),
      }),
      passwords: ["disposable"],
      format: "binary",
      config: { preferredCompressionAlgorithm: enums.compression.zlib },
    });
    expect(encrypted.byteLength).toBeLessThan(32_000);
    await expect(
      decryptBoundedAdditions(
        encrypted,
        "disposable",
        new AdditionsBudget(256_000),
      ),
    ).rejects.toThrow("Compressed OpenPGP packets are unsupported");
  });
});
