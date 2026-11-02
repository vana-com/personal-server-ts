import { CompressedDataPacket, decrypt, readMessage } from "openpgp";
import {
  AdditionsRecoveryError,
  type ByteBudget,
} from "@opendatalabs/personal-server-ts-core/additions";

/** OpenPGP 6.3 constructs this replacement for tag 8 before calling read.
 * Reject here: maxDecompressedMessageSize alone runs after decompression starts.
 */
class RejectedCompressedPacket extends CompressedDataPacket {
  override async read(): Promise<void> {
    throw new Error(
      "Compressed OpenPGP packets are unsupported in bounded recovery",
    );
  }
}

export async function decryptBoundedAdditions(
  encrypted: Uint8Array,
  password: string,
  budget: ByteBudget,
): Promise<Uint8Array> {
  budget.charge(encrypted.byteLength * 4);
  const config = {
    additionalAllowedPackets: [RejectedCompressedPacket],
    maxDecompressedMessageSize: 0,
    ignoreUnsupportedPackets: false,
    ignoreMalformedPackets: false,
  };
  const message = await readMessage({ binaryMessage: encrypted, config });
  let result;
  try {
    result = await decrypt({
      message,
      passwords: [password],
      format: "binary",
      config,
    });
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.includes(
        "Compressed OpenPGP packets are unsupported in bounded recovery",
      )
    )
      throw new AdditionsRecoveryError(
        "compressed_packet",
        "Compressed OpenPGP packets are unsupported in bounded recovery",
      );
    throw error;
  }
  budget.charge();
  if (!(result.data instanceof Uint8Array))
    throw new Error("Unexpected OpenPGP stream");
  if (result.data.byteLength > budget.remaining)
    budget.charge(budget.remaining + 1);
  return result.data;
}
