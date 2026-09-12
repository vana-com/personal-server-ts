import { spawnSync } from "node:child_process";
import { secp256k1 } from "@noble/curves/secp256k1";

const result = spawnSync("phala", ["kms", "phala", "--json"], {
  encoding: "utf8",
});

if (result.error) throw result.error;
if (result.status !== 0) {
  process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}

const { k256_pubkey: compressedKey } = JSON.parse(result.stdout);
if (typeof compressedKey !== "string") {
  throw new Error("phala kms phala --json did not return k256_pubkey");
}

const key = compressedKey.startsWith("0x")
  ? compressedKey.slice(2)
  : compressedKey;
const uncompressed = secp256k1.ProjectivePoint.fromHex(key).toRawBytes(false);
console.log(`0x${Buffer.from(uncompressed).toString("hex")}`);
