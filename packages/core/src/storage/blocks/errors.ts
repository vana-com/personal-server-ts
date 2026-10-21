export type DataBlockStorageErrorCode =
  | "block_manifest_not_found"
  | "block_payload_not_found"
  | "cursor_invalid"
  /** A stored block's bytes differ from the digest its manifest records. */
  | "block_digest_mismatch"
  /** The bytes read are not the version the read was authorized for. */
  | "generation_mismatch";

export class DataBlockStorageError extends Error {
  constructor(
    public readonly code: DataBlockStorageErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "DataBlockStorageError";
  }
}
