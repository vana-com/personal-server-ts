export type DataBlockStorageErrorCode =
  | "block_manifest_not_found"
  | "block_payload_not_found"
  | "cursor_invalid";

export class DataBlockStorageError extends Error {
  constructor(
    public readonly code: DataBlockStorageErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "DataBlockStorageError";
  }
}
