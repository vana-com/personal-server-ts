import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from "node:crypto";
import { decodeCursor, InvalidCursorSyntaxError } from "./cursor.js";
import type { PdppRecordReadPort } from "./read-port.js";
import { compileRecordSchema, redactedPath } from "./schema.js";
import {
  CursorExpiredError,
  InvalidCursorError,
  type PdppRecordRow,
} from "./types.js";

export interface DeclarationWitnessOptions {
  readPort: PdppRecordReadPort;
  /** One connection instance ID, as accepted by listRecords.instanceIds. */
  sourceKey: string;
  stream: string;
  nextSchema: Record<string, unknown>;
  cursor?: string;
  /** Positive safe integer; bounds returned rows and validations per call. */
  limit: number;
}

export interface DeclarationWitnessResult {
  verdict: "pass" | "fail" | "partial";
  /** Rows validated in this call, including the failing row, if any. */
  checked: number;
  nextCursor: string | null;
  failure?: {
    /** Lowercase SHA-256 hex of the UTF-8 record key, never the key itself. */
    recordKeyDigest: string;
    /** JSON pointer; data-derived property names are redacted as "*". */
    instancePath: string;
    keyword: string;
  };
}

export class DeclarationWitnessInputError extends Error {
  constructor() {
    super(
      "Declaration witness requires a source, stream and positive safe-integer limit",
    );
    this.name = "DeclarationWitnessInputError";
  }
}

export class DeclarationWitnessSchemaError extends Error {
  constructor() {
    // Do not attach Ajv errors or schema text to a public error.
    super("Declaration witness schema cannot be compiled synchronously");
    this.name = "DeclarationWitnessSchemaError";
  }
}

export class DeclarationWitnessCursorError extends InvalidCursorError {
  constructor() {
    super(
      "Declaration witness cursor is invalid, expired or belongs to another walk",
    );
    this.name = "DeclarationWitnessCursorError";
  }
}

export class DeclarationWitnessReadError extends Error {
  constructor() {
    super("Declaration witness read port returned an invalid page");
    this.name = "DeclarationWitnessReadError";
  }
}

// The ordinary list cursor is unsigned and not instance/schema-bound.
// Encrypt/authenticate it without changing its bytes or retaining one entry
// per page. Weak keys allow ports and their secrets to be garbage-collected.
// Tokens resume only with the same port object in the same process.
const cursorKeys = new WeakMap<PdppRecordReadPort, Buffer>();
const prefix = "dw1.";

function sealCursor(
  port: PdppRecordReadPort,
  cursor: string,
  context: string,
): string {
  let key = cursorKeys.get(port);
  if (!key) {
    key = randomBytes(32);
    cursorKeys.set(port, key);
  }
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(context, "utf8"));
  const encrypted = Buffer.concat([
    cipher.update(cursor, "utf8"),
    cipher.final(),
  ]);
  return (
    prefix +
    Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url")
  );
}

function openCursor(
  port: PdppRecordReadPort,
  token: string,
  context: string,
): string {
  try {
    const key = cursorKeys.get(port);
    if (!key || !token.startsWith(prefix))
      throw new DeclarationWitnessCursorError();
    const encoded = token.slice(prefix.length);
    if (!/^[A-Za-z0-9_-]+$/.test(encoded))
      throw new DeclarationWitnessCursorError();
    const bytes = Buffer.from(encoded, "base64url");
    if (bytes.length <= 28 || bytes.toString("base64url") !== encoded) {
      throw new DeclarationWitnessCursorError();
    }
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      bytes.subarray(0, 12),
    );
    decipher.setAAD(Buffer.from(context, "utf8"));
    decipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([
      decipher.update(bytes.subarray(28)),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new DeclarationWitnessCursorError();
  }
}

/** Check the store's existing cursor contract; never manufacture a position. */
function storePosition(cursor: string, stream: string) {
  const payload = decodeCursor(cursor);
  if (
    payload.kind !== "list" ||
    payload.stream !== stream ||
    typeof payload.epoch !== "string" ||
    payload.order !== "asc" ||
    (payload.sortValue !== null && typeof payload.sortValue !== "string") ||
    typeof payload.recordKey !== "string" ||
    (payload.horizon !== undefined && typeof payload.horizon !== "string")
  ) {
    throw new DeclarationWitnessCursorError();
  }
  return payload;
}

/**
 * Validate one bounded page of a declaration-upgrade walk.
 *
 * A partial result certifies only the rows already visited. A pass means the
 * read port reported its terminal page and all visited live rows validated.
 * The read port is NOT a snapshot: inserts behind the cursor, updates and
 * deletes can change what the walk observes. The caller MUST keep writes and
 * resets quiescent (or supply a snapshot-backed port) for the entire walk
 * through the upgrade decision. This API supplies no mutation fence.
 *
 * sourceKey is exactly one instance ID, avoiding cross-instance tuple ties.
 * Continuations are opaque, encrypted/authenticated, and scoped to the same
 * port object/process, source, stream and JSON-serialized nextSchema. Restart
 * the walk after recreating a port, restarting the process or changing the
 * schema. A retry may reuse a cursor; the port's live-read caveat still applies.
 * No record data, raw keys, schema contents or validator messages are logged
 * or returned. Array indices and schema-declared property names may appear
 * in the redacted failure pointer.
 */
export async function witnessDeclarationUpgrade({
  readPort,
  sourceKey,
  stream,
  nextSchema,
  cursor,
  limit,
}: DeclarationWitnessOptions): Promise<DeclarationWitnessResult> {
  if (
    !Number.isSafeInteger(limit) ||
    limit <= 0 ||
    typeof sourceKey !== "string" ||
    sourceKey.length === 0 ||
    typeof stream !== "string" ||
    stream.length === 0
  ) {
    throw new DeclarationWitnessInputError();
  }

  let schema: Record<string, unknown>;
  let validate: ReturnType<typeof compileRecordSchema>;
  let schemaDigest: string;
  try {
    // Keep schema compilation, fingerprinting and path redaction on the same
    // object even if the caller mutates its schema while listRecords awaits.
    schema = structuredClone(nextSchema);
    validate = compileRecordSchema(schema);
    if ("$async" in validate && validate.$async)
      throw new DeclarationWitnessSchemaError();
    schemaDigest = createHash("sha256")
      .update(JSON.stringify(schema))
      .digest("hex");
  } catch {
    throw new DeclarationWitnessSchemaError();
  }

  const context = JSON.stringify([prefix, sourceKey, stream, schemaDigest]);
  let storeCursor: string | undefined;
  if (cursor !== undefined) {
    storeCursor = openCursor(readPort, cursor, context);
    try {
      storePosition(storeCursor, stream);
    } catch {
      throw new DeclarationWitnessCursorError();
    }
  }

  let page;
  try {
    page = await readPort.listRecords(stream, {
      instanceIds: [sourceKey],
      order: "asc",
      limit,
      ...(storeCursor === undefined ? {} : { cursor: storeCursor }),
    });
  } catch (error) {
    if (
      error instanceof InvalidCursorError ||
      error instanceof InvalidCursorSyntaxError ||
      error instanceof CursorExpiredError
    ) {
      throw new DeclarationWitnessCursorError();
    }
    // A bridge may include row contents in an error. Do not expose its cause.
    throw new DeclarationWitnessReadError();
  }

  if (
    !page ||
    !Array.isArray(page.data) ||
    page.data.length > limit ||
    typeof page.hasMore !== "boolean" ||
    (!page.hasMore && page.nextCursor !== undefined)
  ) {
    throw new DeclarationWitnessReadError();
  }
  if (page.hasMore) {
    try {
      if (
        !page.nextCursor ||
        page.nextCursor === storeCursor ||
        page.data.length === 0
      ) {
        throw new DeclarationWitnessReadError();
      }
      const position = storePosition(page.nextCursor, stream);
      const last = page.data[page.data.length - 1];
      if (
        !last ||
        position.recordKey !== last.recordKey ||
        position.sortValue !== last.emittedAt
      ) {
        throw new DeclarationWitnessReadError();
      }
    } catch {
      throw new DeclarationWitnessReadError();
    }
  }

  let checked = 0;
  for (const row of page.data as PdppRecordRow[]) {
    if (
      !row ||
      row.instance !== sourceKey ||
      row.stream !== stream ||
      typeof row.recordKey !== "string" ||
      (row.deleted !== true && row.deleted !== false)
    ) {
      throw new DeclarationWitnessReadError();
    }
    // listRecords excludes tombstones by contract; defend against adapters
    // that return them anyway without validating their absent data.
    if (row.deleted) continue;
    checked += 1;
    if (!validate(row.data)) {
      const [error] = validate.errors ?? [];
      return {
        verdict: "fail",
        checked,
        nextCursor: null,
        failure: {
          recordKeyDigest: createHash("sha256")
            .update(row.recordKey)
            .digest("hex"),
          instancePath: error?.instancePath
            ? redactedPath(schema, error.instancePath, row.data)
            : "",
          keyword: error?.keyword ?? "schema",
        },
      };
    }
  }

  return page.hasMore
    ? {
        verdict: "partial",
        checked,
        nextCursor: sealCursor(readPort, page.nextCursor!, context),
      }
    : { verdict: "pass", checked, nextCursor: null };
}
