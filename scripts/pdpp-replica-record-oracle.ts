export type CanonicalRecord = {
  instance: string;
  stream: string;
  record_key: string;
  data: string | null;
  emitted_at: string;
  deleted: number;
  deleted_at: string | null;
  blob_id: string | null;
};

export type ReplicaBlobMap = Record<
  string,
  { sha256: string; bytes: number } | { unavailable: true }
>;

export const CANONICAL_RECORD_COLUMNS = [
  "instance",
  "stream",
  "record_key",
  "data",
  "emitted_at",
  "deleted",
  "deleted_at",
  "blob_id",
] as const satisfies readonly (keyof CanonicalRecord)[];

export function projectCanonicalRecords(
  rows: readonly Record<string, unknown>[],
): CanonicalRecord[] {
  return rows.map((row) => {
    for (const field of CANONICAL_RECORD_COLUMNS) {
      if (!Object.hasOwn(row, field)) {
        throw new Error(`Canonical record is missing field ${field}`);
      }
    }
    if (
      typeof row.instance !== "string" ||
      typeof row.stream !== "string" ||
      typeof row.record_key !== "string" ||
      (typeof row.data !== "string" && row.data !== null) ||
      typeof row.emitted_at !== "string" ||
      typeof row.deleted !== "number" ||
      (typeof row.deleted_at !== "string" && row.deleted_at !== null) ||
      (typeof row.blob_id !== "string" && row.blob_id !== null)
    ) {
      throw new Error("Canonical record has an invalid field value");
    }
    return {
      instance: row.instance,
      stream: row.stream,
      record_key: row.record_key,
      data: row.data,
      emitted_at: row.emitted_at,
      deleted: row.deleted,
      deleted_at: row.deleted_at,
      blob_id: row.blob_id,
    };
  });
}

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

function stableJson(source: string): string {
  let offset = 0;
  const whitespace = () => {
    while (/[ \t\n\r]/.test(source[offset] ?? "")) offset++;
  };
  const parseString = (): string => {
    const start = offset++;
    while (offset < source.length) {
      const char = source[offset++];
      if (char === "\\") offset++;
      else if (char === '"') return JSON.parse(source.slice(start, offset));
    }
    throw new Error("Invalid JSON string");
  };
  const parseNumber = (): string => {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      source.slice(offset),
    );
    if (!match) throw new Error("Invalid JSON number");
    offset += match[0].length;
    const matchParts = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/.exec(
      match[0],
    )!;
    const negative = matchParts[1] === "-";
    let digits = `${matchParts[2]}${matchParts[3] ?? ""}`.replace(/^0+/, "");
    if (!digits) return "0";
    let exponent =
      BigInt(matchParts[4] ?? "0") - BigInt((matchParts[3] ?? "").length);
    const trailingZeroes = /0+$/.exec(digits)?.[0].length ?? 0;
    if (trailingZeroes > 0) {
      digits = digits.slice(0, -trailingZeroes);
      exponent += BigInt(trailingZeroes);
    }
    return `${negative ? "-" : ""}${digits}e${exponent}`;
  };
  const parseValue = (): string => {
    whitespace();
    const char = source[offset];
    if (char === '"') return JSON.stringify(parseString());
    if (char === "[") {
      offset++;
      whitespace();
      const items: string[] = [];
      if (source[offset] === "]") {
        offset++;
        return "[]";
      }
      while (true) {
        items.push(parseValue());
        whitespace();
        const delimiter = source[offset++];
        if (delimiter === "]") return `[${items.join(",")}]`;
        if (delimiter !== ",") throw new Error("Invalid JSON array");
      }
    }
    if (char === "{") {
      offset++;
      whitespace();
      const entries: [string, string][] = [];
      const keys = new Set<string>();
      if (source[offset] === "}") {
        offset++;
        return "{}";
      }
      while (true) {
        whitespace();
        if (source[offset] !== '"') throw new Error("Invalid JSON object key");
        const key = parseString();
        if (keys.has(key)) throw new Error("Duplicate JSON object key");
        keys.add(key);
        whitespace();
        if (source[offset++] !== ":") throw new Error("Invalid JSON object");
        entries.push([key, parseValue()]);
        whitespace();
        const delimiter = source[offset++];
        if (delimiter === "}") {
          entries.sort(([left], [right]) => compareText(left, right));
          return `{${entries
            .map(([entryKey, value]) => `${JSON.stringify(entryKey)}:${value}`)
            .join(",")}}`;
        }
        if (delimiter !== ",") throw new Error("Invalid JSON object");
      }
    }
    if (char === "-" || (char >= "0" && char <= "9")) return parseNumber();
    for (const literal of ["true", "false", "null"]) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length;
        return literal;
      }
    }
    throw new Error("Invalid JSON value");
  };

  const canonical = parseValue();
  whitespace();
  if (offset !== source.length)
    throw new Error("Trailing data after JSON value");
  return canonical;
}

export function sortCanonicalRecords(
  records: readonly CanonicalRecord[],
): CanonicalRecord[] {
  return projectCanonicalRecords(records)
    .map((record) => ({
      ...record,
      data: record.data === null ? null : stableJson(record.data),
    }))
    .sort(
      (left, right) =>
        compareText(left.instance, right.instance) ||
        compareText(left.stream, right.stream) ||
        compareText(left.record_key, right.record_key),
    );
}

export function assertCanonicalRecordsEqual(
  expected: readonly CanonicalRecord[],
  actual: readonly CanonicalRecord[],
): void {
  if (!canonicalRecordsEqual(expected, actual)) {
    const left = sortCanonicalRecords(expected);
    const right = sortCanonicalRecords(actual);
    throw new Error(
      `Canonical record mismatch:\nexpected ${JSON.stringify(left)}\nactual ${JSON.stringify(right)}`,
    );
  }
}

export function canonicalRecordsEqual(
  left: readonly CanonicalRecord[],
  right: readonly CanonicalRecord[],
): boolean {
  return (
    JSON.stringify(sortCanonicalRecords(left)) ===
    JSON.stringify(sortCanonicalRecords(right))
  );
}

export function assertReplicaSnapshotsEqual(
  expected: {
    canonicalRecords: readonly CanonicalRecord[];
    blobs: ReplicaBlobMap;
  },
  actual: {
    canonicalRecords: readonly CanonicalRecord[];
    blobs: ReplicaBlobMap;
  },
): void {
  assertCanonicalRecordsEqual(
    expected.canonicalRecords,
    actual.canonicalRecords,
  );
  assertBlobBytesAvailable(expected.blobs);
  assertBlobBytesAvailable(actual.blobs);
  if (!blobMapsEqual(expected.blobs, actual.blobs)) {
    throw new Error(
      `Replica blob mismatch:\nexpected ${JSON.stringify(expected.blobs)}\nactual ${JSON.stringify(actual.blobs)}`,
    );
  }
}

export function assertBlobBytesAvailable(blobs: ReplicaBlobMap): void {
  const unavailable = Object.entries(blobs)
    .filter(([, value]) => "unavailable" in value)
    .map(([blobId]) => blobId);
  if (unavailable.length > 0) {
    throw new Error(
      `Referenced blob bytes failed verification: ${unavailable.join(", ")}`,
    );
  }
}

export function blobMapsEqual(
  left: ReplicaBlobMap,
  right: ReplicaBlobMap,
): boolean {
  const stable = (blobs: ReplicaBlobMap) =>
    Object.fromEntries(
      Object.entries(blobs).sort(([leftId], [rightId]) =>
        compareText(leftId, rightId),
      ),
    );
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}

export function blobMatches(
  blobs: ReplicaBlobMap,
  blobId: string,
  sha256: string,
): boolean {
  const blob = blobs[blobId];
  return !!blob && "sha256" in blob && blob.sha256 === sha256;
}

export function blobsVerified(blobs: ReplicaBlobMap): boolean {
  return Object.values(blobs).every((value) => !("unavailable" in value));
}
