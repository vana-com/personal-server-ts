export type CanonicalRecord = {
  instance: string;
  stream: string;
  record_key: string;
  data: string | null;
  emitted_at: string;
  deleted: number;
  blob_id: string | null;
};

export const CANONICAL_RECORD_COLUMNS = [
  "instance",
  "stream",
  "record_key",
  "data",
  "emitted_at",
  "deleted",
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
      blob_id: row.blob_id,
    };
  });
}

const compareText = (left: string, right: string) =>
  left < right ? -1 : left > right ? 1 : 0;

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value).sort(([left], [right]) =>
      compareText(left, right),
    );
    return `{${entries
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new Error("JSON value is not serializable");
  return encoded;
}

export function sortCanonicalRecords(
  records: readonly CanonicalRecord[],
): CanonicalRecord[] {
  return projectCanonicalRecords(records)
    .map((record) => ({
      ...record,
      data: record.data === null ? null : stableJson(JSON.parse(record.data)),
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
