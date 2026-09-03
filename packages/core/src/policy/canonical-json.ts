// TODO(sdk-jobs): replace with canonicalJobRequestBytes from the SDK
export function canonicalJsonBytes(value: unknown): Uint8Array {
  const json = serializeValue(value, "property");
  if (json === undefined) {
    throw new TypeError("Value is not JSON serializable");
  }

  return new TextEncoder().encode(json);
}

type ValuePosition = "property" | "array";

function serializeValue(
  value: unknown,
  position: ValuePosition,
): string | undefined {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return serializeArray(value);
  }
  if (typeof value === "object") {
    return serializeObject(value as Record<string, unknown>);
  }

  const serialized = JSON.stringify(value);
  if (serialized !== undefined) {
    return serialized;
  }

  return position === "array" ? "null" : undefined;
}

function serializeArray(values: unknown[]): string {
  const items = Array.from(
    values,
    (value) => serializeValue(value, "array") ?? "null",
  );

  return `[${items.join(",")}]`;
}

function serializeObject(value: Record<string, unknown>): string {
  const properties: string[] = [];
  for (const key of Object.keys(value).sort()) {
    const serialized = serializeValue(value[key], "property");
    if (serialized === undefined) {
      continue;
    }

    properties.push(`${JSON.stringify(key)}:${serialized}`);
  }

  return `{${properties.join(",")}}`;
}
