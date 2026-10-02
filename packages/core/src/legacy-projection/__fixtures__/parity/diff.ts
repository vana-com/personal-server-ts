/**
 * Structural diff between a legacy connector body and a projected body.
 * Arrays of objects that all carry a string `id` (or `uuid`) are matched by
 * that key. A key that occurs more than once on either side is reported at
 * `path[key=id]#count`, and a different order of the keys both sides share is
 * reported at `path[order]`. Other arrays are matched by index. Test support
 * for parity-goldens.test.ts.
 */

export interface BodyDifference {
  path: string;
  legacy: unknown;
  projected: unknown;
}

const ABSENT = "<absent>";

export function diffBodies(
  legacy: unknown,
  projected: unknown,
  path = "",
): BodyDifference[] {
  if (Array.isArray(legacy) && Array.isArray(projected)) {
    const key = arrayKey(legacy, projected);
    if (key) {
      const left = new Map(legacy.map((item) => [item[key] as string, item]));
      const right = new Map(
        projected.map((item) => [item[key] as string, item]),
      );
      const leftIds = legacy.map((item) => item[key] as string);
      const rightIds = projected.map((item) => item[key] as string);
      const ids = [...new Set([...leftIds, ...rightIds])];
      const count = (list: string[], id: string) =>
        list.filter((item) => item === id).length;
      const duplicates = ids.flatMap((id) => {
        const legacyCount = count(leftIds, id);
        const projectedCount = count(rightIds, id);
        return legacyCount > 1 || projectedCount > 1
          ? [
              {
                path: `${path}[${key}=${id}]#count`,
                legacy: legacyCount,
                projected: projectedCount,
              },
            ]
          : [];
      });
      const sharedOrder = (list: string[], other: Map<string, unknown>) =>
        [...new Set(list)].filter((id) => other.has(id));
      const legacyOrder = sharedOrder(leftIds, right);
      const projectedOrder = sharedOrder(rightIds, left);
      const order =
        JSON.stringify(legacyOrder) === JSON.stringify(projectedOrder)
          ? []
          : [
              {
                path: `${path}[order]`,
                legacy: legacyOrder,
                projected: projectedOrder,
              },
            ];
      return [
        ...duplicates,
        ...order,
        ...ids.flatMap((id) =>
          diffBodies(
            left.has(id) ? left.get(id) : ABSENT,
            right.has(id) ? right.get(id) : ABSENT,
            `${path}[${key}=${id}]`,
          ),
        ),
      ];
    }
    const length = Math.max(legacy.length, projected.length);
    return Array.from({ length }, (_, index) =>
      diffBodies(
        index < legacy.length ? legacy[index] : ABSENT,
        index < projected.length ? projected[index] : ABSENT,
        `${path}[${index}]`,
      ),
    ).flat();
  }
  if (isPlainObject(legacy) && isPlainObject(projected)) {
    const keys = [
      ...new Set([...Object.keys(legacy), ...Object.keys(projected)]),
    ].sort();
    return keys.flatMap((key) =>
      diffBodies(
        key in legacy ? legacy[key] : ABSENT,
        key in projected ? projected[key] : ABSENT,
        path ? `${path}.${key}` : key,
      ),
    );
  }
  return JSON.stringify(legacy) === JSON.stringify(projected)
    ? []
    : [{ path, legacy, projected }];
}

function arrayKey(
  left: unknown[],
  right: unknown[],
): "id" | "uuid" | undefined {
  const items = [...left, ...right];
  if (items.length === 0) return undefined;
  for (const key of ["id", "uuid"] as const) {
    if (
      items.every(
        (item) => isPlainObject(item) && typeof item[key] === "string",
      )
    )
      return key;
  }
  return undefined;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
