/** Portable RFC 3339 temporal policy. No rounding or local time zone. */
export type TimeType = "date" | "date-time";
export interface ParsedTime {
  readonly seconds: bigint;
  readonly fraction: string;
}
// IERS inserted leap seconds, through the most recent insertion (2016-12-31).
const leapDates = [
  "1972-06-30",
  "1972-12-31",
  "1973-12-31",
  "1974-12-31",
  "1975-12-31",
  "1976-12-31",
  "1977-12-31",
  "1978-12-31",
  "1979-12-31",
  "1981-06-30",
  "1982-06-30",
  "1983-06-30",
  "1985-06-30",
  "1987-12-31",
  "1989-12-31",
  "1990-12-31",
  "1992-06-30",
  "1993-06-30",
  "1994-06-30",
  "1995-12-31",
  "1997-06-30",
  "1998-12-31",
  "2005-12-31",
  "2008-12-31",
  "2012-06-30",
  "2015-06-30",
  "2016-12-31",
];
const leapTransitions = leapDates.map(
  (d) => Date.parse(`${d}T00:00:00Z`) / 1000 + 86400,
);
export function parseTime(value: unknown, type: TimeType): ParsedTime | null {
  if (typeof value !== "string" || (type !== "date" && type !== "date-time"))
    return null;
  const match = (
    type === "date"
      ? /^(\d{4})-(\d{2})-(\d{2})$/
      : /^(\d{4})-(\d{2})-(\d{2})[tT](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([zZ]|[+-]\d{2}:\d{2})$/
  ).exec(value);
  if (!match) return null;
  const [, y, m, d, h = "0", min = "0", s = "0", fraction = "", offset = "Z"] =
    match;
  const year = Number(y),
    month = Number(m),
    day = Number(d),
    hour = Number(h),
    minute = Number(min),
    second = Number(s);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day >
      [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][
        month - 1
      ]! ||
    hour > 23 ||
    minute > 59 ||
    second > 60
  )
    return null;
  let offsetSeconds = 0;
  if (offset.toUpperCase() !== "Z") {
    const oh = Number(offset.slice(1, 3)),
      om = Number(offset.slice(4, 6));
    if (oh > 23 || om > 59) return null;
    offsetSeconds = (oh * 3600 + om * 60) * (offset[0] === "-" ? -1 : 1);
  }
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, Math.min(second, 59), 0);
  const nominal =
    date.getTime() / 1000 - offsetSeconds + (second === 60 ? 1 : 0);
  if (second === 60 && !leapTransitions.includes(nominal)) return null;
  const prior = leapTransitions.filter((t) =>
    second === 60 ? t < nominal : t <= nominal,
  ).length;
  return {
    seconds: BigInt(nominal) + BigInt(type === "date-time" ? prior : 0),
    fraction: fraction.replace(/0+$/, ""),
  };
}
export function compareTime(
  a: string,
  b: string,
  type: TimeType,
): -1 | 0 | 1 | null {
  const left = parseTime(a, type),
    right = parseTime(b, type);
  if (!left || !right) return null;
  if (left.seconds !== right.seconds)
    return left.seconds < right.seconds ? -1 : 1;
  const width = Math.max(left.fraction.length, right.fraction.length);
  const l = left.fraction.padEnd(width, "0"),
    r = right.fraction.padEnd(width, "0");
  return l === r ? 0 : l < r ? -1 : 1;
}
/** Only eligible top-level temporal schema properties may define candidate bounds. */
export function declaredTimeType(stream: {
  consent_time_field?: string;
  schema?: Record<string, unknown>;
}): TimeType | undefined {
  const properties = stream.schema?.properties as
    Record<string, unknown> | undefined;
  const property = properties?.[stream.consent_time_field ?? ""] as
    { type?: unknown; format?: unknown } | undefined;
  if (
    !property ||
    !(
      property.type === "string" ||
      (Array.isArray(property.type) &&
        property.type.includes("string") &&
        property.type.every((t) => t === "string" || t === "null"))
    )
  )
    return undefined;
  return property.format === "date" || property.format === "date-time"
    ? property.format
    : undefined;
}

/** Current untyped bounds historically accept full dates as midnight UTC. */
export function withinTimeRange(
  value: string | undefined,
  constraint: { type?: TimeType; since?: string; until?: string },
): boolean {
  const type = constraint.type ?? "date-time";
  const normalize = (input: string | undefined): string | undefined =>
    constraint.type === undefined &&
    typeof input === "string" &&
    /^\d{4}-\d{2}-\d{2}$/.test(input)
      ? `${input}T00:00:00Z`
      : input;
  const bound = (input: string): string => {
    const normalized = normalize(input)!;
    // Existing AS profiles deliberately retain their Date.parse bound syntax.
    // Adapt only those frozen bounds; stored record values always stay strict.
    if (constraint.type !== undefined || parseTime(normalized, type))
      return normalized;
    // Date.parse otherwise gives offset-less legacy syntax the host's zone.
    // Freeze those accepted bounds in UTC; preserve an explicit legacy offset.
    const explicitZone =
      /(?:[zZ]|(?:GMT|UTC|UT|[ECMP][SD]T)(?:[+-]\d{1,4})?|\s[+-]\d{4}|(?:[Tt]|\s)\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?[+-]\d{2}:?\d{2})$/.test(
        input.trim(),
      );
    const offsetlessIso =
      /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?$/.test(input);
    const portable = explicitZone
      ? input
      : offsetlessIso
        ? `${input}Z`
        : `${input} UTC`;
    const legacy = Date.parse(portable);
    return Number.isFinite(legacy)
      ? new Date(legacy).toISOString()
      : normalized;
  };
  const record = normalize(value);
  if (!parseTime(record, type)) return false;
  if (constraint.since !== undefined) {
    const order = compareTime(record!, bound(constraint.since), type);
    if (order === null || order < 0) return false;
  }
  if (constraint.until !== undefined) {
    const order = compareTime(record!, bound(constraint.until), type);
    if (order === null || order >= 0) return false;
  }
  return true;
}
