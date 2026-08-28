/**
 * A deliberately tiny front-matter parser for profile documents.
 *
 * Not YAML. It accepts exactly the two shapes the profile format uses —
 * `key: scalar` and a `key:` followed by `  - item` lines — and throws on
 * anything else. The inputs are three files we ship and a test that parses all
 * of them, so strictness costs nothing and rules out a dependency in a package
 * that must stay browser-safe.
 */

export type FrontmatterValue = string | string[];

export interface ParsedDocument {
  meta: Record<string, FrontmatterValue>;
  body: string;
}

const DELIMITER = "---";
const KEY_LINE = /^([A-Za-z][A-Za-z0-9_]*):[ \t]*(.*)$/;
const LIST_ITEM = /^[ \t]+-[ \t]+(.+)$/;

function unquote(raw: string): string {
  const value = raw.trim();
  if (value.length >= 2) {
    const first = value[0];
    const last = value[value.length - 1];
    if ((first === '"' || first === "'") && first === last) {
      return value.slice(1, -1);
    }
  }
  return value;
}

/**
 * Split a profile document into its front matter and body.
 *
 * @throws if the document has no front matter block or contains a line the
 * grammar above does not cover.
 */
export function parseFrontmatter(
  source: string,
  label = "profile",
): ParsedDocument {
  const normalized = source.replace(/\r\n/g, "\n");
  const lines = normalized.split("\n");

  if (lines[0]?.trim() !== DELIMITER) {
    throw new Error(`${label}: expected front matter to open with "---"`);
  }

  const meta: Record<string, FrontmatterValue> = {};
  let currentListKey: string | null = null;
  let index = 1;

  for (; index < lines.length; index += 1) {
    const line = lines[index] ?? "";
    if (line.trim() === DELIMITER) break;
    if (line.trim() === "") continue;

    const listMatch = LIST_ITEM.exec(line);
    if (listMatch) {
      if (currentListKey === null) {
        throw new Error(`${label}: list item on line ${index + 1} has no key`);
      }
      (meta[currentListKey] as string[]).push(unquote(listMatch[1] as string));
      continue;
    }

    const keyMatch = KEY_LINE.exec(line);
    if (!keyMatch) {
      throw new Error(
        `${label}: unparseable front matter on line ${index + 1}: ${line}`,
      );
    }

    const key = keyMatch[1] as string;
    const rest = keyMatch[2] as string;
    if (key in meta) {
      throw new Error(`${label}: duplicate front matter key "${key}"`);
    }

    if (rest.trim() === "") {
      meta[key] = [];
      currentListKey = key;
    } else {
      meta[key] = unquote(rest);
      currentListKey = null;
    }
  }

  if (index >= lines.length) {
    throw new Error(`${label}: front matter is not closed with "---"`);
  }

  return {
    meta,
    body: lines
      .slice(index + 1)
      .join("\n")
      .trim(),
  };
}

/** Read a required scalar. */
export function requireString(
  meta: Record<string, FrontmatterValue>,
  key: string,
  label: string,
): string {
  const value = meta[key];
  if (typeof value !== "string" || value === "") {
    throw new Error(
      `${label}: front matter key "${key}" must be a non-empty string`,
    );
  }
  return value;
}

/** Read a required non-empty list. */
export function requireStringList(
  meta: Record<string, FrontmatterValue>,
  key: string,
  label: string,
): string[] {
  const value = meta[key];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(
      `${label}: front matter key "${key}" must be a non-empty list`,
    );
  }
  return value;
}

/** Read a required integer. */
export function requireInteger(
  meta: Record<string, FrontmatterValue>,
  key: string,
  label: string,
): number {
  const raw = requireString(meta, key, label);
  const parsed = Number(raw);
  if (!Number.isInteger(parsed)) {
    throw new Error(
      `${label}: front matter key "${key}" must be an integer, got "${raw}"`,
    );
  }
  return parsed;
}
