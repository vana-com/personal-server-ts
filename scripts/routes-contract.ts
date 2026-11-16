/**
 * Collects the HTTP route families the Personal Server registers, from the
 * source that registers them, so a host can be checked against them.
 *
 * A route family is a path the server answers: a mount point (`app.route`,
 * `app.use`), a handler path (`app.get`, `app.post`, ...), or a path the
 * lite dispatcher compares or prefix-matches. Hosts may not write these as
 * string literals; they build requests with `createPersonalServerClient`.
 *
 * `/v1` and `/.well-known` alone are roots the server shares with other
 * services, so they are not families. Routes under them appear as their own
 * families where the server names them.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

export type RouteHost = "lite" | "server";

export interface RouteEntry {
  path: string;
  hosts: RouteHost[];
}

export interface RoutesContract {
  format: 1;
  routes: RouteEntry[];
}

const REGISTRATION_METHODS = new Set([
  "route",
  "use",
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "all",
]);
const PATH_NAME =
  /(?:^|[a-z])(?:Prefix|Path|Paths|PATH|PATHS)$|^(?:mountPath|basePath)$/u;
const SHARED_ROOT = /^\/(?:v\d+|\.well-known)$/u;

export interface SourceFile {
  name: string;
  text: string;
}

function literalText(node: ts.Node): string | undefined {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
    ? node.text
    : undefined;
}

function mentionsPath(node: ts.Node): boolean {
  return /\b(?:pathname|path)\b/u.test(node.getText());
}

function declaredName(node: ts.Node): string | undefined {
  const parent = node.parent;
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  if (ts.isPropertyAssignment(parent) && ts.isIdentifier(parent.name)) {
    return parent.name.text;
  }
  return undefined;
}

/** Whether a string literal sits where the source registers or matches a route. */
function isRegistration(literal: ts.Node): boolean {
  const parent = literal.parent;
  if (ts.isCallExpression(parent) && parent.arguments[0] === literal) {
    const callee = parent.expression;
    if (ts.isPropertyAccessExpression(callee)) {
      if (REGISTRATION_METHODS.has(callee.name.text)) {
        return true;
      }
      if (callee.name.text === "startsWith") {
        return mentionsPath(callee.expression);
      }
    }
    return false;
  }
  if (
    ts.isBinaryExpression(parent) &&
    (parent.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
      parent.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken)
  ) {
    const other = parent.left === literal ? parent.right : parent.left;
    return mentionsPath(other);
  }
  if (ts.isArrayLiteralExpression(parent)) {
    const name = declaredName(parent);
    return name !== undefined && PATH_NAME.test(name);
  }
  const name = declaredName(literal);
  return name !== undefined && PATH_NAME.test(name);
}

function normalize(raw: string): string | undefined {
  if (!raw.startsWith("/")) {
    return undefined;
  }
  let value = raw.replace(/\/\*$/u, "");
  while (value.length > 1 && value.endsWith("/")) {
    value = value.slice(0, -1);
  }
  if (value === "/" || value.includes("*") || value.includes(":")) {
    return undefined;
  }
  if (SHARED_ROOT.test(value)) {
    return undefined;
  }
  return value;
}

function firstSegment(value: string): string {
  return value.split("/")[1] ?? "";
}

function registrations(file: SourceFile): string[] {
  const source = ts.createSourceFile(
    file.name,
    file.text,
    ts.ScriptTarget.Latest,
    true,
  );
  const found: string[] = [];
  const visit = (node: ts.Node): void => {
    const text = literalText(node);
    if (text !== undefined && isRegistration(node)) {
      const value = normalize(text);
      if (value !== undefined) {
        found.push(value);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return found;
}

/**
 * Route families from the server's app, its route files and the lite
 * dispatcher. Route files register paths relative to their mount, so only
 * a path whose first segment a mount or the dispatcher already names counts
 * (this admits `/health` and `/pdpp/capabilities`, and not `/trigger`).
 */
export function collectRoutes(input: {
  serverApp: SourceFile;
  serverRoutes: SourceFile[];
  lite: SourceFile[];
}): RoutesContract {
  const hostsByPath = new Map<string, Set<RouteHost>>();
  const add = (value: string, host: RouteHost): void => {
    const hosts = hostsByPath.get(value) ?? new Set<RouteHost>();
    hosts.add(host);
    hostsByPath.set(value, hosts);
  };

  for (const value of registrations(input.serverApp)) {
    add(value, "server");
  }
  for (const file of input.lite) {
    for (const value of registrations(file)) {
      add(value, "lite");
    }
  }
  const roots = new Set([...hostsByPath.keys()].map(firstSegment));
  for (const file of input.serverRoutes) {
    for (const value of registrations(file)) {
      if (roots.has(firstSegment(value))) {
        add(value, "server");
      }
    }
  }

  const routes = [...hostsByPath.entries()]
    .map(([routePath, hosts]) => ({
      path: routePath,
      hosts: [...hosts].sort(),
    }))
    .sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return { format: 1, routes };
}

function readSources(directory: string, recursive: boolean): SourceFile[] {
  return readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile() || (recursive && entry.isDirectory()))
    .flatMap((entry): SourceFile[] => {
      const full = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        return readSources(full, recursive);
      }
      if (!entry.name.endsWith(".ts") || /\.test\.ts$/u.test(entry.name)) {
        return [];
      }
      return [{ name: full, text: readFileSync(full, "utf8") }];
    })
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

/** The contract as this repository's source produces it. */
export function routesContractFromRepo(root: string): RoutesContract {
  const server = path.join(root, "packages/server/src");
  const appFile = path.join(server, "app.ts");
  return collectRoutes({
    serverApp: { name: appFile, text: readFileSync(appFile, "utf8") },
    serverRoutes: readSources(path.join(server, "routes"), false),
    lite: readSources(path.join(root, "packages/lite/src"), false),
  });
}
