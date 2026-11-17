/**
 * Collects the HTTP route families the Personal Server registers, from the
 * source that registers them, so a host can be checked against them.
 *
 * A route family is a path the server answers. The server's families come
 * from its Hono registrations, composed the way Hono composes them: the
 * walk starts at `createApp`, follows every `app.route(prefix, child)` into
 * the child router's own registrations, and joins the prefixes. A path may
 * be a string literal, a template or concatenation of constants, a constant
 * (local or imported), or a loop variable over an array of those. The lite
 * dispatcher compares and prefix-matches `pathname`; those comparisons count
 * too. Hosts may not write these as string literals; they build requests
 * with `createPersonalServerClient`.
 *
 * Nothing is dropped silently. A registration whose path, or whose mounted
 * child, the walk cannot resolve throws, so a new registration form fails the
 * generator instead of leaving the contract short.
 *
 * Left out by design: `/v1` and `/.well-known` alone (roots the server shares
 * with other services), and a path with no static first segment. A path with
 * a parameter or wildcard counts as the static prefix before it.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import ts from "typescript";

export type RouteHost = "lite" | "server";

export interface RouteEntry {
  path: string;
  hosts: RouteHost[];
  /** Methods the server registers a handler for, upper case; server only. */
  methods?: string[];
}

export interface RoutesContract {
  format: 1;
  routes: RouteEntry[];
}

export interface SourceFile {
  name: string;
  text: string;
}

const HANDLER_METHODS = new Set([
  "get",
  "post",
  "put",
  "delete",
  "patch",
  "options",
  "head",
  "all",
]);
const REGISTRATION_METHODS = new Set([
  ...HANDLER_METHODS,
  "route",
  "use",
  "on",
  "mount",
]);
// Router methods that change what a path means; not supported, so not guessed.
const UNSUPPORTED_ROUTER_METHODS = new Set(["basePath"]);
const PATH_NAME =
  /(?:^|[a-z])(?:Prefix|Path|Paths|PATH|PATHS)$|^(?:mountPath|basePath)$/u;
const SHARED_ROOT = /^\/(?:v\d+|\.well-known)$/u;

type Scope = ts.SourceFile | ts.FunctionLikeDeclaration;

interface Registered {
  path: string;
  method?: string;
}

class Program {
  private readonly files = new Map<string, ts.SourceFile>();

  constructor(sources: SourceFile[]) {
    for (const source of sources) {
      this.files.set(
        path.posix.normalize(source.name),
        ts.createSourceFile(
          source.name,
          source.text,
          ts.ScriptTarget.Latest,
          true,
        ),
      );
    }
  }

  file(name: string): ts.SourceFile {
    const found = this.files.get(path.posix.normalize(name));
    if (!found) {
      throw new Error(`routes-contract: ${name} is not among the sources`);
    }
    return found;
  }

  /** The relative import `specifier` of `from`, or undefined. */
  importedFile(
    from: ts.SourceFile,
    specifier: string,
  ): ts.SourceFile | undefined {
    if (!specifier.startsWith(".")) {
      return undefined;
    }
    const base = path.posix.join(path.posix.dirname(from.fileName), specifier);
    const stem = base.replace(/\.(?:js|ts)$/u, "");
    for (const candidate of [`${stem}.ts`, `${stem}/index.ts`]) {
      const found = this.files.get(path.posix.normalize(candidate));
      if (found) {
        return found;
      }
    }
    return undefined;
  }
}

function failAt(node: ts.Node, message: string): never {
  const file = node.getSourceFile();
  const { line } = file.getLineAndCharacterOfPosition(node.getStart());
  throw new Error(
    `routes-contract: ${file.fileName}:${line + 1}: ${message}. Resolve it in scripts/routes-contract.ts or register it in a supported form.`,
  );
}

interface Declaration {
  file: ts.SourceFile;
  node: ts.FunctionDeclaration | ts.VariableDeclaration;
}

function topLevel(
  file: ts.SourceFile,
  name: string,
): Declaration["node"] | undefined {
  for (const statement of file.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
      return statement;
    }
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (
          ts.isIdentifier(declaration.name) &&
          declaration.name.text === name
        ) {
          return declaration;
        }
      }
    }
  }
  return undefined;
}

function exported(
  program: Program,
  file: ts.SourceFile,
  name: string,
  seen = new Set<string>(),
): Declaration | undefined {
  const key = `${file.fileName}\u0000${name}`;
  if (seen.has(key)) {
    return undefined;
  }
  seen.add(key);
  const own = topLevel(file, name);
  if (own) {
    return { file, node: own };
  }
  for (const statement of file.statements) {
    if (!(ts.isExportDeclaration(statement) && statement.moduleSpecifier)) {
      continue;
    }
    const target = program.importedFile(
      file,
      (statement.moduleSpecifier as ts.StringLiteral).text,
    );
    if (!target) {
      continue;
    }
    const clause = statement.exportClause;
    if (!clause || ts.isNamespaceExport(clause)) {
      const via = exported(program, target, name, seen);
      if (via) {
        return via;
      }
      continue;
    }
    for (const element of clause.elements) {
      if (element.name.text === name) {
        const via = exported(
          program,
          target,
          element.propertyName?.text ?? name,
          seen,
        );
        if (via) {
          return via;
        }
      }
    }
  }
  return undefined;
}

/** What a top-level or imported name stands for, or undefined. */
function resolveName(
  program: Program,
  file: ts.SourceFile,
  name: string,
): Declaration | undefined {
  const own = topLevel(file, name);
  if (own) {
    return { file, node: own };
  }
  for (const statement of file.statements) {
    if (!ts.isImportDeclaration(statement)) {
      continue;
    }
    const bindings = statement.importClause?.namedBindings;
    if (!(bindings && ts.isNamedImports(bindings))) {
      continue;
    }
    for (const element of bindings.elements) {
      if (element.name.text !== name) {
        continue;
      }
      const target = program.importedFile(
        file,
        (statement.moduleSpecifier as ts.StringLiteral).text,
      );
      return target
        ? exported(program, target, element.propertyName?.text ?? name)
        : undefined;
    }
  }
  return undefined;
}

function unwrap(expression: ts.Expression): ts.Expression {
  let current = expression;
  while (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isSatisfiesExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isTypeAssertionExpression(current)
  ) {
    current = current.expression;
  }
  return current;
}

function declaresName(
  list: ts.ForInitializer,
  name: string,
): list is ts.VariableDeclarationList {
  return (
    ts.isVariableDeclarationList(list) &&
    list.declarations.some(
      (declaration) =>
        ts.isIdentifier(declaration.name) && declaration.name.text === name,
    )
  );
}

type LocalBinding =
  | { kind: "declaration"; declaration: ts.VariableDeclaration }
  | { kind: "loop"; loop: ts.ForOfStatement };

function localBinding(node: ts.Node, name: string): LocalBinding | undefined {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isForOfStatement(parent) && declaresName(parent.initializer, name)) {
      return { kind: "loop", loop: parent };
    }
    if (
      ts.isBlock(parent) ||
      ts.isSourceFile(parent) ||
      ts.isModuleBlock(parent)
    ) {
      for (const statement of parent.statements) {
        if (!ts.isVariableStatement(statement)) {
          continue;
        }
        for (const declaration of statement.declarationList.declarations) {
          if (
            ts.isIdentifier(declaration.name) &&
            declaration.name.text === name
          ) {
            return { kind: "declaration", declaration };
          }
        }
      }
    }
  }
  return undefined;
}

/**
 * Every string `expression` can be, or undefined when it is not made only of
 * string literals, templates and concatenations of them, constants (local or
 * imported), properties of a constant object, and loop variables over arrays
 * of those.
 */
function strings(
  program: Program,
  expression: ts.Expression,
  depth = 0,
): string[] | undefined {
  if (depth > 20) {
    return undefined;
  }
  const node = unwrap(expression);
  const recurse = (inner: ts.Expression): string[] | undefined =>
    strings(program, inner, depth + 1);
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
    return [node.text];
  }
  if (ts.isTemplateExpression(node)) {
    let results = [node.head.text];
    for (const span of node.templateSpans) {
      const values = recurse(span.expression);
      if (!values) {
        return undefined;
      }
      results = results.flatMap((prefix) =>
        values.map((value) => `${prefix}${value}${span.literal.text}`),
      );
    }
    return results;
  }
  if (
    ts.isBinaryExpression(node) &&
    node.operatorToken.kind === ts.SyntaxKind.PlusToken
  ) {
    const left = recurse(node.left);
    const right = recurse(node.right);
    return left && right
      ? left.flatMap((a) => right.map((b) => `${a}${b}`))
      : undefined;
  }
  if (ts.isIdentifier(node)) {
    const local = localBinding(node, node.text);
    if (local?.kind === "loop") {
      return arrayStrings(program, local.loop.expression, depth + 1);
    }
    if (local?.kind === "declaration") {
      return local.declaration.initializer
        ? recurse(local.declaration.initializer)
        : undefined;
    }
    const found = resolveName(program, node.getSourceFile(), node.text);
    return found &&
      ts.isVariableDeclaration(found.node) &&
      found.node.initializer
      ? recurse(found.node.initializer)
      : undefined;
  }
  if (ts.isPropertyAccessExpression(node)) {
    const object = unwrap(node.expression);
    const local = ts.isIdentifier(object)
      ? localBinding(node, object.text)
      : undefined;
    const holder =
      local?.kind === "declaration"
        ? local.declaration
        : ts.isIdentifier(object)
          ? resolveName(program, node.getSourceFile(), object.text)?.node
          : undefined;
    const initializer =
      holder && ts.isVariableDeclaration(holder)
        ? holder.initializer && unwrap(holder.initializer)
        : undefined;
    if (initializer && ts.isObjectLiteralExpression(initializer)) {
      for (const property of initializer.properties) {
        if (
          ts.isPropertyAssignment(property) &&
          ts.isIdentifier(property.name) &&
          property.name.text === node.name.text
        ) {
          return recurse(property.initializer);
        }
      }
    }
  }
  return undefined;
}

function arrayStrings(
  program: Program,
  expression: ts.Expression,
  depth = 0,
): string[] | undefined {
  const node = unwrap(expression);
  if (ts.isArrayLiteralExpression(node)) {
    const out: string[] = [];
    for (const element of node.elements) {
      const values = strings(program, element, depth + 1);
      if (!values) {
        return undefined;
      }
      out.push(...values);
    }
    return out;
  }
  if (ts.isIdentifier(node)) {
    const local = localBinding(node, node.text);
    if (local?.kind === "loop") {
      return strings(program, node, depth + 1);
    }
    const initializer =
      local?.kind === "declaration"
        ? local.declaration.initializer
        : (() => {
            const found = resolveName(program, node.getSourceFile(), node.text);
            return found && ts.isVariableDeclaration(found.node)
              ? found.node.initializer
              : undefined;
          })();
    return initializer
      ? arrayStrings(program, initializer, depth + 1)
      : undefined;
  }
  return strings(program, node, depth + 1);
}

/** The static prefix of a route path; undefined where it names no family. */
function family(raw: string): string | undefined {
  if (!raw.startsWith("/")) {
    return undefined;
  }
  const kept: string[] = [];
  for (const segment of raw.split("/").filter(Boolean)) {
    if (segment.includes(":") || segment.includes("*")) {
      break;
    }
    kept.push(segment);
  }
  const value = `/${kept.join("/")}`;
  return kept.length === 0 || SHARED_ROOT.test(value) ? undefined : value;
}

function joinPaths(prefix: string, child: string): string {
  const base = prefix.replace(/\/+$/u, "");
  if (child === "/" || child === "") {
    return base === "" ? "/" : base;
  }
  if (child === "*") {
    return `${base}/*`;
  }
  return child.startsWith("/") ? `${base}${child}` : `${base}/${child}`;
}

function isHonoConstruction(expression: ts.Expression | undefined): boolean {
  if (!expression) {
    return false;
  }
  const node = unwrap(expression);
  return (
    ts.isNewExpression(node) &&
    ts.isIdentifier(node.expression) &&
    (node.expression.text === "Hono" || node.expression.text === "OpenAPIHono")
  );
}

/** The identifier a method-call chain starts from: `app` in `app.get().post()`. */
function chainRoot(expression: ts.Expression): ts.Expression {
  let current = unwrap(expression);
  while (
    ts.isCallExpression(current) &&
    ts.isPropertyAccessExpression(current.expression)
  ) {
    current = unwrap(current.expression.expression);
  }
  return current;
}

class Walker {
  private readonly active = new Set<ts.Node>();

  constructor(private readonly program: Program) {}

  /** Every route of the router a function builds and returns. */
  ofFunction(declaration: Declaration): Registered[] {
    const fn = declaration.node;
    const body = ts.isFunctionDeclaration(fn)
      ? fn
      : fn.initializer && unwrap(fn.initializer);
    if (!(
      body &&
      (ts.isFunctionDeclaration(body) ||
        ts.isArrowFunction(body) ||
        ts.isFunctionExpression(body))
    )) {
      return failAt(fn, "a mounted router factory is not a function");
    }
    if (this.active.has(body)) {
      return failAt(body, "route mounts form a cycle");
    }
    this.active.add(body);
    try {
      return this.ofScope(body);
    } finally {
      this.active.delete(body);
    }
  }

  private ofScope(fn: ts.FunctionLikeDeclaration): Registered[] {
    const variables = new Map<string, ts.VariableDeclaration>();
    const returns: ts.Expression[] = [];
    const visit = (node: ts.Node): void => {
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        isHonoConstruction(node.initializer)
      ) {
        variables.set(node.name.text, node);
      } else if (isHonoConstruction(node as ts.Expression)) {
        const parent = node.parent;
        if (!(
          ts.isVariableDeclaration(parent) && parent.initializer === node
        )) {
          failAt(node, "a router is built without being named");
        }
      }
      if (ts.isReturnStatement(node) && node.expression) {
        returns.push(node.expression);
      }
      ts.forEachChild(node, visit);
    };
    if (fn.body) {
      visit(fn.body);
      if (!ts.isBlock(fn.body)) {
        returns.push(fn.body);
      }
    }
    const names = [...variables.keys()];
    const returned = returns
      .map((expression) => unwrap(expression))
      .filter(ts.isIdentifier)
      .map((identifier) => identifier.text)
      .find((name) => variables.has(name));
    const entry = returned ?? (names.length === 1 ? names[0] : undefined);
    if (entry !== undefined) {
      return this.ofVariable(fn, entry);
    }
    // A factory that returns another factory's router.
    if (names.length === 0 && returns.length === 1) {
      return this.ofChild(returns[0]);
    }
    return failAt(fn, "cannot tell which router this function returns");
  }

  /** The routes registered on router variable `name` within `scope`. */
  ofVariable(scope: Scope, name: string): Registered[] {
    const out: Registered[] = [];
    const visit = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        this.registration(node, name, out);
      }
      ts.forEachChild(node, visit);
    };
    visit(ts.isSourceFile(scope) ? scope : (scope.body ?? scope));
    return out;
  }

  private registration(
    call: ts.CallExpression,
    name: string,
    out: Registered[],
  ): void {
    const callee = call.expression;
    // The router passed to a function that registers on it is not followed.
    for (const argument of call.arguments) {
      const value = unwrap(argument);
      if (
        ts.isIdentifier(value) &&
        value.text === name &&
        !(
          ts.isPropertyAccessExpression(callee) &&
          callee.name.text === "route" &&
          call.arguments[1] === argument
        )
      ) {
        failAt(call, `router ${name} is passed to a function`);
      }
    }
    if (!ts.isPropertyAccessExpression(callee)) {
      return;
    }
    const root = chainRoot(callee.expression);
    if (!(ts.isIdentifier(root) && root.text === name)) {
      return;
    }
    const method = callee.name.text;
    if (UNSUPPORTED_ROUTER_METHODS.has(method)) {
      failAt(call, `router.${method} is not supported`);
    }
    if (!REGISTRATION_METHODS.has(method)) {
      return;
    }
    const args = call.arguments;
    if (method === "route") {
      const prefixes = this.resolve(args[0], call, "mount prefix");
      const child = this.ofChild(args[1]);
      for (const prefix of prefixes) {
        for (const route of child) {
          out.push({ ...route, path: joinPaths(prefix, route.path) });
        }
        out.push({ path: joinPaths(prefix, "/") });
      }
      return;
    }
    if (method === "mount") {
      for (const value of this.resolve(args[0], call, "mount path")) {
        out.push({ path: joinPaths(value, "/") });
      }
      return;
    }
    if (method === "use") {
      // `use(middleware)` runs on every path; `use(path, ...)` names one.
      if (args.length >= 2) {
        for (const value of this.resolve(args[0], call, "middleware path")) {
          out.push({ path: joinPaths(value, "/") });
        }
      }
      return;
    }
    const pathIndex = method === "on" ? 1 : 0;
    const pathArg = args[pathIndex];
    if (!pathArg) {
      return;
    }
    const first = unwrap(pathArg);
    if (ts.isArrowFunction(first) || ts.isFunctionExpression(first)) {
      return;
    }
    const methods =
      method === "on"
        ? (
            arrayStrings(this.program, args[0]) ??
            failAt(call, "an `on` method list cannot be resolved")
          ).map((value) => value.toUpperCase())
        : [method.toUpperCase()];
    for (const value of this.resolve(pathArg, call, `${method} path`, true)) {
      for (const m of methods) {
        out.push({ path: joinPaths("", value), method: m });
      }
    }
  }

  private resolve(
    expression: ts.Expression | undefined,
    call: ts.CallExpression,
    what: string,
    allowArray = false,
  ): string[] {
    if (!expression) {
      return failAt(call, `${what} is missing`);
    }
    const values = allowArray
      ? arrayStrings(this.program, expression)
      : strings(this.program, expression);
    if (!values) {
      return failAt(expression, `${what} is not a constant string`);
    }
    return values;
  }

  /** The routes of a mounted child router expression. */
  private ofChild(expression: ts.Expression | undefined): Registered[] {
    if (!expression) {
      throw new Error("routes-contract: a route mount has no child router");
    }
    const node = unwrap(expression);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const found = resolveName(
        this.program,
        node.getSourceFile(),
        node.expression.text,
      );
      if (!found) {
        return failAt(node, `${node.expression.text} cannot be resolved`);
      }
      return this.ofFunction(found);
    }
    if (ts.isIdentifier(node)) {
      const local = localBinding(node, node.text);
      if (
        local?.kind === "declaration" &&
        isHonoConstruction(local.declaration.initializer)
      ) {
        const scope = enclosingScope(local.declaration);
        return this.ofVariable(scope, node.text);
      }
      const found = resolveName(this.program, node.getSourceFile(), node.text);
      if (
        found &&
        ts.isVariableDeclaration(found.node) &&
        isHonoConstruction(found.node.initializer)
      ) {
        return this.ofVariable(found.file, node.text);
      }
    }
    return failAt(
      node,
      "a mounted router is not a call to a factory or a named router",
    );
  }
}

function enclosingScope(node: ts.Node): Scope {
  for (let parent = node.parent; parent; parent = parent.parent) {
    if (ts.isSourceFile(parent) || ts.isFunctionLike(parent)) {
      return parent as Scope;
    }
  }
  return node.getSourceFile();
}

/**
 * Paths a dispatcher compares or prefix-matches (`pathname === "/x"`,
 * `pathname.startsWith("/x/")`), and values of names that hold paths
 * (`syncPrefix`, `BASE_PATHS`). A non-constant value under such a name
 * throws.
 */
function dispatcherPaths(
  program: Program,
  file: ts.SourceFile,
  registrationCalls: boolean,
): string[] {
  const found: string[] = [];
  const mentionsPath = (node: ts.Node): boolean =>
    /\b(?:pathname|path)\b/u.test(node.getText());
  // A module-level constant (or an UPPER_CASE name) that does not evaluate
  // to a string cannot be skipped; a parameter or local can.
  const looksLikeConstant = (node: ts.Expression): boolean => {
    const value = unwrap(node);
    if (ts.isIdentifier(value)) {
      if (/^[A-Z][A-Z0-9_]*$/u.test(value.text)) {
        return true;
      }
      return (
        localBinding(value, value.text) === undefined &&
        resolveName(program, value.getSourceFile(), value.text) !== undefined
      );
    }
    return (
      ts.isPropertyAccessExpression(value) &&
      /^[A-Z][A-Z0-9_]*$/u.test(value.name.text)
    );
  };
  const take = (expression: ts.Expression, array: boolean): void => {
    const values = array
      ? arrayStrings(program, expression)
      : strings(program, expression);
    if (values) {
      found.push(...values);
    } else if (looksLikeConstant(expression)) {
      failAt(expression, "a path constant cannot be resolved");
    }
  };
  const visit = (node: ts.Node): void => {
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression)
    ) {
      const name = node.expression.name.text;
      const first = node.arguments[0];
      if (first && registrationCalls && REGISTRATION_METHODS.has(name)) {
        const values = strings(program, first);
        if (values) {
          found.push(...values);
        }
      } else if (
        first &&
        name === "startsWith" &&
        mentionsPath(node.expression.expression)
      ) {
        take(first, false);
      }
    } else if (
      ts.isBinaryExpression(node) &&
      (node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ||
        node.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken)
    ) {
      const leftPath = mentionsPath(node.left);
      const rightPath = mentionsPath(node.right);
      if (leftPath !== rightPath) {
        take(leftPath ? node.right : node.left, false);
      }
    } else if (
      ts.isVariableDeclaration(node) &&
      ts.isIdentifier(node.name) &&
      PATH_NAME.test(node.name.text) &&
      node.initializer
    ) {
      // A name that holds paths counts when it is made of constant strings;
      // a filesystem path built at run time is not a route.
      const values = arrayStrings(program, node.initializer);
      if (values) {
        found.push(...values);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return found;
}

/**
 * Route families from the server (every router mounted under `createApp`,
 * composed), the server entry's own dispatch comparisons, and the lite
 * dispatcher. `server` holds every server source the walk may follow;
 * `serverEntry` is the file that exports `createApp`.
 */
export function collectRoutes(input: {
  server: SourceFile[];
  serverEntry: string;
  lite: SourceFile[];
}): RoutesContract {
  const program = new Program([...input.server, ...input.lite]);
  const hostsByPath = new Map<
    string,
    { hosts: Set<RouteHost>; methods: Set<string> }
  >();
  const add = (raw: string, host: RouteHost, method?: string): void => {
    const value = family(raw);
    if (value === undefined) {
      return;
    }
    const entry = hostsByPath.get(value) ?? {
      hosts: new Set<RouteHost>(),
      methods: new Set<string>(),
    };
    entry.hosts.add(host);
    if (method) {
      entry.methods.add(method);
    }
    hostsByPath.set(value, entry);
  };

  const entryFile = program.file(input.serverEntry);
  const createApp = exported(program, entryFile, "createApp");
  if (!createApp) {
    throw new Error(`routes-contract: ${input.serverEntry} has no createApp`);
  }
  for (const route of new Walker(program).ofFunction(createApp)) {
    add(route.path, "server", route.method);
  }
  for (const value of dispatcherPaths(program, entryFile, false)) {
    add(value, "server");
  }
  for (const file of input.lite) {
    for (const value of dispatcherPaths(
      program,
      program.file(file.name),
      true,
    )) {
      add(value, "lite");
    }
  }

  const routes = [...hostsByPath.entries()]
    .map(([routePath, { hosts, methods }]): RouteEntry => ({
      path: routePath,
      hosts: [...hosts].sort(),
      ...(methods.size > 0 ? { methods: [...methods].sort() } : {}),
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
  return collectRoutes({
    server: readSources(server, true),
    serverEntry: path.join(server, "app.ts"),
    lite: readSources(path.join(root, "packages/lite/src"), false),
  });
}
