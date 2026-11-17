// Check every emitted JS file in published packages against its own manifest.
import fs from "node:fs";
import { execFileSync } from "node:child_process";
import { builtinModules } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const builtins = new Set(
  builtinModules.flatMap((name) => [name, `node:${name}`]),
);
const violations = [];
// Published browser assets that Node never loads: the server only reads them
// from disk and serves the bytes (packages/server/src/routes/ui.ts, route
// `/:file`, readFileSync + Response), and no Node module imports or requires
// them. Node loader calls inside them cannot break an install, so the loader
// check skips them; their static import/export declarations are still checked.
const servedOnlyBrowserAssets = new Map([
  [
    "packages/server/dist/ui/ps-lite-debug.js",
    "esbuild browser bundle served by the UI route; its inlined unpdf and pdfjs-dist Node branches are never run by Node",
  ],
]);
// Loader uses in Node-loaded files that cannot be proven by shape. Each entry is
// the exact text of the enclosing property, method or function (whitespace
// collapsed). Any change to that text, or any other loader use in the file,
// fails the check.
const unanalysableLoaderAllowlist = [
  {
    file: "packages/lite/dist/browser-tls-rustls/browser_tls_rustls.js",
    ownerText:
      "__wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () { const ret = module.require; return ret; }, arguments); }",
    reason:
      'wasm-bindgen glue hands `module.require` to the wasm module. getrandom 0.2.17 (src/js.rs:83-84) calls it only with the literal "crypto" (a builtin), and only when Web Crypto is missing. In an ES module `module` is undefined, so handleError catches the ReferenceError',
  },
];
const computedImports = [];

// Fail-closed loader analysis. A "loader" is anything that can load a module at
// run time: `require`, `module.require`, `process.mainModule.require`, the
// result of `createRequire(...)` (the factory under any local name), or any
// identifier bound from those. Every reference to a loader identity must be a
// recognised direct call (or `.resolve(...)` call) or a plain binding; anything
// else (alias passed, assigned, destructured, returned, ...) is unanalysable.
const MODULE_PROPS_SAFE = new Set([
  "exports",
  "id",
  "filename",
  "path",
  "loaded",
  "paths",
]);
const LOADER_PROPS_SAFE = new Set(["cache", "extensions", "main"]);
const isWrapper = (node) =>
  ts.isParenthesizedExpression(node) ||
  ts.isAsExpression(node) ||
  ts.isNonNullExpression(node) ||
  ts.isTypeAssertionExpression(node) ||
  ts.isSatisfiesExpression(node);
const unwrapDown = (node) => {
  while (isWrapper(node)) node = node.expression;
  return node;
};
const outerOf = (node) => {
  while (node.parent && isWrapper(node.parent)) node = node.parent;
  return node;
};
const isId = (node, text) => ts.isIdentifier(node) && node.text === text;
const isImportMeta = (node) =>
  ts.isMetaProperty(node) &&
  node.keywordToken === ts.SyntaxKind.ImportKeyword &&
  node.name.text === "meta";

const bindingNames = (name) =>
  ts.isIdentifier(name)
    ? [name.text]
    : name.elements.flatMap((element) =>
        ts.isOmittedExpression(element) ? [] : bindingNames(element.name),
      );
// Nearest enclosing scope that declares `name` (no type checker): a parameter,
// catch variable, import, or declaration among a block's statements. Returns
// undefined for a free (global) name.
const declaredNamesCache = new WeakMap();
// `var` declarations are function-scoped: collect them from anywhere inside a
// function (or source file) body, except nested functions.
const collectVarNames = (node, names) => {
  ts.forEachChild(node, (child) => {
    if (ts.isFunctionLike(child)) return;
    if (
      ts.isVariableDeclarationList(child) &&
      !(child.flags & ts.NodeFlags.BlockScoped)
    )
      for (const d of child.declarations)
        for (const n of bindingNames(d.name)) names.add(n);
    collectVarNames(child, names);
  });
};
const declaredNames = (scope) => {
  let names = declaredNamesCache.get(scope);
  if (names) return names;
  names = new Set();
  if (ts.isFunctionLike(scope)) {
    for (const p of scope.parameters)
      for (const n of bindingNames(p.name)) names.add(n);
    if (scope.body) collectVarNames(scope.body, names);
  }
  if (ts.isSourceFile(scope)) collectVarNames(scope, names);
  if (ts.isCatchClause(scope) && scope.variableDeclaration)
    for (const n of bindingNames(scope.variableDeclaration.name)) names.add(n);
  if (ts.isBlock(scope) || ts.isSourceFile(scope))
    for (const st of scope.statements) {
      if (
        ts.isVariableStatement(st) &&
        st.declarationList.flags & ts.NodeFlags.BlockScoped
      )
        for (const d of st.declarationList.declarations)
          for (const n of bindingNames(d.name)) names.add(n);
      if (
        (ts.isFunctionDeclaration(st) || ts.isClassDeclaration(st)) &&
        st.name
      )
        names.add(st.name.text);
      const clause = ts.isImportDeclaration(st) && st.importClause;
      if (clause) {
        if (clause.name) names.add(clause.name.text);
        const nb = clause.namedBindings;
        if (nb && ts.isNamespaceImport(nb)) names.add(nb.name.text);
        else if (nb) for (const e of nb.elements) names.add(e.name.text);
      }
    }
  declaredNamesCache.set(scope, names);
  return names;
};
const declScope = (node, name = node.text) => {
  for (let scope = node.parent; scope; scope = scope.parent)
    if (declaredNames(scope).has(name)) return scope;
  return undefined;
};
// Source text of the nearest enclosing named property, method or function,
// whitespace collapsed.
const ownerText = (node) => {
  for (let n = node; n; n = n.parent)
    if (
      (ts.isPropertyAssignment(n) ||
        ts.isMethodDeclaration(n) ||
        ts.isFunctionDeclaration(n)) &&
      n.name
    )
      return n.getText().replace(/\s+/g, " ");
  return undefined;
};

// True when `node` is assigned to, updated, deleted, or is a destructuring
// target, so `import.meta.url` cannot be treated as a plain read.
const isWriteTarget = (node) => {
  let current = outerOf(node);
  for (;;) {
    const parent = current.parent;
    if (!parent) return false;
    if (
      ts.isArrayLiteralExpression(parent) ||
      ts.isSpreadElement(parent) ||
      ts.isObjectLiteralExpression(parent) ||
      (ts.isPropertyAssignment(parent) && parent.initializer === current) ||
      ts.isParenthesizedExpression(parent)
    ) {
      // Keep climbing: a write only if the enclosing literal is an assignment
      // pattern, which the binary-expression or for-in/of checks below decide.
      current = parent;
      continue;
    }
    if (ts.isBinaryExpression(parent))
      return (
        parent.left === current &&
        parent.operatorToken.kind >= ts.SyntaxKind.FirstAssignment &&
        parent.operatorToken.kind <= ts.SyntaxKind.LastAssignment
      );
    if (
      ts.isPrefixUnaryExpression(parent) ||
      ts.isPostfixUnaryExpression(parent)
    )
      return (
        parent.operator === ts.SyntaxKind.PlusPlusToken ||
        parent.operator === ts.SyntaxKind.MinusMinusToken
      );
    if (ts.isDeleteExpression(parent)) return true;
    return (
      (ts.isForInStatement(parent) || ts.isForOfStatement(parent)) &&
      parent.initializer === current
    );
  }
};

function createLoaderAnalysis(source) {
  // Derived bindings: name -> scopes where that name is bound to the kind.
  const bound = { loader: new Map(), factory: new Map(), moduleObj: new Map() };
  const literalName = (node) =>
    ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)
      ? node.text
      : undefined;
  const memberName = (node) =>
    ts.isPropertyAccessExpression(node)
      ? node.name.text
      : ts.isElementAccessExpression(node)
        ? literalName(node.argumentExpression)
        : undefined;
  const anyBound = (name) =>
    bound.loader.has(name) ||
    bound.factory.has(name) ||
    bound.moduleObj.has(name);
  const kindOf = (raw) => {
    const node = unwrapDown(raw);
    if (ts.isIdentifier(node)) {
      // `require` and `createRequire` are loader identities under any scope
      // (a parameter named `require` may be a real loader); `module` is the
      // module object only when it is a free name.
      if (node.text === "require") return "loader";
      if (node.text === "createRequire") return "factory";
      const known = node.text === "module" || anyBound(node.text);
      if (!known) return undefined;
      const scope = declScope(node);
      if (node.text === "module" && scope === undefined) return "moduleObj";
      for (const [kind, names] of Object.entries(bound))
        if (names.get(node.text)?.has(scope)) return kind;
      return undefined;
    }
    if (
      ts.isPropertyAccessExpression(node) ||
      ts.isElementAccessExpression(node)
    ) {
      const name = memberName(node);
      const base = kindOf(node.expression);
      if (base === "moduleObj" && name === "require") return "loader";
      if (name === "createRequire") return "factory";
      if (name === "mainModule" && isId(unwrapDown(node.expression), "process"))
        return "moduleObj";
      if (name === "main" && base === "loader") return "moduleObj";
      return undefined;
    }
    if (ts.isCallExpression(node) && kindOf(node.expression) === "factory")
      return "loader";
    return undefined;
  };
  // Bindings first, to a fixed point: traversal order must not change results.
  let changed = true;
  while (changed) {
    changed = false;
    const visit = (node) => {
      let kind;
      let name;
      if (
        ts.isVariableDeclaration(node) &&
        ts.isIdentifier(node.name) &&
        node.initializer
      ) {
        kind = kindOf(node.initializer);
        name = node.name;
      } else if (
        (ts.isImportSpecifier(node) || ts.isBindingElement(node)) &&
        ts.isIdentifier(node.name) &&
        (node.propertyName ?? node.name).text === "createRequire"
      ) {
        kind = "factory";
        name = node.name;
      }
      if (kind) {
        const scopes = bound[kind].get(name.text) ?? new Set();
        const scope = declScope(name);
        if (!scopes.has(scope)) {
          scopes.add(scope);
          bound[kind].set(name.text, scopes);
          changed = true;
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  const isDeclarationName = (node) => {
    const parent = node.parent;
    if (
      !parent ||
      ts.isShorthandPropertyAssignment(parent) ||
      ts.isExportSpecifier(parent)
    )
      return false;
    return parent.name === node || parent.propertyName === node;
  };
  const isCallee = (node) => {
    const outer = outerOf(node);
    return (
      ts.isCallExpression(outer.parent) && outer.parent.expression === outer
    );
  };
  const isResolveCallee = (node) => {
    const outer = outerOf(node);
    return (
      ts.isPropertyAccessExpression(outer.parent) &&
      outer.parent.expression === outer &&
      outer.parent.name.text === "resolve" &&
      isCallee(outer.parent)
    );
  };
  return {
    ownerText,
    // `<loader>(x)`, `<loader>.resolve(x)`, `import.meta.resolve(x)` and
    // `import.meta["resolve"](x)`.
    isLoaderCall(expression) {
      const callee = unwrapDown(expression);
      if (kindOf(callee) === "loader") return true;
      if (
        (ts.isPropertyAccessExpression(callee) ||
          ts.isElementAccessExpression(callee)) &&
        memberName(callee) === "resolve"
      ) {
        const base = unwrapDown(callee.expression);
        return kindOf(base) === "loader" || isImportMeta(base);
      }
      return false;
    },
    // Deny by default: `import.meta` may only be read through `.url` or called
    // through `.resolve(...)`. Any other use (alias, destructuring, computed or
    // unknown member, mutation, passing it on) hands the meta object to code
    // this checker does not follow, so it is unanalysable. No alias tracking.
    isUnanalysableImportMeta(node) {
      if (!isImportMeta(node)) return false;
      const outer = outerOf(node);
      const parent = outer.parent;
      if (!(
        (ts.isPropertyAccessExpression(parent) ||
          ts.isElementAccessExpression(parent)) &&
        parent.expression === outer
      ))
        return true;
      const name = memberName(parent);
      if (name === "url") return isWriteTarget(parent);
      if (name === "resolve") return !isCallee(parent);
      return true;
    },
    // A loader-identity reference that is not a proven form.
    isUnanalysableUse(node) {
      if (isWrapper(node)) return false;
      const kind = kindOf(node);
      if (!kind) return false;
      if (ts.isIdentifier(node)) {
        if (isDeclarationName(node)) return false;
        if (ts.isTypeOfExpression(outerOf(node).parent)) return false;
      }
      const outer = outerOf(node);
      const parent = outer.parent;
      if (
        ts.isVariableDeclaration(parent) &&
        parent.initializer === outer &&
        ts.isIdentifier(parent.name)
      )
        // A plain local binding; exporting it would hand the loader away.
        return !!parent.parent.parent?.modifiers?.some(
          (m) => m.kind === ts.SyntaxKind.ExportKeyword,
        );
      const member =
        ts.isPropertyAccessExpression(parent) && parent.expression === outer
          ? parent.name.text
          : undefined;
      if (kind === "loader")
        return !(
          isCallee(node) ||
          LOADER_PROPS_SAFE.has(member) ||
          (member === "resolve" && isResolveCallee(node))
        );
      if (kind === "factory") return !isCallee(node);
      return !(
        member !== undefined &&
        (member === "require" || MODULE_PROPS_SAFE.has(member))
      );
    },
  };
}

for (const dir of fs.readdirSync(path.join(root, "packages"))) {
  const pkgDir = path.join(root, "packages", dir);
  const manifestPath = path.join(pkgDir, "package.json");
  if (!fs.existsSync(manifestPath)) continue;
  const pkg = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (pkg.private) continue;
  const dist = path.join(pkgDir, "dist");
  if (!fs.existsSync(dist)) {
    violations.push(`${path.relative(root, dist)} is missing`);
    continue;
  }
  const allowed = new Set([
    pkg.name,
    ...Object.keys(pkg.dependencies ?? {}),
    ...Object.keys(pkg.optionalDependencies ?? {}),
    ...Object.keys(pkg.peerDependencies ?? {}),
  ]);
  const packed = JSON.parse(
    execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: pkgDir,
      encoding: "utf8",
    }),
  );
  const [{ files }] = Array.isArray(packed) ? packed : Object.values(packed);
  const packedFiles = new Set(files.map(({ path: packedPath }) => packedPath));
  for (const { path: packedPath } of files) {
    if (!/\.(?:c?js|mjs)$/.test(packedPath)) continue;
    const file = path.join(pkgDir, packedPath);
    const source = ts.createSourceFile(
      file,
      fs.readFileSync(file, "utf8"),
      ts.ScriptTarget.Latest,
      true,
      ts.ScriptKind.JS,
    );
    const loaders = createLoaderAnalysis(source);
    const relFile = path.relative(root, file).split(path.sep).join("/");
    const reportUnanalysable = (node) => {
      const location = `${relFile}:${source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1}`;
      const ownerText = loaders.ownerText(node);
      const reason = unanalysableLoaderAllowlist.find(
        (entry) => entry.file === relFile && entry.ownerText === ownerText,
      )?.reason;
      computedImports.push(
        `${location}${reason ? ` (allowed: ${reason})` : " (unanalysable)"}`,
      );
      if (!reason)
        violations.push(
          `${location} has an unanalysable dynamic import or loader use`,
        );
    };
    const loaderChecked = !servedOnlyBrowserAssets.has(relFile);
    const pending = [source];
    while (pending.length) {
      const node = pending.pop();
      let specifier;
      if (
        (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier &&
        ts.isStringLiteral(node.moduleSpecifier)
      ) {
        specifier = node.moduleSpecifier.text;
      } else if (loaderChecked && ts.isCallExpression(node)) {
        const isDynamicImport =
          node.expression.kind === ts.SyntaxKind.ImportKeyword;
        const isRuntimeLoader = loaders.isLoaderCall(node.expression);
        const arg = node.arguments[0];
        if (
          (isDynamicImport || isRuntimeLoader) &&
          arg &&
          (ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg))
        ) {
          specifier = arg.text;
        } else if (isDynamicImport || isRuntimeLoader) {
          reportUnanalysable(node);
        }
      }
      if (
        loaderChecked &&
        (loaders.isUnanalysableUse(node) ||
          loaders.isUnanalysableImportMeta(node))
      )
        reportUnanalysable(node);
      if (specifier?.startsWith(".")) {
        const target = path.posix.normalize(
          path.posix.join(path.posix.dirname(packedPath), specifier),
        );
        if (!packedFiles.has(target))
          violations.push(
            `${path.relative(root, file)} imports unpacked relative target ${specifier}`,
          );
        // A served-only asset is exempt from loader checks only because no
        // checked file loads it. Any static, dynamic or resolver reference to it
        // voids that premise.
        if (servedOnlyBrowserAssets.has(`packages/${dir}/${target}`))
          violations.push(
            `${relFile} loads served-only browser asset ${target} (${specifier}); the loader checks are skipped for it only because nothing loads it`,
          );
      }
      if (specifier && !specifier.startsWith(".") && !builtins.has(specifier)) {
        const name = specifier.startsWith("@")
          ? specifier.split("/").slice(0, 2).join("/")
          : specifier.split("/")[0];
        if (!allowed.has(name))
          violations.push(`${path.relative(root, file)} imports ${specifier}`);
      }
      ts.forEachChild(node, (child) => {
        pending.push(child);
      });
    }
  }
}
console.log(
  `Computed imports and runtime loaders: ${computedImports.length ? `\n${computedImports.join("\n")}` : "none"}`,
);
if (violations.length) {
  console.error(violations.join("\n"));
  process.exit(1);
}
console.log("ok: published dist imports are declared runtime dependencies");
