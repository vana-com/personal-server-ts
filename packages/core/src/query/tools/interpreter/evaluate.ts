/**
 * A tree-walking evaluator for model-authored JavaScript (design §19.6 item 3:
 * "a tree-walking JS interpreter with no `eval`, where generated code receives
 * only host-supplied authority and can call only host-registered tools").
 *
 * There is no `eval`, no `new Function`, and no host realm reachable from a
 * script value — every property read goes through `readMember`, which severs
 * the `constructor` bridge. The evaluator understands a deliberate subset of
 * the language: enough to write real data-processing code (loops, destructuring,
 * array methods, arithmetic, `await`), and nothing that reaches outward.
 * Unsupported syntax raises {@link ConfinementError} rather than being ignored,
 * so a script never half-runs.
 */
import type { Node } from "acorn";
import {
  ConfinementError,
  FORBIDDEN_IDENTIFIERS,
  readMember,
} from "./realm.js";

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyNode = any;

/** Lexical scope. A `Map` per scope, chained to its parent. */
class Scope {
  readonly vars = new Map<string, unknown>();
  constructor(readonly parent?: Scope) {}

  lookup(name: string): { scope: Scope } | undefined {
    return Scope.walk(this, name);
  }

  /** Walk the scope chain from `start` looking for a binding. */
  private static walk(
    start: Scope,
    name: string,
  ): { scope: Scope } | undefined {
    let s: Scope | undefined = start;
    while (s) {
      if (s.vars.has(name)) return { scope: s };
      s = s.parent;
    }
    return undefined;
  }

  get(name: string): unknown {
    const found = this.lookup(name);
    if (!found) throw new ReferenceError(`${name} is not defined`);
    return found.scope.vars.get(name);
  }

  set(name: string, value: unknown): void {
    const found = this.lookup(name);
    if (!found) throw new ReferenceError(`${name} is not defined`);
    found.scope.vars.set(name, value);
  }

  declare(name: string, value: unknown): void {
    this.vars.set(name, value);
  }
}

/** Control-flow sentinels. Distinct objects so a script value can never forge one. */
const BREAK = Symbol("break");
const CONTINUE = Symbol("continue");
interface Returned {
  __return: true;
  value: unknown;
}
function isReturn(v: unknown): v is Returned {
  return typeof v === "object" && v !== null && "__return" in v;
}

export interface EvaluateOptions {
  /**
   * Upper bound on evaluated nodes. Defence in depth beside the sandbox's CPU
   * limit: it stops a runaway loop deterministically and with a clear message,
   * rather than as a SIGXCPU the caller has to interpret.
   */
  maxSteps?: number;
}

const DENIED_NODES: Record<string, string> = {
  ImportDeclaration: "import is not available; use the vana API",
  ImportExpression: "dynamic import is not available",
  MetaProperty: "import.meta is not available",
  WithStatement: "with is not allowed",
  ClassDeclaration: "class declarations are not allowed in the confined realm",
  ClassExpression: "class expressions are not allowed in the confined realm",
  YieldExpression: "generators are not supported",
  TaggedTemplateExpression: "tagged templates are not supported",
  LabeledStatement: "labels are not supported",
  DebuggerStatement: "debugger is not allowed",
};

export async function evaluateProgram(
  ast: Node,
  globals: Map<string, unknown>,
  options: EvaluateOptions = {},
): Promise<unknown> {
  const maxSteps = options.maxSteps ?? 5_000_000;
  let steps = 0;
  const root = new Scope();
  for (const [k, v] of globals) root.declare(k, v);

  const tick = () => {
    if (++steps > maxSteps) {
      throw new ConfinementError(
        `script exceeded ${maxSteps} evaluation steps — probable infinite loop`,
      );
    }
  };

  async function evalNode(node: AnyNode, scope: Scope): Promise<unknown> {
    tick();
    const denied = DENIED_NODES[node.type as string];
    if (denied) throw new ConfinementError(denied);

    switch (node.type) {
      case "Program":
      case "BlockStatement": {
        const inner = node.type === "Program" ? scope : new Scope(scope);
        await hoist(node.body, inner);
        let last: unknown;
        for (const stmt of node.body) {
          last = await evalNode(stmt, inner);
          if (last === BREAK || last === CONTINUE || isReturn(last))
            return last;
        }
        return last;
      }
      case "EmptyStatement":
        return undefined;
      case "ExpressionStatement":
        return evalNode(node.expression, scope);

      case "VariableDeclaration": {
        for (const d of node.declarations) {
          const value = d.init ? await evalNode(d.init, scope) : undefined;
          await bindPattern(d.id, value, scope, true);
        }
        return undefined;
      }

      case "FunctionDeclaration":
        // Hoisted in `hoist`; nothing to do at execution time.
        return undefined;

      case "ReturnStatement":
        return {
          __return: true,
          value: node.argument
            ? await evalNode(node.argument, scope)
            : undefined,
        } satisfies Returned;

      case "IfStatement":
        if (truthy(await evalNode(node.test, scope))) {
          return evalNode(node.consequent, scope);
        }
        return node.alternate ? evalNode(node.alternate, scope) : undefined;

      case "ForStatement": {
        const s = new Scope(scope);
        if (node.init) await evalNode(node.init, s);
        while (node.test ? truthy(await evalNode(node.test, s)) : true) {
          tick();
          const r = await evalNode(node.body, new Scope(s));
          if (r === BREAK) break;
          if (isReturn(r)) return r;
          if (node.update) await evalNode(node.update, s);
        }
        return undefined;
      }

      case "ForOfStatement": {
        const iterable = await evalNode(node.right, scope);
        for (const item of iterable as Iterable<unknown>) {
          tick();
          const s = new Scope(scope);
          await bindForTarget(node.left, item, s);
          const r = await evalNode(node.body, s);
          if (r === BREAK) break;
          if (isReturn(r)) return r;
        }
        return undefined;
      }

      case "ForInStatement": {
        const obj = await evalNode(node.right, scope);
        for (const key of Object.keys((obj ?? {}) as object)) {
          tick();
          const s = new Scope(scope);
          await bindForTarget(node.left, key, s);
          const r = await evalNode(node.body, s);
          if (r === BREAK) break;
          if (isReturn(r)) return r;
        }
        return undefined;
      }

      case "WhileStatement":
        while (truthy(await evalNode(node.test, scope))) {
          tick();
          const r = await evalNode(node.body, new Scope(scope));
          if (r === BREAK) break;
          if (isReturn(r)) return r;
        }
        return undefined;

      case "DoWhileStatement":
        do {
          tick();
          const r = await evalNode(node.body, new Scope(scope));
          if (r === BREAK) break;
          if (isReturn(r)) return r;
        } while (truthy(await evalNode(node.test, scope)));
        return undefined;

      case "BreakStatement":
        return BREAK;
      case "ContinueStatement":
        return CONTINUE;

      case "ThrowStatement":
        throw await evalNode(node.argument, scope);

      case "TryStatement": {
        try {
          const r = await evalNode(node.block, scope);
          if (isReturn(r) || r === BREAK || r === CONTINUE) return r;
        } catch (err) {
          // A confinement violation is not the script's to catch: letting a
          // script swallow it would turn a hard denial into a silent retry.
          if (err instanceof ConfinementError) throw err;
          if (node.handler) {
            const s = new Scope(scope);
            if (node.handler.param) {
              await bindPattern(node.handler.param, err, s, true);
            }
            const r = await evalNode(node.handler.body, s);
            if (isReturn(r) || r === BREAK || r === CONTINUE) return r;
          } else if (!node.finalizer) {
            throw err;
          }
        } finally {
          if (node.finalizer) await evalNode(node.finalizer, scope);
        }
        return undefined;
      }

      case "SwitchStatement": {
        const disc = await evalNode(node.discriminant, scope);
        const s = new Scope(scope);
        let matched = false;
        for (const c of node.cases) {
          if (!matched && c.test !== null) {
            if ((await evalNode(c.test, s)) !== disc) continue;
          }
          if (
            !matched &&
            c.test === null &&
            !node.cases.some((x: AnyNode) => x.test !== null)
          ) {
            matched = true;
          }
          matched = true;
          for (const stmt of c.consequent) {
            const r = await evalNode(stmt, s);
            if (r === BREAK) return undefined;
            if (isReturn(r)) return r;
          }
        }
        return undefined;
      }

      /* ---------- expressions ---------- */

      case "Literal":
        return node.value;

      case "Identifier":
        if (FORBIDDEN_IDENTIFIERS.has(node.name)) {
          throw new ConfinementError(
            `"${node.name}" is not available in the confined realm`,
          );
        }
        return scope.get(node.name);

      case "TemplateLiteral": {
        let out = "";
        for (let i = 0; i < node.quasis.length; i++) {
          out += node.quasis[i].value.cooked ?? "";
          if (i < node.expressions.length) {
            out += String(await evalNode(node.expressions[i], scope));
          }
        }
        return out;
      }

      case "ArrayExpression": {
        const out: unknown[] = [];
        for (const el of node.elements) {
          if (el === null) {
            out.push(undefined);
          } else if (el.type === "SpreadElement") {
            out.push(...((await evalNode(el.argument, scope)) as unknown[]));
          } else {
            out.push(await evalNode(el, scope));
          }
        }
        return out;
      }

      case "ObjectExpression": {
        const out: Record<string, unknown> = {};
        for (const p of node.properties) {
          if (p.type === "SpreadElement") {
            Object.assign(out, await evalNode(p.argument, scope));
            continue;
          }
          const key = p.computed
            ? String(await evalNode(p.key, scope))
            : p.key.type === "Identifier"
              ? p.key.name
              : String(p.key.value);
          if (key === "__proto__" || key === "constructor") {
            throw new ConfinementError(
              `object literal may not define "${key}"`,
            );
          }
          out[key] = await evalNode(p.value, scope);
        }
        return out;
      }

      case "MemberExpression": {
        const obj = await evalNode(node.object, scope);
        if (node.optional && (obj === null || obj === undefined))
          return undefined;
        const key = node.computed
          ? ((await evalNode(node.property, scope)) as PropertyKey)
          : node.property.name;
        return readMember(obj, key);
      }

      case "ChainExpression":
        return evalNode(node.expression, scope);

      case "CallExpression": {
        let thisArg: unknown;
        let fn: unknown;
        if (node.callee.type === "MemberExpression") {
          thisArg = await evalNode(node.callee.object, scope);
          if (
            node.callee.optional &&
            (thisArg === null || thisArg === undefined)
          ) {
            return undefined;
          }
          const key = node.callee.computed
            ? ((await evalNode(node.callee.property, scope)) as PropertyKey)
            : node.callee.property.name;
          fn = readMember(thisArg, key);
        } else {
          fn = await evalNode(node.callee, scope);
        }
        if (node.optional && (fn === null || fn === undefined))
          return undefined;
        const args = await evalArgs(node.arguments, scope);
        if (typeof fn !== "function") {
          throw new TypeError(`${describe(node.callee)} is not a function`);
        }
        return (fn as (...a: unknown[]) => unknown)(...args);
      }

      case "NewExpression": {
        const ctor = await evalNode(node.callee, scope);
        const args = await evalArgs(node.arguments, scope);
        const allowed = [
          Map,
          Set,
          Date,
          RegExp,
          Error,
          TypeError,
          RangeError,
          Array,
        ];
        if (!allowed.includes(ctor as never)) {
          throw new ConfinementError(
            `new ${describe(node.callee)} is not allowed in the confined realm`,
          );
        }
        return new (ctor as new (...a: unknown[]) => unknown)(...args);
      }

      case "BinaryExpression": {
        const l = await evalNode(node.left, scope);
        const r = await evalNode(node.right, scope);
        return binary(node.operator, l, r);
      }

      case "LogicalExpression": {
        const l = await evalNode(node.left, scope);
        if (node.operator === "&&")
          return truthy(l) ? evalNode(node.right, scope) : l;
        if (node.operator === "||")
          return truthy(l) ? l : evalNode(node.right, scope);
        return l === null || l === undefined ? evalNode(node.right, scope) : l;
      }

      case "UnaryExpression": {
        if (node.operator === "delete") {
          throw new ConfinementError("delete is not allowed");
        }
        const v = await evalNode(node.argument, scope);
        switch (node.operator) {
          case "-":
            return -(v as number);
          case "+":
            return +(v as number);
          case "!":
            return !truthy(v);
          case "~":
            return ~(v as number);
          case "typeof":
            return typeof v;
          case "void":
            return undefined;
          default:
            throw new ConfinementError(`unary ${node.operator} not supported`);
        }
      }

      case "UpdateExpression": {
        const name = node.argument.name as string;
        const old = Number(scope.get(name));
        const next = node.operator === "++" ? old + 1 : old - 1;
        scope.set(name, next);
        return node.prefix ? next : old;
      }

      case "AssignmentExpression": {
        const value = await evalNode(node.right, scope);
        if (node.operator === "=") {
          await assign(node.left, value, scope);
          return value;
        }
        const current = await evalNode(node.left, scope);
        const op = node.operator.slice(0, -1);
        const next = binary(op, current, value);
        await assign(node.left, next, scope);
        return next;
      }

      case "ConditionalExpression":
        return truthy(await evalNode(node.test, scope))
          ? evalNode(node.consequent, scope)
          : evalNode(node.alternate, scope);

      case "SequenceExpression": {
        let last: unknown;
        for (const e of node.expressions) last = await evalNode(e, scope);
        return last;
      }

      case "AwaitExpression":
        return await evalNode(node.argument, scope);

      case "ArrowFunctionExpression":
      case "FunctionExpression":
        return makeFunction(node, scope);

      default:
        throw new ConfinementError(`unsupported syntax: ${String(node.type)}`);
    }
  }

  function makeFunction(node: AnyNode, closure: Scope) {
    const fn = (...args: unknown[]) => {
      const s = new Scope(closure);
      const run = async () => {
        for (let i = 0; i < node.params.length; i++) {
          const p = node.params[i];
          if (p.type === "RestElement") {
            await bindPattern(p.argument, args.slice(i), s, true);
            break;
          }
          await bindPattern(p, args[i], s, true);
        }
        const body =
          node.body.type === "BlockStatement"
            ? await evalNode(node.body, s)
            : { __return: true, value: await evalNode(node.body, s) };
        return isReturn(body) ? body.value : undefined;
      };
      // Every script function is async: the evaluator is async throughout, and
      // a synchronous callback could not `await` a vana call anyway.
      return run();
    };
    return fn;
  }

  async function evalArgs(nodes: AnyNode[], scope: Scope): Promise<unknown[]> {
    const out: unknown[] = [];
    for (const a of nodes) {
      if (a.type === "SpreadElement") {
        out.push(...((await evalNode(a.argument, scope)) as unknown[]));
      } else {
        out.push(await evalNode(a, scope));
      }
    }
    return out;
  }

  /** Hoist function declarations so mutual recursion and forward calls work. */
  async function hoist(body: AnyNode[], scope: Scope): Promise<void> {
    for (const stmt of body) {
      if (stmt.type === "FunctionDeclaration") {
        scope.declare(stmt.id.name, makeFunction(stmt, scope));
      }
    }
  }

  async function bindForTarget(left: AnyNode, value: unknown, scope: Scope) {
    if (left.type === "VariableDeclaration") {
      await bindPattern(left.declarations[0].id, value, scope, true);
    } else {
      await assign(left, value, scope);
    }
  }

  async function bindPattern(
    pattern: AnyNode,
    value: unknown,
    scope: Scope,
    declare: boolean,
  ): Promise<void> {
    switch (pattern.type) {
      case "Identifier": {
        if (FORBIDDEN_IDENTIFIERS.has(pattern.name)) {
          throw new ConfinementError(
            `"${pattern.name}" may not be bound in the confined realm`,
          );
        }
        if (declare) scope.declare(pattern.name, value);
        else scope.set(pattern.name, value);
        return;
      }
      case "ObjectPattern": {
        const seen: string[] = [];
        for (const p of pattern.properties) {
          if (p.type === "RestElement") {
            const rest: Record<string, unknown> = {};
            for (const [k, v] of Object.entries((value ?? {}) as object)) {
              if (!seen.includes(k)) rest[k] = v;
            }
            await bindPattern(p.argument, rest, scope, declare);
            continue;
          }
          const key = p.computed
            ? String(await evalNode(p.key, scope))
            : p.key.type === "Identifier"
              ? p.key.name
              : String(p.key.value);
          seen.push(key);
          await bindPattern(p.value, readMember(value, key), scope, declare);
        }
        return;
      }
      case "ArrayPattern": {
        const arr = (value ?? []) as unknown[];
        for (let i = 0; i < pattern.elements.length; i++) {
          const el = pattern.elements[i];
          if (el === null) continue;
          if (el.type === "RestElement") {
            await bindPattern(el.argument, arr.slice(i), scope, declare);
            break;
          }
          await bindPattern(el, arr[i], scope, declare);
        }
        return;
      }
      case "AssignmentPattern": {
        const v =
          value === undefined ? await evalNode(pattern.right, scope) : value;
        await bindPattern(pattern.left, v, scope, declare);
        return;
      }
      default:
        throw new ConfinementError(
          `unsupported binding pattern: ${String(pattern.type)}`,
        );
    }
  }

  async function assign(target: AnyNode, value: unknown, scope: Scope) {
    if (target.type === "Identifier") {
      await bindPattern(target, value, scope, false);
      return;
    }
    if (target.type === "MemberExpression") {
      const obj = await evalNode(target.object, scope);
      const key = target.computed
        ? ((await evalNode(target.property, scope)) as PropertyKey)
        : target.property.name;
      const name = String(key);
      if (
        name === "__proto__" ||
        name === "constructor" ||
        name === "prototype"
      ) {
        throw new ConfinementError(`assignment to "${name}" is not allowed`);
      }
      (obj as Record<PropertyKey, unknown>)[key] = value;
      return;
    }
    await bindPattern(target, value, scope, false);
  }

  const result = await evalNode(ast, root);
  return isReturn(result) ? result.value : result;
}

function truthy(v: unknown): boolean {
  return Boolean(v);
}

function describe(node: AnyNode): string {
  return node?.name ?? node?.type ?? "expression";
}

function binary(op: string, l: any, r: any): unknown {
  switch (op) {
    case "+":
      return l + r;
    case "-":
      return l - r;
    case "*":
      return l * r;
    case "/":
      return l / r;
    case "%":
      return l % r;
    case "**":
      return l ** r;
    case "==":
      return l == r;
    case "!=":
      return l != r;
    case "===":
      return l === r;
    case "!==":
      return l !== r;
    case "<":
      return l < r;
    case "<=":
      return l <= r;
    case ">":
      return l > r;
    case ">=":
      return l >= r;
    case "&":
      return l & r;
    case "|":
      return l | r;
    case "^":
      return l ^ r;
    case "<<":
      return l << r;
    case ">>":
      return l >> r;
    case ">>>":
      return l >>> r;
    case "in":
      return String(l) in (r as object);
    case "instanceof":
      return l instanceof r;
    default:
      throw new ConfinementError(`unsupported operator ${op}`);
  }
}
