import { parse } from "acorn";
import { evaluateProgram, type EvaluateOptions } from "./evaluate.js";
import { ConfinementError, createRealm } from "./realm.js";

export {
  ConfinementError,
  FORBIDDEN_IDENTIFIERS,
  FORBIDDEN_KEYS,
} from "./realm.js";
export type { EvaluateOptions } from "./evaluate.js";

export interface RunScriptOptions extends EvaluateOptions {
  /** Called for `console.log` and friends inside the script. */
  onConsole?: (message: string) => void;
}

/**
 * Parse and run model-authored JavaScript with no ambient authority.
 *
 * `acorn` only parses — it never executes — so the single execution path is
 * {@link evaluateProgram}, which walks the AST and can reach nothing the realm
 * does not bind. This is the language boundary of design §19.7; the OS sandbox
 * is the other layer and neither substitutes for the other.
 */
export async function runConfinedScript(
  source: string,
  vana: unknown,
  options: RunScriptOptions = {},
): Promise<unknown> {
  let ast;
  try {
    ast = parse(source, {
      ecmaVersion: 2022,
      sourceType: "script",
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
    });
  } catch (err) {
    throw new ConfinementError(
      `script did not parse: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  const realm = createRealm(vana, options.onConsole ?? (() => {}));
  return evaluateProgram(ast, realm, options);
}
