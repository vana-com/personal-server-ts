// Compile-time proof of what the `ChangeCursor` type refuses. `tsc --build`
// fails here if `ChangeCursor` is ever loosened to a bare `string` or a
// `number`, or its brand is lost: each line below must be a type error, and an
// unused `@ts-expect-error` is one. Nothing calls this function.
//
// The cursor is a branded string, so TypeScript still allows `<`, `>`, `+`,
// `Number(...)`, `BigInt(...)`, `.length` and a template literal on it. The
// gateway's cursor has no order and no number inside; ESLint refuses the
// relational and parsing forms on cursor-named values in the files that handle
// cursors (`eslint.config.js`). A cursor under another name escapes that rule.
import type { ChangeCursor } from "./ports.js";

export function aCursorIsABrandedString(
  a: ChangeCursor,
  b: ChangeCursor,
): void {
  // @ts-expect-error no arithmetic
  void (a - b);
  // @ts-expect-error no arithmetic
  void (a * 2);
  // @ts-expect-error not a symbol: this compiled when the brand was `symbol`, and threw
  void Symbol.keyFor(a);
  // @ts-expect-error a bare string is not a cursor
  const fromString: ChangeCursor = "12";
  // @ts-expect-error a number is not a cursor
  const fromNumber: ChangeCursor = 12;
  void fromString;
  void fromNumber;
  // A cursor is a string: it is held and sent as one, and compared with ===.
  const asString: string = a;
  void asString;
  void (a === b);
}
