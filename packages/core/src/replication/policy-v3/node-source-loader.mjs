/** Node24 trusted-kernel checks: resolve source .js specifiers to adjacent .ts.
 * No code substitutions, schema mocks, or transpiler dependency are involved.
 */
export async function resolve(specifier, context, nextResolve) {
  if (
    specifier.startsWith(".") &&
    specifier.endsWith(".js") &&
    context.parentURL
  ) {
    return nextResolve(
      new URL(specifier.slice(0, -3) + ".ts", context.parentURL).href,
      context,
    );
  }
  return nextResolve(specifier, context);
}
