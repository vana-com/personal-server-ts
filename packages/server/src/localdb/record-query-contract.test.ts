import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { createLocalResolver } from "../../../core/src/localdb/resolve.js";
import { describe, expect, it } from "vitest";

/**
 * `RecordQuery` is exported: a host that serves the records routes implements
 * it, and must not have to implement what only the local alias resolver asks
 * of the database. The build does not compile test files, so this compiles a
 * probe module in the test: the four methods a `RecordQuery` had before alias
 * paging must still satisfy it, the resolver must still be callable with one,
 * and the resolver's `AliasRecordQuery` must ask for the rest.
 */
const here = dirname(fileURLToPath(import.meta.url));
const probe = join(here, "record-query-contract.probe.ts");

function diagnosticsOf(source: string): string[] {
  const options: ts.CompilerOptions = {
    strict: true,
    noEmit: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.Node16,
    moduleResolution: ts.ModuleResolutionKind.Node16,
    esModuleInterop: true,
    skipLibCheck: true,
    resolveJsonModule: true,
    isolatedModules: true,
  };
  const host = ts.createCompilerHost(options);
  const readFile = host.readFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  host.readFile = (name) => (name === probe ? source : readFile(name));
  host.fileExists = (name) => name === probe || fileExists(name);
  const program = ts.createProgram([probe], options, host);
  return ts
    .getPreEmitDiagnostics(program, program.getSourceFile(probe))
    .map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
}

const QUERY = "../../../core/src/localdb/query.js";
const DEPS = "../../../core/src/localdb/deps.js";
const RESOLVE = "../../../core/src/localdb/resolve.js";
const FOUR = `
  listRecords: null as never,
  getRecord: null as never,
  changesSince: null as never,
  streamRecords: null as never,`;

describe("the exported RecordQuery contract", () => {
  it("is met by an implementation that never pages an alias", () => {
    expect(
      diagnosticsOf(
        `import type { RecordQuery } from "${QUERY}";
         export const downstream: RecordQuery = {${FOUR}};`,
      ),
    ).toEqual([]);
  }, 60_000);

  it("is met by a resolver call that passes a RecordQuery and no alias query", () => {
    // How the resolver was called before alias paging: it must still compile,
    // and an alias read is given its own query beside it.
    expect(
      diagnosticsOf(
        `import type { RecordQuery, AliasRecordQuery } from "${QUERY}";
         import type { LocalSyncDeps } from "${DEPS}";
         import { createLocalResolver } from "${RESOLVE}";
         declare const deps: LocalSyncDeps;
         declare const query: RecordQuery;
         declare const aliasQuery: AliasRecordQuery;
         export const existing = createLocalResolver(deps, { query });
         export const paged = createLocalResolver(deps, { query, aliasQuery });`,
      ),
    ).toEqual([]);
  }, 60_000);

  it("refuses a plain RecordQuery where the alias query goes", () => {
    const messages = diagnosticsOf(
      `import type { RecordQuery } from "${QUERY}";
       import type { LocalSyncDeps } from "${DEPS}";
       import { createLocalResolver } from "${RESOLVE}";
       declare const deps: LocalSyncDeps;
       declare const query: RecordQuery;
       export const wrong = createLocalResolver(deps, { query, aliasQuery: query });`,
    );
    expect(messages.join("\n")).toMatch(/streamStats/);
  }, 60_000);

  it("accepts alias configuration with a plain RecordQuery, and refuses a spool with one", () => {
    // Main's call shape: a plain RecordQuery with alias scopes and targets.
    // It is served on the in-memory path; only a query that can size its rows
    // takes a spool.
    expect(
      diagnosticsOf(
        `import type { RecordQuery, AliasRecordQuery } from "${QUERY}";
         import type { StreamSyncFiles } from "../../../core/src/stream-sync/ports.js";
         import type { LocalSyncDeps } from "${DEPS}";
         import { createLocalResolver } from "${RESOLVE}";
         declare const deps: LocalSyncDeps;
         declare const query: RecordQuery;
         declare const aliasQuery: AliasRecordQuery;
         declare const aliasSpool: StreamSyncFiles;
         export const plain = createLocalResolver(deps, {
           query, aliasScopes: () => [], aliasTargets: () => [],
         });
         // @ts-expect-error a plain RecordQuery has no spool
         export const wrong = createLocalResolver(deps, { query, aliasScopes: () => [], aliasSpool });
         export const spooled = createLocalResolver(deps, {
           query, aliasQuery, aliasScopes: () => [], aliasTargets: () => [], aliasSpool,
         });`,
      ),
    ).toEqual([]);
  }, 60_000);

  it("accepts main's call shape: a query that already has the alias methods", () => {
    // On main a caller passes `{ query: createRecordQuery(db), aliasScopes }`
    // and that query implements the alias methods. It stays a valid call, with
    // no `aliasQuery` beside it (and may take a spool).
    expect(
      diagnosticsOf(
        `import type { AliasRecordQuery } from "${QUERY}";
         import type { LocalSyncDeps } from "${DEPS}";
         import { createLocalResolver } from "${RESOLVE}";
         declare const deps: LocalSyncDeps;
         declare const query: AliasRecordQuery;
         export const main = createLocalResolver(deps, {
           query, aliasScopes: () => [], aliasTargets: () => [],
         });`,
      ),
    ).toEqual([]);
  }, 60_000);

  it("does not throw at construction when alias configuration comes with a plain query", () => {
    const deps = {} as never;
    const query = {} as never;
    expect(() =>
      createLocalResolver(deps, { query, aliasScopes: () => [] }),
    ).not.toThrow();
    expect(() =>
      createLocalResolver(deps, { query, aliasTargets: () => [] }),
    ).not.toThrow();
  });

  it("leaves the alias read's extra methods to AliasRecordQuery", () => {
    const messages = diagnosticsOf(
      `import type { AliasRecordQuery } from "${QUERY}";
       export const downstream: AliasRecordQuery = {${FOUR}};`,
    );
    expect(messages.join("\n")).toMatch(
      /streamStats.*recordSizes.*recordsByHash/s,
    );
  }, 60_000);
});
