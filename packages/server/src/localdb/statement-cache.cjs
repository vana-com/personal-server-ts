"use strict";

/**
 * Shared bounded native-statement owner for local SQL and borrowed legacy
 * handles. Callers clear the cache when their access lifetime ends.
 *
 * Plain CommonJS so the SQLite worker thread can load it without a build step
 * of its own; the types live in `statement-cache.d.cts`.
 */
function createStatementCache(db) {
  // Recompiling every row's SQL leaves native statement allocations waiting
  // for V8 collection through long synchronous merge loops. Reuse a bounded,
  // connection-local set; run/all reset statements and clear their bindings.
  const statements = new Map();
  const prepare = (sql) => {
    let statement = statements.get(sql);
    if (statement && !statement.busy) {
      statements.delete(sql);
      statements.set(sql, statement);
      return statement;
    }
    statement = db.prepare(sql);
    statements.set(sql, statement);
    if (statements.size > 64) statements.delete(statements.keys().next().value);
    return statement;
  };
  return { prepare, clear: () => statements.clear() };
}

module.exports = { createStatementCache };
