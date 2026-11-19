import { world, sName } from "./log-world.test-utils.js";
const [edge, target] = process.argv.slice(2);
const whole = target === "whole";
const w = await world({ streams: 1, partTargetBytes: whole ? 65536 : 2048 });
const a = await w.device("writer");
const stream = sName(0);
await a.run(
  "first",
  Array.from({ length: 30 }, (_, id) => ({ stream, id, v: 1 })),
);
await a.cycle();
const before = await a.position();
await a.run(
  "next",
  [
    { stream, id: 0, v: 2 },
    { stream, id: 1, v: 2 },
  ],
  { observedAt: 5000 },
);
const [database] = await a.db.query<{ file: string }>("PRAGMA database_list");
const batch = a.db.batch.bind(a.db);
let operation = "";
a.db.batch = async (statements) => {
  const frozen = statements.find((s) => s.sql.includes("SELECT ?, 'changes'"));
  if (frozen) operation = String(frozen.params?.[0]);
  const match = statements.some((s) => {
    if (target === "cleanup")
      return s.sql.includes("UPDATE workspaces SET phase='clean'");
    if (target === "freeze") return s === frozen;
    if (target === "selection")
      return (
        s.sql.includes("INSERT OR IGNORE INTO workspace_receipts") &&
        s.params?.[1] === "selection"
      );
    if (target === "publication")
      return (
        s.sql.includes("INSERT OR IGNORE INTO workspace_receipts") &&
        s.params?.[1] === "publication"
      );
    return s.sql.includes("INSERT OR REPLACE INTO log_state");
  });
  const stop = async () => {
    process.send!({ path: database!.file, before, operation, whole });
    await new Promise(() => {});
  };
  if (match && edge === "before") await stop();
  const result = await batch(statements);
  if (match && edge === "after") await stop();
  return result;
};
await a.cycle();
throw new Error("boundary_not_reached");
