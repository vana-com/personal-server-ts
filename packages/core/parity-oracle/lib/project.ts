// Runs the REAL adapter over golden stream rows.
// usage: npx tsx lib/project.ts <adapterDir> <in.json> <out.json>
//   in.json: { [scope]: { fetchedStreams, streams: {stream: rows[]} } }
// The clock is frozen to the same instant the scripts saw, so the adapter's
// now()-derived fields (fetched_at, null created_at fallback) are comparable.
import { readFileSync, writeFileSync } from "node:fs";
const [adapterDir, inPath, outPath] = process.argv.slice(2);
const FIXED = Date.parse(process.env.PROJECTION_NOW ?? "2026-10-01T00:00:00.000Z");
const RealDate = Date;
class FrozenDate extends RealDate {
  constructor(...a: unknown[]) { if (a.length === 0) super(FIXED); else super(...(a as [string])); }
  static now() { return FIXED; }
}
(globalThis as { Date: DateConstructor }).Date = FrozenDate as unknown as DateConstructor;
const adapter = await import(`${adapterDir}/index.ts`);
if (inPath === "--bindings") {
  const scopes = outPath.split(",");
  console.log(JSON.stringify(Object.fromEntries(scopes.map((s) => {
    const b = adapter.LEGACY_SCOPE_BINDINGS.get(s);
    return [s, { pdppSource: b.pdppSource, pdppStreams: b.pdppStreams, primaryKey: b.primaryKey }];
  }))));
  process.exit(0);
}
const input = JSON.parse(readFileSync(inPath, "utf8"));
const out: Record<string, unknown> = {};
for (const [scope, { fetchedStreams, streams }] of Object.entries<any>(input)) {
  const binding = adapter.LEGACY_SCOPE_BINDINGS.get(scope);
  const records = Object.entries<any[]>(streams).flatMap(([stream, rows]) => rows.map((data) => ({ stream, data })));
  out[scope] = {
    binding: { pdppSource: binding.pdppSource, pdppStreams: binding.pdppStreams, primaryKey: binding.primaryKey, lossy: binding.lossy },
    result: adapter.projectPdppRecordsToLegacyPayload(scope, records, { fetchedStreams }),
  };
}
writeFileSync(outPath, JSON.stringify(out, null, 2));
