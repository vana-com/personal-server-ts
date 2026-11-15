// How many registry batch requests does one sync cycle make when several
// connections finish together, with and without `crossConnectionBatch`?
//
// Real publish driver, real SQLite, real gateway adapter, against the fake
// gateway whose batch request takes `fixedMs + perRowMs * rows` of real time
// (the dev gateway: ~347 ms fixed, ~37 ms per row; WEEKEND-PLAN). Every stream
// finishes its transfer at once (memory blobs), so the first request leaves
// alone and the rest wait for it: what "finish together" does.
//
//   npx tsx packages/server/src/localdb/cross-connection-batch.workload.ts \
//     --connections 6 --streams 5 [--scale 0.1] [--policy 64,1010]
//
// Prints one JSON object per mode: requests, rows per request, the modeled
// gateway time (the sum of every request's fixed + per-row cost) and the
// cycle's wall time (real time, divided by --scale).
import { runCycle } from "../../../core/src/localdb/cycle.js";
import { closeWorlds, world } from "./cross-connection-world.test-helper.js";

function arg(name: string, fallback: string): string {
  const at = process.argv.indexOf(`--${name}`);
  return at >= 0 ? process.argv[at + 1]! : fallback;
}

const connections = Number(arg("connections", "6"));
const streams = Number(arg("streams", "5"));
const scale = Number(arg("scale", "0.1"));
const [policyRows, policyRequires] = arg("policy", "64,1010")
  .split(",")
  .map(Number) as [number, number];
const FIXED_MS = 347;
const PER_ROW_MS = 37;

async function measure(crossConnectionBatch: boolean) {
  const w = await world({
    streams: Array(connections).fill(streams) as number[],
    crossConnectionBatch,
    gateway: {
      policy: { rows: policyRows, requires: policyRequires, bytes: 2_000_000 },
    },
  });
  w.gateway.beforeBatch = async (call) => {
    const rows = call.body.rows.length;
    await new Promise((r) =>
      setTimeout(r, (FIXED_MS + PER_ROW_MS * rows) * scale),
    );
  };
  const started = Date.now();
  const report = await runCycle(w.deps);
  const wallMs = (Date.now() - started) / scale;
  const errors = report.connections.filter((c) => c.error !== null).length;
  const sizes = w.gateway.batches().map((b) => b.body.rows.length);
  const requests = sizes.length;
  return {
    crossConnectionBatch,
    connections,
    streamsPerConnection: streams,
    errors,
    published: report.connections.flatMap((c) => c.published).length,
    requests,
    rowsPerRequest: sizes,
    modeledGatewayMs: sizes.reduce(
      (a, rows) => a + FIXED_MS + PER_ROW_MS * rows,
      0,
    ),
    cycleWallMs: Math.round(wallMs),
  };
}

try {
  console.log(JSON.stringify(await measure(false)));
  console.log(JSON.stringify(await measure(true)));
} finally {
  await closeWorlds();
}
