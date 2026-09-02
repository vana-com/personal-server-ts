// Samples pg_stat_activity every 5 s for DURATION_S seconds; prints max gateway connections.
import pg from 'pg';
const c = new pg.Client({ connectionString: 'postgres://gateway:gateway@localhost:5433/gateway' });
await c.connect();
const end = Date.now() + Number(process.argv[2] ?? 180) * 1000;
let max = 0;
while (Date.now() < end) {
  const r = await c.query("select count(*)::int as n from pg_stat_activity where datname='gateway' and pid <> pg_backend_pid()");
  max = Math.max(max, r.rows[0].n);
  await new Promise((r) => setTimeout(r, 5000));
}
console.log(JSON.stringify({ maxConnections: max }));
await c.end();
