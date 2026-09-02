// Kill-recovery check: a long job's worker is SIGKILLed mid-job; another
// worker must recover the job after the lease lapses.
import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';

const REPO = process.env['REPO']!;
const GW = 'http://localhost:3000';
const TTL = 15;
const builder = privateKeyToAccount(generatePrivateKey());
const b64u = (s: string) => Buffer.from(s).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
async function sign(method: string, uri: string, body: Buffer) {
  const now = Math.floor(Date.now() / 1000);
  const p = b64u(JSON.stringify({ aud: GW, method, uri, bodyHash: `sha256:${createHash('sha256').update(body).digest('hex')}`, iat: now, exp: now + 300 }));
  return `Web3Signed ${p}.${await builder.signMessage({ message: p })}`;
}
async function status(id: string) {
  const r = await fetch(`${GW}/v1/jobs/${id}`, { headers: { authorization: await sign('GET', `/v1/jobs/${id}`, Buffer.alloc(0)) } });
  return ((await r.json()) as { job: Record<string, unknown> }).job;
}
function worker(id: string, workMs: number) {
  const p = spawn(`${REPO}/node_modules/.bin/tsx`, [`${REPO}/scripts/jobs-worker.ts`], {
    env: { ...process.env, GATEWAY_URL: GW, NODE_ID: id, WORK_MS: String(workMs), CLAIM_TTL_SECONDS: String(TTL) },
    stdio: ['ignore', 'pipe', 'inherit'],
    detached: true, // own process group: tsx forks a child node, SIGKILL must reach both
  });
  p.stdout.on('data', (d) => process.stdout.write(`[${id}] ${d}`));
  return p;
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const log = (...a: unknown[]) => console.log(new Date().toISOString(), ...a);

const victim = worker('victim', 120_000);
await sleep(1500);
const body = Buffer.from(JSON.stringify({ owner: '0x1000000000000000000000000000000000000001', grantId: `0x${'ab'.repeat(32)}`, scope: 's', operation: 'raw_read', idempotencyKey: randomUUID(), requestCiphertext: randomBytes(64).toString('base64') }));
const res = await fetch(`${GW}/v1/jobs`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: await sign('POST', '/v1/jobs', body) }, body });
const { jobId } = (await res.json()) as { jobId: string };
log('submitted', jobId, res.status);
let j = await status(jobId);
while (j['state'] === 'queued') { await sleep(250); j = await status(jobId); }
log('claimed by victim: state', j['state'], 'attempt', j['attempt']);
await sleep(TTL * 1000 * 0.5); // let one heartbeat happen so the lease is renewed
j = await status(jobId);
log('before kill: state', j['state'], 'attempt', j['attempt']);
const killedAt = Date.now();
process.kill(-victim.pid!, 'SIGKILL');
log('SIGKILL victim; lease ttl', TTL, 's');
const rescuer = worker('rescuer', 200);
for (;;) {
  j = await status(jobId);
  if (j['state'] === 'completed' || j['state'] === 'failed' || j['state'] === 'expired') break;
  await sleep(500);
}
log('final state', j['state'], 'attempt', j['attempt'], 'kill->complete', Date.now() - killedAt, 'ms', 'claimedAt', j['claimedAt'], 'completedAt', j['completedAt']);
process.kill(-rescuer.pid!, 'SIGTERM');
process.exit(0);
