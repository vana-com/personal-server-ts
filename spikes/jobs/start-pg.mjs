import EmbeddedPostgres from 'embedded-postgres';
const pg = new EmbeddedPostgres({
  databaseDir: new URL('./data', import.meta.url).pathname,
  user: 'gateway', password: 'gateway', port: 5433, persistent: true,
  initdbFlags: ['--encoding=UTF8'],
  postgresFlags: ['-c', 'timezone=UTC', '-c', 'max_connections=200'],
});
await pg.initialise();
await pg.start();
await pg.createDatabase('gateway').catch(() => {});
console.log('pg up on 5433');
process.on('SIGTERM', async () => { await pg.stop(); process.exit(0); });
setInterval(() => {}, 1 << 30);
