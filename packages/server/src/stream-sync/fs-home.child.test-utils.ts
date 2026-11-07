/**
 * Test helper for `fs-home.test.ts`: a separate process that tries to open one
 * stream-sync home, reports `held` or `busy` on stdout, and then stays alive
 * (holding the home if it got it) until it is killed.
 */
import { openFsStreamSyncHome } from "./fs-home.js";

const [root, owner, network] = process.argv.slice(2);
const home = await openFsStreamSyncHome({
  root: root!,
  ownerAddress: owner as `0x${string}`,
  network: network!,
});
process.stdout.write(home ? "held\n" : "busy\n");
setInterval(() => {}, 1_000);
