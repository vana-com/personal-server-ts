/**
 * Writes `contracts/host-contract.json` from `hostContract()`.
 * Run `npm run contracts:write` after changing the run-intake contract.
 */
import { writeFileSync } from "node:fs";
import { hostContract } from "../src/stream-sync/host-contract.js";

const target = new URL("../contracts/host-contract.json", import.meta.url);
writeFileSync(target, `${JSON.stringify(hostContract(), null, 2)}\n`);
console.log(`wrote ${target.pathname}`);
