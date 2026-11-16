/**
 * Writes `packages/core/contracts/routes.json` from the route registrations.
 * Run `npm run contracts:write` after adding or moving a route.
 */
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { routesContractFromRepo } from "./routes-contract.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const target = new URL(
  "../packages/core/contracts/routes.json",
  import.meta.url,
);
writeFileSync(
  target,
  `${JSON.stringify(routesContractFromRepo(root), null, 2)}\n`,
);
console.log(`wrote ${target.pathname}`);
