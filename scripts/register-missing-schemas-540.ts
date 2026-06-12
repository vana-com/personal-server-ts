// One-off: re-register schemas wiped by the DPv2 registry reset for the
// scopes blocking the local drain. Mirrors data-gateway's
// register-slack-schemas.ts convention (raw.githubusercontent definitionUrl).
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const GATEWAY_URL = "https://dp-rpc-dev.vana.org";
const CHAIN_ID = 14800;
const REFINER = "0x93c3EF89369fDcf08Be159D9DeF0F18AB6Be008c" as const;
const BASE =
  "https://raw.githubusercontent.com/vana-com/data-connectors/main/connectors";

const SCHEMAS = [
  {
    name: "Claude Conversations",
    scope: "claude.conversations",
    file: `${BASE}/anthropic/schemas/claude.conversations.json`,
  },
  {
    name: "Claude Projects",
    scope: "claude.projects",
    file: `${BASE}/anthropic/schemas/claude.projects.json`,
  },
  {
    name: "Instagram Posts",
    scope: "instagram.posts",
    file: `${BASE}/meta/schemas/instagram.posts.json`,
  },
  {
    name: "Instagram Following",
    scope: "instagram.following",
    file: `${BASE}/meta/schemas/instagram.following.json`,
  },
  {
    name: "Instagram Ads",
    scope: "instagram.ads",
    file: `${BASE}/meta/schemas/instagram.ads.json`,
  },
];

const TYPES = {
  SchemaRegistration: [
    { name: "ownerAddress", type: "address" },
    { name: "name", type: "string" },
    { name: "definitionUrl", type: "string" },
    { name: "scope", type: "string" },
    { name: "dialect", type: "string" },
  ],
} as const;

async function main() {
  const owner = privateKeyToAccount(generatePrivateKey());
  for (const s of SCHEMAS) {
    const msg = {
      ownerAddress: owner.address,
      name: s.name,
      definitionUrl: s.file,
      scope: s.scope,
      dialect: "json",
    };
    const sig = await owner.signTypedData({
      domain: {
        name: "Vana Data Portability",
        version: "1",
        chainId: CHAIN_ID,
        verifyingContract: REFINER,
      },
      types: TYPES,
      primaryType: "SchemaRegistration",
      message: msg,
    });
    const res = await fetch(`${GATEWAY_URL}/v1/schemas`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Web3Signed ${sig}`,
      },
      body: JSON.stringify(msg),
    });
    const body = await res.text();
    console.log(`${s.scope}: ${res.status} ${body.slice(0, 120)}`);
  }
}
main();
