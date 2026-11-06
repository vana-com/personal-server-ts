// Minimal JSON-RPC: every contract read answers zero; enough for a gateway
// whose fee registry is off and whose on-chain versions are all zero.
import http from "node:http";
const port = Number(process.argv[2]);
http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const one = (m) => {
      const result =
        m.method === "eth_chainId" ? "0x39d0" :
        m.method === "eth_blockNumber" ? "0x10" :
        m.method === "eth_call" ? "0x" + "0".repeat(256) :
        m.method === "eth_getBlockByNumber" ? { number: "0x10", hash: "0x" + "1".repeat(64), timestamp: "0x0" } :
        null;
      return { jsonrpc: "2.0", id: m.id, result };
    };
    const parsed = JSON.parse(body || "{}");
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(Array.isArray(parsed) ? parsed.map(one) : one(parsed)));
  });
}).listen(port, "127.0.0.1", () => console.log(`rpc on ${port}`));
