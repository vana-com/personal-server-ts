// A write-once blob store with the Vana storage HTTP shape, as a process.
// Same behaviour as `startLocalStorage` in the stream-sync oracle utilities.
// Usage: node storage.mjs <port>
import http from "node:http";

const port = Number(process.argv[2]);
const blobs = new Map();
http
  .createServer((req, res) => {
    const path = decodeURIComponent(
      new URL(req.url ?? "/", "http://x").pathname,
    );
    if (req.method === "GET" && path === "/__count") {
      res.end(String(blobs.size));
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      if (req.method === "PUT") {
        const existing = blobs.get(path);
        if (existing && !existing.equals(body)) {
          res.statusCode = 409;
          res.end("different bytes");
          return;
        }
        blobs.set(path, body);
        res.setHeader("content-type", "application/json");
        res.end(
          JSON.stringify({
            url: path,
            size: body.length,
            key: path,
            etag: "e",
          }),
        );
        return;
      }
      if (req.method === "GET") {
        const blob = blobs.get(path);
        res.statusCode = blob ? 200 : 404;
        res.end(blob ?? "not found");
        return;
      }
      if (req.method === "DELETE") {
        res.statusCode = blobs.delete(path) ? 200 : 404;
        res.end();
        return;
      }
      res.statusCode = 405;
      res.end();
    });
  })
  .listen(port, "127.0.0.1", () => console.log(`storage on ${port}`));
