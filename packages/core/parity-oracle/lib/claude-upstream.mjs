// Fake claude.ai (+ signed export storage) served from inputs/claude/*.json.
// The export ZIP is built deterministically from export-entries.json
// (deflate, fixed entry order, zeroed timestamps).
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { deflateRawSync } from "node:zlib";
import { html, json } from "./host.mjs";

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

/** A valid deflate ZIP of JSON entries ([name, value] pairs, order kept). */
export function zipOf(pairs) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, value] of pairs) {
    const nameBytes = Buffer.from(name);
    const raw = Buffer.from(JSON.stringify(value, null, 2));
    const data = deflateRawSync(raw, { level: 9 });
    const crc = crc32(raw);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBytes, data);
    centrals.push(Buffer.concat([central, nameBytes]));
    offset += 30 + nameBytes.length + data.length;
  }
  const dir = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(centrals.length, 8);
  eocd.writeUInt16LE(centrals.length, 10);
  eocd.writeUInt32LE(dir.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, dir, eocd]);
}

export function claudeUpstream(inputDir) {
  const load = (name) => JSON.parse(readFileSync(join(inputDir, name), "utf8"));
  const entries = load("export-entries.json");
  const organizations = load("organizations.json");
  const site = load("site.json");
  // Variant knob: the account-menu display name differs from users.json
  // full_name (Claude lets users pick what Claude calls them).
  if (process.env.CLAUDE_MENU_NAME) site.menuName = process.env.CLAUDE_MENU_NAME;
  const archive = zipOf(entries);
  const unknown = [];
  const ORG = site.organizationId;
  const signedHost = new URL(site.signedUrl).hostname;
  let minted = false;

  // Logged-in claude.ai shell: the account menu both connectors read for
  // name + plan, and the sidebar/new-chat markers the legacy login check uses.
  const home = html(
    `<nav aria-label="Sidebar"><a href="/new" aria-label="New chat">New chat</a></nav>` +
      `<button data-testid="user-menu-button"><span>${site.menuName}</span><span>${site.menuPlan}</span></button>`,
  );

  function resolve(raw, { method = "GET" } = {}) {
    const url = new URL(raw);
    if (url.hostname === signedHost) return { status: 200, contentType: "application/zip", body: archive };
    if (url.hostname !== "claude.ai") {
      unknown.push(`${method} ${raw}`);
      return { status: 404, contentType: "text/html", body: "" };
    }
    const p = url.pathname;
    // Old-format download route: a navigation here yields the archive as a
    // browser download (legacy desktop runner path).
    if (p === `/export/${ORG}/download/${site.nonce}`) return { status: 200, contentType: "application/zip", body: archive };
    if (p === "/login") return html('<form><input type="email" name="email"><button type="submit">Continue</button></form>');
    if (!p.startsWith("/api/")) return home;
    if (p === "/api/organizations" && method === "GET") return json(organizations);
    if (p === `/api/organizations/${ORG}/export_data` && method === "POST") return json({ nonce: site.nonce });
    if (p === `/api/organizations/${ORG}/export_signed_url/${site.nonce}` && method === "POST") {
      if (minted) return json({ error: "nonce consumed" }, 410);
      minted = true;
      return json({ signed_url: site.signedUrl });
    }
    unknown.push(`${method} ${p}${url.search}`);
    return json({ error: "not found" }, 404);
  }
  return { resolve, unknown, archive, site };
}
