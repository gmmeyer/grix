// A static server for the demo with the headers that make the page
// cross-origin isolated (QEMU's threads need SharedArrayBuffer):
// node web/serve.mjs DIR [PORT]
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(process.argv[2] ?? 'web/dist');
const port = Number(process.argv[3] ?? 8080);
const types = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.mjs': 'text/javascript',
  '.wasm': 'application/wasm', '.json': 'application/json', '.css': 'text/css',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon',
};

http.createServer((req, res) => {
  let file;
  try {
    file = path.join(root, decodeURIComponent(new URL(req.url, 'http://x').pathname));
  } catch {
    return res.writeHead(400).end(); // a lone %, say
  }
  // Inside root (not a sibling whose name starts with its), and a path fs
  // takes (no NUL, which it throws on).
  if ((file !== root && !file.startsWith(root + path.sep)) || file.includes('\0')) return res.writeHead(403).end();
  try {
    if (fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  } catch {}
  fs.readFile(file, (err, data) => {
    if (err) return res.writeHead(404).end('not found');
    res.writeHead(200, {
      'Content-Type': types[path.extname(file)] ?? 'application/octet-stream',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      // Embeddable from pages elsewhere, as from a CDN.
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-cache',
    });
    res.end(data);
  });
}).listen(port, () => console.log(`http://localhost:${port}/ serving ${root}`));
