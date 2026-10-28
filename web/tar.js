// Files for grix.run from a tar (ustar/pax, as `tar -czf` makes), gzipped
// or not: [{ path, data, mode } | { path, dir } | { path, symlink }].
// Hard links become copies.

export async function fetchTar(url, guestRoot = '/') {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  let body = res.body;
  if (url.endsWith('.gz') || url.endsWith('.tgz')) body = body.pipeThrough(new DecompressionStream('gzip'));
  return untar(new Uint8Array(await new Response(body).arrayBuffer()), guestRoot);
}

export function untar(buf, guestRoot = '/') {
  const files = [];
  const byPath = new Map();
  const dec = new TextDecoder();
  const str = (o, n) => {
    const s = buf.subarray(o, o + n);
    const end = s.indexOf(0);
    return dec.decode(end < 0 ? s : s.subarray(0, end));
  };
  const oct = (o, n) => parseInt(str(o, n).trim() || '0', 8);
  const join = (p) => {
    p = p.replace(/^\.?\/*/, '').replace(/\/+$/, '');
    const root = guestRoot.replace(/\/+$/, '');
    return p ? `${root}/${p}` : (root || '/');
  };
  let pax = {};
  let longName = null;
  for (let o = 0; o + 512 <= buf.length;) {
    if (buf[o] === 0) break;
    const hdr = o;
    const size = oct(hdr + 124, 12);
    const type = String.fromCharCode(buf[hdr + 156] || 48);
    const data = buf.subarray(hdr + 512, hdr + 512 + size);
    o += 512 + Math.ceil(size / 512) * 512;
    if (type === 'x') {
      for (const rec of dec.decode(data).split('\n')) {
        const m = rec.match(/^\d+ ([^=]+)=(.*)$/s);
        if (m) pax[m[1]] = m[2];
      }
      continue;
    }
    if (type === 'L') {
      longName = dec.decode(data).replace(/\0.*$/s, '');
      continue;
    }
    const prefix = str(hdr + 345, 155);
    const name = pax.path ?? longName ?? (prefix ? `${prefix}/${str(hdr, 100)}` : str(hdr, 100));
    const linkname = pax.linkpath ?? str(hdr + 157, 100);
    pax = {};
    longName = null;
    const path = join(name);
    const mode = oct(hdr + 100, 8) & 0o7777;
    let entry;
    if (type === '5') entry = { path, dir: true, mode };
    else if (type === '2') entry = { path, symlink: linkname };
    else if (type === '1') {
      const target = byPath.get(join(linkname));
      if (!target) continue;
      entry = { path, data: target.data, mode: target.mode };
    } else if (type === '0' || type === '7') entry = { path, data: data.slice(), mode };
    else continue;
    if (path === '/') continue;
    byPath.set(path, entry);
    files.push(entry);
  }
  return files;
}
