// HTTPS with optional SOCKS5 (Tor) or HTTP CONNECT proxy, written out here instead of pulled in as
// dependencies so the whole network path is readable in one file.
//
// Through a proxy the hostname is always sent to the proxy unresolved, so DNS lookups never leave
// this computer directly (the "socks5h" behaviour). Certificates are always verified.
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import crypto from 'node:crypto';

const UA = 'counterlure-cli'; // no version, OS or Node details

function reader(sock) {
  let buf = Buffer.alloc(0), wait = null;
  const pump = () => { if (wait && buf.length >= wait.n) { const out = buf.subarray(0, wait.n); buf = buf.subarray(wait.n); const w = wait; wait = null; w.ok(out); } };
  sock.on('data', (d) => { buf = Buffer.concat([buf, d]); pump(); });
  const fail = (e) => { if (wait) { const w = wait; wait = null; w.no(e); } };
  sock.on('error', fail);
  sock.on('close', () => fail(new Error('proxy closed the connection')));
  const read = (n) => new Promise((ok, no) => { wait = { n, ok, no }; pump(); });
  return {
    read,
    until: async (marker) => { // for HTTP CONNECT replies: one byte at a time, so nothing past the header is consumed
      let s = '';
      while (!s.endsWith(marker)) {
        s += (await read(1)).toString('latin1');
        if (s.length > 16384) throw new Error('proxy reply too long');
      }
      return s;
    },
    done: () => { sock.removeAllListeners('data'); sock.removeAllListeners('error'); sock.removeAllListeners('close'); },
  };
}

function connect(host, port) {
  return new Promise((ok, no) => { const s = net.connect(port, host, () => ok(s)); s.once('error', no); s.setTimeout(30000, () => s.destroy(new Error('proxy timed out'))); });
}

async function socks5(p, host, port) {
  const sock = await connect(p.hostname, Number(p.port) || 1080);
  const r = reader(sock);
  const user = decodeURIComponent(p.username || ''), pass = decodeURIComponent(p.password || '');
  sock.write(Buffer.from(user ? [5, 1, 2] : [5, 1, 0]));
  const [ver, method] = await r.read(2);
  if (ver !== 5 || method === 0xff) throw new Error('SOCKS proxy refused the connection');
  if (method === 2) {
    const u = Buffer.from(user), pw = Buffer.from(pass);
    sock.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([pw.length]), pw]));
    const [, st] = await r.read(2);
    if (st !== 0) throw new Error('SOCKS proxy refused the username');
  } else if (method !== 0) throw new Error('SOCKS proxy wants an unsupported login method');
  const h = Buffer.from(host);
  sock.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 255])]));
  const [, rep, , atyp] = await r.read(4);
  if (rep !== 0) throw new Error(`SOCKS proxy could not reach ${host} (code ${rep})`);
  const len = atyp === 1 ? 4 : atyp === 4 ? 16 : (await r.read(1))[0];
  await r.read(len + 2);
  r.done();
  return sock;
}

async function httpConnect(p, host, port) {
  const sock = await connect(p.hostname, Number(p.port) || 8080);
  const r = reader(sock);
  const auth = p.username ? `Proxy-Authorization: Basic ${Buffer.from(`${decodeURIComponent(p.username)}:${decodeURIComponent(p.password)}`).toString('base64')}\r\n` : '';
  sock.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n${auth}\r\n`);
  const head = await r.until('\r\n\r\n');
  if (!/^HTTP\/1\.[01] 200/.test(head)) throw new Error(`proxy refused: ${head.split('\r\n')[0]}`);
  r.done();
  return sock;
}

// "tor" is shorthand for Tor's local SOCKS port. A random username per run asks Tor to use a
// separate circuit (IsolateSOCKSAuth), so this tool's traffic doesn't share an exit with your browser.
export function resolveProxy(opt) {
  const v = opt || process.env.COUNTERLURE_PROXY || process.env.ALL_PROXY || process.env.HTTPS_PROXY || process.env.https_proxy || '';
  if (!v) return null;
  if (v === 'tor') return new URL(`socks5h://cl-${crypto.randomBytes(6).toString('hex')}:x@127.0.0.1:9050`);
  const u = new URL(v);
  if (!['socks5h:', 'socks5:', 'socks:', 'http:'].includes(u.protocol)) throw new Error(`Unsupported proxy ${u.protocol} (use socks5h://host:port or http://host:port)`);
  return u;
}

export async function request(url, { method = 'GET', body, headers = {}, proxy = null, maxBytes = 64 * 1024 * 1024, onData } = {}) {
  const u = new URL(url);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) throw new Error(`Refusing non-HTTPS URL ${u.origin}`);
  const port = Number(u.port) || (u.protocol === 'https:' ? 443 : 80);
  let raw = null;
  if (proxy) raw = proxy.protocol === 'http:' ? await httpConnect(proxy, u.hostname, port) : await socks5(proxy, u.hostname, port);
  const mod = u.protocol === 'https:' ? https : await import('node:http');
  return new Promise((ok, no) => {
    const opts = {
      method, host: u.hostname, port, path: u.pathname + u.search, servername: u.hostname,
      headers: { 'user-agent': UA, accept: '*/*', ...headers, ...(body ? { 'content-length': Buffer.byteLength(body) } : {}) },
      timeout: 120000,
    };
    // Node only uses createConnection when no agent is set at all; with agent:false it would quietly
    // open its own direct connection and skip the proxy. So: no agent through a proxy, a fresh one without.
    if (!raw) opts.agent = false;
    else opts.createConnection = () => (u.protocol === 'https:' ? tls.connect({ socket: raw, servername: u.hostname, ALPNProtocols: ['http/1.1'] }) : raw);
    const req = mod.request(opts, (res) => {
      const chunks = []; let n = 0;
      res.on('data', (d) => {
        n += d.length;
        if (n > maxBytes) { req.destroy(new Error('response too large')); return; }
        if (onData) onData(d); else chunks.push(d);
      });
      res.on('end', () => ok({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
      res.on('error', no);
    });
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', no);
    if (body) req.write(body);
    req.end();
  });
}
