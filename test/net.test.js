// Network path: proxies are used as configured, and hostnames reach the proxy unresolved.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { request, resolveProxy } from '../lib/net.js';
import { cosine } from '../lib/faceprint.js';

test('proxy settings', () => {
  const a = resolveProxy('tor'), b = resolveProxy('tor');
  assert.equal(a.protocol, 'socks5h:');
  assert.equal(a.host, '127.0.0.1:9050');
  assert.notEqual(a.username, b.username, 'a separate Tor circuit per run');
  assert.equal(resolveProxy('http://proxy.example:3128').port, '3128');
  assert.throws(() => resolveProxy('ftp://x'), /Unsupported proxy/);
});

test('plain HTTP is refused except to this computer', async () => {
  await assert.rejects(request('http://example.com/'), /non-HTTPS/);
});

test('SOCKS5 gets the hostname, not an IP address', async () => {
  const web = http.createServer((req, res) => res.end(`ok ${req.headers['user-agent']}`));
  await new Promise((ok) => web.listen(0, '127.0.0.1', ok));
  let asked = null; const open = [];
  const socks = net.createServer((c) => {
    open.push(c);
    c.once('data', () => {
      c.write(Buffer.from([5, 0]));
      c.once('data', (d) => {
        assert.equal(d[3], 3, 'ATYP 3: domain name');
        asked = d.subarray(5, 5 + d[4]).toString();
        const up = net.connect(web.address().port, '127.0.0.1', () => {
          open.push(up);
          c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
          c.pipe(up).pipe(c);
        });
      });
    });
  });
  await new Promise((ok) => socks.listen(0, '127.0.0.1', ok));
  const r = await request('http://localhost/x', { proxy: new URL(`socks5h://127.0.0.1:${socks.address().port}`) });
  assert.equal(asked, 'localhost');
  assert.equal(r.body.toString(), 'ok counterlure-cli', 'no version or OS in the user agent');
  for (const s of open) s.destroy();
  web.closeAllConnections(); socks.close(); web.close();
});

test('cosine', () => {
  assert.equal(cosine([1, 0], [1, 0]), 1);
  assert.equal(cosine([1, 0], [0, 1]), 0);
});
