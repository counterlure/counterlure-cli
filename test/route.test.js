// Which server a run talks to, and that the onion route never leaves Tor.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { ONION, SITE, NoTor, resolveRoute } from '../lib/route.js';
import { findTor, request } from '../lib/net.js';

const tor = async () => new URL('socks5h://cl-test:x@127.0.0.1:9050');
const none = async () => null;

test('default: the onion service, through Tor found on this computer', async () => {
  const r = await resolveRoute({}, { env: {}, find: tor });
  assert.equal(r.server, ONION);
  assert.equal(r.onion, true);
  assert.equal(r.proxy.protocol, 'socks5h:');
  assert.match(r.label, /onion service \(over Tor\)/);
});

test('default without Tor: refuses, and does not fall back to the website', async () => {
  await assert.rejects(resolveRoute({}, { env: {}, find: none }), (e) => e instanceof NoTor && /--direct/.test(e.message));
});

test('--direct: the website, and the label says Cloudflare sees the address', async () => {
  const r = await resolveRoute({ direct: true }, { env: {}, find: none });
  assert.equal(r.server, SITE);
  assert.equal(r.proxy, null);
  assert.match(r.label, /Cloudflare: it sees your network address/);
});

test('--direct --tor needs Tor too; with it, the website over Tor', async () => {
  await assert.rejects(resolveRoute({ direct: true, tor: true }, { env: {}, find: none }), NoTor);
  const r = await resolveRoute({ direct: true, tor: true }, { env: {}, find: tor });
  assert.equal(r.server, SITE);
  assert.match(r.label, /over Tor, then Cloudflare/);
});

test('onion with an explicit proxy: SOCKS is fine, HTTP is refused', async () => {
  const r = await resolveRoute({ proxy: 'socks5h://127.0.0.1:9999' }, { env: {}, find: none });
  assert.equal(r.proxy.port, '9999');
  await assert.rejects(resolveRoute({ proxy: 'http://127.0.0.1:8080' }, { env: {}, find: tor }), /SOCKS/);
});

test('--server: a custom server is used as given, without a Cloudflare note', async () => {
  const r = await resolveRoute({ server: 'http://127.0.0.1:8090/' }, { env: {}, find: none });
  assert.equal(r.server, 'http://127.0.0.1:8090');
  assert.equal(r.custom, true);
  assert.doesNotMatch(r.label, /Cloudflare/);
  const e = await resolveRoute({}, { env: { COUNTERLURE_URL: 'https://example.test' }, find: none });
  assert.equal(e.server, 'https://example.test');
});

test('findTor: tries 9050 then 9150, honours COUNTERLURE_TOR, isolates circuits', async () => {
  const seen = [];
  const probe = async (h, p) => { seen.push(`${h}:${p}`); return p === 9150; };
  const a = await findTor({ env: {}, probe });
  assert.deepEqual(seen, ['127.0.0.1:9050', '127.0.0.1:9150']);
  assert.equal(a.port, '9150');
  const b = await findTor({ env: {}, probe });
  assert.notEqual(a.username, b.username, 'each run gets its own Tor circuit');
  seen.length = 0;
  assert.equal(await findTor({ env: { COUNTERLURE_TOR: '10.1.2.3:9999' }, probe }), null);
  assert.deepEqual(seen, ['10.1.2.3:9999']);
  await assert.rejects(findTor({ env: { COUNTERLURE_TOR: 'not a port' }, probe }), /host:port/);
});

test('findTor: a real listener that is not SOCKS is not mistaken for Tor', async () => {
  const srv = net.createServer((s) => s.end('HTTP/1.1 400 Bad Request\r\n\r\n'));
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  try {
    assert.equal(await findTor({ env: { COUNTERLURE_TOR: `127.0.0.1:${srv.address().port}` } }), null);
  } finally { srv.close(); }
});

test('an onion address is never dialled outside Tor', async () => {
  const host = new URL(ONION).host;
  await assert.rejects(request(`http://${host}/api/cli`), /only be reached through Tor/);
  await assert.rejects(request(`http://${host}/api/cli`, { proxy: new URL('http://127.0.0.1:8080') }), /only be reached through Tor/);
});
