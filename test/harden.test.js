// Hardening: what the tool refuses to parse, print, download or send.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import * as openpgp from 'openpgp';
import sharp from '../lib/sharp.js';
import { plain } from '../lib/term.js';
import { ensureModels, trusted } from '../lib/models.js';
import { request } from '../lib/net.js';
import { PAD_TO, pad } from '../lib/proto.js';
import { SERVER_KEY } from '../lib/server-key.js';

test('only JPEG, PNG and WebP are decoded', async () => {
  const png = await sharp({ create: { width: 8, height: 8, channels: 3, background: '#f00' } }).png().toBuffer();
  for (const fmt of ['jpeg', 'png', 'webp']) {
    const ok = await sharp(await sharp(png)[fmt]().toBuffer()).metadata();
    assert.equal(ok.width, 8, fmt);
  }
  const svg = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"><rect width="8" height="8"/></svg>');
  const refused = { svg, gif: await sharp(png).gif().toBuffer(), tiff: await sharp(png).tiff().toBuffer() };
  for (const [fmt, bytes] of Object.entries(refused)) {
    await assert.rejects(sharp(bytes).raw().toBuffer(), /unsupported image format/, fmt);
  }
});

test('server text cannot drive the terminal', () => {
  assert.equal(plain('a\u001b[2Jb\u009b31mc\rd\u0007'), 'a[2Jb31mcd', 'escape, C1, carriage return and bell are dropped');
  assert.equal(plain('0xAB\u202e12\u2066\u200b'), '0xAB12', 'reordering and invisible marks are dropped');
  assert.equal(plain('line one\n\tline two ▄▀█ é 名'), 'line one\n\tline two ▄▀█ é 名', 'ordinary text and QR blocks pass');
});

test('model downloads follow redirects to GitHub only', () => {
  const ok = (u) => trusted(new URL(u));
  assert.ok(ok('https://github.com/opencv/opencv_zoo/raw/main/models/x.onnx'));
  assert.ok(ok('https://media.githubusercontent.com/media/opencv/x.onnx'));
  assert.ok(!ok('http://github.com/x'), 'plain HTTP');
  assert.ok(!ok('https://github.com:8443/x'), 'odd port');
  assert.ok(!ok('https://github.com.example.org/x'), 'look-alike suffix');
  assert.ok(!ok('https://evilgithubusercontent.com/x'), 'look-alike prefix');
  assert.ok(!ok('https://127.0.0.1/x'), 'local address');
});

test('a failed model download leaves nothing behind', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cl-models-'));
  const proxy = new URL('http://127.0.0.1:1'); // nothing listens there
  await assert.rejects(ensureModels(dir, { proxy }), /ECONNREFUSED/);
  assert.deepEqual(fs.readdirSync(dir), []);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('long SOCKS fields are refused, not truncated', async () => {
  const sent = [];
  const socks = net.createServer((c) => { c.on('error', () => {}); c.once('data', () => { c.write(Buffer.from([5, 2])); c.on('data', (d) => sent.push(d)); }); });
  await new Promise((ok) => socks.listen(0, '127.0.0.1', ok));
  const at = `127.0.0.1:${socks.address().port}`;
  await assert.rejects(request('https://example.com/', { proxy: new URL(`socks5h://${'u'.repeat(300)}:x@${at}`) }), /username is too long/);
  await assert.rejects(request(`https://${'a.'.repeat(140)}example/`, { proxy: new URL(`socks5h://${at}`) }), /host name is too long/);
  assert.deepEqual(sent, [], 'nothing was sent after the greeting');
  socks.close();
});

test('requests are the same size whatever they say', async () => {
  const key = await openpgp.readKey({ armoredKey: SERVER_KEY });
  const seal = async (args) => (await openpgp.encrypt({
    message: await openpgp.createMessage({ text: pad({ op: 'x', args }, PAD_TO) }),
    encryptionKeys: key, format: 'binary',
    config: { preferredCompressionAlgorithm: openpgp.enums.compression.uncompressed },
  })).length;
  assert.equal(await seal({ a: 'a' }), await seal({ a: 'z'.repeat(9000), b: [1, 2, 3] }));
});
