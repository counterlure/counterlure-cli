// The encrypted request/reply envelope.
//
// 1. A fresh OpenPGP key pair is made for every request and forgotten afterwards.
// 2. The request (operation, arguments, the fresh public key, a random nonce, the time) is padded to a
//    fixed size, so a login and a face check look the same on the wire, and encrypted to the server's
//    key. That key is embedded in this tool and checked against a pinned fingerprint before use.
// 3. The reply must be encrypted to the fresh key, signed by the pinned server key, and echo the nonce.
//    Anything else is rejected, so a proxy or CDN in the middle can neither read nor forge answers.
import fs from 'node:fs';
import crypto from 'node:crypto';
import * as openpgp from 'openpgp';
import { SERVER_KEY, SERVER_FINGERPRINT } from './server-key.js';
import { request } from './net.js';

export const PROTOCOL = 'counterlure-cli/1';
const PAD_TO = 16384;

let pinned = null;
async function serverKey() {
  if (pinned) return pinned;
  let armored = SERVER_KEY, want = SERVER_FINGERPRINT;
  if (process.env.COUNTERLURE_SERVER_KEY) { // for testing against your own server; says so loudly
    armored = fs.readFileSync(process.env.COUNTERLURE_SERVER_KEY, 'utf8');
    want = (await openpgp.readKey({ armoredKey: armored })).getFingerprint();
    process.stderr.write(`warning: using server key from COUNTERLURE_SERVER_KEY (${want}), not the pinned one\n`);
  }
  if (!armored || !want) throw new Error('This copy of the tool has no server key pinned yet. Install a release from the official repository.');
  const key = await openpgp.readKey({ armoredKey: armored });
  if (key.isPrivate() || key.getFingerprint().toLowerCase() !== want.toLowerCase()) throw new Error('The embedded server key does not match its pinned fingerprint. Do not use this copy of the tool.');
  pinned = key;
  return key;
}

export async function call(server, op, args, { proxy } = {}) {
  const key = await serverKey();
  const eph = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'counterlure-cli one-time key' }], format: 'object' });
  const nonce = crypto.randomBytes(16).toString('hex');
  const msg = { protocol: PROTOCOL, op, args, nonce, ts: Date.now(), replyKey: eph.publicKey.armor() };
  let text = JSON.stringify(msg);
  if (text.length < PAD_TO) text = JSON.stringify({ ...msg, pad: 'x'.repeat(PAD_TO - text.length - 10) });
  const body = await openpgp.encrypt({ message: await openpgp.createMessage({ text }), encryptionKeys: key });

  const res = await request(new URL('/api/cli', server).toString(), {
    method: 'POST', body, proxy, maxBytes: 1024 * 1024,
    headers: { 'content-type': 'application/pgp-encrypted', accept: 'application/pgp-encrypted' },
  });
  if (res.status === 429) throw new Error('Too many requests. Wait a minute and try again.');
  if (res.status === 403) throw new Error('The server refused the connection. If you use Tor or a VPN, Cloudflare may be blocking that exit; try another, or no proxy.');
  if (res.status !== 200 || !String(res.headers['content-type'] || '').startsWith('application/pgp-encrypted')) {
    throw new Error(`Unexpected reply from the server (HTTP ${res.status}). Nothing was sent in the clear.`);
  }
  let reply;
  try {
    const { data } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: res.body.toString('utf8') }),
      decryptionKeys: eph.privateKey, verificationKeys: key, expectSigned: true,
    });
    reply = JSON.parse(data);
  } catch {
    throw new Error('The reply was not signed by the pinned Counterlure key. It was discarded.');
  }
  if (reply.protocol !== PROTOCOL || reply.echo !== nonce) throw new Error('The reply did not belong to this request. It was discarded.');
  if (!reply.ok) throw new Error(reply.error || 'The server refused the request.');
  return reply;
}
