// Request/reply envelope for counterlure-cli/1.
//
// Threat model for the transport: TLS to www.counterlure.com terminates at Cloudflare, so anything
// sent in the clear inside TLS is readable at the edge. We assume the edge, and any proxy or Tor exit
// in between, is an observer. What it can see is that a client talked to the service, when, and how
// many bytes moved. What it must not see or alter is the content.
//
//   1. A one-time OpenPGP key pair is generated per request and discarded after the reply.
//   2. The request (op, args, one-time public key, 128-bit nonce, timestamp, optional proof of work)
//      is padded to a fixed bucket and encrypted to the server key compiled into this tool, which is
//      checked against a pinned fingerprint before every use.
//        - control traffic (login, whoami, check, withdraw) pads to 16 KB
//        - reports pad to REPORT_PAD, so every report is the same size whatever the photo
//   3. The reply must decrypt with the one-time key, carry a valid signature from the pinned key, and
//      echo the nonce. Anything else is discarded, so the edge can neither read nor forge an answer.
//      The server pads replies to 4 KB multiples, so a match and a miss look alike.
//
// The server accepts each nonce once and only within five minutes of its clock, so a captured
// request can't be replayed.
import fs from 'node:fs';
import crypto from 'node:crypto';
import * as openpgp from 'openpgp';
import { SERVER_KEY, SERVER_FINGERPRINT } from './server-key.js';
import { request } from './net.js';
import { PROTOCOL_ID } from './protocol-id.js';
import { solve } from './pow.js';

export const PROTOCOL = PROTOCOL_ID;
export const PAD_TO = 16 * 1024;
export const REPORT_PAD = 224 * 1024;

let pinned = null;
async function serverKey() {
  if (pinned) return pinned;
  let armored = SERVER_KEY, want = SERVER_FINGERPRINT;
  if (process.env.COUNTERLURE_SERVER_KEY) { // pointing at your own server; announced on every run
    armored = fs.readFileSync(process.env.COUNTERLURE_SERVER_KEY, 'utf8');
    want = (await openpgp.readKey({ armoredKey: armored })).getFingerprint();
    process.stderr.write(`warning: using server key from COUNTERLURE_SERVER_KEY (${want}), not the pinned one\n`);
  }
  if (!armored || !want) throw new Error('This build has no server key pinned. Install a release from the official repository.');
  const key = await openpgp.readKey({ armoredKey: armored });
  if (key.isPrivate() || key.getFingerprint().toLowerCase() !== want.toLowerCase()) {
    throw new Error('The embedded server key does not match its pinned fingerprint. Treat this copy of the tool as tampered with.');
  }
  pinned = key;
  return key;
}

// Serialises msg padded to exactly padTo bytes. Throws rather than send an off-size request.
export function pad(msg, padTo) {
  const bare = JSON.stringify({ ...msg, pad: '' });
  const fill = padTo - Buffer.byteLength(bare);
  if (fill < 0) throw new Error('The request is larger than its envelope. Nothing was sent.');
  return JSON.stringify({ ...msg, pad: 'x'.repeat(fill) });
}

// A refusal from the server. reply carries machine-readable fields such as powBits.
export class Refused extends Error {
  constructor(reply) { super(reply.error || 'The server refused the request.'); this.reply = reply; }
}

// opts: proxy (from net.resolveProxy), pow (bits of work to attach), padTo, onWork (called before
// grinding, so the caller can say why the terminal has gone quiet).
export async function call(server, op, args, { proxy, pow, padTo = PAD_TO, onWork } = {}) {
  const key = await serverKey();
  const eph = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'counterlure-cli one-time key' }], format: 'object' });
  const msg = { protocol: PROTOCOL, op, args, nonce: crypto.randomBytes(16).toString('hex'), ts: Date.now(), replyKey: eph.publicKey.armor() };
  if (pow) {
    onWork?.(pow);
    msg.pow = solve(msg.nonce, msg.ts, pow);
  }
  const body = await openpgp.encrypt({ message: await openpgp.createMessage({ text: pad(msg, padTo) }), encryptionKeys: key });

  const res = await request(new URL('/api/cli', server).toString(), {
    method: 'POST', body, proxy, maxBytes: 1024 * 1024,
    headers: { 'content-type': 'application/pgp-encrypted', accept: 'application/pgp-encrypted' },
  });
  if (res.status === 429) throw new Error('Rate limited. Wait a minute and try again.');
  if (res.status === 403) throw new Error('The edge refused the connection. Over Tor or a VPN this usually means the exit is blocked; try another circuit or route.');
  if (res.status === 413) throw new Error('The server refused the request size. Update the tool.');
  if (res.status !== 200 || !String(res.headers['content-type'] || '').startsWith('application/pgp-encrypted')) {
    throw new Error(`Unexpected reply from the server (HTTP ${res.status}). Nothing was disclosed: the request was encrypted.`);
  }
  let reply;
  try {
    const { data } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: res.body.toString('utf8') }),
      decryptionKeys: eph.privateKey, verificationKeys: key, expectSigned: true,
    });
    reply = JSON.parse(data);
  } catch {
    throw new Error('The reply was not signed by the pinned Counterlure key and was discarded.');
  }
  if (reply.protocol !== PROTOCOL || reply.echo !== msg.nonce) throw new Error('The reply did not answer this request and was discarded.');
  if (!reply.ok) throw new Refused(reply);
  return reply;
}
