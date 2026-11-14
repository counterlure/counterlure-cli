// Proof of work for reports filed without an account.
//
// An unauthenticated intake is the obvious place to attack a corroboration system: script a few
// thousand reports against one face and hope the volume reads as independent sourcing. The server
// already treats every no-account CLI report as a single source, and rate-limits them per network
// and overall. Proof of work adds a cost per report that the reporter pays in CPU, not identity.
//
// The work is bound to the request's single-use nonce and timestamp, so it can't be precomputed,
// reused, or replayed:
//
//   sha256("counterlure-cli/1|pow|<nonce>|<ts>|<counter>") must start with <bits> zero bits
//
// At the default of 21 bits that is about two million hashes, a few seconds on a laptop.
import crypto from 'node:crypto';
import { PROTOCOL_ID } from './protocol-id.js';

export const DEFAULT_BITS = 21;
// Refuse to grind past this, whatever the server asks. 2^26 hashes is already about a minute.
export const MAX_BITS = 26;

export function zeroBits(buf) {
  let n = 0;
  for (const byte of buf) {
    if (byte === 0) { n += 8; continue; }
    return n + Math.clz32(byte) - 24;
  }
  return n;
}

const digest = (nonce, ts, counter) =>
  crypto.createHash('sha256').update(`${PROTOCOL_ID}|pow|${nonce}|${ts}|${counter}`).digest();

export function verify(nonce, ts, counter, bits) {
  return typeof counter === 'string' && counter.length <= 32 && zeroBits(digest(nonce, ts, counter)) >= bits;
}

export function solve(nonce, ts, bits) {
  if (!Number.isInteger(bits) || bits < 1 || bits > MAX_BITS) throw new Error(`Proof of work of ${bits} bits is outside what this tool will do.`);
  for (let i = 0; ; i++) {
    const counter = i.toString(36);
    if (zeroBits(digest(nonce, ts, counter)) >= bits) return counter;
  }
}
