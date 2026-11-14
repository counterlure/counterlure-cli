// Report path: proof of work, fixed-size envelopes, and what the face crop does and does not carry.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import sharp from 'sharp';
import { solve, verify, zeroBits, MAX_BITS } from '../lib/pow.js';
import { pad, PAD_TO, REPORT_PAD } from '../lib/proto.js';
import { cropRegion, faceCrop, MAX_SIDE, MAX_B64 } from '../lib/crop.js';

test('zero-bit count', () => {
  assert.equal(zeroBits(Buffer.from([0xff])), 0);
  assert.equal(zeroBits(Buffer.from([0x00, 0x80])), 8);
  assert.equal(zeroBits(Buffer.from([0x00, 0x01])), 15);
  assert.equal(zeroBits(Buffer.from([0x0f, 0x00])), 4);
});

test('proof of work is bound to nonce and timestamp', () => {
  const nonce = crypto.randomBytes(16).toString('hex'), ts = Date.now();
  const c = solve(nonce, ts, 12);
  assert.ok(verify(nonce, ts, c, 12));
  // Reference check, written independently of lib/pow.js: this is what the server computes.
  const h = crypto.createHash('sha256').update(`counterlure-cli/1|pow|${nonce}|${ts}|${c}`).digest();
  assert.ok(h[0] === 0 && h[1] >> 4 === 0, 'first 12 bits are zero');
  const other = crypto.randomBytes(16).toString('hex');
  // A different nonce or time almost never accepts the same counter (2^-12 by chance; try several).
  const reused = [other, nonce].map((n, i) => verify(n, ts + (i ? 1 : 0), c, 12));
  assert.ok(!reused.every(Boolean), 'work does not carry over to another request');
  assert.throws(() => solve(nonce, ts, MAX_BITS + 1), /outside/);
});

test('every request in a class is the same size', () => {
  const base = { protocol: 'counterlure-cli/1', op: 'report', nonce: 'a'.repeat(32), ts: Date.now(), replyKey: 'k'.repeat(700) };
  const small = pad({ ...base, args: { photo: 'A'.repeat(1000), name: 'X' } }, REPORT_PAD);
  const large = pad({ ...base, args: { photo: 'A'.repeat(MAX_B64), name: 'Some Longer Name', handle: 'h'.repeat(200) }, pow: 'zzzzzz' }, REPORT_PAD);
  assert.equal(Buffer.byteLength(small), REPORT_PAD);
  assert.equal(Buffer.byteLength(large), REPORT_PAD);
  assert.equal(Buffer.byteLength(pad({ ...base, op: 'whoami', args: { token: 't'.repeat(64) } }, PAD_TO)), PAD_TO);
  assert.throws(() => pad({ ...base, args: { photo: 'A'.repeat(REPORT_PAD) } }, REPORT_PAD), /larger than its envelope/);
  assert.equal(JSON.parse(small).args.photo.length, 1000, 'padding sits outside the arguments');
});

// A 2000x1000 test card: red left half, blue right half, carrying EXIF with a GPS position and a
// camera serial, and an EXIF orientation that rotates it 90 degrees clockwise on display.
async function tagged() {
  const left = await sharp({ create: { width: 1000, height: 1000, channels: 3, background: { r: 220, g: 20, b: 20 } } }).png().toBuffer();
  return sharp({ create: { width: 2000, height: 1000, channels: 3, background: { r: 20, g: 20, b: 220 } } })
    .composite([{ input: left, left: 0, top: 0 }])
    .withExif({ IFD0: { Make: 'TestCam', Model: 'Serial-0042', Copyright: 'secret' }, IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '51/1 30/1 0/1' } })
    .jpeg({ quality: 95 }).toBuffer()
    .then((b) => sharp(b).withMetadata({ orientation: 6 }).jpeg({ quality: 95 }).toBuffer());
}

test('the crop is the face only, freshly encoded, with nothing carried over', async () => {
  const src = await tagged();
  const before = await sharp(src).metadata();
  assert.equal(before.orientation, 6);
  assert.ok(before.exif?.length, 'the test image does carry EXIF');

  // Displayed (rotated) the image is 1000 wide, 2000 tall: red on top, blue below.
  const { jpeg, width, height } = await faceCrop(src, { x: 300, y: 300, w: 300, h: 300 });
  const meta = await sharp(jpeg).metadata();
  assert.equal(meta.format, 'jpeg');
  assert.equal(meta.exif, undefined, 'no EXIF');
  assert.equal(meta.icc, undefined, 'no colour profile');
  assert.equal(meta.xmp, undefined, 'no XMP');
  assert.equal(meta.orientation, undefined, 'no orientation tag: pixels are already upright');
  assert.ok(!jpeg.includes('Serial-0042') && !jpeg.includes('TestCam') && !jpeg.includes('secret'));
  assert.ok(width <= MAX_SIDE && height <= MAX_SIDE && Math.max(width, height) === MAX_SIDE);
  const { channels: [r, , b] } = await sharp(jpeg).stats();
  assert.ok(r.mean > 180 && b.mean < 60, 'crop taken from the upright frame (red region)');
  assert.ok(Math.ceil(jpeg.length / 3) * 4 <= MAX_B64);
});

test('the crop shrinks its margin to keep other faces out of frame', () => {
  const face = { x: 400, y: 200, w: 200, h: 200 };
  const neighbour = { x: 560, y: 200, w: 200, h: 200 }; // centre x=660, inside the 35% margin (edge 670)
  const has = (r, o) => o.x + o.w / 2 >= r.left && o.x + o.w / 2 < r.left + r.width && o.y + o.h / 2 >= r.top && o.y + o.h / 2 < r.top + r.height;
  const wide = cropRegion(face, [], 1200, 600);
  assert.ok(has(wide, neighbour), 'the default margin would take in the neighbour');
  const tight = cropRegion(face, [neighbour], 1200, 600);
  assert.ok(!has(tight, neighbour), 'margin shrunk until the neighbour is out');
  assert.ok(has(tight, face) && tight.width >= face.w, 'the subject is still whole');
  const edge = cropRegion({ x: 0, y: 0, w: 100, h: 100 }, [], 1200, 600);
  assert.deepEqual([edge.left, edge.top], [0, 0], 'clamped to the image');
});
