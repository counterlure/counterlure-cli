#!/usr/bin/env node
// counterlure: query and feed the Counterlure face watchlist from a terminal.
//
//   check    members only. The photo stays on this machine; a 128-value face template is sent.
//   report   anyone. Sends one cropped, re-encoded face and the selectors you supply (name, context,
//            handle). Without an account the report is filed unattributed, behind proof of work.
//   withdraw anyone holding a receipt.
//
// Every request is OpenPGP-encrypted to a pinned server key and padded to a fixed size; see lib/proto.js.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { MODEL_VERSION, faceprints } from '../lib/faceprint.js';
import { ensureModels } from '../lib/models.js';
import { resolveProxy } from '../lib/net.js';
import { REPORT_PAD, Refused, call } from '../lib/proto.js';
import { DEFAULT_BITS, MAX_BITS } from '../lib/pow.js';
import { faceCrop } from '../lib/crop.js';
import { SERVER_FINGERPRINT } from '../lib/server-key.js';

const VERSION = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8')).version;
const DEFAULT_SERVER = 'https://www.counterlure.com';
const CONTEXTS = ['dating-app', 'social-media', 'event-or-conference', 'work-or-business', 'introduced', 'other'];

// Same statement the website requires before a report is accepted.
const STATEMENT = [
  'I am in contact with this person personally and I am unsure about their intentions.',
  'I am not using this to track an ex-partner or anyone else, and nothing about my report',
  'is based on their nationality or ethnicity.',
];

const HELP = `counterlure ${VERSION}

Query and contribute to the Counterlure watchlist of faces tied to suspected approach operations
against people in tech. All traffic is OpenPGP-encrypted to a pinned key and padded to fixed sizes.

Commands
  check IMAGE [IMAGE...]   Members. Screen the faces in one or more photos against corroborated
                           cases and published burn notices. Face detection and the face template
                           are computed locally; the photo itself is never sent.
  report IMAGE             Anyone. File a report on one face. Sends a tight crop of that face only,
                           re-encoded with no metadata, plus the selectors below.
      --name NAME          the name they gave you (required)
      --context C          where the approach happened: ${CONTEXTS.join(', ')}
      --handle H           the profile, handle or URL they used (optional)
      --face N             which face, when the photo has more than one (largest is 1)
      --anon               file unattributed even when signed in
      --dry-run            do everything except send; with --save-crop, inspect what would leave
      --save-crop FILE     write the exact crop that is (or would be) sent
      --yes                skip the confirmation prompt (you still make the statement)
  withdraw RECEIPT         Withdraw a report. The stored crop and face template are destroyed.
  login [--user NAME]      Members. Sign in with username and authenticator code (24 h session).
  whoami | logout          Show or end the current session.
  models                   Download and verify the face models (SHA-256 pinned).
  key                      Print the pinned server key fingerprint for out-of-band verification.

Network
  --tor                    route through Tor at 127.0.0.1:9050, fresh circuit per run
  --proxy URL              socks5h://host:port or http://host:port (also COUNTERLURE_PROXY)
  --server URL             a different server (also COUNTERLURE_URL)

Output
  --json                   machine-readable output for check and report

Reports filed without an account carry a proof-of-work stamp (a few seconds of CPU), count as a
single source however many are filed, and never return match results. Use --tor if you do not
want the service to see your network address at all.
`;

const dirs = {
  config: process.env.COUNTERLURE_HOME || (process.platform === 'win32'
    ? path.join(process.env.APPDATA || os.homedir(), 'counterlure')
    : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'counterlure')),
};
dirs.session = path.join(dirs.config, 'session.json');
dirs.models = process.env.COUNTERLURE_MODELS || path.join(dirs.config, 'models');

function saveSession(s) {
  fs.mkdirSync(dirs.config, { recursive: true, mode: 0o700 });
  fs.writeFileSync(dirs.session, JSON.stringify(s), { mode: 0o600 });
  try { fs.chmodSync(dirs.session, 0o600); } catch {}
}
function loadSession() {
  try {
    const s = JSON.parse(fs.readFileSync(dirs.session, 'utf8'));
    if (new Date(s.expiresAt) > new Date()) return s;
  } catch {}
  return null;
}
function forgetSession() { fs.rmSync(dirs.session, { force: true }); }

const say = (s) => process.stderr.write(`${s}\n`);

// Reads a line from the terminal; with hide, typed characters are not echoed.
function prompt(question, { hide = false } = {}) {
  return new Promise((ok, no) => {
    const stdin = process.stdin;
    process.stderr.write(question);
    if (!stdin.isTTY) {
      let data = '';
      stdin.setEncoding('utf8');
      stdin.on('data', (d) => { data += d; const i = data.indexOf('\n'); if (i >= 0) { stdin.pause(); ok(data.slice(0, i).trim()); } });
      stdin.on('end', () => ok(data.trim()));
      return;
    }
    let s = '';
    stdin.setRawMode(true); stdin.resume(); stdin.setEncoding('utf8');
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') { stdin.setRawMode(false); stdin.pause(); stdin.off('data', onData); process.stderr.write('\n'); return ok(s.trim()); }
        if (c === '\u0003') { stdin.setRawMode(false); process.stderr.write('\n'); return no(new Error('cancelled')); }
        if (c === '\u007f' || c === '\b') { if (s) { s = s.slice(0, -1); if (!hide) process.stderr.write('\b \b'); } continue; }
        s += c; if (!hide) process.stderr.write(c);
      }
    };
    stdin.on('data', onData);
  });
}

function level(m) {
  const what = m.source === 'burn-notice'
    ? `burn notice: ${m.name}${m.aliases?.length ? ` (also: ${m.aliases.join(', ')})` : ''}`
    : `a face reported by ${m.reporters} independent sources`;
  return `${m.level === 'strong' ? 'STRONG POSSIBLE MATCH' : 'possible match'} with ${what}`;
}

const models = (net) => ensureModels(dirs.models, { ...net, log: say });

async function check(s, files, net, json) {
  await models(net);
  const out = [];
  for (const file of files) {
    const faces = await faceprints(fs.readFileSync(file), { modelsDir: dirs.models });
    if (!faces.length) { out.push({ file, faces: [], note: 'no face found' }); continue; }
    const r = await call(s.server, 'check', { token: s.token, model: MODEL_VERSION, faces: faces.map((f) => f.embedding) }, net);
    out.push({ file, checksLeft: r.checksLeft, faces: faces.map((f, i) => ({ box: f.box, small: f.box.w < 64, matches: r.results[i] })) });
  }
  if (json) return console.log(JSON.stringify(out, null, 2));
  let any = false;
  for (const r of out) {
    console.log(`\n${r.file}`);
    if (!r.faces.length) { console.log('  No face found. Use a clearer, front-facing photo.'); continue; }
    r.faces.forEach((f, i) => {
      const where = `face ${i + 1} at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)${f.small ? ', small: low confidence' : ''}`;
      if (!f.matches.length) return console.log(`  ${where}: no match`);
      any = true;
      console.log(`  ${where}:`);
      for (const m of f.matches) console.log(`    ${level(m)}`);
    });
    if (r.checksLeft !== undefined) console.log(`  (${r.checksLeft} checks left today)`);
  }
  console.log(any
    ? '\nA match is a lead, not an identification. Faces resemble each other. Corroborate through other\nmeans before acting, and never harass or publish anyone on the strength of this result.\nIf you have something new on this person, file it: counterlure report IMAGE --name ...'
    : '\nNo match is not a clearance: only faces already reported can match.');
}

async function report(file, o, s, net, server) {
  // Validate everything local before spending CPU on models and proof of work.
  const asMember = Boolean(s) && !o.anon;
  const name = (o.name ?? (process.stdin.isTTY ? await prompt('Name they gave you: ') : '')).trim();
  if (name.length < 2 || name.length > 120) throw new Error('--name is required: the name they gave you (2 to 120 characters).');
  const context = o.context || 'other';
  if (!CONTEXTS.includes(context)) throw new Error(`--context must be one of: ${CONTEXTS.join(', ')}`);
  const handle = o.handle?.trim() || undefined;
  if (handle && handle.length > 200) throw new Error('--handle is limited to 200 characters.');
  if (!o.yes && !o['dry-run'] && !process.stdin.isTTY) throw new Error('No terminal to confirm on. Re-run with --yes to make the statement non-interactively.');

  await models(net);
  const input = fs.readFileSync(file);
  const faces = await faceprints(input, { modelsDir: dirs.models });
  if (!faces.length) throw new Error('No face found. Use a clearer, front-facing photo.');
  const list = () => faces.map((f, i) => `  ${i + 1}: at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)`).join('\n');
  let n = o.face === undefined ? 1 : Number(o.face);
  if (o.face === undefined && faces.length > 1) throw new Error(`${faces.length} faces in this photo. Pick one with --face N:\n${list()}`);
  if (!Number.isInteger(n) || n < 1 || n > faces.length) throw new Error(`--face must be between 1 and ${faces.length}:\n${list()}`);
  const face = faces[n - 1];
  const crop = await faceCrop(input, face.box, faces.filter((f) => f !== face).map((f) => f.box));
  if (o['save-crop']) fs.writeFileSync(o['save-crop'], crop.jpeg, { mode: 0o600 });

  const route = net.proxy ? (o.tor ? 'Tor' : `proxy ${net.proxy.protocol}//${net.proxy.host}`) : 'direct';
  say([
    '',
    'Report',
    `  Subject      face ${n} of ${faces.length} in ${path.basename(file)} (${face.box.w}x${face.box.h}px${face.box.w < 64 ? ', small: may be rejected' : ''})`,
    `  Name given   ${name}`,
    `  Context      ${context}`,
    `  Handle       ${handle || '-'}`,
    `  Leaves here  ${crop.width}x${crop.height} JPEG of that face only, no metadata (${Math.round(crop.jpeg.length / 1024)} KB)`,
    `  Attribution  ${asMember ? `member ${s.username}: counts once for you, and you are told if the case is acted on` : 'none: filed as the shared anonymous source; no match result comes back'}`,
    `  Route        ${route}`,
    '',
    'Statement',
    ...STATEMENT.map((l) => `  ${l}`),
    '',
  ].join('\n'));
  if (!asMember && !net.proxy) say('note: without --tor the service sees your network address. It keeps only a keyed hash of it, for rate limiting, and deletes that within a day.\n');
  if (o['dry-run']) return say(`Dry run: nothing sent.${o['save-crop'] ? ` Crop written to ${o['save-crop']}.` : ''}`);
  if (!o.yes && (await prompt('Type "yes" to make this statement and file the report: ')).toLowerCase() !== 'yes') throw new Error('Not filed.');

  const args = { name, context, handle, photo: crop.jpeg.toString('base64'), attest: true };
  if (asMember) args.token = s.token;
  const target = asMember ? s.server : server;
  let bits = asMember ? 0 : DEFAULT_BITS, r;
  for (let attempt = 0; ; attempt++) {
    try {
      r = await call(target, 'report', args, { ...net, padTo: REPORT_PAD, pow: bits || undefined, onWork: (b) => say(`Computing proof of work (${b} bits)...`) });
      break;
    } catch (e) {
      const need = e instanceof Refused ? e.reply.powBits : undefined;
      if (!need || attempt > 0 || need === bits) throw e;
      if (need > MAX_BITS) throw new Error(`The server is asking for ${need} bits of proof of work, more than this tool will do. Sign in, or try later.`);
      bits = need;
    }
  }
  if (o.json) return console.log(JSON.stringify({ receipt: r.receipt, attributedTo: r.attributedTo }));
  console.log(`\nFiled. Receipt: ${r.receipt}`);
  console.log('Keep the receipt offline. It is the only way to withdraw this report, and this tool does not store it.');
  if (!r.attributedTo) console.log('Filed unattributed: nobody can contact you about it, and it adds weight only alongside other sources.');
}

async function main() {
  const { values: o, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      tor: { type: 'boolean' }, proxy: { type: 'string' }, json: { type: 'boolean' },
      server: { type: 'string' }, user: { type: 'string' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
      name: { type: 'string' }, context: { type: 'string' }, handle: { type: 'string' }, face: { type: 'string' },
      anon: { type: 'boolean' }, yes: { type: 'boolean' }, 'dry-run': { type: 'boolean' }, 'save-crop': { type: 'string' },
    },
  });
  const [cmd, ...rest] = positionals;
  if (o.version) return console.log(VERSION);
  if (o.help || !cmd) return process.stdout.write(HELP);

  const server = o.server || process.env.COUNTERLURE_URL || DEFAULT_SERVER;
  if (server !== DEFAULT_SERVER) say(`note: using server ${server}`);
  const net = { proxy: resolveProxy(o.tor ? 'tor' : o.proxy) };

  if (cmd === 'key') {
    console.log(`Pinned Counterlure CLI key fingerprint:\n  ${SERVER_FINGERPRINT.toUpperCase().replace(/(.{4})/g, '$1 ').trim()}\nVerify against ${DEFAULT_SERVER}/#cli and ${DEFAULT_SERVER}/api/cli/key`);
    return;
  }
  if (cmd === 'models') {
    await models(net);
    console.log(`Models verified in ${dirs.models}`);
    return;
  }
  if (cmd === 'login') {
    const username = o.user || await prompt('Username: ');
    const code = await prompt('Authenticator code: ', { hide: true });
    const r = await call(server, 'login', { username, code }, net);
    saveSession({ server, token: r.token, username: r.username, expiresAt: r.expiresAt });
    console.log(`Signed in as ${r.username} until ${new Date(r.expiresAt).toLocaleString()}.`);
    if (r.recoveryLeft !== undefined) console.log(`You used a recovery code: ${r.recoveryLeft} left. Re-enrol your authenticator on the website.`);
    return;
  }
  if (cmd === 'withdraw') {
    if (rest.length !== 1) throw new Error('Usage: counterlure withdraw RECEIPT');
    await call(server, 'withdraw', { receipt: rest[0] }, net);
    console.log('Withdrawn. The stored face crop and template have been destroyed.');
    return;
  }

  const s = loadSession();
  if (cmd === 'report') {
    if (rest.length !== 1) throw new Error('Usage: counterlure report IMAGE --name NAME [--context C] [--handle H]');
    return report(rest[0], o, s, net, server);
  }
  if (cmd === 'logout') {
    if (s) await call(s.server, 'logout', { token: s.token }, net).catch(() => {});
    forgetSession();
    console.log('Signed out. The saved session was deleted.');
    return;
  }
  if (!s) throw new Error('Not signed in. Run: counterlure login');
  if (cmd === 'whoami') {
    const r = await call(s.server, 'whoami', { token: s.token }, net);
    console.log(`${r.username} (session valid until ${new Date(s.expiresAt).toLocaleString()})`);
    return;
  }
  if (cmd === 'check') {
    if (!rest.length) throw new Error('Usage: counterlure check IMAGE [IMAGE...]');
    return check(s, rest, net, o.json);
  }
  throw new Error(`Unknown command "${cmd}". Run: counterlure --help`);
}

main().catch((e) => { process.stderr.write(`error: ${e.message}\n`); process.exit(1); });
