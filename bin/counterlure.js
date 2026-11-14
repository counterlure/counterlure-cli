#!/usr/bin/env node
// counterlure: query and feed the Counterlure face watchlist from a terminal.
//
//   signup   open an account: username, authenticator, crypto payment. No email, phone or name.
//   check    members only. The photo stays on this machine; a 128-value face template is sent.
//   report   anyone. Sends one cropped, re-encoded face and the selectors you supply (name, context,
//            handle). Without an account the report is filed unattributed, behind proof of work.
//   inbox    members. Messages between you and the Counterlure team; send writes to them.
//   withdraw anyone holding a receipt.
//
// By default everything goes to Counterlure's onion service over Tor (lib/route.js), and every
// request is OpenPGP-encrypted to a pinned server key and padded to a fixed size (lib/proto.js).
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { MODEL_VERSION, faceprints } from '../lib/faceprint.js';
import { ensureModels } from '../lib/models.js';
import { REPORT_PAD, Refused, call } from '../lib/proto.js';
import { DEFAULT_BITS, MAX_BITS } from '../lib/pow.js';
import { faceCrop } from '../lib/crop.js';
import { SERVER_FINGERPRINT } from '../lib/server-key.js';
import { ONION, SITE, resolveRoute } from '../lib/route.js';

const VERSION = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8')).version;
const CONTEXTS = ['dating-app', 'social-media', 'event-or-conference', 'work-or-business', 'introduced', 'other'];

// Same statement the website requires before a report is accepted.
const STATEMENT = [
  'I am in contact with this person personally and I am unsure about their intentions.',
  'I am not using this to track an ex-partner or anyone else, and nothing about my report',
  'is based on their nationality or ethnicity.',
];

const HELP = `counterlure ${VERSION}

Query and contribute to the Counterlure watchlist of faces tied to suspected approach operations
against people in tech. Traffic goes to Counterlure's onion service over Tor, and every request is
OpenPGP-encrypted to a pinned key and padded to a fixed size.

Account
  signup [--user NAME]     Open an account: pick a username, link an authenticator app, pay in
         [--chain ID]      crypto. No email, phone or name is asked for. Resumes where it stopped.
  login [--user NAME]      Sign in with username and authenticator code (24 h session).
  whoami | logout          Show or end the current session (logout also abandons a signup).

Messages (members)
  inbox [--all]            Read your conversation with the Counterlure team; marks it read.
  send [MESSAGE...]        Write to the team. Without MESSAGE, type it (end with a line holding
       [--subject S]       only ".") or pipe it in. Replies arrive in your inbox.

Faces
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
  models                   Download and verify the face models (SHA-256 pinned).
  key                      Print the pinned server key fingerprint and onion address.

Network
  (default)                Counterlure's onion service through the Tor running on this computer
                           (Tor Browser on 9150, or the tor service on 9050; COUNTERLURE_TOR=host:port
                           elsewhere). Your network address never reaches us.
  --direct                 Use the website (www.counterlure.com) instead. Cloudflare, in front of
                           it, sees your network address unless you add --tor or --proxy.
  --tor                    With --direct: reach the website through Tor.
  --proxy URL              socks5h://host:port or http://host:port (also COUNTERLURE_PROXY).
                           Without --direct it must be a SOCKS proxy into Tor.
  --server URL             a different server (also COUNTERLURE_URL)

Output
  --json                   machine-readable output for check, report and inbox

Reports filed without an account carry a proof-of-work stamp (a few seconds of CPU), count as a
single source however many are filed, and never return match results.
`;

const dirs = {
  config: process.env.COUNTERLURE_HOME || (process.platform === 'win32'
    ? path.join(process.env.APPDATA || os.homedir(), 'counterlure')
    : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'counterlure')),
};
dirs.session = path.join(dirs.config, 'session.json');
dirs.signup = path.join(dirs.config, 'signup.json');
dirs.models = process.env.COUNTERLURE_MODELS || path.join(dirs.config, 'models');

function writePrivate(file, data) {
  fs.mkdirSync(dirs.config, { recursive: true, mode: 0o700 });
  fs.writeFileSync(file, JSON.stringify(data), { mode: 0o600 });
  try { fs.chmodSync(file, 0o600); } catch {}
}
function readUnexpired(file) {
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (new Date(s.expiresAt) > new Date()) return s;
  } catch {}
  return null;
}
const saveSession = (s) => writePrivate(dirs.session, s);
const loadSession = () => readUnexpired(dirs.session);
const forgetSession = () => fs.rmSync(dirs.session, { force: true });
// A signup in progress: the short-lived token that lets it resume. Nothing else is kept.
const saveSignup = (s) => writePrivate(dirs.signup, s);
const loadSignup = () => readUnexpired(dirs.signup);
const forgetSignup = () => fs.rmSync(dirs.signup, { force: true });

const say = (s) => process.stderr.write(`${s}\n`);
const when = (d) => new Date(d).toLocaleString();
const sleep = (ms) => new Promise((ok) => setTimeout(ok, ms));

// One reader for every prompt, so text typed or piped ahead (several answers at once, a pasted
// message) is kept for the next prompt instead of lost. On a terminal, input is read raw, so hide
// can keep a code off the screen. Resolves null at end of input.
let pending = '', stdinEnded = false;
function prompt(question, { hide = false } = {}) {
  const stdin = process.stdin, tty = Boolean(stdin.isTTY);
  if (question) process.stderr.write(question);
  return new Promise((ok, no) => {
    let line = '';
    const finish = (err, v) => {
      stdin.off('data', onData); stdin.off('end', onEnd);
      if (tty) stdin.setRawMode(false);
      stdin.pause();
      stdin.unref?.(); // an open pipe must not keep the process alive once the last prompt is answered
      if (err) no(err); else ok(v);
    };
    const feed = () => {
      while (pending.length) {
        const c = pending[0];
        pending = pending.slice(1);
        if (c === '\n' || (tty && c === '\r')) {
          if (tty) process.stderr.write('\n');
          return finish(null, line.replace(/\r$/, '')), true;
        }
        if (tty) {
          if (c === '\u0003') { process.stderr.write('\n'); return finish(new Error('cancelled')), true; }
          if (c === '\u0004' && !line) { process.stderr.write('\n'); return finish(null, null), true; }
          if (c === '\u007f' || c === '\b') { if (line) { line = line.slice(0, -1); if (!hide) process.stderr.write('\b \b'); } continue; }
          if (c === '\u001b') { pending = pending.replace(/^\[[0-9;]*[A-Za-z~]/, ''); continue; } // arrow keys and the like
          if (!hide) process.stderr.write(c);
        }
        line += c;
      }
      return false;
    };
    const onData = (d) => { pending += d; feed(); };
    const onEnd = () => { stdinEnded = true; finish(null, line || null); };
    if (feed()) return;
    if (stdinEnded) return finish(null, line || null);
    if (tty) stdin.setRawMode(true);
    stdin.setEncoding('utf8');
    stdin.on('data', onData);
    stdin.once('end', onEnd);
    stdin.ref?.();
    stdin.resume();
  });
}
const ask = async (q, opts) => (await prompt(q, opts) ?? '').trim();

function level(m) {
  const what = m.source === 'burn-notice'
    ? `burn notice: ${m.name}${m.aliases?.length ? ` (also: ${m.aliases.join(', ')})` : ''}`
    : `a face reported by ${m.reporters} independent sources`;
  return `${m.level === 'strong' ? 'STRONG POSSIBLE MATCH' : 'possible match'} with ${what}`;
}

const models = (net) => ensureModels(dirs.models, { ...net, log: say });

// Calls that need proof of work: begin at the default, and do the extra work once if the server
// asks for more (it raises the bar when it is under load).
async function callWithWork(server, op, args, net, extra = {}) {
  let bits = DEFAULT_BITS;
  for (let attempt = 0; ; attempt++) {
    try {
      return await call(server, op, args, { ...net, ...extra, pow: bits, onWork: (b) => say(`Computing proof of work (${b} bits)...`) });
    } catch (e) {
      const need = e instanceof Refused ? e.reply.powBits : undefined;
      if (!need || attempt > 0 || need === bits) throw e;
      if (need > MAX_BITS) throw new Error(`The server is asking for ${need} bits of proof of work, more than this tool will do. Try later.`);
      bits = need;
    }
  }
}

async function check(s, files, net, server, json) {
  await models(net);
  const out = [];
  for (const file of files) {
    const faces = await faceprints(fs.readFileSync(file), { modelsDir: dirs.models });
    if (!faces.length) { out.push({ file, faces: [], note: 'no face found' }); continue; }
    const r = await call(server, 'check', { token: s.token, model: MODEL_VERSION, faces: faces.map((f) => f.embedding) }, net);
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

async function report(file, o, s, net, route) {
  // Validate everything local before spending CPU on models and proof of work.
  const asMember = Boolean(s) && !o.anon;
  const name = (o.name ?? (process.stdin.isTTY ? await ask('Name they gave you: ') : '')).trim();
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
  const n = o.face === undefined ? 1 : Number(o.face);
  if (o.face === undefined && faces.length > 1) throw new Error(`${faces.length} faces in this photo. Pick one with --face N:\n${list()}`);
  if (!Number.isInteger(n) || n < 1 || n > faces.length) throw new Error(`--face must be between 1 and ${faces.length}:\n${list()}`);
  const face = faces[n - 1];
  const crop = await faceCrop(input, face.box, faces.filter((f) => f !== face).map((f) => f.box));
  if (o['save-crop']) fs.writeFileSync(o['save-crop'], crop.jpeg, { mode: 0o600 });

  say([
    '',
    'Report',
    `  Subject      face ${n} of ${faces.length} in ${path.basename(file)} (${face.box.w}x${face.box.h}px${face.box.w < 64 ? ', small: may be rejected' : ''})`,
    `  Name given   ${name}`,
    `  Context      ${context}`,
    `  Handle       ${handle || '-'}`,
    `  Leaves here  ${crop.width}x${crop.height} JPEG of that face only, no metadata (${Math.round(crop.jpeg.length / 1024)} KB)`,
    `  Attribution  ${asMember ? `member ${s.username}: counts once for you, and you are told if the case is acted on` : 'none: filed as the shared anonymous source; no match result comes back'}`,
    `  Route        ${route.label}`,
    '',
    'Statement',
    ...STATEMENT.map((l) => `  ${l}`),
    '',
  ].join('\n'));
  if (o['dry-run']) return say(`Dry run: nothing sent.${o['save-crop'] ? ` Crop written to ${o['save-crop']}.` : ''}`);
  if (!o.yes && (await ask('Type "yes" to make this statement and file the report: ')).toLowerCase() !== 'yes') throw new Error('Not filed.');

  const args = { name, context, handle, photo: crop.jpeg.toString('base64'), attest: true };
  let r;
  if (asMember) r = await call(route.server, 'report', { ...args, token: s.token }, { ...net, padTo: REPORT_PAD });
  else r = await callWithWork(route.server, 'report', args, net, { padTo: REPORT_PAD });
  if (o.json) return console.log(JSON.stringify({ receipt: r.receipt, attributedTo: r.attributedTo }));
  console.log(`\nFiled. Receipt: ${r.receipt}`);
  console.log('Keep the receipt offline. It is the only way to withdraw this report, and this tool does not store it.');
  if (!r.attributedTo) console.log('Filed unattributed: nobody can contact you about it, and it adds weight only alongside other sources.');
}

// ------------------------------------------------------------------ signup

const indent = (text, by = '  ') => text.replace(/\n+$/, '').split('\n').map((l) => by + l).join('\n');

function showAuthenticator(st) {
  say([
    '',
    'Step 1 of 3: link an authenticator app',
    '  Scan this with an authenticator app (Aegis, Raivo, 2FAS, Google Authenticator, 1Password...).',
    '  It is the only way into your account: there is no email or password to reset.',
    '',
    indent(st.qrText),
    '',
    `  Or enter this key by hand: ${st.secret.replace(/(.{4})/g, '$1 ').trim()}`,
    `  (account: ${st.username}, time-based, 6 digits, 30 seconds)`,
    '',
  ].join('\n'));
}

async function pickChain(o, server, net) {
  const opts = await call(server, 'pay_options', {}, net);
  const sale = opts.regularUsd && opts.regularUsd > opts.priceUsd
    ? ` (regularly $${opts.regularUsd}${opts.offerEndsAt ? `, this price until ${new Date(opts.offerEndsAt).toLocaleDateString()}` : ''})` : '';
  say([
    '',
    'Step 2 of 3: choose how to pay',
    `  Membership: $${opts.priceUsd}${sale}, paid once in crypto. No card, no name, no address.`,
    '',
    ...opts.chains.map((c, i) => `  ${i + 1}. ${c.label}  (--chain ${c.id})`),
    '',
  ].join('\n'));
  if (o.chain) {
    if (!opts.chains.some((c) => c.id === o.chain)) throw new Error(`--chain must be one of: ${opts.chains.map((c) => c.id).join(', ')}`);
    return o.chain;
  }
  for (let tries = 0; tries < 3; tries++) {
    const a = await ask(`Pay with (1-${opts.chains.length}): `);
    const hit = opts.chains[Number(a) - 1] || opts.chains.find((c) => c.id === a.toLowerCase());
    if (hit) return hit.id;
    if (!process.stdin.isTTY) break;
  }
  throw new Error(`Choose a payment method: counterlure signup --chain ${opts.chains[0]?.id || 'ID'}`);
}

function showOrder(st) {
  say([
    '',
    'Step 3 of 3: pay',
    `  Send exactly   ${st.amount} ${st.symbol}`,
    `  on             ${st.chainLabel}`,
    `  to             ${st.address}`,
    '',
    '  The exact amount, down to the last digit, is how this payment is matched to your signup.',
    '  Send it in one transaction and do not round it. Sending from an exchange is fine.',
    st.expiresAt ? `  The amount is held for you until ${when(st.expiresAt)}.` : '',
    '',
    indent(st.qrText),
    '',
  ].filter((l) => l !== null).join('\n'));
}

const resumeHint = 'Run: counterlure signup   (it picks up where it stopped)';

// Payment: ask for the transaction ID, then check until it is confirmed or needs a person.
async function settle(st, sign, server, net) {
  let txHash = st.txHash || sign.txHash;
  if (!txHash) {
    showOrder(st);
    txHash = await ask('Once sent, paste the transaction ID (or press Enter to finish later): ');
    if (!txHash) { say(`\nNothing to check yet. ${resumeHint}`); return null; }
    saveSignup({ ...sign, txHash });
  }
  for (let round = 0; round < 25; round++) {
    let r;
    try {
      r = await call(server, 'pay_verify', { signupToken: sign.signupToken, txHash }, net);
    } catch (e) {
      if (!(e instanceof Refused) || !/transaction ID|already been used/i.test(e.message)) throw e;
      say(e.message);
      saveSignup({ ...sign, txHash: undefined });
      txHash = await ask('Transaction ID (or Enter to finish later): ');
      if (!txHash) { say(resumeHint); return null; }
      saveSignup({ ...sign, txHash });
      continue;
    }
    if (r.step !== 'pay') return r;
    if (r.status === 'review') {
      say(`\nThe payment needs a person to look at it${r.reason ? ` (${r.reason})` : ''}. That usually takes under a day.\n${resumeHint}\nTo add a note, open the website's inbox once your account is open, or wait for the review.`);
      return null;
    }
    if (r.state === 'mismatch') {
      say(`\n${r.reason || 'That transaction does not match this order.'}`);
      saveSignup({ ...sign, txHash: undefined });
      txHash = await ask('Another transaction ID (or Enter to finish later): ');
      if (!txHash) { say(resumeHint); return null; }
      saveSignup({ ...sign, txHash });
      continue;
    }
    say(`${r.reason || 'Not confirmed yet.'} Checking again in a minute. Ctrl-C stops; ${resumeHint.replace('Run: ', 'later run ')}`);
    await sleep(60000);
  }
  say(`Still waiting on the network. ${resumeHint}`);
  return null;
}

async function finish(st, sign, server, net) {
  const sess = st.session;
  if (!sess) throw new Error('The account is open but no session came back. Run: counterlure login');
  saveSession({ server, token: sess.token, username: sess.username, expiresAt: sess.expiresAt });
  forgetSignup();
  if (st.step === 'done' && st.recoveryCodes?.length) {
    say([
      '',
      'Your account is open. Recovery codes:',
      '',
      ...st.recoveryCodes.map((c) => `    ${c}`),
      '',
      '  Each one signs you in once, in place of an authenticator code. Write them down or keep them',
      '  in a password manager, offline. They are shown once and this tool does not store them.',
      '',
    ].join('\n'));
    if (process.stdin.isTTY) {
      while ((await ask('Type "saved" once they are somewhere safe: ')).toLowerCase() !== 'saved');
    }
    await call(server, 'codes_saved', { token: sess.token }, net);
  }
  console.log(`\nSigned in as ${sess.username} until ${when(sess.expiresAt)}.`);
  console.log('Next: counterlure check PHOTO, counterlure inbox, or counterlure send "a message to the team".');
}

async function signup(o, server, net) {
  let sign = loadSignup(), st;
  if (sign && o.user && o.user.toLowerCase() !== sign.username.toLowerCase()) {
    throw new Error(`A signup for "${sign.username}" is in progress here. Finish it with: counterlure signup\nor abandon it with: counterlure logout`);
  }
  if (sign) {
    say(`Resuming signup for ${sign.username}.`);
    try {
      st = await call(server, 'signup_state', { signupToken: sign.signupToken }, net);
    } catch (e) {
      if (e instanceof Refused && /expired/i.test(e.message)) forgetSignup();
      throw e;
    }
  } else {
    if (o.resume) throw new Error('No signup in progress on this computer. If you already linked an authenticator, run: counterlure login');
    const s = loadSession();
    if (s) throw new Error(`Already signed in as ${s.username}. Run counterlure logout first to open another account.`);
    say('A Counterlure account is a username and an authenticator app. No email, phone number or name.');
    const username = o.user || await ask('Choose a username (3-32 characters: letters, numbers, . - _): ');
    if (!username) throw new Error('A username is required.');
    const r = await callWithWork(server, 'signup_begin', { username }, net);
    sign = { server, signupToken: r.signupToken, username: r.username, expiresAt: r.expiresAt };
    saveSignup(sign);
    st = { step: 'totp', ...r };
  }

  for (let guard = 0; guard < 20; guard++) {
    if (st.step === 'totp') {
      showAuthenticator(st);
      let ok = false;
      for (let tries = 0; tries < 3 && !ok; tries++) {
        const code = await ask('Code from the app: ');
        if (!code) throw new Error(`No code entered. ${resumeHint}`);
        try { await call(server, 'signup_confirm', { signupToken: sign.signupToken, code }, net); ok = true; } catch (e) {
          if (!(e instanceof Refused) || !/did not match/i.test(e.message)) throw e;
          say(e.message);
        }
      }
      if (!ok) throw new Error(`Too many wrong codes. Check your phone's clock, then: ${resumeHint.replace('Run: ', '')}`);
      say('Authenticator linked.');
      st = await call(server, 'signup_state', { signupToken: sign.signupToken }, net);
    } else if (st.step === 'chain') {
      const chain = await pickChain(o, server, net);
      st = await call(server, 'pay_order', { signupToken: sign.signupToken, chain }, net);
      saveSignup({ ...sign, txHash: undefined });
      sign = loadSignup();
    } else if (st.step === 'pay') {
      const r = await settle(st, sign, server, net);
      if (!r) return;
      st = r;
    } else if (st.step === 'done' || st.step === 'active') {
      return finish(st, sign, server, net);
    } else {
      throw new Error(`Unexpected signup step "${st.step}". Update the tool.`);
    }
  }
  throw new Error(`Signup did not settle. ${resumeHint}`);
}

// ------------------------------------------------------------------ messages

function showThread(r, all) {
  const msgs = [...r.messages].reverse(); // oldest first, like a conversation
  const shown = all ? msgs : msgs.slice(-10);
  if (!msgs.length) {
    console.log('No messages yet. Write to the team with: counterlure send "your message"');
    return;
  }
  if (shown.length < msgs.length) console.log(`(${msgs.length - shown.length} earlier messages; --all shows them)\n`);
  for (const m of shown) {
    const who = m.from === 'admin' ? 'Counterlure' : 'You';
    const fresh = m.from === 'admin' && !m.readAt ? '  [new]' : '';
    console.log(`--- ${who}, ${when(m.createdAt)}${fresh}`);
    if (m.subject) console.log(`Subject: ${m.subject}`);
    if (m.caseId) console.log('About one of your reports.');
    console.log(`${m.body}\n`);
  }
}

async function compose(rest) {
  if (rest.length) return rest.join(' ');
  const lines = [];
  if (process.stdin.isTTY) say('Write your message. Finish with a line holding only "." (Ctrl-C cancels).');
  for (;;) {
    const l = await prompt('');
    if (l === null || (process.stdin.isTTY && l.trim() === '.')) break;
    lines.push(l);
  }
  return lines.join('\n');
}

// ------------------------------------------------------------------ main

async function main() {
  const { values: o, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      tor: { type: 'boolean' }, direct: { type: 'boolean' }, proxy: { type: 'string' }, json: { type: 'boolean' },
      server: { type: 'string' }, user: { type: 'string' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
      name: { type: 'string' }, context: { type: 'string' }, handle: { type: 'string' }, face: { type: 'string' },
      anon: { type: 'boolean' }, yes: { type: 'boolean' }, 'dry-run': { type: 'boolean' }, 'save-crop': { type: 'string' },
      subject: { type: 'string', short: 's' }, chain: { type: 'string' }, resume: { type: 'boolean' }, all: { type: 'boolean' },
    },
  });
  const [cmd, ...rest] = positionals;
  if (o.version) return console.log(VERSION);
  if (o.help || !cmd) return process.stdout.write(HELP);

  if (cmd === 'key') {
    console.log([
      'Pinned Counterlure CLI key fingerprint:',
      `  ${SERVER_FINGERPRINT.toUpperCase().replace(/(.{4})/g, '$1 ').trim()}`,
      'Onion service this tool talks to by default:',
      `  ${new URL(ONION).hostname}`,
      `Verify both against ${SITE}/#cli and ${SITE}/api/cli/key`,
    ].join('\n'));
    return;
  }

  // Everything below talks to the network. Nothing is sent until the route is settled.
  const route = await resolveRoute(o);
  const net = { proxy: route.proxy };
  const server = route.server;
  if (route.custom || !route.onion) say(`note: ${route.label}`);

  if (cmd === 'models') {
    await models(net);
    console.log(`Models verified in ${dirs.models}`);
    return;
  }
  if (cmd === 'signup' || cmd === 'pay') return signup(o, server, net);
  if (cmd === 'login') {
    const username = o.user || await ask('Username: ');
    const code = await ask('Authenticator code: ', { hide: true });
    const r = await call(server, 'login', { username, code }, net);
    if (r.pendingSignup) {
      saveSignup({ server, signupToken: r.signupToken, username: r.username, expiresAt: r.expiresAt });
      say(`${r.username} is not paid for yet. Continuing the signup.`);
      return signup({ ...o, user: undefined }, server, net);
    }
    saveSession({ server, token: r.token, username: r.username, expiresAt: r.expiresAt });
    forgetSignup();
    console.log(`Signed in as ${r.username} until ${when(r.expiresAt)}.`);
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
    return report(rest[0], o, s, net, route);
  }
  if (cmd === 'logout') {
    const sign = loadSignup();
    if (s || sign) await call(server, 'logout', { token: s?.token, signupToken: sign?.signupToken }, net).catch(() => {});
    forgetSession();
    forgetSignup();
    console.log(sign && !s ? 'Signup abandoned. Its saved state was deleted here.' : 'Signed out. The saved session was deleted.');
    return;
  }
  if (!s) {
    throw new Error(loadSignup()
      ? 'Your signup is not finished. Run: counterlure signup'
      : 'Not signed in. Run: counterlure login   (no account yet? counterlure signup)');
  }
  if (cmd === 'whoami') {
    const r = await call(server, 'whoami', { token: s.token }, net);
    console.log(`${r.username} (session valid until ${when(s.expiresAt)})`);
    if (r.unread) console.log(`${r.unread} unread message${r.unread === 1 ? '' : 's'} from the team. Run: counterlure inbox`);
    return;
  }
  if (cmd === 'inbox') {
    const r = await call(server, 'inbox', { token: s.token, markRead: true }, net);
    if (o.json) return console.log(JSON.stringify(r, null, 2));
    return showThread(r, o.all);
  }
  if (cmd === 'send') {
    const body = (await compose(rest)).trim();
    if (!body) throw new Error('Nothing to send. Usage: counterlure send "your message" [--subject S]');
    if (body.length > 4000) throw new Error(`Messages are 4000 characters at most (this one is ${body.length}).`);
    const r = await call(server, 'send', { token: s.token, subject: o.subject, body }, net);
    if (o.json) return console.log(JSON.stringify(r));
    console.log('Sent to the Counterlure team. Replies arrive in: counterlure inbox');
    return;
  }
  if (cmd === 'check') {
    if (!rest.length) throw new Error('Usage: counterlure check IMAGE [IMAGE...]');
    return check(s, rest, net, server, o.json);
  }
  throw new Error(`Unknown command "${cmd}". Run: counterlure --help`);
}

main().catch((e) => { process.stderr.write(`error: ${e.message}\n`); process.exitCode = 1; });
