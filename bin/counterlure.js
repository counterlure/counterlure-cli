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
import { ensureModels, importModels, modelStatus, missingModelsText, findLocalModels } from '../lib/models.js';
import { REPORT_PAD, Refused, call, serverFingerprint } from '../lib/proto.js';
import { DEFAULT_BITS, MAX_BITS } from '../lib/pow.js';
import { faceCrop } from '../lib/crop.js';
import { SERVER_FINGERPRINT } from '../lib/server-key.js';
import { ONION, SITE, resolveRoute } from '../lib/route.js';
import { out, say } from '../lib/term.js';

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
                           Photos must be JPEG, PNG or WebP; no other format is opened.
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
  models                   Show whether the two face models are installed and verified.
  models import PATH...    Bring in model files you downloaded yourself (files or folders).
                           Each is accepted only if it matches a pinned SHA-256.
  models --download        Fetch the missing models from OpenCV's GitHub (asks first).
      --fetch-models       (any command) consent in advance to fetching missing models;
                           without it, nothing is downloaded unless you type yes.
  key                      Print the pinned server key fingerprint and onion address.

Organization (Enterprise Cluster Defense — zero-knowledge employee anonymity)
  org enroll CODE          Enroll this device anonymously using your organization's code.
                           No employee name, email or identity is ever recorded.
  org check IMAGE [...]    Screen faces against both your organization's alerts and the global
                           Counterlure pool. Photos never leave your machine.
  org report IMAGE         File a zero-knowledge biometric report into your organization's private
      [--context C]        namespace (128-d face vector only: no photo, no name, no identity).
      [--face N] [--yes]   Escalates automatically when 3+ distinct staff report the same face.
  org inbox [--all]        Read private alerts (including coordinated-attack notices).
  org status               Show your organization's aggregate threat status and unread alerts.
  org withdraw RECEIPT     Withdraw an organization report by its CLO-... receipt.
  org leave                Delete the local anonymous device credential.

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
dirs.org = path.join(dirs.config, 'org.json');
dirs.models = process.env.COUNTERLURE_MODELS || path.join(dirs.config, 'models');

// Saved sessions and signups are tied to the server key they came from (the key is the server's
// identity). Pointed at another server, this tool does not find them, so a token never goes to a
// server it was not issued by. Files written before this was recorded belong to the pinned key.
let trustedKey = SERVER_FINGERPRINT.toLowerCase();

// Written whole or not at all: to a temporary file, private from its first byte, then renamed.
function writePrivate(file, data) {
  fs.mkdirSync(dirs.config, { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(tmp, JSON.stringify({ ...data, key: trustedKey }), { mode: 0o600, flag: 'wx' });
    fs.renameSync(tmp, file);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}
function readUnexpired(file) {
  try {
    const s = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (new Date(s.expiresAt) > new Date() && (s.key || SERVER_FINGERPRINT).toLowerCase() === trustedKey) return s;
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
const saveOrg = (s) => writePrivate(dirs.org, s);
function loadOrg() {
  try {
    const s = JSON.parse(fs.readFileSync(dirs.org, 'utf8'));
    if (s?.orgToken && (s.key || SERVER_FINGERPRINT).toLowerCase() === trustedKey) return s;
  } catch {}
  return null;
}
const forgetOrg = () => fs.rmSync(dirs.org, { force: true });

const when = (d) => new Date(d).toLocaleString();
// How often to ask whether a payment has arrived (shorter only in tests).
const POLL_MS = Number(process.env.COUNTERLURE_POLL_MS) || 30_000;
// Rechecks of a pasted transaction ID; the same variable shortens both for tests.
const CONFIRM_POLL_MS = Number(process.env.COUNTERLURE_POLL_MS) || 60_000;
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
  if (m.source === 'org-campaign') {
    return `${m.level === 'strong' ? 'STRONG MATCH' : 'possible match'} with ACTIVE CAMPAIGN TARGETING YOUR ORGANIZATION (${m.caseRef}, ${m.reporters} distinct staff reports) — please report this contact to your security team`;
  }
  const what = m.source === 'burn-notice'
    ? `burn notice: ${m.name}${m.aliases?.length ? ` (also: ${m.aliases.join(', ')})` : ''}`
    : `a face reported by ${m.reporters} independent sources`;
  return `${m.level === 'strong' ? 'STRONG POSSIBLE MATCH' : 'possible match'} with ${what}`;
}

// Model consent. Verified copies already on this computer are used first (see lib/models.js). If any
// are still missing, nothing is fetched until the person says so: they are shown where to get the
// files themselves, and asked. Without a terminal to ask on, only --fetch-models counts as yes.
const modelPolicy = { fetch: false, route: '' };
async function modelConsent(missing) {
  say(missingModelsText(missing, dirs.models));
  if (modelPolicy.fetch) { say('--fetch-models given: downloading.'); return true; }
  if (!process.stdin.isTTY) {
    say('No terminal to ask on, so nothing was downloaded. Import the files yourself, or rerun with --fetch-models.');
    return false;
  }
  const a = (await ask(`Download them now from GitHub over ${modelPolicy.route || 'the configured route'}? Type yes to proceed: `)).toLowerCase();
  if (a === 'yes' || a === 'y') return true;
  say('Nothing was downloaded. When you have the files: counterlure models import FILE-OR-FOLDER ...');
  return false;
}
const models = (net) => ensureModels(dirs.models, { ...net, log: say, consent: modelConsent });


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

// Reads a photo and finds its faces. Only JPEG, PNG and WebP are decoded (lib/sharp.js).
async function facesIn(file) {
  let input;
  try {
    input = fs.readFileSync(file);
  } catch (e) {
    throw new Error(`Could not read ${file}: ${e.code || e.message}`);
  }
  try {
    const faces = await faceprints(input, { modelsDir: dirs.models });
    return { input, faces, skipped: faces.skipped || 0 };
  } catch (e) {
    if (/unsupported image format/i.test(e.message)) throw new Error(`${file} is not a JPEG, PNG or WebP image.`);
    throw e;
  }
}

const isTooSmall = (box) => box.w < 64 || box.h < 64;

async function check(s, files, net, server, json) {
  await models(net);
  const results = [];
  for (const file of files) {
    let found;
    try {
      found = await facesIn(file);
    } catch (e) {
      results.push({ file, faces: [], error: e.message });
      continue;
    }
    const { faces, skipped } = found;
    if (!faces.length) { results.push({ file, faces: [], note: 'no face found' }); continue; }
    const usable = faces.filter((f) => !isTooSmall(f.box));
    let r = { results: [] };
    if (usable.length) {
      r = await call(server, 'check', { token: s.token, model: MODEL_VERSION, faces: usable.map((f) => f.embedding) }, net);
    }
    let uIdx = 0;
    results.push({
      file,
      ...(r.checksLeft !== undefined ? { checksLeft: r.checksLeft } : {}),
      ...(skipped ? { skipped } : {}),
      faces: faces.map((f) => (isTooSmall(f.box)
        ? { box: f.box, refused: `face too small (${f.box.w}x${f.box.h}px, minimum 64x64px)`, matches: [] }
        : { box: f.box, matches: dedupeOrgMatches(r.results?.[uIdx++] ?? []) })),
    });
  }
  if (json) return out(JSON.stringify(results, null, 2));
  let any = false;
  for (const r of results) {
    out(`\n${r.file}`);
    if (r.error) { out(`  Error: ${r.error}`); continue; }
    if (!r.faces.length) { out('  No face found. Use a clearer, front-facing photo.'); continue; }
    if (r.skipped) out(`  Note: ${r.skipped} additional face${r.skipped === 1 ? '' : 's'} skipped (at most 5 largest faces checked per photo).`);
    r.faces.forEach((f, i) => {
      const where = `face ${i + 1} at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)`;
      if (f.refused) return out(`  ${where}: refused — ${f.refused}`);
      if (!f.matches.length) return out(`  ${where}: no match`);
      any = true;
      out(`  ${where}:`);
      for (const m of f.matches) out(`    ${level(m)}`);
    });
    if (r.checksLeft !== undefined) out(`  (${r.checksLeft} checks left today)`);
  }
  out(any
    ? '\nA match is a lead, not an identification. Faces resemble each other. Corroborate through other\nmeans before acting, and never harass or publish anyone on the strength of this result.\nIf you have something new on this person, file it: counterlure report IMAGE --name ...'
    : '\nNo match is not a clearance: only faces already reported can match.');
}

async function report(file, o, s, net, route) {
  // Validate everything local before spending CPU on models and proof of work.
  const org = loadOrg();
  if (org) {
    say(`warning: This device is enrolled in ${org.orgName}. "counterlure report" submits a cropped face photo to the PUBLIC Counterlure intake, not your organization's private namespace. Use "counterlure org report IMAGE" for private organization reporting.`);
    if (!o.yes && !o['dry-run'] && !process.stdin.isTTY) {
      throw new Error(`This device is enrolled in ${org.orgName} and "counterlure report" goes to the public intake. Re-run with --yes to confirm, or use: counterlure org report IMAGE`);
    }
  }
  const asMember = Boolean(s) && !o.anon;
  const name = (o.name ?? (process.stdin.isTTY ? await ask('Name they gave you: ') : '')).trim();
  if (name.length < 2 || name.length > 120) throw new Error('--name is required: the name they gave you (2 to 120 characters).');
  const context = o.context || 'other';
  if (!CONTEXTS.includes(context)) throw new Error(`--context must be one of: ${CONTEXTS.join(', ')}`);
  const handle = o.handle?.trim() || undefined;
  if (handle && handle.length > 200) throw new Error('--handle is limited to 200 characters.');
  if (!o.yes && !o['dry-run'] && !process.stdin.isTTY) throw new Error('No terminal to confirm on. Re-run with --yes to make the statement non-interactively.');

  await models(net);
  const { input, faces } = await facesIn(file);
  if (!faces.length) throw new Error('No face found. Use a clearer, front-facing photo.');
  const list = () => faces.map((f, i) => `  ${i + 1}: at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)`).join('\n');
  const n = o.face === undefined ? 1 : Number(o.face);
  if (o.face === undefined && faces.length > 1) throw new Error(`${faces.length} faces in this photo. Pick one with --face N:\n${list()}`);
  if (!Number.isInteger(n) || n < 1 || n > faces.length) throw new Error(`--face must be between 1 and ${faces.length}:\n${list()}`);
  const face = faces[n - 1];
  if (isTooSmall(face.box)) throw new Error(`Face is too small (${face.box.w}x${face.box.h}px). Use a clearer photo where the face is at least 64x64px.`);
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
  const confirmPrompt = org
    ? 'Type "yes" to confirm sending to the PUBLIC Counterlure intake and make this statement: '
    : 'Type "yes" to make this statement and file the report: ';
  if (!o.yes && (await ask(confirmPrompt)).toLowerCase() !== 'yes') throw new Error('Not filed.');

  const args = { name, context, handle, photo: crop.jpeg.toString('base64'), attest: true };
  let r;
  if (asMember) r = await call(route.server, 'report', { ...args, token: s.token }, { ...net, padTo: REPORT_PAD });
  else r = await callWithWork(route.server, 'report', args, net, { padTo: REPORT_PAD });
  if (o.json) return out(JSON.stringify({ receipt: r.receipt, attributedTo: r.attributedTo }));
  out(`\nFiled. Receipt: ${r.receipt}`);
  out('Keep the receipt offline. It is the only way to withdraw this report, and this tool does not store it.');
  if (!r.attributedTo) out('Filed unattributed: nobody can contact you about it, and it adds weight only alongside other sources.');
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
    opts.autoDetect ? `  You get a payment address made for your account alone, valid for ${span(opts.addressMinutes * 60000)}.` : null,
    '',
    ...opts.chains.map((c, i) => `  ${i + 1}. ${c.label}  (--chain ${c.id})`),
    '',
  ].filter((l) => l !== null).join('\n'));
  const byId = (a) => opts.chains.find((c) => c.id.toLowerCase() === String(a).trim().toLowerCase());
  if (o.chain) {
    const hit = byId(o.chain);
    if (!hit) throw new Error(`--chain must be one of: ${opts.chains.map((c) => c.id).join(', ')}`);
    return hit.id;
  }
  for (let tries = 0; tries < 3; tries++) {
    const a = await ask(`Pay with (1-${opts.chains.length}): `);
    const hit = opts.chains[Number(a) - 1] || byId(a);
    if (hit) return hit.id;
    if (!process.stdin.isTTY) break;
  }
  throw new Error(`Choose a payment method: counterlure signup --chain ${opts.chains[0]?.id || 'ID'}`);
}

// "1 h 05 min", "12 min": what is left of an address's window.
function span(ms) {
  const m = Math.max(1, Math.ceil(ms / 60000));
  return m >= 60 ? `${Math.floor(m / 60)} h ${String(m % 60).padStart(2, '0')} min` : `${m} min`;
}

// When the order's address stops taking payments, on this computer's clock. The server says what its
// own clock read (serverNow), so a computer whose clock is off still counts down correctly.
const deadline = (st) => Date.now() + (Date.parse(st.expiresAt) - Date.parse(st.serverNow || new Date().toISOString()));

function showOrder(st) {
  if (!st.autoDetect) {
    return say([
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
    ].join('\n'));
  }
  const end = deadline(st);
  say([
    '',
    'Step 3 of 3: pay',
    `  Send           ${st.amount} ${st.symbol}`,
    `  on             ${st.chainLabel}`,
    `  to             ${st.address}`,
    `  send before    ${when(end)}  (${span(end - Date.now())} from now)`,
    '',
    '  This address was made for your account alone, so the payment is found by itself: no',
    '  transaction ID needed. Send at least the amount, from your own wallet or an exchange.',
    `  Do not send to this address after ${when(end)}. After that, run counterlure signup again`,
    '  for a new address.',
    '',
    indent(st.qrText),
    '',
  ].join('\n'));
}

// Waits for a payment to the member's own address to be found, asking the server every 30 s.
// Returns the next state (done, or chain when the address expired with nothing sent), or null to stop.
async function awaitPayment(st, sign, server, net) {
  const end = deadline(st);
  let warned = false;
  let seen = '';
  say('Waiting for the payment to arrive. This can take a few minutes after it is sent. Ctrl-C stops;');
  say(`${resumeHint.replace('Run: ', 'later run ')}`);
  // Up to the end of the window plus 3 hours for a payment already seen to confirm.
  for (const stop = end + 3 * 3600_000; Date.now() < stop;) {
    await sleep(POLL_MS);
    let r;
    try {
      r = await call(server, 'signup_state', { signupToken: sign.signupToken }, net);
    } catch (e) {
      if (e instanceof Refused) throw e;
      say(`Could not reach the server (${e.message}). Trying again.`);
      continue;
    }
    // The window ended while waiting: the server is back at choosing a coin. Name the address here,
    // once, so the generic notice in the main loop is not repeated.
    if (r.step === 'chain') {
      say(`\nThe address ${st.address} has expired. Do NOT send to it.`);
      return { ...r, lastOrderExpired: false };
    }
    if (r.step !== 'pay') return r;
    if (r.status === 'review') return r;
    if (r.detected) {
      const now = `${r.detected.amount} ${r.detected.chainLabel}`;
      if (now !== seen) say(`Payment seen: ${now}. Waiting for it to confirm on the network.`);
      seen = now;
      continue;
    }
    const left = end - Date.now();
    if (left <= 0 || r.addressExpired || !r.address) {
      say(`\nThe address ${st.address} has expired. Do NOT send to it.`);
      return r;
    }
    if (left < 10 * 60000 && !warned) {
      warned = true;
      say(`Less than ${span(left)} left on this address. If your payment is not on its way, do not send it now: wait, and run counterlure signup again for a new address.`);
    }
  }
  say(`Nothing confirmed yet. ${resumeHint}`);
  return null;
}

const resumeHint = 'Run: counterlure signup   (it picks up where it stopped)';

function reviewed(r) {
  say(`\nThe payment needs a person to look at it${r.reason ? ` (${r.reason})` : ''}. That usually takes under a day.\n${resumeHint}\nTo add a note, open the website's inbox once your account is open, or wait for the review.`);
  return null;
}

// Payment: ask for the transaction ID, then check until it is confirmed or needs a person.
async function settle(st, sign, server, net) {
  let txHash = st.txHash || sign.txHash;
  if (!txHash && st.autoDetect) {
    if (st.status === 'review') return reviewed(st);
    if (st.detected) {
      say(`\nPayment seen: ${st.detected.amount} ${st.detected.chainLabel}. Waiting for it to confirm on the network.`);
      return awaitPayment(st, sign, server, net);
    }
    if (!st.address) {
      // Its window ended: the server never hands it out again.
      say('\nThat payment address has expired. Do NOT send to it. Choose again for a new one.');
      return { step: 'chain', lastOrderExpired: true };
    }
    showOrder(st);
    const a = await prompt('Once sent, press Enter to wait for it (or paste the transaction ID, or type q to finish later): ');
    if (a === null || a.trim().toLowerCase() === 'q') { say(`\nNothing to check yet. ${resumeHint}`); return null; }
    if (!a.trim()) return awaitPayment(st, sign, server, net);
    txHash = a.trim();
    saveSignup({ ...sign, txHash });
  }
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
    if (r.status === 'review') return reviewed(r);
    if (r.state === 'mismatch') {
      say(`\n${r.reason || 'That transaction does not match this order.'}`);
      saveSignup({ ...sign, txHash: undefined });
      txHash = await ask('Another transaction ID (or Enter to finish later): ');
      if (!txHash) { say(resumeHint); return null; }
      saveSignup({ ...sign, txHash });
      continue;
    }
    say(`${r.reason || 'Not confirmed yet.'} Checking again in a minute. Ctrl-C stops; ${resumeHint.replace('Run: ', 'later run ')}`);
    await sleep(CONFIRM_POLL_MS);
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
  out(`\nSigned in as ${sess.username} until ${when(sess.expiresAt)}.`);
  out('Next: counterlure check PHOTO, counterlure inbox, or counterlure send "a message to the team".');
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
      if (st.lastOrderExpired) say('\nYour last payment address expired before a payment reached it. Do NOT send to it any more.');
      const chain = await pickChain(o, server, net);
      st = await call(server, 'pay_order', { signupToken: sign.signupToken, chain }, net);
      saveSignup({ ...sign, txHash: undefined });
      sign = loadSignup();
    } else if (st.step === 'pay') {
      const r = await settle(st, sign, server, net);
      if (!r) return;
      if (r.step === 'pay' && r.status === 'review') return reviewed(r);
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
    out('No messages yet. Write to the team with: counterlure send "your message"');
    return;
  }
  if (shown.length < msgs.length) out(`(${msgs.length - shown.length} earlier messages; --all shows them)\n`);
  for (const m of shown) {
    const who = m.from === 'admin' ? 'Counterlure' : 'You';
    const fresh = m.from === 'admin' && !m.readAt ? '  [new]' : '';
    out(`--- ${who}, ${when(m.createdAt)}${fresh}`);
    if (m.subject) out(`Subject: ${m.subject}`);
    if (m.caseId) out('About one of your reports.');
    out(`${m.body}\n`);
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

// ------------------------------------------------------------------ enterprise (org CLI)

async function orgCall(server, op, args, net, orgName) {
  try {
    return await call(server, op, args, net);
  } catch (e) {
    if (e instanceof Refused) {
      const code = e.reply?.code;
      if (code === 'org_suspended') {
        throw new Error(`Organization suspended: ${e.message}`);
      }
      if (code === 'org_unpaid') {
        throw new Error(`Organization license inactive: ${e.message}`);
      }
      if (code === 'org_revoked' || (code === 'org_not_enrolled' && args?.orgToken)) {
        throw new Error(`Device enrollment revoked or no longer active${orgName ? ` for ${orgName}` : ''}. Ask your security team for a new one-time code and run: counterlure org enroll CODE --replace`);
      }
    }
    throw e;
  }
}

function dedupeOrgMatches(matches) {
  const out = [];
  const seenRefs = new Set();
  const hasOrgCampaign = (matches || []).some((m) => m.source === 'org-campaign');
  for (const m of matches || []) {
    if (m.source === 'org-campaign') {
      const ref = m.caseRef || JSON.stringify(m);
      if (seenRefs.has(ref)) continue;
      seenRefs.add(ref);
      out.push(m);
      continue;
    }
    // If an org's own promoted case was also published to the global pool, avoid listing it twice.
    if (hasOrgCampaign && m.source === 'reports' && m.caseRef && seenRefs.has(m.caseRef)) continue;
    out.push(m);
  }
  return out;
}

async function orgCheckCmd(org, files, net, server, json) {
  if (!files.length) throw new Error('Usage: counterlure org check IMAGE [IMAGE...]');
  await models(net);
  const results = [];
  for (const file of files) {
    let found;
    try {
      found = await facesIn(file);
    } catch (e) {
      results.push({ file, faces: [], error: e.message });
      continue;
    }
    const { faces, skipped } = found;
    if (!faces.length) { results.push({ file, faces: [], note: 'no face found' }); continue; }
    const usable = faces.filter((f) => !isTooSmall(f.box));
    let r = { results: [], orgName: org.orgName };
    if (usable.length) {
      r = await orgCall(server, 'org_check', { orgToken: org.orgToken, model: MODEL_VERSION, faces: usable.map((f) => f.embedding) }, net, org.orgName);
    }
    let uIdx = 0;
    results.push({
      file,
      orgName: r.orgName || org.orgName,
      ...(skipped ? { skipped } : {}),
      faces: faces.map((f) => (isTooSmall(f.box)
        ? { box: f.box, refused: `face too small (${f.box.w}x${f.box.h}px, minimum 64x64px)`, matches: [] }
        : { box: f.box, matches: dedupeOrgMatches(r.results?.[uIdx++] ?? []) })),
    });
  }
  if (json) return out(JSON.stringify(results, null, 2));
  let any = false;
  for (const r of results) {
    out(`\n${r.file}  (checked against ${org.orgName} alerts + global pool)`);
    if (r.error) { out(`  Error: ${r.error}`); continue; }
    if (!r.faces.length) { out('  No face found. Use a clearer, front-facing photo.'); continue; }
    if (r.skipped) out(`  Note: ${r.skipped} additional face${r.skipped === 1 ? '' : 's'} skipped (at most 5 largest faces checked per photo).`);
    r.faces.forEach((f, i) => {
      const where = `face ${i + 1} at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)`;
      if (f.refused) return out(`  ${where}: refused — ${f.refused}`);
      if (!f.matches.length) return out(`  ${where}: no match`);
      any = true;
      out(`  ${where}:`);
      for (const m of f.matches) out(`    ${level(m)}`);
    });
  }
  out(any
    ? '\nIf this contact matches an active campaign targeting your organization, please alert your security team.'
    : '\nNo match in global pool or active org alerts. To log this contact anonymously inside your org namespace: counterlure org report IMAGE');
}

async function orgReportCmd(org, file, o, net, route) {
  if (!file) throw new Error('Usage: counterlure org report IMAGE [--context C] [--face N] [--dry-run] [--yes]');
  if (o.anon) throw new Error('--anon cannot be used with org report. Organization reports always use your anonymous device token; for a public unattributed report, use: counterlure report --anon IMAGE --name ...');
  if (o['save-crop']) throw new Error('--save-crop is not supported for org report because no image crop is created or sent (only a 128-value face fingerprint).');
  const context = o.context || 'other';
  if (!CONTEXTS.includes(context)) throw new Error(`--context must be one of: ${CONTEXTS.join(', ')}`);
  if (!o.yes && !o['dry-run'] && !process.stdin.isTTY) throw new Error('No terminal to confirm on. Re-run with --yes to confirm non-interactively.');

  await models(net);
  const { faces } = await facesIn(file);
  if (!faces.length) throw new Error('No face found. Use a clearer, front-facing photo.');
  const list = () => faces.map((f, i) => `  ${i + 1}: at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)`).join('\n');
  const n = o.face === undefined ? 1 : Number(o.face);
  if (o.face === undefined && faces.length > 1) throw new Error(`${faces.length} faces in this photo. Pick one with --face N:\n${list()}`);
  if (!Number.isInteger(n) || n < 1 || n > faces.length) throw new Error(`--face must be between 1 and ${faces.length}:\n${list()}`);
  const face = faces[n - 1];
  if (isTooSmall(face.box)) throw new Error(`Face is too small (${face.box.w}x${face.box.h}px). Use a clearer photo where the face is at least 64x64px.`);

  say([
    '',
    'Organization Report',
    `  Organization ${org.orgName}`,
    `  Subject      face ${n} of ${faces.length} in ${path.basename(file)} (${face.box.w}x${face.box.h}px)`,
    `  Context      ${context}`,
    `  Leaves here  128-value face fingerprint, model version (${MODEL_VERSION}), context (${context}), reporting attestation, and your anonymous device token (no photo, no name, no employee identity)`,
    `  Privacy      Isolated to ${org.orgName} until ${org.threshold || 3} distinct staff report the same face; a Counterlure reviewer decides whether an escalated case joins the wider pool`,
    `  Route        ${route.label}`,
    '',
    'Statement',
    ...STATEMENT.map((l) => `  ${l}`),
    '',
  ].join('\n'));
  if (o['dry-run']) return say('Dry run: nothing sent.');
  if (!o.yes && (await ask('Type "yes" to make this statement and file the report: ')).toLowerCase() !== 'yes') throw new Error('Not filed.');

  const r = await orgCall(route.server, 'org_report', { orgToken: org.orgToken, model: MODEL_VERSION, face: face.embedding, context, attest: true }, net, org.orgName);
  if (o.json) return out(JSON.stringify({ receipt: r.receipt, orgName: r.orgName }));
  out(`\nFiled anonymously inside ${r.orgName}. Receipt: ${r.receipt}`);
  out('No photo, name, or employee identity was sent. Check for private alerts anytime with: counterlure org inbox');
}

async function orgInboxCmd(org, o, net, server) {
  const r = await orgCall(server, 'org_inbox', { orgToken: org.orgToken, markRead: true }, net, org.orgName);
  if (o.json) return out(JSON.stringify({ messages: r.messages || [], unread: r.unread ?? 0 }, null, 2));
  if (!r.messages.length) return out(`No private alerts for your anonymous ${org.orgName} device.`);
  const msgs = [...r.messages].reverse();
  const shown = o.all ? msgs : msgs.slice(-10);
  for (const m of shown) {
    const fresh = !m.readAt ? '  [NEW]' : '';
    out(`--- Counterlure (${org.orgName}), ${when(m.createdAt)}${fresh}`);
    if (m.subject) out(`Subject: ${m.subject}`);
    out(`${m.body}\n`);
  }
}

async function orgStatusCmd(org, o, net, server) {
  const r = await orgCall(server, 'org_status', { orgToken: org.orgToken }, net, org.orgName);
  if (o.json) {
    const payload = {
      orgName: r.orgName,
      underAttack: Boolean(r.underAttack),
      severity: r.severity,
      activeCampaigns: r.activeCampaigns ?? 0,
      unread: r.unread ?? 0,
    };
    if (r.countsFrom) payload.countsFrom = r.countsFrom;
    return out(JSON.stringify(payload, null, 2));
  }
  out(`Organization: ${r.orgName} (anonymous device enrolled)`);
  out(`Threat status: ${r.underAttack ? `UNDER COORDINATED TARGETING (${String(r.severity).toUpperCase()}, ${r.activeCampaigns} active campaign${r.activeCampaigns === 1 ? '' : 's'})` : 'All clear (no active coordinated campaigns)'}`);
  if (r.unread) out(`${r.unread} unread private alert${r.unread === 1 ? '' : 's'}. Run: counterlure org inbox`);
}

async function orgCmd(rest, o, server, net, route) {
  const [sub, ...args] = rest;
  if (!sub || sub === 'help') return process.stdout.write(HELP);
  if (sub === 'enroll') {
    const existing = loadOrg();
    if (existing && !o.replace) {
      throw new Error(`Already enrolled in ${existing.orgName}. Run "counterlure org leave" first, or pass --replace to replace this device's enrollment.`);
    }
    const code = args[0] || await ask('Organization enrollment code: ');
    if (!code) throw new Error('Usage: counterlure org enroll CODE [--replace]');
    const r = await call(server, 'org_enroll', { code }, net);
    saveOrg({ server, orgToken: r.deviceToken, orgName: r.orgName, threshold: r.threshold });
    if (o.json) return out(JSON.stringify({ enrolled: true, orgName: r.orgName, threshold: r.threshold }));
    out(`Enrolled anonymously in ${r.orgName}.`);
    out('Your device holds an anonymous random token — no employee name, email, or photo is ever shared with your employer.');
    out('Next: counterlure org check PHOTO   or   counterlure org report PHOTO');
    return;
  }
  if (sub === 'leave') {
    const org = loadOrg();
    if (!org) throw new Error('Not enrolled in an organization.');
    let r;
    try {
      r = await call(server, 'org_leave', { orgToken: org.orgToken, withdraw: Boolean(o.withdraw) }, net);
    } catch (e) {
      if (e instanceof Refused && e.reply?.code === 'org_not_enrolled') {
        forgetOrg();
        out('This device was no longer enrolled on the server. Local organization credential deleted.');
        return;
      }
      throw new Error(`Could not reach the server to leave ${org.orgName} (${e.message}). Local enrollment file was kept so you can retry.`);
    }
    forgetOrg();
    const extra = r?.withdrawn ? ` ${r.withdrawn} report${r.withdrawn === 1 ? '' : 's'} withdrawn.` : '';
    out(`Left ${org.orgName} and deleted local anonymous organization credential.${extra}`);
    return;
  }
  const org = loadOrg();
  if (!org) throw new Error('Not enrolled in an organization. Run: counterlure org enroll CODE');
  if (sub === 'status') return orgStatusCmd(org, o, net, server);
  if (sub === 'check') return orgCheckCmd(org, args, net, server, o.json);
  if (sub === 'report') return orgReportCmd(org, args[0], o, net, route);
  if (sub === 'inbox') return orgInboxCmd(org, o, net, server);
  if (sub === 'withdraw') {
    if (args.length !== 1) throw new Error('Usage: counterlure org withdraw RECEIPT');
    const r = await orgCall(server, 'org_withdraw', { orgToken: org.orgToken, receipt: args[0] }, net, org.orgName);
    if (o.json) return out(JSON.stringify({ withdrawn: Boolean(r.withdrawn) }));
    if (!r.withdrawn) throw new Error('The server did not confirm withdrawal.');
    out('Withdrawn. Your organization report has been removed.');
    return;
  }
  throw new Error(`Unknown org command "${sub}". Run: counterlure --help`);
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
      replace: { type: 'boolean' }, withdraw: { type: 'boolean' }, 'fetch-models': { type: 'boolean' }, download: { type: 'boolean' },
    },
  });
  const [cmd, ...rest] = positionals;
  if (o.version) return out(VERSION);
  if (o.help || !cmd) return process.stdout.write(HELP);

  if (cmd === 'key') {
    out([
      'Pinned Counterlure CLI key fingerprint:',
      `  ${SERVER_FINGERPRINT.toUpperCase().replace(/(.{4})/g, '$1 ').trim()}`,
      'Onion service this tool talks to by default:',
      `  ${new URL(ONION).hostname}`,
      `Verify both against ${SITE}/#cli and ${SITE}/api/cli/key`,
    ].join('\n'));
    return;
  }

  modelPolicy.fetch = Boolean(o['fetch-models']);
  if (cmd === 'models' && !o.download) {
    const [sub, ...paths] = rest;
    if (sub === 'import') {
      if (!paths.length) throw new Error('Usage: counterlure models import FILE-OR-FOLDER ...');
      const { imported, rejected } = await importModels(dirs.models, paths);
      for (const i of imported) out(`Imported ${i.file}  (from ${i.from}, SHA-256 verified)`);
      for (const r of rejected) say(`Skipped ${r.file}: ${r.why}`);
    } else if (sub && sub !== 'status') {
      throw new Error(`Unknown models command "${sub}". Run: counterlure --help`);
    } else {
      for (const x of await findLocalModels(dirs.models)) say(`Using the verified copy of ${x.file} found at ${x.from}`);
    }
    const st = await modelStatus(dirs.models);
    if (o.json) return out(JSON.stringify({ dir: dirs.models, models: st.map((m) => ({ file: m.file, sha256: m.sha256, installed: m.installed })) }));
    for (const m of st) out(`  ${m.installed ? 'verified' : 'missing '}  ${m.file}`);
    const missing = st.filter((m) => !m.installed);
    if (missing.length) {
      say('');
      say(missingModelsText(missing, dirs.models));
      say('  To fetch them with this tool instead: counterlure models --download');
      process.exitCode = 1;
    } else out(`Both models verified in ${dirs.models}`);
    return;
  }

  // Everything below talks to the network. Nothing is sent until the route is settled.
  const route = await resolveRoute(o);
  const net = { proxy: route.proxy };
  const server = route.server;
  trustedKey = await serverFingerprint();
  if (route.custom || !route.onion) say(`note: ${route.label}`);
  modelPolicy.route = route.label;

  if (cmd === 'models') {
    await models(net);
    out(`Models verified in ${dirs.models}`);
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
    out(`Signed in as ${r.username} until ${when(r.expiresAt)}.`);
    if (r.recoveryLeft !== undefined) out(`You used a recovery code: ${r.recoveryLeft} left. Re-enrol your authenticator on the website.`);
    return;
  }
  if (cmd === 'withdraw') {
    if (rest.length !== 1) throw new Error('Usage: counterlure withdraw RECEIPT');
    if (String(rest[0]).toUpperCase().startsWith('CLO-')) {
      const org = loadOrg();
      if (!org) throw new Error('Not enrolled in an organization. Run: counterlure org enroll <code>');
      const r = await orgCall(server, 'org_withdraw', { orgToken: org.orgToken, receipt: rest[0] }, net, org.orgName);
      if (o.json) return out(JSON.stringify({ withdrawn: Boolean(r.withdrawn) }));
      if (!r.withdrawn) throw new Error('The server did not confirm withdrawal.');
      out('Withdrawn. Your organization report has been removed.');
      return;
    }
    const r = await call(server, 'withdraw', { receipt: rest[0] }, net);
    if (o.json) return out(JSON.stringify({ withdrawn: Boolean(r.withdrawn) }));
    if (!r.withdrawn) throw new Error('The server did not confirm withdrawal.');
    out('Withdrawn. The stored face crop and template have been destroyed.');
    return;
  }
  if (cmd === 'org') return orgCmd(rest, o, server, net, route);

  const s = loadSession();
  const org = loadOrg();
  if (cmd === 'report') {
    if (rest.length !== 1) throw new Error('Usage: counterlure report IMAGE --name NAME [--context C] [--handle H]');
    return report(rest[0], o, s, net, route);
  }
  if (cmd === 'logout') {
    const sign = loadSignup();
    if (s || sign) await call(server, 'logout', { token: s?.token, signupToken: sign?.signupToken }, net).catch(() => {});
    forgetSession();
    forgetSignup();
    out(sign && !s ? 'Signup abandoned. Its saved state was deleted here.' : 'Signed out. The saved session was deleted.');
    return;
  }
  if (!s && org && (cmd === 'check' || cmd === 'inbox' || cmd === 'whoami')) {
    if (cmd === 'check') return orgCheckCmd(org, rest, net, server, o.json);
    if (cmd === 'inbox') return orgInboxCmd(org, o, net, server);
    if (cmd === 'whoami') return orgStatusCmd(org, o, net, server);
  }
  if (!s) {
    throw new Error(loadSignup()
      ? 'Your signup is not finished. Run: counterlure signup'
      : 'Not signed in. Run: counterlure login   (no account yet? counterlure signup, or counterlure org enroll CODE)');
  }
  if (cmd === 'whoami') {
    const r = await call(server, 'whoami', { token: s.token }, net);
    out(`${r.username} (session valid until ${when(s.expiresAt)})`);
    if (r.unread) out(`${r.unread} unread message${r.unread === 1 ? '' : 's'} from the team. Run: counterlure inbox`);
    return;
  }
  if (cmd === 'inbox') {
    const r = await call(server, 'inbox', { token: s.token, markRead: true }, net);
    if (o.json) return out(JSON.stringify(r, null, 2));
    return showThread(r, o.all);
  }
  if (cmd === 'send') {
    const body = (await compose(rest)).trim();
    if (!body) throw new Error('Nothing to send. Usage: counterlure send "your message" [--subject S]');
    if (body.length > 4000) throw new Error(`Messages are 4000 characters at most (this one is ${body.length}).`);
    const r = await call(server, 'send', { token: s.token, subject: o.subject, body }, net);
    if (o.json) return out(JSON.stringify(r));
    out('Sent to the Counterlure team. Replies arrive in: counterlure inbox');
    return;
  }
  if (cmd === 'check') {
    if (!rest.length) throw new Error('Usage: counterlure check IMAGE [IMAGE...]');
    return check(s, rest, net, server, o.json);
  }
  throw new Error(`Unknown command "${cmd}". Run: counterlure --help`);
}

main().catch((e) => { say(`error: ${e.message}`); process.exitCode = 1; });
