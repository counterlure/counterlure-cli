#!/usr/bin/env node
// counterlure: check a photo against faces reported to Counterlure, without the photo leaving your computer.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { MODEL_VERSION, faceprints } from '../lib/faceprint.js';
import { ensureModels } from '../lib/models.js';
import { resolveProxy } from '../lib/net.js';
import { call } from '../lib/proto.js';
import { SERVER_FINGERPRINT } from '../lib/server-key.js';

const VERSION = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8')).version;
const DEFAULT_SERVER = 'https://www.counterlure.com';

const HELP = `counterlure ${VERSION}: check photos against faces reported to Counterlure

Your photo is analysed on this computer. Only a face fingerprint (128 numbers that cannot be
turned back into a photo of good quality) is sent, OpenPGP-encrypted to Counterlure's pinned key.

Usage:
  counterlure login [--user NAME]     sign in with your username and authenticator-app code
  counterlure check IMAGE [IMAGE...]  check the faces in one or more photos
  counterlure whoami                  show who is signed in
  counterlure logout                  sign out and delete the saved sign-in
  counterlure models                  download and verify the face models now
  counterlure key                     show the pinned server key fingerprint

Options:
  --tor             send everything through Tor (needs Tor running on 127.0.0.1:9050)
  --proxy URL       socks5h://host:port or http://host:port (also COUNTERLURE_PROXY)
  --json            machine-readable output for check
  --server URL      a different Counterlure server (also COUNTERLURE_URL)
  -h, --help        this help
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
    : `a face reported by ${m.reporters} independent people`;
  return `${m.level === 'strong' ? 'STRONG POSSIBLE MATCH' : 'possible match'} with ${what}`;
}

async function main() {
  const { values: o, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      tor: { type: 'boolean' }, proxy: { type: 'string' }, json: { type: 'boolean' },
      server: { type: 'string' }, user: { type: 'string' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean' },
    },
  });
  const [cmd, ...rest] = positionals;
  if (o.version) return console.log(VERSION);
  if (o.help || !cmd) return process.stdout.write(HELP);

  const server = o.server || process.env.COUNTERLURE_URL || DEFAULT_SERVER;
  if (server !== DEFAULT_SERVER) process.stderr.write(`note: using server ${server}\n`);
  const proxy = resolveProxy(o.tor ? 'tor' : o.proxy);
  const net = { proxy };

  if (cmd === 'key') {
    console.log(`Pinned Counterlure CLI key fingerprint:\n  ${SERVER_FINGERPRINT.toUpperCase().replace(/(.{4})/g, '$1 ').trim()}\nCompare with ${DEFAULT_SERVER}/#cli and ${DEFAULT_SERVER}/api/cli/key`);
    return;
  }

  if (cmd === 'models') {
    await ensureModels(dirs.models, { ...net, log: (s) => process.stderr.write(`${s}\n`) });
    console.log(`Models verified in ${dirs.models}`);
    return;
  }

  if (cmd === 'login') {
    const username = o.user || await prompt('Username: ');
    const code = await prompt('Authenticator code: ', { hide: true });
    const r = await call(server, 'login', { username, code }, net);
    saveSession({ server, token: r.token, username: r.username, expiresAt: r.expiresAt });
    console.log(`Signed in as ${r.username} until ${new Date(r.expiresAt).toLocaleString()}.`);
    if (r.recoveryLeft !== undefined) console.log(`You used a recovery code: ${r.recoveryLeft} left. Set up your authenticator again on the website.`);
    return;
  }

  const s = loadSession();
  if (cmd === 'logout') {
    if (s) await call(s.server, 'logout', { token: s.token }, net).catch(() => {});
    forgetSession();
    console.log('Signed out. The saved sign-in was deleted.');
    return;
  }
  if (!s) throw new Error('Not signed in. Run: counterlure login');

  if (cmd === 'whoami') {
    const r = await call(s.server, 'whoami', { token: s.token }, net);
    console.log(`${r.username} (sign-in valid until ${new Date(s.expiresAt).toLocaleString()})`);
    return;
  }

  if (cmd === 'check') {
    if (!rest.length) throw new Error('Usage: counterlure check IMAGE [IMAGE...]');
    await ensureModels(dirs.models, { ...net, log: (m) => process.stderr.write(`${m}\n`) });
    const report = [];
    for (const file of rest) {
      const faces = await faceprints(fs.readFileSync(file), { modelsDir: dirs.models });
      if (!faces.length) { report.push({ file, faces: [], note: 'no face found' }); continue; }
      const r = await call(s.server, 'check', { token: s.token, model: MODEL_VERSION, faces: faces.map((f) => f.embedding) }, net);
      report.push({ file, checksLeft: r.checksLeft, faces: faces.map((f, i) => ({ box: f.box, small: f.box.w < 64, matches: r.results[i] })) });
    }
    if (o.json) return console.log(JSON.stringify(report, null, 2));
    let any = false;
    for (const r of report) {
      console.log(`\n${r.file}`);
      if (!r.faces.length) { console.log('  No face found. Use a clearer, front-facing photo.'); continue; }
      r.faces.forEach((f, i) => {
        const where = `face ${i + 1} at ${f.box.x},${f.box.y} (${f.box.w}x${f.box.h}px)${f.small ? ', small: less reliable' : ''}`;
        if (!f.matches.length) return console.log(`  ${where}: no match`);
        any = true;
        console.log(`  ${where}:`);
        for (const m of f.matches) console.log(`    ${level(m)}`);
      });
      if (r.checksLeft !== undefined) console.log(`  (${r.checksLeft} checks left today)`);
    }
    console.log(any
      ? '\nA match is a lead, not proof. Faces can look alike. Verify the person through other means before acting,\nand never harass or publish anyone based on this result. Report new information at https://www.counterlure.com.'
      : '\nNo match does not mean a person is safe: only reported faces can match.');
    return;
  }
  throw new Error(`Unknown command "${cmd}". Run: counterlure --help`);
}

main().catch((e) => { process.stderr.write(`error: ${e.message}\n`); process.exit(1); });
