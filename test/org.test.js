// Enterprise CLI tests (C1-C10): runs bin/counterlure.js against an in-process OpenPGP mock server.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import * as openpgp from 'openpgp';

const execFileAsync = promisify(execFile);
const BIN = fileURLToPath(new URL('../bin/counterlure.js', import.meta.url));

let tmpDir, keyFile, srvKey, srvFp, server, port, calls = [], handler;

async function runCli(args, { home, stdin, env = {} } = {}) {
  const childEnv = {
    ...process.env,
    COUNTERLURE_HOME: home,
    COUNTERLURE_SERVER_KEY: keyFile,
    ...env,
  };
  return new Promise((resolve) => {
    const p = execFile(process.execPath, [BIN, '--server', `http://127.0.0.1:${port}`, ...args], { env: childEnv }, (err, stdout, stderr) => {
      resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr });
    });
    if (stdin !== undefined) {
      p.stdin.end(stdin);
    } else {
      p.stdin.end();
    }
  });
}

function makeHome(orgData = null) {
  const dir = fs.mkdtempSync(path.join(tmpDir, 'home-'));
  if (orgData) {
    fs.writeFileSync(path.join(dir, 'org.json'), JSON.stringify({ key: srvFp, ...orgData }));
  }
  return dir;
}

before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cl-cli-org-'));
  const gen = await openpgp.generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'test-server' }], format: 'object',
  });
  srvKey = gen.privateKey;
  srvFp = srvKey.getFingerprint().toLowerCase();
  keyFile = path.join(tmpDir, 'server.asc');
  fs.writeFileSync(keyFile, gen.publicKey.armor());

  server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    const { data } = await openpgp.decrypt({
      message: await openpgp.readMessage({ armoredMessage: body }),
      decryptionKeys: srvKey,
    });
    const msg = JSON.parse(data);
    calls.push({ op: msg.op, args: msg.args });
    const out = handler ? await handler(msg.op, msg.args) : { ok: true };
    const reply = { protocol: msg.protocol, ts: Date.now(), echo: msg.nonce, ...out, pad: 'x'.repeat(2048) };
    const replyKey = await openpgp.readKey({ armoredKey: msg.replyKey });
    const signed = await openpgp.sign({
      message: await openpgp.createMessage({ text: JSON.stringify(reply) }),
      signingKeys: srvKey, format: 'object',
    });
    const armored = await openpgp.encrypt({ message: signed, encryptionKeys: replyKey });
    res.writeHead(200, { 'content-type': 'application/pgp-encrypted' });
    res.end(armored);
  });
  await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
  port = server.address().port;
});

after(async () => {
  server?.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('C1: org report refuses --anon and --save-crop instead of silently ignoring them', async () => {
  calls = [];
  const home = makeHome({ orgToken: 'org_testtoken12345678901234567890', orgName: 'Acme Corp', threshold: 3 });
  const rAnon = await runCli(['org', 'report', 'photo.jpg', '--anon', '--yes'], { home });
  assert.notEqual(rAnon.code, 0);
  assert.match(rAnon.stderr, /--anon/);
  assert.equal(calls.length, 0, 'nothing sent when --anon refused');

  const rCrop = await runCli(['org', 'report', 'photo.jpg', '--save-crop', 'out.jpg', '--yes'], { home });
  assert.notEqual(rCrop.code, 0);
  assert.match(rCrop.stderr, /--save-crop/);
  assert.equal(calls.length, 0, 'nothing sent when --save-crop refused');
});

test('C2: org enroll stops when already enrolled unless --replace is given', async () => {
  calls = [];
  handler = async (op) => {
    if (op === 'org_enroll') return { ok: true, deviceToken: 'org_newtoken12345678901234567890', orgName: 'Beta Corp', threshold: 3 };
    return { ok: true };
  };
  const home = makeHome({ orgToken: 'org_oldtoken12345678901234567890', orgName: 'Acme Corp', threshold: 3 });
  const r1 = await runCli(['org', 'enroll', 'CLORG-AAAA-BBBB-CCCC-DDDD'], { home });
  assert.notEqual(r1.code, 0);
  assert.match(r1.stderr, /Already enrolled in Acme Corp/);
  assert.match(r1.stderr, /--replace/);
  assert.equal(calls.length, 0, 'no server call without --replace');

  const r2 = await runCli(['org', 'enroll', 'CLORG-AAAA-BBBB-CCCC-DDDD', '--replace'], { home });
  assert.equal(r2.code, 0, r2.stderr);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].op, 'org_enroll');
  const saved = JSON.parse(fs.readFileSync(path.join(home, 'org.json'), 'utf8'));
  assert.equal(saved.orgName, 'Beta Corp');
  assert.equal(saved.orgToken, 'org_newtoken12345678901234567890');
});

test('C3: org leave calls server org_leave before removing local file, and keeps file if server is unreachable', async () => {
  calls = [];
  handler = async (op, args) => {
    if (op === 'org_leave') return { ok: true, left: true, withdrawn: args.withdraw ? 2 : 0 };
    return { ok: true };
  };
  const home = makeHome({ orgToken: 'org_leavetoken123456789012345678', orgName: 'Acme Corp', threshold: 3 });

  // Unreachable server: local file must be kept
  const badRes = await new Promise((resolve) => {
    const p = execFile(process.execPath, [BIN, '--server', 'http://127.0.0.1:1', 'org', 'leave'], {
      env: { ...process.env, COUNTERLURE_HOME: home, COUNTERLURE_SERVER_KEY: keyFile },
    }, (err, stdout, stderr) => resolve({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
    p.stdin.end();
  });
  assert.notEqual(badRes.code, 0);
  assert.match(badRes.stderr, /Local enrollment file was kept/i);
  assert.ok(fs.existsSync(path.join(home, 'org.json')), 'org.json kept when server unreachable');

  // Reachable server: calls org_leave then deletes local file
  const okRes = await runCli(['org', 'leave', '--withdraw'], { home });
  assert.equal(okRes.code, 0, okRes.stderr);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].op, 'org_leave');
  assert.equal(calls[0].args.withdraw, true);
  assert.match(okRes.stdout, /2 reports withdrawn/);
  assert.equal(fs.existsSync(path.join(home, 'org.json')), false, 'org.json removed after server confirmed leave');
});

test('C4: org withdraw calls server and reports the true result (success or refusal)', async () => {
  calls = [];
  const home = makeHome({ orgToken: 'org_wdtoken12345678901234567890', orgName: 'Acme Corp', threshold: 3 });

  handler = async () => ({ ok: false, error: 'No report of yours has that receipt.' });
  const rFail = await runCli(['org', 'withdraw', 'CLO-1111-2222-3333-4444'], { home });
  assert.notEqual(rFail.code, 0);
  assert.match(rFail.stderr, /No report of yours has that receipt/);
  assert.equal(calls[0].op, 'org_withdraw');

  handler = async () => ({ ok: true, withdrawn: false });
  const rFalse = await runCli(['org', 'withdraw', 'CLO-1111-2222-3333-4444'], { home });
  assert.notEqual(rFalse.code, 0);
  assert.match(rFalse.stderr, /did not confirm withdrawal/);

  handler = async () => ({ ok: true, withdrawn: true });
  const rOk = await runCli(['org', 'withdraw', 'CLO-1111-2222-3333-4444', '--json'], { home });
  assert.equal(rOk.code, 0, rOk.stderr);
  assert.deepEqual(JSON.parse(rOk.stdout), { withdrawn: true });
});
