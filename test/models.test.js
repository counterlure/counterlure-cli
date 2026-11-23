// Getting the face models: copies already on the machine are used first, files you downloaded yourself
// are accepted only by their pinned SHA-256, and nothing is fetched without consent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { MODELS } from '../lib/faceprint.js';
import { ensureModels, importModels, modelStatus, findLocalModels, missingModelsText, ModelsMissing } from '../lib/models.js';

const BIN = fileURLToPath(new URL('../bin/counterlure.js', import.meta.url));
const REAL = [process.env.COUNTERLURE_TEST_MODELS, 'c:/dev/counterlure/models'].filter(Boolean)
  .find((d) => fs.existsSync(path.join(d, MODELS.detector.file)) && fs.existsSync(path.join(d, MODELS.recognizer.file)));
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), `cl-${p}-`));
const rm = (...d) => d.forEach((x) => fs.rmSync(x, { recursive: true, force: true }));

function cli(args, env) {
  return new Promise((ok) => {
    const p = execFile(process.execPath, [BIN, ...args], { env: { ...process.env, ...env } }, (err, stdout, stderr) => ok({ code: err ? (err.code ?? 1) : 0, stdout, stderr }));
    p.stdin.end();
  });
}

test('nothing is downloaded when consent is refused, and the reason is a ModelsMissing', async () => {
  const dir = tmp('models');
  const empty = tmp('search');
  let asked = null;
  const proxy = new URL('http://127.0.0.1:1'); // a download attempt would fail loudly with ECONNREFUSED
  await assert.rejects(
    ensureModels(dir, { proxy, searchDirs: [empty], consent: async (missing) => { asked = missing.map((m) => m.file); return false; } }),
    (e) => e instanceof ModelsMissing,
  );
  assert.deepEqual(asked.sort(), [MODELS.detector.file, MODELS.recognizer.file].sort());
  assert.deepEqual(fs.readdirSync(dir), []);
  rm(dir, empty);
});

test('the missing-models text names the official source, the hashes and the import command', async () => {
  const st = await modelStatus(tmp('status'));
  const t = missingModelsText(st, '/x/models');
  for (const m of Object.values(MODELS)) { assert.ok(t.includes(m.sha256)); assert.ok(t.includes(m.url)); }
  assert.match(t, /github\.com\/opencv\/opencv_zoo/);
  assert.match(t, /counterlure models import/);
});

test('files that are not the pinned models are refused by import and left alone', async () => {
  const dir = tmp('models');
  const src = tmp('src');
  fs.writeFileSync(path.join(src, 'face_detection_yunet_2023mar.onnx'), Buffer.alloc(MODELS.detector.bytes, 7)); // right name and size, wrong bytes
  fs.writeFileSync(path.join(src, 'other.onnx'), 'not a model');
  const { imported, rejected } = await importModels(dir, [src, path.join(src, 'absent.onnx')]);
  assert.equal(imported.length, 0);
  assert.equal(rejected.length, 3);
  assert.deepEqual(fs.readdirSync(dir), []);
  assert.equal((await findLocalModels(dir, { searchDirs: [src] })).length, 0, 'a same-named fake is not adopted');
  assert.deepEqual(fs.readdirSync(dir), []);
  rm(dir, src);
});

test('genuine models are found by name, imported under any name, and need no consent', { skip: !REAL && 'real model files not present' }, async () => {
  // Found under their own names in a search folder (like Downloads): adopted without asking.
  const dir = tmp('models');
  await ensureModels(dir, { searchDirs: [REAL], consent: async () => assert.fail('must not ask when copies are already here') });
  assert.ok((await modelStatus(dir)).every((m) => m.installed));
  rm(dir);

  // Renamed copies, brought in with import: identified by hash alone.
  const dir2 = tmp('models');
  const src = tmp('src');
  fs.copyFileSync(path.join(REAL, MODELS.detector.file), path.join(src, 'yunet.onnx'));
  fs.copyFileSync(path.join(REAL, MODELS.recognizer.file), path.join(src, 'sface (1).onnx'));
  const { imported } = await importModels(dir2, [src]);
  assert.deepEqual(imported.map((i) => i.file).sort(), [MODELS.detector.file, MODELS.recognizer.file].sort());
  assert.ok((await modelStatus(dir2)).every((m) => m.installed));
  rm(dir2, src);
});

test('"counterlure models" reports what is missing, makes no request, and fetches nothing without a terminal', async () => {
  const home = tmp('home');
  const models = path.join(home, 'm');
  const cwd = tmp('cwd');
  // --proxy to a closed port: if anything tried the network, it would say so.
  const r = await cli(['models', '--proxy', 'socks5h://127.0.0.1:1'], { COUNTERLURE_HOME: home, COUNTERLURE_MODELS: models, USERPROFILE: cwd, HOME: cwd });
  assert.equal(r.code, 1);
  assert.match(r.stdout, /missing\s+face_detection_yunet_2023mar\.onnx/);
  assert.match(r.stderr, /get them yourself/i);
  assert.match(r.stderr, /counterlure models import/);
  assert.doesNotMatch(r.stderr, /ECONNREFUSED|Downloading/);

  const d = await cli(['models', '--download', '--proxy', 'socks5h://127.0.0.1:1'], { COUNTERLURE_HOME: home, COUNTERLURE_MODELS: models, USERPROFILE: cwd, HOME: cwd });
  assert.equal(d.code, 1);
  assert.match(d.stderr, /nothing was downloaded/i);
  assert.doesNotMatch(d.stderr, /Downloading/);
  rm(home, cwd);
});

test('"counterlure models import" brings in a renamed genuine copy', { skip: !REAL && 'real model files not present' }, async () => {
  const home = tmp('home');
  const models = path.join(home, 'm');
  const src = tmp('src');
  fs.copyFileSync(path.join(REAL, MODELS.detector.file), path.join(src, 'detector.onnx'));
  fs.copyFileSync(path.join(REAL, MODELS.recognizer.file), path.join(src, 'recognizer.onnx'));
  const r = await cli(['models', 'import', src], { COUNTERLURE_HOME: home, COUNTERLURE_MODELS: models });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /Both models verified/);
  rm(home, src);
});
