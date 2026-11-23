// Downloads the two open face models from OpenCV's model zoo on first use and checks each against a
// SHA-256 pinned in faceprint.js. The download is hashed as it arrives and only takes its real name
// once the hash matches, so a file under a model's name is always one that was verified.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { MODELS } from './faceprint.js';
import { request } from './net.js';

// The model zoo lives on GitHub, which redirects to its own file hosts. Nothing else is followed.
export const trusted = (u) => u.protocol === 'https:' && !u.port && (u.hostname === 'github.com' || u.hostname.endsWith('.githubusercontent.com'));

function sha256File(file) {
  return new Promise((ok, no) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (d) => h.update(d)).on('end', () => ok(h.digest('hex'))).on('error', no);
  });
}

// One GET into tmp, never more than the model's known size. Returns the reply and the body's hash.
async function fetchTo(url, tmp, limit, proxy) {
  const hash = crypto.createHash('sha256');
  const file = fs.createWriteStream(tmp, { mode: 0o600 });
  let failed = null;
  file.on('error', (e) => { failed = e; });
  try {
    const res = await request(url, { proxy, maxBytes: limit, onData: (d) => { hash.update(d); file.write(d); } });
    return { res, sha256: hash.digest('hex') };
  } finally {
    await new Promise((ok) => file.end(ok));
    if (failed) throw failed;
  }
}

async function download(m, dest, proxy) {
  const tmp = `${dest}.${crypto.randomBytes(4).toString('hex')}.part`;
  let url = new URL(m.url);
  try {
    for (let hops = 0; hops < 5; hops++) {
      if (!trusted(url)) throw new Error(`Refusing to fetch ${m.file} from ${url.host}: not GitHub.`);
      const { res, sha256 } = await fetchTo(url, tmp, m.bytes, proxy);
      if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
        url = new URL(res.headers.location, url);
        continue;
      }
      if (res.status !== 200) throw new Error(`download failed (${res.status}) for ${url}`);
      if (sha256 !== m.sha256) throw new Error(`${m.file} did not match its pinned SHA-256 and was discarded. Expected ${m.sha256}, got ${sha256}.`);
      fs.renameSync(tmp, dest);
      return;
    }
    throw new Error('too many redirects');
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

// ------------------------------------------------------------------ finding copies already here
//
// Nothing is downloaded without consent. Before asking, the tool looks for copies that are already
// on this computer: in the models folder, and under the model's own file name in the current folder
// and the Downloads folder. A file is only ever accepted on its SHA-256, so where it came from does
// not matter, and a renamed copy can be brought in with "counterlure models import".

const MAX_MODEL_BYTES = Math.max(...Object.values(MODELS).map((m) => m.bytes));

// The pinned model a file is, by hash, or null. Files of the wrong size are not even read.
async function identify(file) {
  let st;
  try { st = fs.statSync(file); } catch { return null; }
  if (!st.isFile() || !Object.values(MODELS).some((m) => m.bytes === st.size)) return null;
  const h = await sha256File(file);
  return Object.values(MODELS).find((m) => m.sha256 === h) || null;
}

// Copies a verified file into the models folder under its proper name (written aside, then renamed).
function adopt(src, m, dir) {
  const dest = path.join(dir, m.file);
  if (path.resolve(src) === path.resolve(dest)) return dest;
  const tmp = `${dest}.${crypto.randomBytes(4).toString('hex')}.part`;
  try {
    fs.copyFileSync(src, tmp);
    fs.renameSync(tmp, dest);
  } finally {
    fs.rmSync(tmp, { force: true });
  }
  return dest;
}

export function defaultSearchDirs() {
  const home = process.env.USERPROFILE || process.env.HOME || '';
  return [process.cwd(), home && path.join(home, 'Downloads')].filter(Boolean);
}

// What is in place, and what is missing. Each entry: { ...model, key, installed }.
export async function modelStatus(dir) {
  const out = [];
  for (const [key, m] of Object.entries(MODELS)) {
    const file = path.join(dir, m.file);
    out.push({ ...m, key, installed: fs.existsSync(file) && (await sha256File(file)) === m.sha256 });
  }
  return out;
}

// Looks for missing models under their own file names in searchDirs, and adopts verified copies.
export async function findLocalModels(dir, { searchDirs = defaultSearchDirs() } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  const found = [];
  for (const m of (await modelStatus(dir)).filter((s) => !s.installed)) {
    for (const d of searchDirs) {
      const cand = path.join(d, m.file);
      if ((await identify(cand))?.sha256 === m.sha256) {
        adopt(cand, m, dir);
        found.push({ file: m.file, from: cand });
        break;
      }
    }
  }
  return found;
}

// "counterlure models import PATH...": every file given, or every .onnx file in a folder given, is
// checked against the pinned hashes. Matches are copied in; everything else is reported and left alone.
export async function importModels(dir, paths) {
  fs.mkdirSync(dir, { recursive: true });
  const imported = [];
  const rejected = [];
  const files = [];
  for (const p of paths) {
    let st;
    try { st = fs.statSync(p); } catch { rejected.push({ file: p, why: 'not found' }); continue; }
    if (st.isDirectory()) {
      for (const f of fs.readdirSync(p)) if (f.toLowerCase().endsWith('.onnx')) files.push(path.join(p, f));
    } else files.push(p);
  }
  for (const f of files) {
    let size = 0;
    try { size = fs.statSync(f).size; } catch { /* reported below */ }
    if (size > MAX_MODEL_BYTES) { rejected.push({ file: f, why: 'not one of the pinned models (wrong size)' }); continue; }
    const m = await identify(f);
    if (!m) { rejected.push({ file: f, why: 'does not match either pinned SHA-256' }); continue; }
    adopt(f, m, dir);
    imported.push({ file: m.file, from: f });
  }
  return { imported, rejected };
}

export class ModelsMissing extends Error {}

// Makes sure both models are in place. Copies already on this computer are used first. Anything
// still missing is downloaded only if consent(missing) resolves true; otherwise ModelsMissing.
export async function ensureModels(dir, { proxy = null, log = () => {}, consent = async () => true, searchDirs } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  for (const f of await findLocalModels(dir, { searchDirs })) log(`Using the verified copy of ${f.file} found at ${f.from}`);
  const missing = (await modelStatus(dir)).filter((s) => !s.installed);
  if (!missing.length) return dir;
  if (!(await consent(missing))) throw new ModelsMissing('The face models are not installed, and nothing was downloaded.');
  for (const m of missing) {
    log(`Downloading ${m.file} (${(m.bytes / 1e6).toFixed(1)} MB) from OpenCV's model zoo on GitHub...`);
    await download(m, path.join(dir, m.file), proxy);
  }
  return dir;
}

// The text shown when models are missing: what they are, where to get them yourself, and the hashes.
export function missingModelsText(missing, dir) {
  const name = { detector: 'YuNet face detector', recognizer: 'SFace face recognizer' };
  const size = (b) => (b > 1e6 ? `${(b / 1e6).toFixed(1)} MB` : `${Math.round(b / 1e3)} KB`);
  return [
    'The two open face models this tool runs locally are not on this computer yet.',
    'They find and measure faces on your machine; no photo is involved in getting them.',
    '',
    ...missing.flatMap((m) => [
      `  ${name[m.key] || m.key}, ${size(m.bytes)}: ${m.file}`,
      `    from    ${m.url}`,
      `    SHA-256 ${m.sha256}`,
    ]),
    '',
    'Option 1, get them yourself (this tool makes no request):',
    '  Download them from OpenCV\'s own repository, https://github.com/opencv/opencv_zoo, or any',
    '  mirror you trust, at a time and over a connection of your choosing. Only the hash counts,',
    '  not where the file came from. Then run:',
    '    counterlure models import FILE-OR-FOLDER ...',
    `  or place them, under the names above, in ${dir}`,
    '  Step-by-step guide: README.md, "Getting the face models yourself".',
    '',
    'Option 2, let this tool fetch them from GitHub now, over the same route as everything else.',
    '  Each file is checked against the hash above and discarded if it does not match.',
  ].join('\n');
}
