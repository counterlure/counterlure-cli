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

export async function ensureModels(dir, { proxy = null, log = () => {} } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  for (const m of Object.values(MODELS)) {
    const file = path.join(dir, m.file);
    if (fs.existsSync(file) && (await sha256File(file)) === m.sha256) continue;
    log(`Downloading ${m.file} (${(m.bytes / 1e6).toFixed(1)} MB) from OpenCV's model zoo on GitHub...`);
    await download(m, file, proxy);
  }
  return dir;
}
