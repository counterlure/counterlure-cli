// Downloads the two open face models from OpenCV's model zoo on first use and checks each against a
// SHA-256 pinned in faceprint.js. A file that doesn't match is deleted and never loaded.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { MODELS } from './faceprint.js';
import { request } from './net.js';

function sha256File(file) {
  return new Promise((ok, no) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (d) => h.update(d)).on('end', () => ok(h.digest('hex'))).on('error', no);
  });
}

async function download(url, dest, { proxy, log }) {
  for (let hops = 0; hops < 5; hops++) {
    const tmp = `${dest}.part`;
    const out = fs.createWriteStream(tmp, { mode: 0o644 });
    const res = await request(url, { proxy, onData: (d) => out.write(d) });
    await new Promise((ok) => out.end(ok));
    if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
      fs.rmSync(tmp, { force: true });
      url = new URL(res.headers.location, url).toString();
      continue;
    }
    if (res.status !== 200) { fs.rmSync(tmp, { force: true }); throw new Error(`download failed (${res.status}) for ${url}`); }
    fs.renameSync(tmp, dest);
    return;
  }
  throw new Error('too many redirects');
}

export async function ensureModels(dir, { proxy = null, log = () => {} } = {}) {
  fs.mkdirSync(dir, { recursive: true });
  for (const m of Object.values(MODELS)) {
    const file = path.join(dir, m.file);
    if (fs.existsSync(file) && (await sha256File(file)) === m.sha256) continue;
    log(`Downloading ${m.file} (${(m.bytes / 1e6).toFixed(1)} MB) from OpenCV's model zoo on GitHub...`);
    await download(m.url, file, { proxy, log });
    const got = await sha256File(file);
    if (got !== m.sha256) {
      fs.rmSync(file, { force: true });
      throw new Error(`${m.file} did not match its pinned SHA-256 and was deleted. Expected ${m.sha256}, got ${got}.`);
    }
  }
  return dir;
}
