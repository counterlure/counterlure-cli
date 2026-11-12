// Face fingerprints, computed entirely on this computer.
//
//   image --sharp--> RGB pixels --YuNet--> face boxes + 5 landmarks
//         --similarity transform--> 112x112 aligned face --SFace--> 128 numbers
//
// The 128 numbers (an "embedding") are scaled to length 1, so two faces compare by a
// dot product (cosine similarity). OpenCV's published threshold for SFace is 0.363.
// The Counterlure server runs this same file, so both sides produce identical numbers.
import path from 'node:path';
import sharp from 'sharp';
import ort from 'onnxruntime-node';

export const MODEL_VERSION = 'yunet2023mar+sface2021dec/v1';
export const MATCH_THRESHOLD = 0.363;
export const STRONG_THRESHOLD = 0.5;

export const MODELS = {
  detector: {
    file: 'face_detection_yunet_2023mar.onnx',
    url: 'https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx',
    sha256: '8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4',
    bytes: 232589,
  },
  recognizer: {
    file: 'face_recognition_sface_2021dec.onnx',
    url: 'https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx',
    sha256: '0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79',
    bytes: 38696353,
  },
};

const SIZE = 640; // YuNet's fixed input
const SCORE_MIN = 0.6; // YuNet scores tilted faces 0.85-0.9; recognition, not detection, decides a match
const NMS_IOU = 0.3;
const MAX_FACES = 5;
const MIN_FACE_PX = 24; // below this a face is too blurry to compare at all; the CLI warns under 64
// Where SFace expects the eyes, nose and mouth corners in its 112x112 input (from OpenCV).
const TEMPLATE = [[38.2946, 51.6963], [73.5318, 51.5014], [56.0252, 71.7366], [41.5493, 92.3655], [70.7299, 92.2041]];

const sessions = new Map();
async function session(dir, which) {
  const key = `${dir}|${which}`;
  if (!sessions.has(key)) {
    const opts = { executionProviders: ['cpu'], graphOptimizationLevel: 'all', intraOpNumThreads: 1, logSeverityLevel: 3 };
    sessions.set(key, ort.InferenceSession.create(path.join(dir, MODELS[which].file), opts));
  }
  return sessions.get(key);
}

// Decode any image sharp understands, honour EXIF rotation, drop alpha. Metadata never leaves sharp.
async function decode(input) {
  const { data, info } = await sharp(input, { limitInputPixels: 50e6 }).rotate().removeAlpha().toColourspace('srgb')
    .raw().toBuffer({ resolveWithObject: true });
  return { px: data, w: info.width, h: info.height, c: info.channels };
}

function iou(a, b) {
  const x1 = Math.max(a.x, b.x), y1 = Math.max(a.y, b.y);
  const x2 = Math.min(a.x + a.w, b.x + b.w), y2 = Math.min(a.y + a.h, b.y + b.h);
  const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
  return inter / (a.w * a.h + b.w * b.h - inter || 1);
}

async function detect(dir, img) {
  const scale = Math.min(SIZE / img.w, SIZE / img.h);
  const w = Math.max(1, Math.round(img.w * scale)), h = Math.max(1, Math.round(img.h * scale));
  const small = await sharp(img.px, { raw: { width: img.w, height: img.h, channels: img.c } })
    .resize(w, h, { kernel: 'linear' }).raw().toBuffer();
  // YuNet takes BGR, 0-255, NCHW; the unused area right and below stays black.
  const plane = SIZE * SIZE, input = new Float32Array(3 * plane);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const s = (y * w + x) * 3, d = y * SIZE + x;
      input[d] = small[s + 2]; input[plane + d] = small[s + 1]; input[2 * plane + d] = small[s];
    }
  }
  const sess = await session(dir, 'detector');
  const out = await sess.run({ input: new ort.Tensor('float32', input, [1, 3, SIZE, SIZE]) });

  const found = [];
  for (const stride of [8, 16, 32]) {
    const cls = out[`cls_${stride}`].data, obj = out[`obj_${stride}`].data;
    const box = out[`bbox_${stride}`].data, kps = out[`kps_${stride}`].data;
    const cols = SIZE / stride, rows = SIZE / stride;
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const i = r * cols + c;
        const score = Math.sqrt(Math.min(1, Math.max(0, cls[i])) * Math.min(1, Math.max(0, obj[i])));
        if (score < SCORE_MIN) continue;
        const cx = (c + box[i * 4]) * stride, cy = (r + box[i * 4 + 1]) * stride;
        const bw = Math.exp(box[i * 4 + 2]) * stride, bh = Math.exp(box[i * 4 + 3]) * stride;
        const marks = [];
        for (let k = 0; k < 5; k++) marks.push([(kps[i * 10 + 2 * k] + c) * stride / scale, (kps[i * 10 + 2 * k + 1] + r) * stride / scale]);
        found.push({ x: (cx - bw / 2) / scale, y: (cy - bh / 2) / scale, w: bw / scale, h: bh / scale, score, marks });
      }
    }
  }
  found.sort((a, b) => b.score - a.score);
  const keep = [];
  for (const f of found) if (keep.every((k) => iou(k, f) <= NMS_IOU)) keep.push(f);
  return keep;
}

// Least-squares similarity transform (rotation, uniform scale, shift) taking src points onto dst.
// x' = a*x - b*y + tx,  y' = b*x + a*y + ty
export function similarity(src, dst) {
  const n = src.length;
  const ms = [0, 0], md = [0, 0];
  for (let i = 0; i < n; i++) { ms[0] += src[i][0] / n; ms[1] += src[i][1] / n; md[0] += dst[i][0] / n; md[1] += dst[i][1] / n; }
  let num1 = 0, num2 = 0, den = 0;
  for (let i = 0; i < n; i++) {
    const xs = src[i][0] - ms[0], ys = src[i][1] - ms[1], xd = dst[i][0] - md[0], yd = dst[i][1] - md[1];
    num1 += xs * xd + ys * yd; num2 += xs * yd - ys * xd; den += xs * xs + ys * ys;
  }
  const a = num1 / den, b = num2 / den;
  return { a, b, tx: md[0] - (a * ms[0] - b * ms[1]), ty: md[1] - (b * ms[0] + a * ms[1]) };
}

// Warp the face into SFace's 112x112 frame with bilinear sampling, as RGB, 0-255, NCHW.
function align(img, marks) {
  const { a, b, tx, ty } = similarity(marks, TEMPLATE);
  const det = a * a + b * b; // invert x' = M x + t
  const plane = 112 * 112, out = new Float32Array(3 * plane);
  for (let v = 0; v < 112; v++) {
    for (let u = 0; u < 112; u++) {
      const du = u - tx, dv = v - ty;
      const x = (a * du + b * dv) / det, y = (-b * du + a * dv) / det;
      const x0 = Math.floor(x), y0 = Math.floor(y), fx = x - x0, fy = y - y0;
      for (let ch = 0; ch < 3; ch++) {
        const p = (xx, yy) => (xx < 0 || yy < 0 || xx >= img.w || yy >= img.h ? 0 : img.px[(yy * img.w + xx) * img.c + ch]);
        const val = p(x0, y0) * (1 - fx) * (1 - fy) + p(x0 + 1, y0) * fx * (1 - fy) + p(x0, y0 + 1) * (1 - fx) * fy + p(x0 + 1, y0 + 1) * fx * fy;
        out[ch * plane + v * 112 + u] = val;
      }
    }
  }
  return out;
}

function unit(v) {
  let s = 0;
  for (const x of v) s += x * x;
  const n = Math.sqrt(s) || 1;
  return Array.from(v, (x) => x / n);
}

export const cosine = (a, b) => a.reduce((s, x, i) => s + x * b[i], 0);

// Returns up to 5 faces, largest first: { box, score, embedding: number[128] }.
export async function faceprints(input, { modelsDir }) {
  const img = await decode(input);
  const faces = (await detect(modelsDir, img)).filter((f) => f.w >= MIN_FACE_PX && f.h >= MIN_FACE_PX)
    .sort((p, q) => q.w * q.h - p.w * p.h).slice(0, MAX_FACES);
  const rec = await session(modelsDir, 'recognizer');
  const out = [];
  for (const f of faces) {
    const res = await rec.run({ [rec.inputNames[0]]: new ort.Tensor('float32', align(img, f.marks), [1, 3, 112, 112]) });
    out.push({
      box: { x: Math.round(f.x), y: Math.round(f.y), w: Math.round(f.w), h: Math.round(f.h) },
      score: Math.round(f.score * 1000) / 1000,
      embedding: unit(res[rec.outputNames[0]].data),
    });
  }
  return out;
}
