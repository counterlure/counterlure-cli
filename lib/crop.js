// The only image material a report ever sends: one face, cropped and re-encoded on this computer.
//
// Minimisation is the point. The source photo can carry a lot that is no business of ours and can
// burn the reporter: GPS and device serials in EXIF, a thumbnail of the uncropped original, other
// people in the frame, the room, a screen, a reflection. None of that is sent. What leaves is:
//
//   - the chosen face plus a margin, shrunk if needed so no other detected face is in frame
//   - decoded to raw pixels and encoded fresh as a baseline JPEG, so no metadata, colour profile
//     or embedded thumbnail from the original can survive (there is nothing to strip; it is never
//     copied in the first place)
//   - scaled to fit MAX_SIDE, and compressed until it fits the fixed request envelope
//
// Coordinates are in the EXIF-rotated frame, the same frame faceprint.js detects faces in.
import sharp from './sharp.js';

export const MAX_SIDE = 480;
export const MAX_B64 = 190_000; // the server takes 200,000; the request envelope is sized for this
const MARGIN = 0.35;
const QUALITIES = [85, 78, 70, 60, 50];

export function cropRegion(face, others, w, h) {
  const cx = face.x + face.w / 2, cy = face.y + face.h / 2;
  const inside = (r, o) => {
    const ox = o.x + o.w / 2, oy = o.y + o.h / 2;
    return ox >= r.left && ox < r.left + r.width && oy >= r.top && oy < r.top + r.height;
  };
  for (let step = 7; step >= 0; step--) { // margin 0.35, 0.30 ... 0: integer steps, no float drift
    const m = (MARGIN * step) / 7;
    const side = Math.max(face.w, face.h) * (1 + 2 * m);
    const left = Math.max(0, Math.floor(cx - side / 2)), top = Math.max(0, Math.floor(cy - side / 2));
    const r = {
      left, top,
      width: Math.max(1, Math.min(w, Math.ceil(cx + side / 2)) - left),
      height: Math.max(1, Math.min(h, Math.ceil(cy + side / 2)) - top),
    };
    if (step === 0 || !others.some((o) => inside(r, o))) return r;
  }
}

// face and others are { x, y, w, h } boxes from faceprints(). Returns { jpeg, width, height }.
export async function faceCrop(input, face, others = []) {
  const { data, info } = await sharp(input, { limitInputPixels: 50e6 }).rotate().removeAlpha().toColourspace('srgb')
    .raw().toBuffer({ resolveWithObject: true });
  const r = cropRegion(face, others, info.width, info.height);
  const raw = { raw: { width: info.width, height: info.height, channels: info.channels } };
  const pixels = await sharp(data, raw).extract(r)
    .resize({ width: MAX_SIDE, height: MAX_SIDE, fit: 'inside' })
    .raw().toBuffer({ resolveWithObject: true });
  for (const quality of QUALITIES) {
    const jpeg = await sharp(pixels.data, { raw: pixels.info }).jpeg({ quality, progressive: false, chromaSubsampling: '4:2:0' }).toBuffer();
    if (Math.ceil(jpeg.length / 3) * 4 <= MAX_B64) return { jpeg, width: pixels.info.width, height: pixels.info.height };
  }
  throw new Error('The face crop would not compress small enough to send.');
}
