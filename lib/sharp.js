// The only place sharp is imported from. Everything else imports it from here.
//
// libvips ships decoders for many formats: SVG, GIF, TIFF, HEIF, PDF and more. Each one is a parser
// that would be fed bytes from a photo of unknown origin, and image parsers are where memory-safety
// bugs live. Only the three formats Counterlure accepts stay loadable. The rest are blocked before
// any image is opened, so their decoders are never reached, whatever the file claims to be.
import sharp from 'sharp';

export const FORMATS = ['Jpeg', 'Png', 'Webp'];

sharp.block({ operation: ['VipsForeignLoad'] });
sharp.unblock({ operation: FORMATS.flatMap((f) => [`VipsForeignLoad${f}Buffer`, `VipsForeignLoad${f}File`]) });

export default sharp;
