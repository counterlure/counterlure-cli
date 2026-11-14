// Everything this tool prints goes through here.
//
// Replies are signed by the pinned key, so only the Counterlure server can put text on this screen.
// The screen still must not obey it: a name in a burn notice or a line in a message was typed by
// someone, and a terminal acts on escape sequences (move the cursor, rewrite a line above, set the
// window title, and on some terminals worse). So every control character except newline and tab is
// removed, along with the Unicode marks that reorder text (an address shown right-to-left reads as
// a different address) and the invisible ones that hide inside it.
const RANGES = [
  [0x00, 0x08], [0x0b, 0x1f], // C0 controls, keeping tab and newline
  [0x7f, 0x9f],               // delete and the C1 controls (0x9b starts an escape sequence by itself)
  [0x061c, 0x061c], [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x2069], [0xfeff, 0xfeff], // reordering and invisible marks
];
const unsafe = (c) => RANGES.some(([a, b]) => c >= a && c <= b);

export const plain = (s) => Array.from(String(s)).filter((ch) => !unsafe(ch.codePointAt(0))).join('');

// Progress, prompts and explanations go to stderr; results go to stdout, so they can be piped.
export const say = (s) => process.stderr.write(`${plain(s)}\n`);
export const out = (s) => process.stdout.write(`${plain(s)}\n`);
