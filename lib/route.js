// Which server this run talks to, and how the traffic gets there.
//
//   default         Counterlure's onion service, through Tor running on this computer. The request
//                   never touches Cloudflare or any public address of ours, and it reaches our
//                   server from Tor, not from you: there is no network address of yours to receive.
//   --direct        the website, www.counterlure.com, through Cloudflare. Add --tor or --proxy to
//                   hide your address from Cloudflare; without them, Cloudflare sees it.
//   --server URL    another server (your own, for testing). An .onion URL goes through Tor.
//
// Nothing falls back from the onion route to the website on its own: if Tor is not running the
// tool stops and says so, and going direct is always something you ask for.
import { findTor, isOnionHost, resolveProxy } from './net.js';

export const SITE = 'https://www.counterlure.com';
export const ONION = 'http://4qcqgpa4o6gc7yhqvqvdndx7jeeplsishebyxwf3667kphalxxtvfkad.onion';

export class NoTor extends Error {
  constructor(forOnion) {
    super([
      forOnion
        ? 'Tor is not running on this computer, so there is no private route to Counterlure.'
        : '--tor was given, but Tor is not running on this computer.',
      '',
      'By default this tool talks only to Counterlure\'s onion service, over Tor. Your network',
      'address then never reaches us: not our edge, not our servers, not our logs.',
      '',
      'Start Tor, then run the command again:',
      '  Tor Browser, left open          listens on 127.0.0.1:9150',
      '  the tor service                 127.0.0.1:9050 (apt install tor; brew install tor && brew services start tor)',
      '  Tor somewhere else              set COUNTERLURE_TOR=host:port',
      '',
      'Or add --direct to use the website instead. Cloudflare, which fronts it, then sees your',
      'network address (we do not store it). --direct --tor sends that through Tor as well.',
    ].join('\n'));
  }
}

// o: parsed options (server, direct, tor, proxy). find: Tor discovery, replaceable in tests.
export async function resolveRoute(o, { env = process.env, find = findTor } = {}) {
  const custom = o.server || env.COUNTERLURE_URL;
  const server = (custom || (o.direct ? SITE : ONION)).replace(/\/+$/, '');
  let u;
  try { u = new URL(server); } catch { throw new Error(`Not a URL: ${server}`); }
  const onion = isOnionHost(u.hostname);
  const explicit = o.proxy || env.COUNTERLURE_PROXY;

  let proxy;
  if (onion || o.tor) {
    proxy = explicit && !o.tor ? resolveProxy(explicit) : await find({ env });
    if (!proxy) throw new NoTor(onion);
    if (onion && proxy.protocol === 'http:') throw new Error('An onion address needs a SOCKS proxy (Tor). An HTTP proxy cannot reach it.');
  } else {
    proxy = resolveProxy(o.proxy);
  }

  const where = custom ? server : onion ? 'Counterlure onion service' : 'www.counterlure.com';
  const edge = custom ? '' : ', then Cloudflare';
  const how = onion ? 'over Tor'
    : o.tor ? `over Tor${edge}`
    : proxy ? `via proxy ${proxy.host}${edge}`
    : custom ? 'direct' : 'direct, via Cloudflare: it sees your network address';
  return { server, proxy, onion, custom: Boolean(custom), label: `${where} (${how})` };
}
