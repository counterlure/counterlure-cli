# Security

## Reporting a vulnerability

Report privately through GitHub: this repository's **Security** tab, **Report a vulnerability**. Do not open a public issue.

We acknowledge within 7 days and ask for a reasonable window to fix before disclosure. Credit is given unless you prefer otherwise.

In scope:

* this tool, including the crop and metadata handling in `lib/crop.js`
* the `counterlure-cli/1` protocol: envelope, padding, nonce and replay handling, reply signatures, proof of work
* the `/api/cli` endpoint of www.counterlure.com and of the onion service
* account signup and payment through the tool, and member messages
* the routing in `lib/route.js` and `lib/net.js`: Tor discovery, onion only over SOCKS, no silent fallback

Of particular interest: anything that lets a request or reply be read or altered in transit, lets unattributed reports count as more than one source, lets a report or check leak match information, lets source-photo metadata or other faces reach the server, reveals a user's network address beyond what the README states (on the default onion route, that is nothing), lets one account read or write another's messages, or opens an account without a matching payment.

Out of scope: other members' accounts, automated scanning of the website, volumetric testing, and attempts to get around Cloudflare's protections. Test protocol issues against your own server instead (see "Testing against your own server" in the README).

## Release checks

Before each tagged release:

* The server key fingerprint in `lib/server-key.js` matches https://www.counterlure.com/api/cli/key and the website's CLI section.
* The onion address in `lib/route.js` matches the website's CLI section, and the service answers on it.
* The model hashes in `lib/faceprint.js` match OpenCV's published files, and `lib/faceprint.js` is identical to the server's copy, so local templates match what the service indexes.
* Dependencies are pinned to exact versions and `package-lock.json` is committed. CI installs with `--ignore-scripts`.
* GitHub Actions are pinned to commit hashes.
* `npm test` passes, including the crop metadata tests and fixed request sizes.
