# Security

## Reporting a problem

Please report security problems privately through GitHub: on this repository's **Security** tab, choose **Report a vulnerability**. Do not open a public issue for them.

We aim to answer within 7 days. Please give us a reasonable time to fix a problem before you publish it.

In scope: this tool, the encrypted protocol it uses, and the `/api/cli` endpoint of www.counterlure.com. Please don't test against other members' accounts, don't run automated scans against the website, and don't try to get around Cloudflare's protection.

## What we check before each release

* The server key fingerprint in `lib/server-key.js` matches https://www.counterlure.com/api/cli/key.
* The model hashes in `lib/faceprint.js` match OpenCV's published files.
* Dependencies are pinned to exact versions, and `package-lock.json` is committed.
