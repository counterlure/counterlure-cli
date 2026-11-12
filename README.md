# counterlure-cli

Check a photo against faces reported to [Counterlure](https://www.counterlure.com) without the photo leaving your computer.

Counterlure collects reports of honeypot and social-engineering approaches aimed at people in tech. When several people independently report the same face, it is flagged. This tool lets members check someone's photo against those flagged faces and against published burn notices.

```
$ counterlure check profile.jpg

profile.jpg
  face 1 at 198,200 (168x206px):
    STRONG POSSIBLE MATCH with a face reported by 7 independent people
```

## How it works

1. **On your computer**, the photo is decoded and two open models from [OpenCV's model zoo](https://github.com/opencv/opencv_zoo) run locally: YuNet finds faces, SFace turns each face into a fingerprint of 128 numbers.
2. The fingerprints (never the photo) are put in a request, padded to a fixed size and **encrypted with OpenPGP** to Counterlure's server key. That key is built into this tool and checked against a pinned fingerprint.
3. Each request carries a one-time key made for that request alone. The server's answer must be encrypted to it, signed by the pinned server key, and echo a random nonce, or the tool discards it.
4. The server compares the fingerprints with its list and answers with a level only: `strong` or `possible`, plus the source. No similarity scores are returned, so repeated queries can't be used to home in on a reported face.

The server stores **nothing** about a check: not the fingerprint, not the result. It keeps a count per member per day for the limit of 50 checks.

## Install

Needs Node.js 22 or newer.

```bash
git clone --branch v0.1.0 --depth 1 https://github.com/counterlure/counterlure-cli.git
cd counterlure-cli
npm ci
npm link        # makes the `counterlure` command available
```

On first use the tool downloads the two models (39 MB) from OpenCV's repository on GitHub and checks each against a SHA-256 hash pinned in [lib/faceprint.js](lib/faceprint.js). A file that doesn't match is deleted.

## Use

You need a Counterlure member account with an authenticator app set up ([join here](https://www.counterlure.com/join)).

```bash
counterlure login                  # username, then the 6-digit code from your authenticator app
counterlure check photo.jpg        # one or more photos
counterlure check --json photo.jpg # for scripts
counterlure whoami
counterlure logout                 # ends the sign-in on the server and deletes it here
counterlure key                    # shows the pinned server key fingerprint
counterlure models                 # downloads and verifies the models now
```

A sign-in lasts 24 hours. It is saved in `~/.config/counterlure/session.json` (Windows: `%APPDATA%\counterlure\session.json`), readable only by you on Linux and macOS. On Windows the folder is in your own profile; protect it as you would your browser's.

### Through Tor or a proxy

```bash
counterlure --tor check photo.jpg                        # Tor running on 127.0.0.1:9050
counterlure --proxy socks5h://127.0.0.1:1080 check photo.jpg
export COUNTERLURE_PROXY=socks5h://127.0.0.1:9050         # or set it once
```

Hostnames are always handed to the proxy unresolved, so no DNS lookup leaves your computer directly. With `--tor`, each run asks Tor for its own circuit. The proxy code is in [lib/net.js](lib/net.js) with no extra dependencies, so you can read the whole network path in one file. The model download goes through the same proxy.

## Reading results

* **A match is a lead, not proof.** Faces can look alike, and face recognition is less accurate on small, blurry, side-on or heavily filtered photos. Verify the person through other means before you act.
* **No match does not mean someone is safe.** Only faces that have been reported can match.
* Never harass, threaten or publish anyone based on a result. If you have new information, report it at [counterlure.com](https://www.counterlure.com).

## Privacy and threat model

What this protects:

* **Your photo** never leaves your computer.
* **What you check and what comes back** are encrypted end to end between this tool and Counterlure's server. HTTPS ends at Cloudflare's network in front of the server; the OpenPGP layer means Cloudflare, proxies and anyone else in between see only that you sent a padded, encrypted blob.
* **Answers can't be forged** by anyone in the middle: they must be signed by the pinned key and tied to your request.
* **Counterlure's server address** is not in this repository or used by it: the tool talks only to `www.counterlure.com`, which is served through Cloudflare.

What it does not protect:

* **Counterlure knows which member made a check**, because you sign in. It does not keep what you checked.
* **Your IP address is visible** to Cloudflare and to Counterlure unless you use Tor or a proxy. Cloudflare's bot protection sometimes blocks Tor exits; if so, try again later or use another proxy.
* **The model download** comes from GitHub, which sees your IP address unless you use a proxy.
* **A face fingerprint is personal data.** It can't be turned back into a good photo, but it can be compared with other photos of the same face. It is sent encrypted and is not stored.

Check the pinned key yourself: the fingerprint printed by `counterlure key` should match the one at https://www.counterlure.com/#cli and the key served at https://www.counterlure.com/api/cli/key.

## For testing against your own server

`COUNTERLURE_URL` points the tool at another server and `COUNTERLURE_SERVER_KEY` at a file with that server's public key. The tool prints a warning whenever either is in use. Plain `http://` is allowed only for `localhost`.

## Licence

The code is MIT licensed (see [LICENSE](LICENSE)). The models are not part of this repository. They are downloaded from OpenCV's model zoo: YuNet under the MIT licence, SFace under the Apache 2.0 licence.
