# counterlure-cli

Command-line access to [Counterlure](https://www.counterlure.com), a register of honeypot and social-engineering approaches against people in tech.

Counterlure looks for one face turning up under different names. Reports come in from people who were approached. When enough independent sources report the same face, an analyst reviews the case, and corroborated cases can end in a published burn notice. This tool gives you two things from a terminal:

* **Screen** a photo against corroborated cases and burn notices without the photo leaving your machine. This needs a member account.
* **File** a report on a face. This needs no account at all.

```
$ counterlure check profile.jpg

profile.jpg
  face 1 at 198,200 (168x206px):
    STRONG POSSIBLE MATCH with a face reported by 7 independent sources

$ counterlure report profile.jpg --name "Anna K." --context dating-app --handle @anna.k
...
Filed. Receipt: CL-7Q2M-XK4D-91TF-HC3P
```

## What leaves your machine

Face detection (YuNet) and face templating (SFace) run locally on open models from [OpenCV's model zoo](https://github.com/opencv/opencv_zoo). What is transmitted depends on the operation.

| Operation | Sent | Never sent | Kept by the service |
|---|---|---|---|
| `check` | one 128-number SFace template per face | the photo, file names, EXIF | nothing about the query; a per-member daily counter |
| `report` | a crop of the chosen face, the name given, context, optional handle | the rest of the photo, other faces in frame, EXIF/GPS, device data | the crop and template (encrypted at rest), name and handle (sealed), a hash of the receipt |
| `withdraw` | the receipt | anything else | nothing: the crop and template are destroyed |

Every request is OpenPGP-encrypted to a server key compiled into the tool and padded to a fixed size: 16 KB for control traffic, 224 KB for every report regardless of the photo. Anyone on the path (Cloudflare's edge, your ISP, a proxy, a Tor exit) sees that a client talked to the service and when, but not what was asked or answered, and not whether a check was a hit.

## Install

Node.js 22 or later.

```bash
git clone --branch v0.2.0 --depth 1 https://github.com/counterlure/counterlure-cli.git
cd counterlure-cli
npm ci
npm link
```

The first `check` or `report` pulls the two models (39 MB) from OpenCV's repository and verifies each against a SHA-256 hash pinned in [lib/faceprint.js](lib/faceprint.js). A file that fails verification is deleted before it is ever loaded. Run `counterlure models` to fetch them in advance, for example before going offline or switching to Tor.

## Screening a photo (members)

```bash
counterlure login                  # username, then the 6-digit authenticator code
counterlure check a.jpg b.jpg      # every face in every photo
counterlure check --json a.jpg     # for pipelines
counterlure whoami
counterlure logout                 # revokes the session server-side and deletes it locally
```

Membership and authenticator setup: [counterlure.com/join](https://www.counterlure.com/join). A session lasts 24 hours and is stored in `~/.config/counterlure/session.json` (Windows: `%APPDATA%\counterlure\session.json`), mode 0600 on Linux and macOS. Checks are limited to 50 per member per day.

The server answers with a level only, `strong` or `possible`, and the source type (corroborated case or burn notice). It returns no similarity scores, so repeated queries with doctored images can't be used to walk toward a reported face.

Screening only covers corroborated material. A face reported once, by one person, will not match. That is deliberate: a single report is an allegation, and the watchlist is not a tool for checking up on a name someone gave you once.

## Filing a report (anyone)

```bash
counterlure report photo.jpg --name "Anna K." --context dating-app --handle @anna.k
```

| Option | |
|---|---|
| `--name` | the name they used with you. Required. A cover name is still useful: the same face under several names is the signal. |
| `--context` | where the approach happened: `dating-app`, `social-media`, `event-or-conference`, `work-or-business`, `introduced`, `other` |
| `--handle` | the profile, handle or URL they used. Optional. Sealed on arrival. |
| `--face N` | which face, when the photo has more than one. The tool refuses to guess and lists them. |
| `--dry-run` | do everything except transmit |
| `--save-crop FILE` | write the exact JPEG that is, or would be, sent, so you can inspect it |
| `--anon` | file unattributed even while signed in |
| `--yes` | skip the prompt for scripted use; you are still making the statement below |

Before anything is sent you are shown a summary of exactly what will leave, and asked to confirm this statement:

> I am in contact with this person personally and I am unsure about their intentions. I am not using this to track an ex-partner or anyone else, and nothing about my report is based on their nationality or ethnicity.

**The crop.** The photo is decoded to raw pixels, rotated upright, cut down to the chosen face plus a margin, and encoded as a new JPEG of at most 480 px. The margin shrinks if it would take in another detected face. Because the output is built from pixels and not copied from the source file, no EXIF, GPS position, device serial, colour profile or embedded thumbnail can survive into it. Check this yourself with `--dry-run --save-crop crop.jpg` and any metadata viewer.

**The receipt.** A successful report returns a receipt such as `CL-7Q2M-XK4D-91TF-HC3P`. It is the only handle on the report: the tool does not store it, and the service holds only a keyed hash of it. Record it offline. To withdraw:

```bash
counterlure withdraw CL-7Q2M-XK4D-91TF-HC3P
```

The report leaves the case, and the stored crop and template are destroyed.

### Attributed and unattributed reports

| | Signed in | No account, or `--anon` |
|---|---|---|
| Counts toward a case as | one source per member | **one source shared by every unattributed CLI report** |
| Feedback | you are told privately if the case is acted on | none |
| Proof of work | none | yes, a few seconds of CPU |
| Limit | 20 per member per day | 3 per network per hour, 150 a day across the service |
| Match result returned | no | no |

Unattributed intake is where a corroboration system gets attacked: script a few hundred reports against one face and hope the volume reads as independent sourcing. So every unattributed CLI report shares a single source identity. However many are filed, they add up to one source, and a case needs at least three independent sources including a member, or five from anyone, before an analyst even looks at it. Anonymous CLI reports can strengthen a case but cannot create one.

Each unattributed report also carries a proof-of-work stamp, a SHA-256 partial preimage bound to that request's one-time nonce, so it can't be precomputed or reused. The default is 21 bits, about two million hashes. If the service raises the bar, the tool retries once at the level it names, and it refuses to go past 26 bits whatever it is told.

Filing a report never returns a match result, whether you are signed in or not. Reporting is not a side channel into the watchlist.

## Network exposure

Without a proxy the service sees your IP address. For signed-in use that adds little, since it already knows the account. For unattributed reports, the service keeps a keyed hash of the address for the hourly limit and deletes it within a day. If you do not want it to see the address at all, route through Tor:

```bash
counterlure --tor report photo.jpg --name "Anna K."             # Tor SOCKS on 127.0.0.1:9050
counterlure --proxy socks5h://127.0.0.1:1080 check photo.jpg
export COUNTERLURE_PROXY=socks5h://127.0.0.1:9050               # set once
```

Hostnames go to the proxy unresolved, so no DNS query leaves your machine directly. Each `--tor` run uses its own circuit through Tor's SOCKS isolation, so the tool never shares an exit with your browser. The model download takes the same route. The whole network path is [lib/net.js](lib/net.js), about a hundred lines with no third-party dependencies. Cloudflare sometimes challenges Tor exits; if a request is refused, try again on a new circuit.

## Reading a result

* A match is a lead, not an identification. Faces resemble each other, and recognition degrades on small, blurred, off-angle or filtered images. Corroborate through other means before acting.
* No match is not a clearance. Only faces that have been reported and corroborated can match.
* Do not confront, harass or publish anyone on the strength of a result. If you have new information, file it.

## Threat model

Protected:

* **Your photo**, on `check`. It never leaves the machine.
* **Everything beyond the face**, on `report`. Background, bystanders, location and device metadata stay with you.
* **Content in transit.** TLS ends at Cloudflare's edge. The OpenPGP layer inside it means the edge, proxies and exits see only fixed-size ciphertext.
* **Integrity of answers.** A reply must be signed by the pinned key, encrypted to the one-time key generated for that request, and echo its nonce. Anything else is discarded.
* **Replay.** The service accepts each nonce once, within five minutes of its clock.
* **The origin.** The tool talks only to `www.counterlure.com` behind Cloudflare. No origin address is in this repository.

Not protected:

* **Who checked.** On `check` the service knows which member asked, though it keeps no record of what was asked.
* **Your address**, unless you use Tor or a proxy.
* **The face itself, on `report`.** A face crop is personal data about the person reported. It is held encrypted, used for matching, and destroyed on withdrawal. File only on people who actually approached you.
* **A compromised endpoint.** If your machine is compromised, nothing here helps.

## Verifying the server key

`counterlure key` prints the pinned fingerprint. Compare it against at least two independent sources: the [CLI section of the website](https://www.counterlure.com/#cli), the key served at <https://www.counterlure.com/api/cli/key>, and the tagged release on GitHub. The tool checks the compiled-in key against the pinned fingerprint before every request.

## Testing against your own server

`COUNTERLURE_URL` points the tool at another server and `COUNTERLURE_SERVER_KEY` at a file holding its public key. The tool warns on every run while either is set. Plain `http://` is accepted only for `localhost`.

```bash
npm test
```

## Licence

MIT (see [LICENSE](LICENSE)). The models are not distributed here. They are fetched from OpenCV's model zoo: YuNet under MIT, SFace under Apache 2.0.
