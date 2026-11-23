# counterlure-cli

Command-line access to [Counterlure](https://www.counterlure.com), a register of honeypot and social-engineering approaches against people in tech.

Counterlure looks for one face turning up under different names. Reports come in from people who were approached. When enough independent sources report the same face, an analyst reviews the case, and corroborated cases can end in a published burn notice. From a terminal you can:

* **Open an account** with a username and an authenticator app, and pay for it in crypto. No email, phone number or name, ever.
* **Screen** a photo against corroborated cases and burn notices without the photo leaving your machine. This needs an account.
* **File** a report on a face. This needs no account at all.
* **Write to the Counterlure team** and read their replies.
* **Organization / Enterprise mode**: enroll anonymously with your organization's code (`counterlure org enroll`), screen against both org alerts and the global pool, and file zero-knowledge biometric reports that escalate only when 3+ distinct staff report the same face.

By default all of it runs over Tor to Counterlure's onion service, so your network address never reaches us.

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
| `signup` | the username you pick, authenticator codes, the transaction ID of your payment | email, phone, name, card details | the username, the authenticator secret and the payment record (encrypted) |
| `send` / `inbox` | your message / your session | anything else | the conversation, encrypted at rest |
| `org enroll` / `org check` / `org report` | enrollment code or anonymous device token; 128-number SFace template only | employee name, email, photo, EXIF, IP | anonymous device token hash; embedding isolated to org namespace until 3+ distinct staff match |

Every request is OpenPGP-encrypted to a server key compiled into the tool and padded to a fixed size: 16 KB for control traffic, 224 KB for every report regardless of the photo. Anyone on the path (a Tor relay, or on `--direct` Cloudflare's edge and your ISP) sees that a client talked to the service and when, but not what was asked or answered, and not whether a check was a hit.

## Install

Node.js 22 or later.

```bash
git clone --branch v0.4.3 --depth 1 https://github.com/counterlure/counterlure-cli.git
cd counterlure-cli
npm ci
npm link
```

You also need the two open face models (39 MB) from OpenCV. The tool never downloads them without asking: you can fetch them yourself first, from OpenCV's own repository, and hand them over with `counterlure models import`. See [Getting the face models](#getting-the-face-models) below.

You also need Tor running on the same computer: either [Tor Browser](https://www.torproject.org/download/) left open, or the tor service (`apt install tor`, `brew install tor && brew services start tor`). The tool finds it on 127.0.0.1:9050 or 9150 by itself. Without Tor it stops and says so; it never quietly falls back to the website.

## Getting the face models

The tool runs two open models from [OpenCV's model zoo](https://github.com/opencv/opencv_zoo) on your own computer: YuNet finds faces, SFace turns a face into the 128 numbers that are compared. They are not bundled here, and **the tool never downloads them without asking you first.**

| Model | File name | Size | SHA-256 |
|---|---|---|---|
| YuNet face detector (MIT) | `face_detection_yunet_2023mar.onnx` | 232,589 bytes | `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4` |
| SFace face recognizer (Apache 2.0) | `face_recognition_sface_2021dec.onnx` | 38,696,353 bytes | `0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79` |

The hashes are pinned in [lib/faceprint.js](lib/faceprint.js). A file is accepted only if its hash matches, so it makes no difference where you got it.

When a command needs the models, the tool does this, in order:

1. **It looks for copies already on your computer**: in its models folder, then under the exact file names above in the current folder and in your `Downloads` folder. A copy whose hash matches is used with no network request.
2. **If any are still missing, it stops and shows you** the table above, the official links, and how to get the files yourself.
3. **It downloads only if you type `yes`.** The download goes over the same route as everything else (Tor by default), only from GitHub, and any file that fails the hash is deleted before it is ever loaded. In scripts, where there is nobody to ask, nothing is downloaded unless you pass `--fetch-models`.

Run `counterlure models` at any time to see which models are installed and verified. It makes no network request.

### Downloading the models yourself (recommended)

Fetching the files yourself means the Counterlure tool never makes the request. You choose when, from where and over which connection, and the download looks like anyone else getting OpenCV's models.

**Step 1. Download both files.** Use one of these methods.

*In a browser (Tor Browser works):* open each model's page and use GitHub's **Download raw file** button (the arrow icon above the file view).

- https://github.com/opencv/opencv_zoo/blob/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
- https://github.com/opencv/opencv_zoo/blob/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx

*With curl over Tor* (macOS, Linux, or Windows 10 and later; use port 9150 if Tor Browser is what is running):

```bash
curl -L --socks5-hostname 127.0.0.1:9050 -o face_detection_yunet_2023mar.onnx \
  https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
curl -L --socks5-hostname 127.0.0.1:9050 -o face_recognition_sface_2021dec.onnx \
  https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx
```

Drop `--socks5-hostname 127.0.0.1:9050` to download over your normal connection.

*In Windows PowerShell* (normal connection):

```powershell
Invoke-WebRequest -OutFile face_detection_yunet_2023mar.onnx https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx
Invoke-WebRequest -OutFile face_recognition_sface_2021dec.onnx https://github.com/opencv/opencv_zoo/raw/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx
```

*With git:* the model zoo stores its `.onnx` files with Git LFS. Install [git-lfs](https://git-lfs.com) first. Without it, a clone gives you small pointer files of about 130 bytes, and they will not match the hash. A sparse checkout avoids pulling the whole zoo:

```bash
git lfs install
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --filter=blob:none --sparse https://github.com/opencv/opencv_zoo.git
cd opencv_zoo
git sparse-checkout set models/face_detection_yunet models/face_recognition_sface
git lfs pull --include="models/face_detection_yunet/face_detection_yunet_2023mar.onnx,models/face_recognition_sface/face_recognition_sface_2021dec.onnx"
```

Any mirror you trust works too, such as an internal artifact store. Only the hash counts.

**Step 2. Check the hashes yourself (optional; the tool checks again).** Compare the output with the table above.

```bash
sha256sum face_*.onnx                  # Linux
shasum -a 256 face_*.onnx              # macOS
```
```powershell
Get-FileHash -Algorithm SHA256 face_*.onnx   # Windows PowerShell
certutil -hashfile face_recognition_sface_2021dec.onnx SHA256   # Windows cmd, one file at a time
```

**Step 3. Hand them to the tool.** Use any one of these:

```bash
counterlure models import ~/Downloads/face_detection_yunet_2023mar.onnx ~/Downloads/face_recognition_sface_2021dec.onnx
counterlure models import ./opencv_zoo/models      # a folder: every .onnx file in it is checked
```

`import` identifies each file by its hash, so renamed files (`yunet.onnx`, `sface (1).onnx`) are fine. It copies the matches into the models folder and leaves everything else alone, reporting why each one was skipped. You can also skip `import` and leave the files under their original names in your `Downloads` folder, or in the folder you run the tool from; it will find them there. Or copy them into the models folder yourself:

- Windows: `%APPDATA%\counterlure\models`
- macOS and Linux: `~/.config/counterlure/models` (or `$XDG_CONFIG_HOME/counterlure/models`)
- Anywhere else, by setting `COUNTERLURE_MODELS=/path/to/folder`

**Step 4. Confirm.**

```bash
counterlure models
#   verified  face_detection_yunet_2023mar.onnx
#   verified  face_recognition_sface_2021dec.onnx
# Both models verified in ...
```

### Letting the tool download them

```bash
counterlure models --download     # shows the sources and hashes, then asks: type yes
counterlure check photo.jpg --fetch-models   # consent in advance, e.g. in a script
```

If you answer anything other than `yes`, nothing is fetched and the command stops with the instructions above.

## Opening an account

```bash
counterlure signup
```

Three steps, all in the terminal:

1. **Username.** Pick one (3 to 32 letters, numbers, `.`, `-`, `_`). This step carries a few seconds of proof of work.
2. **Authenticator.** A QR code is drawn in the terminal. Scan it with Aegis, 2FAS, Raivo, Google Authenticator, 1Password or any TOTP app, or type the key shown under it, then enter the 6-digit code to confirm. The authenticator is the only way in: there is no email or password to reset.
3. **Payment.** Choose a coin (for example `--chain USDC_BASE`, `ETH_BASE`, `USDC_ERC20`, `USDT_ERC20` or `ETH`, whichever the service currently accepts). You get a payment address made for your account alone, the amount, and the time until which the address may be used, as text and as a QR code. Send at least the amount before that time, then press Enter: the tool waits until the payment is found and confirmed. You can also paste the transaction ID instead.

   **Never send to an address after its time is up.** The tool says when it has expired and stops showing it; run `counterlure signup` again to get a new one.

When the payment confirms, the account opens and you get ten recovery codes, once. Each signs you in a single time in place of an authenticator code. Write them down offline: the tool does not store them.

You can stop at any step. `counterlure signup` picks up where you left off; the token for that is kept in `signup.json` beside the session file and deleted when the account opens. Typing `q` at the payment prompt saves your place, so you can pay from an exchange that takes a while; the payment is found whenever it arrives within the address's time. If the payment needs a person to look at it, for example a slightly wrong amount, the tool says so and you can check back later. `counterlure logout` abandons a signup in progress.

Unpaid signups are deleted after 30 days, and signups whose authenticator was never confirmed after an hour.

### Why a lifetime account costs $5,000

The launch offer is lower, but $5,000 is the real price. The price is part of the defence.

- **Sybil resistance.** Adversaries will try to flood the registry with noise, to poison the face fingerprints or to fish for false positives. Requiring payment creates economic friction against automated sockpuppet spam.
- **Adversarial resilience, technical and legal.** Counterlure is designed to burn active operatives, so we fully expect sustained pushback from sophisticated malicious actors, including state-sponsored ones. Defending this infrastructure takes continuous hardening against DDoS, infiltration and targeted exploits, and a dedicated legal war chest to fight off SLAPP suits, abusive takedown demands and jurisdictional pressure.

We don't run ads, sell data or take VC money that could be pressured into shutting the registry down. Member-funded lifetime accounts directly bankroll the code defence and legal armour that keep the service alive. The same explanation is on the website: <https://www.counterlure.com/#why-price>.

## Screening a photo (members)

```bash
counterlure login                  # username, then the 6-digit authenticator code
counterlure check a.jpg b.jpg      # every face in every photo
counterlure check --json a.jpg     # for pipelines
counterlure whoami
counterlure logout                 # revokes the session server-side and deletes it locally
```

An account opened on the website ([counterlure.com/join](https://www.counterlure.com/join)) works here too, and the other way round. A session lasts 24 hours and is stored in `~/.config/counterlure/session.json` (Windows: `%APPDATA%\counterlure\session.json`), mode 0600 on Linux and macOS. Checks are limited to 50 per member per day.

The server answers with a level only, `strong` or `possible`, and the source type (corroborated case or burn notice). It returns no similarity scores, so repeated queries with doctored images can't be used to walk toward a reported face.

Screening only covers corroborated material. A face reported once, by one person, will not match. That is deliberate: a single report is an allegation, and the watchlist is not a tool for checking up on a name someone gave you once.

## Messages to the team (members)

```bash
counterlure send "The profile I reported last week now uses a second handle"
counterlure send --subject "Payment" "I sent the wrong amount, tx ..."
counterlure send < notes.txt                   # from a file or a pipe
counterlure send                               # type it; finish with a line holding only "."
counterlure inbox                              # the conversation, oldest first; --all for everything
counterlure whoami                             # also shows how many replies are unread
```

A message lands in the Counterlure team's inbox. Replies come back to `counterlure inbox`, and to the inbox on the website, which shows the same conversation. Messages are encrypted at rest, up to 4,000 characters each, 20 a day.

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

**The crop.** The photo is decoded to raw pixels, rotated upright, cut down to the chosen face plus a margin, and encoded as a new JPEG of at most 480 px. The margin shrinks if it would take in another detected face. Because the output is built from pixels and not copied from the source file, no EXIF, GPS position, device serial, colour profile or embedded thumbnail can survive into it. Check this yourself with `--dry-run --save-crop crop.jpg` and any metadata viewer. `check` and `org report` send no image at all, only the 128-number face template, so there is no photo metadata to leak.

The website's report form does the same in the browser: the photo is decoded and redrawn on a canvas and re-encoded as a new JPEG before upload, so EXIF, GPS, device data, thumbnails and the original file name never leave the device. The server re-encodes every upload again on arrival.

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
| Limit | 20 per member per day | 25 an hour and 150 a day across the service, shared by everyone |
| Match result returned | no | no |

Unattributed intake is where a corroboration system gets attacked: script a few hundred reports against one face and hope the volume reads as independent sourcing. So every unattributed CLI report shares a single source identity. However many are filed, they add up to one source, and a case needs at least three independent sources including a member, or five from anyone, before an analyst even looks at it. Anonymous CLI reports can strengthen a case but cannot create one.

Each unattributed report also carries a proof-of-work stamp, a SHA-256 partial preimage bound to that request's one-time nonce, so it can't be precomputed or reused. The default is 21 bits, about two million hashes. If the service raises the bar, the tool retries once at the level it names, and it refuses to go past 26 bits whatever it is told.

Filing a report never returns a match result, whether you are signed in or not. Reporting is not a side channel into the watchlist.

### Abuse and moderation

A service that accepts photos from strangers will be sent things it should never hold: floods of junk meant to run up costs or bury real reports, and pornography or child sexual abuse material sent on purpose to get the service taken down. Every report photo goes through the same screen on the server, whether it came from this tool or the website, before anything is stored.

**What the screen refuses.**

| Refused | What happens |
|---|---|
| Blank, tiny or featureless images | Refused by a local check before any paid classifier sees them. Floods of near-empty images cost almost nothing to turn away. |
| No face, or more than one prominent face | Refused, with a message saying how to fix the photo. |
| Sexual content or nudity | Refused. If the only photo you have is explicit, crop it to the face first. |
| Graphic violence or gore | Refused. |
| A person who appears to be under 18 | Refused. Counterlure only accepts reports about adults. |
| A minor together with any sexual or suggestive content | Refused with a message that gives no reason, and the reporter is suspended at once. |

**Nothing refused is kept.** A refused photo is never written to storage and no person ever looks at it. The server records the outcome, the classifier's label names and scores, and, for sexual, violent or abusive refusals, a SHA-256 hash of the file. The hash goes on a blocklist, so the same file sent again is refused straight away without being classified again.

**Only the face is stored.** Even an accepted photo is not kept whole. The server cuts it down to the face plus a small margin, and that crop is the only image sealed and indexed. This tool already sends only a face crop, so in practice the server's cut changes little for CLI reports.

**Repeat senders are cut off.** Refusals count as strikes against the reporter: the member, the website visitor, or the shared identity of all unattributed CLI reports. One child-abuse refusal, or a few sexual or violent ones in a month, suspends reporting from that source until an administrator reviews it. Many refusals of any kind in a day pause it until the next day. The service also has a daily ceiling on photo checks, so a flood cannot run up an unbounded bill. When the ceiling is reached, reports are turned away until the next day.

**Fails closed.** If the content classifier is unavailable, reports are refused with a "try again later" error. They are never accepted unscreened.

**Screening a photo is different.** `counterlure check` never sends an image, only a 128-number template computed on your machine, so there is nothing on that path to moderate. It has its own daily limit per member.

Automated classifiers make mistakes in both directions. If a genuine photo of an adult is refused, crop it more tightly to the face and try again, or send a message to the team.

## Organization / Enterprise mode (Cluster Defense)

> **For Security Teams, CISOs, and AppSec Reviewers:** See the exhaustive **[Enterprise Cluster Defense Manual (ENTERPRISE.md)](ENTERPRISE.md)** for full cryptographic architecture, portal deployment instructions, incident response playbook, copy-pasteable staff rollout memo, and AppSec code audit checklist.

Organizations enrolled in [Counterlure Enterprise](https://www.counterlure.com/enterprise) distribute an internal enrollment code to their staff so engineers, researchers, and executives can screen and report suspicious contacts with **zero-knowledge employee anonymity**:

```bash
counterlure org enroll CLORG-XXXX-XXXX    # receive an anonymous per-device credential
counterlure org check photo.jpg           # screen against org alerts + global Counterlure pool
counterlure org report photo.jpg --context work-or-business
counterlure org inbox                     # read private alerts (including org-under-attack notices)
counterlure org status                    # aggregate org threat posture & unread alerts
counterlure org withdraw CLO-...          # withdraw an organization report by receipt
counterlure org leave                     # delete the local device credential
```

- **Zero employee PII**: No name, corporate email, or IP address is ever collected on employee devices.
- **No photos leave your machine**: `org report` sends only the 128-number mathematical face template, stored strictly inside your organization's private namespace.
- **Dual-tier escalation (threshold = 3)**: Single reports remain completely private. Only when **3 distinct anonymous devices** within your organization independently report the same face does the cluster promote to the global Counterlure pool, alert your security team (case reference and count only — no photos, names, or reporters), and send a private message to your `org inbox` advising you to step forward to your security team.

### Why staff need an outside channel

Studies of employee security reporting find that staff notice suspicious approaches and still say nothing, because reporting costs them more than silence:

- **Fear of blame and liability** (Burda et al., Eindhoven University of Technology, 2025): employees hold back for fear of being blamed, and because they are unsure an approach is truly malicious.
- **Not at their own expense** (Carleton University, 2024): staff feel a strong pull to do nothing, out of fear of retaliation, social friction, and personal scrutiny.
- **Distrust of internal confidentiality** (International Journal of Critical Infrastructure Protection, 2018): low confidence that reports stay confidential, and fear of a false alarm, suppress formal reporting.
- **Shame and peer disapproval** (University of Sussex & University of Auckland, 2020): shame and fear of colleagues' judgment deter admitting engagement with a lure.
- **Privacy and handling friction** (RAID '24): uncertainty over how reports are handled, and reluctance to expose personal message threads, reduce reporting.

Counterlure is an independent, external tool: the employer never learns who reported, never sees a photo or a message thread, and hears nothing until at least three people independently report the same face.

### Licensing and why there is no sales team

Licenses are one-time and lifetime, sized by seats (one enrolled device or one unused enrollment code): Small enterprise, up to 25 seats, $50,000 ($2,000 per seat); SME, up to 200 seats, $250,000 ($1,250 per seat); Large organization, up to 5,000 seats, $500,000 ($100 per seat). 50% off every license paid by December 31, 2026. Moving up later costs the difference.

Counterlure runs unattended, enterprise included: no sales calls, demos, account managers, or named staff. Operating a tool that exposes recruitment and honeypot campaigns makes its operators a target, so opsec comes first, and it starts with staying anonymous. Payment on public blockchains serves the same end: no card processor or bank account ties the register to a person. Blockchain transfers are public and traceable; this protects the operators' identities, not the privacy of a payment. Details in [ENTERPRISE.md](ENTERPRISE.md).

## Network: no address of yours reaches us

By default the tool talks only to Counterlure's onion service:

```
4qcqgpa4o6gc7yhqvqvdndx7jeeplsishebyxwf3667kphalxxtvfkad.onion
```

The request goes from the Tor on your computer through Tor relays to Tor on our server, which hands it to a listener on 127.0.0.1 that serves nothing but this tool's API. It never touches Cloudflare, a load balancer or any public address of ours. It arrives from localhost, so there is no address of yours in it to log, store or hand over. The onion address is itself the service's public key, so no relay can impersonate us, and the OpenPGP layer works the same as on any other route.

Each run uses its own Tor circuit (SOCKS isolation), so the tool never shares a path with your browser. Hostnames go to Tor unresolved: no DNS query about us leaves your machine. The tool refuses to contact an `.onion` address any way except through SOCKS, and if Tor isn't running it stops with instructions instead of trying another route.

Other routes, when you ask for them:

```bash
counterlure --direct whoami                          # the website, www.counterlure.com, through Cloudflare
counterlure --direct --tor whoami                    # the website, through Tor
counterlure --direct --proxy socks5h://127.0.0.1:1080 whoami
COUNTERLURE_TOR=10.0.0.5:9050 counterlure whoami     # Tor running somewhere other than 9050 or 9150
```

On `--direct` without Tor or a proxy, Cloudflare (which fronts the website) sees your address. The service itself does not keep it: no CLI operation records or rate-limits by network address, on any route.

The whole network path is [lib/net.js](lib/net.js) and [lib/route.js](lib/route.js), with no third-party dependencies. The model download takes the same route.

## Reading a result

* A match is a lead, not an identification. Faces resemble each other, and recognition degrades on small, blurred, off-angle or filtered images. Corroborate through other means before acting.
* No match is not a clearance. Only faces that have been reported and corroborated can match.
* Do not confront, harass or publish anyone on the strength of a result. If you have new information, file it.

## Threat model

Protected:

* **Your photo**, on `check`. It never leaves the machine.
* **Everything beyond the face**, on `report`. Background, bystanders, location and device metadata stay with you.
* **Your network address.** On the default onion route it never reaches us. On `--direct` it reaches Cloudflare, but not our records.
* **Content in transit.** On the onion route Tor encrypts end to end; on `--direct`, TLS ends at Cloudflare's edge. Either way the OpenPGP layer inside means relays, the edge and proxies see only fixed-size ciphertext.
* **Integrity of answers.** A reply must be signed by the pinned key, encrypted to the one-time key generated for that request, and echo its nonce. Anything else is discarded.
* **Replay.** The service accepts each nonce once, within five minutes of its clock.
* **The origin.** The tool talks to the onion service, or to `www.counterlure.com` behind Cloudflare. No origin address is in this repository.

Not protected:

* **Who checked.** On `check` the service knows which member asked, though it keeps no record of what was asked.
* **Your address on `--direct`**, from Cloudflare, unless you add `--tor` or `--proxy`.
* **Your payment.** Blockchains are public. The transaction is linked to your account in our records, and anyone who knows your wallet can see it on chain. Pay from a wallet that isn't tied to your name if that matters to you.
* **The face itself, on `report`.** A face crop is personal data about the person reported. It is held encrypted, used for matching, and destroyed on withdrawal. File only on people who actually approached you.
* **A compromised endpoint.** If your machine is compromised, nothing here helps.

## Verifying the server key and onion address

`counterlure key` prints the pinned fingerprint and the onion address. Compare it against at least two independent sources: the [CLI section of the website](https://www.counterlure.com/#cli), the key served at <https://www.counterlure.com/api/cli/key>, and the tagged release on GitHub. The tool checks the compiled-in key against the pinned fingerprint before every request.

## Testing against your own server

`COUNTERLURE_URL` points the tool at another server and `COUNTERLURE_SERVER_KEY` at a file holding its public key. The tool warns on every run while either is set. `--server URL` does the same as `COUNTERLURE_URL` for one run. Plain `http://` is accepted only for `localhost` and `.onion` addresses.

```bash
npm test
```

## Supporting the project

The CLI is free and open source, and filing a report is free. If you want to help keep Counterlure
running without opening an account, you can send a contribution through Fluidkey:
<https://counterlure.fkey.id>

Any amount helps. Fluidkey gives you a fresh address each time, so contributions don't sit together
in one public wallet. A contribution doesn't buy membership or any feature, and it never affects
how a report is reviewed. Check that the address is `counterlure.fkey.id` before you send: we never
ask for funds anywhere else, and never by message.

## Licence

Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Versions up to 0.3.0 were released under MIT and stay under MIT.

You may read, run, change and share the code. The licence gives no right to the Counterlure name: a changed copy must not call itself Counterlure or the official CLI. Only releases from this repository are official, and only they hold the pinned server key that checks every reply comes from Counterlure.

The models are not distributed here. You get them from OpenCV's model zoo yourself, or the tool fetches them from there once you agree: YuNet under MIT, SFace under Apache 2.0.
