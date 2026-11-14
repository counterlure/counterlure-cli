# counterlure-cli

Command-line access to [Counterlure](https://www.counterlure.com), a register of honeypot and social-engineering approaches against people in tech.

Counterlure looks for one face turning up under different names. Reports come in from people who were approached. When enough independent sources report the same face, an analyst reviews the case, and corroborated cases can end in a published burn notice. From a terminal you can:

* **Open an account** with a username and an authenticator app, and pay for it in crypto. No email, phone number or name, ever.
* **Screen** a photo against corroborated cases and burn notices without the photo leaving your machine. This needs an account.
* **File** a report on a face. This needs no account at all.
* **Write to the Counterlure team** and read their replies.

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

Every request is OpenPGP-encrypted to a server key compiled into the tool and padded to a fixed size: 16 KB for control traffic, 224 KB for every report regardless of the photo. Anyone on the path (a Tor relay, or on `--direct` Cloudflare's edge and your ISP) sees that a client talked to the service and when, but not what was asked or answered, and not whether a check was a hit.

## Install

Node.js 22 or later.

```bash
git clone --branch v0.3.1 --depth 1 https://github.com/counterlure/counterlure-cli.git
cd counterlure-cli
npm ci
npm link
```

The first `check` or `report` pulls the two models (39 MB) from OpenCV's repository and verifies each against a SHA-256 hash pinned in [lib/faceprint.js](lib/faceprint.js). A file that fails verification is deleted before it is ever loaded. Run `counterlure models` to fetch them in advance. The download takes the same route as everything else (see below).

You also need Tor running on the same computer: either [Tor Browser](https://www.torproject.org/download/) left open, or the tor service (`apt install tor`, `brew install tor && brew services start tor`). The tool finds it on 127.0.0.1:9050 or 9150 by itself. Without Tor it stops and says so; it never quietly falls back to the website.

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
| Limit | 20 per member per day | 25 an hour and 150 a day across the service, shared by everyone |
| Match result returned | no | no |

Unattributed intake is where a corroboration system gets attacked: script a few hundred reports against one face and hope the volume reads as independent sourcing. So every unattributed CLI report shares a single source identity. However many are filed, they add up to one source, and a case needs at least three independent sources including a member, or five from anyone, before an analyst even looks at it. Anonymous CLI reports can strengthen a case but cannot create one.

Each unattributed report also carries a proof-of-work stamp, a SHA-256 partial preimage bound to that request's one-time nonce, so it can't be precomputed or reused. The default is 21 bits, about two million hashes. If the service raises the bar, the tool retries once at the level it names, and it refuses to go past 26 bits whatever it is told.

Filing a report never returns a match result, whether you are signed in or not. Reporting is not a side channel into the watchlist.

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

## Licence

Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Versions up to 0.3.0 were released under MIT and stay under MIT.

You may read, run, change and share the code. The licence gives no right to the Counterlure name: a changed copy must not call itself Counterlure or the official CLI. Only releases from this repository are official, and only they hold the pinned server key that checks every reply comes from Counterlure.

The models are not distributed here. They are fetched from OpenCV's model zoo: YuNet under MIT, SFace under Apache 2.0.
