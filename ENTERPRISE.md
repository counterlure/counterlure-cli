# Counterlure Enterprise — Organization Manual

> **Audience:** CISOs, Insider Threat Leads, Corporate Security Teams, AppSec Reviewers, and Enrolled Staff  
> **Portal:** <https://www.counterlure.com/org> · **Apply:** <https://www.counterlure.com/enterprise>  
> **Client:** Open-source Apache-2.0 CLI (`counterlure-cli`)

---

## 1. Threat Model: Off-Platform Human Targeting

Strategic competition has shifted. Proprietary research, foundation models, chip designs, source code, and corporate data are now primary targets for state-sponsored intelligence services alongside traditional military assets. When perimeter defenses and endpoint controls hold, collection shifts to the people who have access.

EDR, DLP, SIEM, and email gateways monitor corporate devices and corporate networks. They do not see who is approaching your engineers, researchers, and executives off-platform:

- A researcher meets a plausible "investor" or "academic" at an AI, defense, or semiconductor conference.
- A cleared engineer receives a message from a "specialist recruiter" on LinkedIn who moves the conversation to WhatsApp or Telegram.
- An executive matches with a well-researched persona on a dating app who slowly probes roadmaps, travel, or colleagues.

State-sponsored intelligence services and organized espionage groups rarely target one person in isolation. The same operative works multiple staff inside the same organization in parallel using the same face under different cover names.

Traditional security hotlines miss these campaigns because employees rarely report personal approaches to HR or Security. They worry about embarrassment, internal scrutiny, or clearance review if the contact turns out to be harmless. Counterlure Enterprise closes that gap by keeping individual employee reports unattributed and invisible to the employer.

---

## 2. Cryptographic Architecture & Data Boundary

Counterlure Enterprise uses a **Dual-Tier Clustering** model:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EMPLOYEE'S LOCAL MACHINE                         │
│                                                                         │
│   Photo (JPG/PNG/WebP) ──► YuNet Face Detection + SFace 128-d Vector    │
│   [Photo NEVER leaves       (SHA-256 pinned ONNX models, local CPU)     │
│    employee's machine]                        │                         │
│                                               ▼                         │
│                       OpenPGP Encrypted to Pinned Server Key            │
│                       + Fixed-Size Padding (16 KB request envelopes)    │
│                       + Routed over Tor v3 Onion Service (no client IP) │
└───────────────────────────────────────────────┬─────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   ORGANIZATION PRIVATE NAMESPACE (Tier 1)               │
│                                                                         │
│   • Isolated strictly to your org_id (invisible to public & other orgs) │
│   • Stores the 128-d face vector, model, context, day & random device   │
│   • NO employee name, NO corporate email, NO photo, NO IP address       │
│   • Single reports (1 or 2 staff) remain private & invisible            │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
         Only when 3+ DISTINCT anonymous devices report the same face
                           │
          ┌────────────────┴────────────────┬─────────────────────────────┐
          ▼                                 ▼                             ▼
┌───────────────────┐          ┌─────────────────────────┐     ┌────────────────────┐
│  REVIEWER GATE    │          │  ORG SECURITY TEAM      │     │  REPORTING STAFF   │
│  (Tier 2)         │          │  (Email + /org Portal)  │     │  (CLI org inbox)   │
│                   │          │                         │     │                    │
│ Counterlure human │          │ Alert: ORG-XXXX         │     │ Private message:   │
│ reviewer decides  │          │ Distinct reports: 3+    │     │ "Your org appears  │
│ whether the case  │          │ Severity: ELEVATED/HIGH │     │  to be under       │
│ joins the wider   │          │                         │     │  attack — please   │
│ global pool       │          │ ZERO photos, ZERO names │     │  contact your      │
│                   │          │ ZERO employee IDs       │     │  security team."   │
└───────────────────┘          └─────────────────────────┘     └────────────────────┘
```

### Data-Flow Matrix

| Data Type | Leaves Employee Machine? | Stored by Counterlure? | Visible to Employer (`/org`)? |
|---|---|---|---|
| Employee name / corporate email | **Never** | **Never** | **Never** |
| Employee IP address | **Never** (Tor onion default) | **Never** | **Never** |
| Face photo / image bytes | **Never** (in `org check` & `org report`) | **Never** | **Never** |
| 128-d face vector, model version, approach context & attestation | Yes (OpenPGP encrypted, 16 KB padded) | Yes (isolated to org until threshold) | **Never** |
| Anonymous random device token | Yes (OpenPGP encrypted) | SHA-256 hash + enrollment/last-seen day | **Never** (aggregate count only) |
| Single / uncorroborated report (1–2 staff) | Vector + context + token | Private org namespace | **Never** |
| Corroborated campaign (3+ distinct staff) | — | Counterlure reviewer decides on wider pool | **Case ref (`ORG-XXXX`), count, severity, dates only** |

---

## 3. Security Admin Onboarding & Portal Guide (`/org`)

> **No clickable auth links:** Counterlure never sends clickable verification or sign-in links by email. Corporate email checks and first-time portal logins use plain-text 6-digit codes, so corporate email gateways (Proofpoint, Mimecast, Defender Safe Links) cannot consume tokens or flag auth messages as link phishing.

### Step 1 — Corporate Application & 6-Digit Email Verification
1. Apply at <https://www.counterlure.com/enterprise> using an authorized **corporate email address** matching your organization's domain (consumer/free-mail domains are rejected).
2. Enter the **6-digit verification code** sent to your corporate inbox directly on the `/enterprise` page to confirm domain ownership.
3. Once approved by Counterlure, you will receive an activation notice for the **Organization Security Portal** at <https://www.counterlure.com/org>.

### Step 2 — First Sign-In, Mandatory Authenticator (TOTP) & License Activation
1. Open <https://www.counterlure.com/org> and enter your verified corporate email.
2. **First Login (Email OTP):** Enter the one-time **6-digit code** delivered to your corporate inbox (expires in 15 minutes).
3. **Mandatory Authenticator Provisioning (TOTP):** Immediately after email verification, scan the locally generated QR code (or copy the manual Base32 setup key) into your authenticator app (1Password, Microsoft Authenticator, Google Authenticator, or Authy) and confirm with a 6-digit code.
4. **All Subsequent Sign-Ins:** Entering your corporate email prompts directly for your **6-digit authenticator code** (no email OTP is sent again). Sessions use `HttpOnly`, `SameSite=Strict`, `Secure` cookies; 5 consecutive failed TOTP attempts trigger a 15-minute lockout and time-steps cannot be replayed.
5. **License Activation:** On first activation, complete the on-screen settlement step inside `/org` to unlock your Command Center and single-use employee CLI enrollment codes.

> **Lost Authenticator Access?** Email `overwatch@counterlure.com` from your verified corporate address to request an authenticator reset. Counterlure Support will clear the TOTP secret, revoke active sessions, and re-enable one-time email verification so you can provision a new authenticator app.

### Step 3 — Creating and Handing Out Single-Use Enrollment Codes
Inside `/org`, the **Staff Enrollment Codes** panel provides:
- **One-time enrollment codes** (e.g. `CLORG-XXXX-XXXX-XXXX-XXXX`): create one code per employee. Codes are shown once when created; Counterlure stores only a hash and deletes each code the moment it is redeemed, so nothing links a code to the device it enrolled.
- **Aggregate enrolled device count** (total only, never tied to individuals)
- **Cancel unused codes** and **Revoke all devices** controls (in case an unused batch leaks)
- **Pre-filled Staff Memo** under the **Guides & Staff Rollout** tab

> **Operational Security — Use a Personal Device:** Advise staff to install and run `counterlure-cli` on a **personal device on a personal network**, not on a company-managed laptop. Corporate-managed computers, endpoint agents (EDR/MDM), shell history, and corporate networks can observe the installation, command-line history, and Tor traffic even though Counterlure itself collects no employee identity. Give each employee one single-use code directly rather than deploying the CLI through corporate MDM or posting shared codes in Slack/Teams.

### Step 4 — Threat Posture & Alert Triage
The `/org` Command Center displays your live threat posture:
- **ALL CLEAR** (`none`): No face has reached the corroboration threshold.
- **ELEVATED**: 1 active coordinated campaign (3 distinct staff).
- **HIGH**: 2+ active campaigns, or 4+ distinct staff targeted by the same face.
- **CRITICAL**: 3+ active campaigns, or 6+ distinct staff targeted by one face, or 10+ total targeted reports across active campaigns.

Each escalated alert displays its reference (`ORG-XXXX`), distinct report count, first/last seen dates, and status (`promoted` → `acknowledged` → `resolved`).

### Step 5 — Incident Response Playbook (When an Alert Fires)
1. **Do not try to identify who filed the report.** Attempting to correlate network logs or endpoint telemetry breaks staff trust and stops future reporting.
2. **Wait for voluntary disclosures and make coming forward safe.** The moment an alert fires, Counterlure privately notifies every reporting employee via `counterlure org inbox` advising them to contact your security team.
3. **Issue a calm internal advisory** (for `HIGH` or `CRITICAL`): Let staff know Security has detected a coordinated external approach campaign and provide a confidential, no-blame channel to speak with your team.
4. **Coordinate with Counterlure:** Quote your `ORG-XXXX` reference when requesting cross-industry context from Counterlure analysts.

---

## 4. Employee Quick-Start Guide

### Installation (Node.js 22+ and Tor)
```bash
git clone --branch v0.4.1 --depth 1 https://github.com/counterlure/counterlure-cli.git
cd counterlure-cli
npm ci
npm link
```
Ensure Tor is running locally (Tor Browser open, or the `tor` service on port 9050/9150). To pre-download and SHA-256 verify the local face models:
```bash
counterlure models
```

### Everyday Commands for Staff
```bash
# 1. One-time anonymous device enrollment (each code works once; add --replace to overwrite an existing enrollment)
counterlure org enroll CLORG-XXXX-XXXX-XXXX-XXXX

# 2. Screen a suspicious contact's photo against BOTH your org's alerts and the global pool
#    (Photo stays on your machine; only the 128-d face vector and device token are sent)
counterlure org check contact.jpg

# 3. File an anonymous report inside your org's private namespace
#    (Sends the 128-d face vector, model version, context, attestation, and device token; no photo or identity)
counterlure org report contact.jpg --context work-or-business
# Contexts: dating-app, social-media, event-or-conference, work-or-business, introduced, other
# Add --dry-run to inspect what would be sent without sending anything.

# 4. Check your private CLI inbox for coordinated-attack alerts
counterlure org inbox

# 5. Check aggregate org threat status & unread private alerts
counterlure org status

# 6. Withdraw a report at any time using the receipt you were given
counterlure org withdraw CLO-XXXX-XXXX-XXXX-XXXX

# 7. Deactivate this device on the server and remove the local credential (add --withdraw to also remove reports)
counterlure org leave
```

> **Shortcut:** When a machine is enrolled in an organization and not signed in to a personal Counterlure account, `counterlure check PHOTO`, `counterlure inbox`, and `counterlure whoami` automatically use the anonymous organization device.

---

## 5. Internal Staff Rollout Memo Template

> **Subject:** Optional Anonymous Tool to Screen Suspicious External Contacts (Counterlure CLI)
>
> Team,
>
> Like other technology and R&D organizations, our staff are occasionally approached outside work — at conferences, on LinkedIn, messaging apps, or dating platforms — by actors probing for technical or strategic information.
>
> We have deployed **Counterlure Enterprise** so anyone can check or report a suspicious approach without sharing personal details with the company. It is an open-source CLI that lets you:
>
> 1. **Screen** a suspicious contact's photo against known global cases and active campaigns (`counterlure org check photo.jpg`).
> 2. **Report** an uneasy approach anonymously (`counterlure org report photo.jpg`).
>
> **How your privacy is enforced in code:**
> - **No employee identity:** The CLI never asks for your name, corporate email, or SSO login.
> - **No photo uploads:** Photos stay on your machine. Only a 128-number mathematical face vector is transmitted, encrypted with OpenPGP over Tor.
> - **No single-report visibility:** Security never sees single reports, photos, or who used the tool. Security is notified only if **3 or more distinct colleagues** independently report the same face — and you receive a private alert in `counterlure org inbox` so you can decide whether to contact Security.
>
> **Setup:**
> 1. Review or install the open-source CLI: <https://github.com/counterlure/counterlure-cli>
> 2. Enroll anonymously: `counterlure org enroll <INSERT_YOUR_CODE>`
>
> — *Your Security Team*

---

## 6. AppSec Code Audit Checklist

Your AppSec team can audit the entire client in under 20 minutes before approving internal deployment:

| File | What to verify |
|---|---|
| `bin/counterlure.js` | `orgReportCmd` and `orgCheckCmd` transmit **only** `face.embedding` (128 floats) — never raw image buffers, filenames, usernames, or environment variables. Local credential `org.json` is written `0600` and bound to the pinned server key fingerprint. |
| `lib/faceprint.js` | Local YuNet + SFace ONNX inference; SHA-256 hashes of model weights are hardcoded and verified before loading. |
| `lib/models.js` | Model downloads only follow redirects to GitHub and delete any file failing SHA-256 verification. |
| `lib/proto.js` | End-to-end OpenPGP encryption to `SERVER_FINGERPRINT` (`lib/server-key.js`), single-use nonces, and 4 KB fixed-size payload padding. |
| `lib/route.js` | Defaults strictly to Counterlure's Tor v3 `.onion` service; never silently falls back to clearnet. |
| `test/*.test.js` | Run `npm test` locally to verify all 24 transport, padding, format, and Tor isolation tests. |
