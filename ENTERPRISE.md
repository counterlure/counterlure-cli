# Counterlure Enterprise Cluster Defense — Complete Organization Manual

> **Audience:** CISOs, Insider Threat Leads, Corporate Security Teams, General Counsel, AppSec Reviewers, and Enrolled Staff.  
> **Portal:** <https://www.counterlure.com/org> · **Apply:** <https://www.counterlure.com/enterprise>  
> **License:** Open-source Apache-2.0 CLI (`counterlure-cli`)

---

## 1. Executive Threat Brief: The Human-Layer Blindspot

Modern enterprise security stacks (EDR, DLP, SIEM, email gateways, PAM) monitor **corporate devices and corporate networks**. They have zero visibility into the **personal human layer** where modern clandestine recruitment and industrial espionage actually begin:

- A researcher meets an engaging "investor" or "fellow academic" at an AI or semiconductor conference.
- A cleared engineer receives a warm approach from a "specialist recruiter" on LinkedIn who moves the conversation to WhatsApp or Telegram.
- An executive matches with a plausible, articulate persona on a dating app who gradually asks casual questions about roadmaps, travel, or colleagues.

Intelligence services and organized espionage groups rarely target one person in isolation. They run **cluster campaigns**: the same operative — using the same face, often under different cover names — approaches **multiple staff inside the same organization in parallel**.

### Why Traditional Hotlines Fail (The Silence Paradox)
Employees almost never report suspicious personal contacts to HR or Corporate Security. They fear embarrassment, HR scrutiny, security-clearance review, or appearing foolish if the person turns out to be harmless. That silence lets an operative work down an org chart uncontested until proprietary work leaves the building.

**Counterlure Enterprise breaks that silence by making employer surveillance mathematically impossible.**

---

## 2. Cryptographic & Zero-Knowledge Architecture

Counterlure Enterprise operates on a **Dual-Tier Clustering** architecture backed by strict cryptographic guarantees:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EMPLOYEE'S LOCAL MACHINE                         │
│                                                                         │
│   Photo (JPG/PNG/WebP) ──► YuNet Face Detection + SFace 128-d Vector    │
│   [Photo NEVER leaves       (SHA-256 pinned ONNX models, local CPU)     │
│    employee's machine]                        │                         │
│                                               ▼                         │
│                       OpenPGP Encrypted to Pinned Server Key            │
│                       + Fixed-Size Padding (no size side-channel)       │
│                       + Routed over Tor Onion Service (no client IP)    │
└───────────────────────────────────────────────┬─────────────────────────┘
                                                │
                                                ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   ORGANIZATION PRIVATE NAMESPACE (Tier 1)               │
│                                                                         │
│   • Isolated strictly to your org_id (invisible to public & other orgs) │
│   • Stores ONLY the 128-d face vector + anonymous random device_id      │
│   • NO employee name, NO corporate email, NO photo, NO IP address       │
│   • Single reports (1 or 2 staff) remain 100% private & invisible       │
└──────────────────────────┬──────────────────────────────────────────────┘
                           │
         Only when 3+ DISTINCT anonymous devices report the same face
                           │
          ┌────────────────┴────────────────┬─────────────────────────────┐
          ▼                                 ▼                             ▼
┌───────────────────┐          ┌─────────────────────────┐     ┌────────────────────┐
│  GLOBAL POOL      │          │  ORG SECURITY TEAM      │     │  REPORTING STAFF   │
│  (Tier 2)         │          │  (Email + /org Portal)  │     │  (CLI org inbox)   │
│                   │          │                         │     │                    │
│ 128-d vector      │          │ Alert: ORG-XXXX         │     │ Private message:   │
│ promoted to       │          │ Distinct reports: 3+    │     │ "Your org appears  │
│ global watchlist  │          │ Severity: ELEVATED/HIGH │     │  to be under       │
│ for cross-case    │          │                         │     │  attack — please   │
│ matching          │          │ ZERO photos, ZERO names │     │  contact your      │
│                   │          │ ZERO employee IDs       │     │  security team."   │
└───────────────────┘          └─────────────────────────┘     └────────────────────┘
```

### Exact Data-Flow Matrix

| Data Type | Leaves Employee Machine? | Stored by Counterlure? | Visible to Employer (`/org`)? |
|---|---|---|---|
| Employee name / corporate email | **Never** | **Never** | **Never** |
| Employee IP address | **Never** (Tor onion default) | **Never** | **Never** |
| Face photo / image bytes | **Never** (in `org check` & `org report`) | **Never** | **Never** |
| 128-d mathematical face vector | Yes (OpenPGP encrypted) | Yes (isolated to org until threshold) | **Never** |
| Anonymous random device token | Yes (OpenPGP encrypted) | SHA-256 hash only | **Never** (aggregate count only) |
| Single / uncorroborated report (1–2 staff) | Vector only | Private org namespace | **Never** |
| Corroborated campaign (3+ distinct staff) | — | Promoted to global pool | **Case ref (`ORG-XXXX`), count, severity, dates only** |

---

## 3. Security Admin Onboarding & Portal Guide (`/org`)

### Step 1 — Corporate Application & Domain Verification
1. Apply at <https://www.counterlure.com/enterprise> using an authorized **corporate email address** matching your organization's domain (consumer/free-mail domains are rejected).
2. Click the verification link sent to your corporate inbox to prove domain ownership.
3. Once approved and onboarded by Counterlure, you will receive an activation email with access to the **Organization Security Portal** at <https://www.counterlure.com/org>.

### Step 2 — Signing In to the Security Portal
- Visit <https://www.counterlure.com/org> and enter your verified corporate email.
- Enter the one-time **6-digit sign-in code** delivered to your corporate inbox (passwordless authentication; expires in 15 minutes; HttpOnly `SameSite=Strict` encrypted session).

### Step 3 — Distributing the In-House CLI Enrollment Code
Inside `/org`, the **In-House CLI Distribution** panel shows:
- **Active enrollment code** (e.g. `CLORG-XXXX-XXXX`)
- **Copyable staff command** (`counterlure org enroll CLORG-XXXX-XXXX`)
- **Enrolled anonymous device count** (aggregate total only — never tied to individuals)
- **Rotate enrollment code** button

> **Operational Best Practice:** Distribute the enrollment code over your internal wiki, intranet, Slack/Teams `#security-announcements`, or MDM software catalog. Rotating the enrollment code invalidates the old code for *new* enrollments while keeping all already-enrolled anonymous employee devices working without interruption.

### Step 4 — Reading Threat Posture & Managing Alerts
The `/org` portal displays a live **Threat Posture** banner:
- **ALL CLEAR** (`none`): No face has reached the corroboration threshold.
- **ELEVATED**: 1 active coordinated campaign (3 distinct staff).
- **HIGH**: 2+ active campaigns, or 4+ distinct staff targeted by the same face.
- **CRITICAL**: 3+ active campaigns, or 6+ distinct staff targeted by one face, or 10+ total targeted reports across active campaigns.

Each promoted alert shows its reference (`ORG-XXXX`), distinct report count, first/last seen dates, and status (`promoted` → `acknowledged` → `resolved`).

### Step 5 — Incident Response Playbook (When an Alert Fires)
1. **Do NOT hunt for who filed the report.** Attempting to correlate network logs or endpoint telemetry destroys staff trust and defeats the program.
2. **Wait for voluntary disclosures — and make it safe.** The moment an alert fires, Counterlure automatically sends a private message to every reporting employee's `counterlure org inbox` advising them to contact your security team voluntarily.
3. **Publish a calm internal advisory** (optional for `HIGH`/`CRITICAL`): Remind staff that your organization has detected a coordinated external approach campaign and provide a confidential, no-blame channel to speak with Security.
4. **Correlate with Counterlure**: Quote your `ORG-XXXX` reference when coordinating with Counterlure analysts for broader cross-industry context.

---

## 4. Employee Quick-Start Guide

### Installation (Node.js 22+ and Tor)
```bash
git clone --branch v0.4.1 --depth 1 https://github.com/counterlure/counterlure-cli.git
cd counterlure-cli
npm ci
npm link
```
Ensure Tor is running locally (Tor Browser open, or `tor` service on port 9050/9150). To verify models in advance:
```bash
counterlure models
```

### Everyday Commands for Staff
```bash
# 1. One-time anonymous device enrollment (run once with your company's code)
counterlure org enroll CLORG-XXXX-XXXX

# 2. Screen a suspicious contact's photo against BOTH your org's alerts and the global pool
#    (Photo stays on your machine; only the 128-d face vector is sent)
counterlure org check contact.jpg

# 3. File a zero-knowledge anonymous report inside your org's private namespace
#    (No photo, no name, no employee identity leaves your machine)
counterlure org report contact.jpg --context work-or-business
# Contexts: dating-app, social-media, event-or-conference, work-or-business, introduced, other

# 4. Check your private CLI inbox for coordinated-attack alerts
counterlure org inbox

# 5. Check aggregate org threat status & unread private alerts
counterlure org status

# 6. Withdraw a report at any time using the receipt you were given
counterlure org withdraw CLO-XXXX-XXXX-XXXX-XXXX

# 7. Remove the local anonymous device token from your machine
counterlure org leave
```

> **Shortcut:** If your machine is enrolled in an organization and not signed in to a personal Counterlure account, `counterlure check PHOTO`, `counterlure inbox`, and `counterlure whoami` automatically route to your anonymous organization device.

---

## 5. Copy-Pasteable Internal Rollout Memo (For CISOs / Security Teams)

> **Subject:** New Optional Privacy-First Tool to Screen Suspicious External Contacts
>
> Team,
>
> Like other leading technology and R&D organizations, our people are occasionally approached outside work — at conferences, on LinkedIn, messaging apps, or dating platforms — by sophisticated actors fishing for technical or strategic information.
>
> To help you protect yourself without ever having to share personal details with the company, we have enrolled in **Counterlure Enterprise**. It is an open-source command-line tool that lets you:
>
> 1. **Screen** a suspicious contact's photo against known global honeypots and active campaigns (`counterlure org check photo.jpg`).
> 2. **Report** an uneasy approach completely anonymously (`counterlure org report photo.jpg`).
>
> **Your privacy is guaranteed by math, not policy:**
> - **No employee identity:** The tool never asks for your name, corporate email, or SSO login.
> - **No photos leave your computer:** Only a 128-number mathematical face vector is sent, encrypted with OpenPGP over Tor.
> - **No employer visibility into individual reports:** Security never sees single reports, photos, or who used the tool. We are only notified if **3 or more distinct colleagues** independently report the exact same face — at which point you also receive a private alert in `counterlure org inbox` so you can choose to reach out to Security.
>
> **Get started in 60 seconds:**
> 1. Inspect or install the open-source CLI: <https://github.com/counterlure/counterlure-cli>
> 2. Enroll anonymously: `counterlure org enroll <INSERT_YOUR_CODE>`
>
> — *Your Security Team*

---

## 6. AppSec Code Audit Checklist

Before approving `counterlure-cli` for internal deployment, your AppSec team can audit the entire client in under 20 minutes:

| File | What to verify |
|---|---|
| `bin/counterlure.js` | `orgReportCmd` and `orgCheckCmd` transmit **only** `face.embedding` (128 floats) — never raw image buffers, filenames, usernames, or environment variables. Local credential `org.json` is written `0600` and bound to the pinned server key fingerprint. |
| `lib/faceprint.js` | Local YuNet + SFace ONNX inference; SHA-256 hashes of model weights are hardcoded and verified before loading. |
| `lib/models.js` | Model downloads only follow redirects to GitHub and delete any file failing SHA-256 verification. |
| `lib/proto.js` | End-to-end OpenPGP encryption to `SERVER_FINGERPRINT` (`lib/server-key.js`), single-use nonces, and fixed-size payload padding. |
| `lib/route.js` | Defaults strictly to Counterlure's Tor v3 `.onion` service; never silently falls back to clearnet. |
| `test/*.test.js` | Run `npm test` locally to verify all 24 transport, padding, format, and Tor isolation tests. |
