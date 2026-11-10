# 🛡️ Skill-AI — Enterprise Agent Skills Repository

Production-grade AI Agent Skills engineered for **Antigravity**, **Claude Code**, **Cursor**, and **Codex**.

---

## 📂 Repository Structure

```text
skill-ai/
├── README.md                                                  # Repository index & installation guide
├── skill-router                                               # Intelligent skill routing & comparison engine (v3.0)
└── sovereign-auth-architect/                                  # Tier-0 Zero-Trust Account & Authentication Architect
    ├── SKILL.md                                               # Primary agent skill instructions & execution workflow
    ├── BLUEPRINT.md                                           # Comprehensive architectural blueprint (Arabic reference)
    └── references/                                            # Modular copy-pasteable engineering specifications (7 modules)
        ├── 01-identity-validation-and-forbidden-words.md      # Multi-identifier intake, Gmail/E.164 normalization & 5-category blocklist
        ├── 02-password-cryptography-and-strength.md           # Bounded scrypt/bcrypt worker queue, constant-time dummy hash & zxcvbn
        ├── 03-rate-limiting-lockout-and-antifraud.md          # Dual-bucket rate limiting, progressive lockout & identity graveyard
        ├── 04-otp-2fa-and-email-architecture.md               # Salted HMAC-SHA256 OTP, RFC 6238 TOTP, trusted devices & hardened SMTP
        ├── 05-sessions-jwt-csrf-and-rbac.md                   # Opaque __Host- sessions, JWT rotation, <2ms revocation, CSRF & RBAC
        ├── 06-database-schemas-and-api-contracts.md           # Complete 14-model Prisma/SQL schema, REST API contracts & 12-test suite
        └── 07-advanced-zero-trust-and-passkeys.md             # Passkeys (WebAuthn), Sudo Mode, 72h email revert, freeze & 14d soft-delete
```

---

## 🚀 Included Skills

### 1. [`sovereign-auth-architect`](./sovereign-auth-architect/SKILL.md) — Sovereign Account & Authentication System
An end-to-end, financial-grade authentication and account management skill encompassing **13 Core Pillars + 8 Zero-Trust Extensions**:

- **Multi-Identifier Intake & 5-Category Forbidden Dictionary:**
  - Single-field login supporting **Email OR Username OR Phone Number (`E.164`)**.
  - **Gmail Canonicalization** (dot `.` stripping, `+tag` removal, `@googlemail.com` normalization) + trusted provider whitelist + `.edu`/`.gov` support + 25+ disposable email domain blocklist.
  - **Unicode Homograph, Zero-Width & Leet-Speak Sanitizer** (`NFKC` normalization, Cyrillic/Greek confusable folding, invisible/bidi character stripping) + **5-Category Bilingual Blocklist** (System/Admin reserved handles, English profanity, Arabic & Franco-Arab/Arabizi profanity, sacred religious terms, and global brand names) + dynamic `ProfileSubstringBan`.
- **Password Cryptography & DoS-Resilient Hashing:**
  - `scrypt` (`N=131072, r=8, p=1, 64B`) or `bcrypt` (`12 rounds`) protected by a **Bounded Worker Queue** (max 2 active + 8 queued; excess requests fail fast with `503 AUTH_BUSY` to prevent CPU/RAM exhaustion).
  - Memory buffer zeroization (`Buffer.fill(0)`), constant-time dummy hash verification (`verifyAgainstDummyPassword`), contextual `zxcvbn` scoring, privacy-preserving **k-Anonymity HaveIBeenPwned** check, and **Last-1 Password Reuse Prevention (`previousPasswordHash`)**.
- **Dual-Bucket Rate Limiting, Anti-Fraud & Permanent Identity Graveyard:**
  - Dual-Bucket (`IP` + `SHA-256(identifier)`) sliding limits across all auth endpoints with Redis primary + bounded 10,000-entry memory fallback (`OWASP API4:2023`) and standard RFC `429` headers.
  - Minimum **8-second response floor** (`withMinimumDuration(8000)`) on password reset requests to eliminate SMTP timing side-channels.
  - Account-level progressive lockout (`lockedUntil` after 5 failed attempts), Honeypot + Cloudflare Turnstile / reCAPTCHA, MaxMind minFraud scoring, referral IP anti-farming, and a **Permanent `RegisteredIdentity` Graveyard** that survives account deletion to prevent free-trial abuse and ban evasion.
- **Sovereign OTP, Dual-Channel 2FA & WebAuthn Passkeys:**
  - Automatic Eastern Arabic (`٠-٩`) and Persian (`۰-۹`) numeral normalization preserving leading zeros.
  - **Purpose-Bound Salted HMAC-SHA256 OTP Storage** with `SELECT ... FOR UPDATE` row-level locking, 60-second resend cooldown, and automatic code burn after **5 failed attempts**.
  - **Dual-Channel 2FA (`RFC 6238 TOTP` + `Email OTP`)** with `lastTotpStep` anti-replay protection, **WebAuthn / Passkeys (`FIDO2`)** with `signCount` clone detection, Admin 2FA policy governance with **Anti-Trap Checkpoint Guard**, 8 single-use recovery codes, `AES-256-GCM` encrypted **Trusted Device Cookie** (`30d`), and a 15-minute Admin Emergency Bypass Code with **Supreme Admin Guard**.
- **Sessions, `<2ms` Global Revocation, Zero-Trust Controls & RBAC:**
  - Hardened `__Host-session` cookies or `JWT Access (15m) + Refresh Token Rotation (1d/30d)` with **Reuse Detection** and `<2ms` global session revocation via `tokenVersion` bumping + zero-downtime `kid` key rotation.
  - **Step-Up Authentication (`Sudo Mode` — 10m window)** for sensitive actions, **Dual-Handshake Email Change** with a **72-hour single-click Emergency Revert Link**, **Impossible Travel & New-Device Detection** with one-click **Emergency Account Freeze**, **Cryptographic Admin Impersonation (`Shadow Session`)**, and a **14-Day Soft-Delete Grace Period (`PENDING_DELETION`)**.
  - Dual-Phase CSRF protection, hierarchical RBAC (`sortOrder`), bitwise `AccountPermission` flags, 48-hour `SubAccountInvitation` team flows, OAuth unlink lockout prevention, inline **Unverified Account Recovery Banner**, and a full **Account Security Center** (`0–100` Security Health Score, Active Device Manager, Audit Log, and `GDPR/PDPL` JSON data export).

📖 **Additional Documentation:**
- **Skill Specification (English):** [`sovereign-auth-architect/SKILL.md`](./sovereign-auth-architect/SKILL.md)
- **Architectural Blueprint (Arabic):** [`sovereign-auth-architect/BLUEPRINT.md`](./sovereign-auth-architect/BLUEPRINT.md)

---

### 2. [`skill-router`](./skill-router) — Intelligent Skill Router (v3.0)
Context-aware routing engine that compares installed skills, selects the optimal workflow (Comparison, Auto-Pilot, or Hybrid mode), and chains multiple skills sequentially.

---

## ⚙️ Installation

Clone this repository and copy the desired skill into your agent's skills directory:

### Windows (PowerShell)
```powershell
git clone https://github.com/qsaiwolf/skill-ai.git
Copy-Item -Path ".\skill-ai\sovereign-auth-architect" -Destination "$HOME\.gemini\config\skills\sovereign-auth-architect" -Recurse -Force
```

### macOS / Linux
```bash
git clone https://github.com/qsaiwolf/skill-ai.git
cp -r ./skill-ai/sovereign-auth-architect ~/.gemini/config/skills/sovereign-auth-architect
```

*(For Claude Code, copy into `~/.claude/skills/sovereign-auth-architect` or `.claude/skills/sovereign-auth-architect`).*

---

## 💻 Usage

Invoke `sovereign-auth-architect` in any new or existing project by prompting your agent:

```text
Design and implement the complete login, registration, and account security system using sovereign-auth-architect.
```
