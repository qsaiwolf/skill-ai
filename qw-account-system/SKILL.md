---
name: qw-account-system
description: Design, implement, and audit enterprise-grade authentication, login, registration, and full-featured account management systems (qw-account-system / qw_accountSystem). Use whenever the user asks to build or upgrade login, signup, user accounts, rate limiting, forbidden words/reserved usernames filter, email/phone normalization, OTP verification, dual-channel 2FA (TOTP Authenticator + Email OTP), trusted devices, password hashing/reset, sessions, JWT refresh rotation, CSRF protection, RBAC, sub-accounts, or account security dashboards.
---

# QW Account System Architect (`qw-account-system`)

You are building the user's signature **12-Pillar QW Account & Authentication System**—synthesized from 17 production codebases (`course_online`, `Oman`, `PPU-Complaints-Public`, `vehosts`, `pterodactyl/Slender`, `finflow-accounting`, `store`, `fluxer`, `msaea`, and `al-deeb-family`).

Whenever invoked to design or implement login, registration, or account management, **never build a basic or toy auth flow**. Implement the complete, production-hardened 12-Pillar architecture below unless the user explicitly scopes down specific modules.

---

## The 12-Pillar QW Account Architecture

1. **Multi-Identifier & Canonicalized Identity Intake** ([`references/01-identity-validation-and-forbidden-words.md`](references/01-identity-validation-and-forbidden-words.md))
   - Single-field Login accepting **Email OR Username OR Phone Number** automatically.
   - **Email Normalization & Domain Governance:** Reject control chars (`/[\u0000-\u001f\u007f]/`), canonicalize Gmail (`.` dot-stripping, `+tag` subaddress stripping, `@googlemail.com` -> `@gmail.com` to stop multi-account farming), block 25+ disposable mail domains (`mailinator`, `yopmail`, `10minutemail`, `mohmal`, etc.), and enforce trusted provider whitelist + `.edu`/`.gov` TLD support (or strict institutional regex when requested).
   - **Phone E.164 Validation:** Normalize via `libphonenumber-js`, convert leading `00` to `+`, and reject sequential/repeating dummy numbers (`11111111`, `1234567`).

2. **5-Category Forbidden Words, Reserved Usernames & Leet-Speak Filter** ([`references/01-identity-validation-and-forbidden-words.md`](references/01-identity-validation-and-forbidden-words.md))
   - **Username Rules:** 5–30 chars, lowercase `a-z0-9._`, starts with a letter, at least 3 letters, cannot end with `.` or `_`, no consecutive separators (`..`, `__`, `._`, `_.`).
   - **Leet-Speak De-Obfuscation:** Normalize `@/4->a`, `3->e`, `1/!->i`, `0->o`, `$/5->s`, `7->t` and strip separators before checking blocklists.
   - **5-Category Bilingual Dictionary:**
     1. *System & Official Reserved (EN + AR):* `admin`, `root`, `support`, `staff`, `moderator`, `system`, `official`, `verified`, `api`, `webhook`, `ادمن`, `أدمن`, `مدير`, `إدارة`, `مشرف`, `دعم`, `رسمي`, `موثق` (plus critical substring ban anywhere in handle).
     2. *English Profanity & NSFW.*
     3. *Arabic Script & Franco-Arab (Arabizi) Profanity* (`شرموطة`, `قحبة`, `كسم`, `عرص`, `خول`, `sharmouta`, `qa7ba`, `ksmk`, `3ars`, `5ara`, etc.).
     4. *Sacred Religious Names & Figures (AR/EN)* to prevent handle desecration.
     5. *Global Brand Names* (`google`, `apple`, `microsoft`, `stripe`, `paypal`, `discord`, etc.) to prevent impersonation.
   - **Admin Scoped Substring Bans:** Optional `ProfileSubstringBan` table across `username`, `firstName`, `lastName`, `bio`.

3. **Password Cryptography, Bounded Worker Queue & Contextual Strength** ([`references/02-password-cryptography-and-strength.md`](references/02-password-cryptography-and-strength.md))
   - **Rules:** 8–128 chars (never silently truncated), requires `A-Z`, `a-z`, `0-9`, special char, no 4+ repeating chars, no keyboard walks (`qwerty`, `123456`).
   - **Contextual `zxcvbn` + Breach Check:** Reject `score < 2`, passing `[username, email, firstName, lastName, phone]` as dictionary inputs so users cannot include their own name/email in their password; check HaveIBeenPwned `uncompromised()` where supported.
   - **Hashing & CPU/RAM DoS Protection:** `scrypt` (`N=131072, r=8, p=1, 64B key, 16B salt`) or `bcrypt` (`12 rounds`) wrapped in a **Bounded Worker Queue** (max 2 active + max 8 queued; 11th concurrent request fails fast with `503 AUTH_BUSY`).
   - **Memory Zeroization & Constant-Time Unknown User Check:** Overwrite key buffers (`derivedKey.fill(0)`) in `finally` blocks, and verify unknown login identifiers against a precomputed `DUMMY_PASSWORD_HASH` to prevent timing enumeration.

4. **Dual-Bucket Rate Limiting & Progressive Account Lockout** ([`references/03-rate-limiting-lockout-and-antifraud.md`](references/03-rate-limiting-lockout-and-antifraud.md))
   - **Dual-Bucket (IP + SHA-256 Identifier Hash):** Login (`10/15m`), Register (`5/15m`), OTP Send (`5/15m` IP, `3/15m` ID + **60s cooldown**), OTP Verify (`15/15m`), Forgot Password (`5/15m` IP, `3/15m` ID + **minimum 8-second response floor** `withMinimumDuration(8000)`).
   - **Redis Primary + Bounded Memory Fallback:** Hard cap of `10,000` entries with 5-minute `unref()` TTL eviction timer (`OWASP API4:2023`) and standard RFC 429 headers (`Retry-After`, `X-RateLimit-*`).
   - **Account-Level Lockout:** 5 failed password attempts set `lockedUntil = now + 15m` on the `User` row; clear login throttle upon entering 2FA checkpoint.

5. **QW OTP & Dual-Channel 2FA Engine (TOTP + Email/SMS)** ([`references/04-otp-2fa-and-email-architecture.md`](references/04-otp-2fa-and-email-architecture.md))
   - **Arabic/Persian Numeral Normalization:** Convert `٠-٩` and `۰-۹` to ASCII `0-9` before verification while preserving leading zeros.
   - **Purpose-Bound Salted HMAC-SHA256 OTP Storage:** Never store plaintext or unsalted 6-digit OTPs. Store `HMAC-SHA256(secret, "otp:v1:" + purpose + ":" + targetId + ":" + salt + ":" + code)` with `SELECT ... FOR UPDATE` row locking and a persistent DB counter burning the code after **5 failed attempts**.
   - **Pure RFC 6238 TOTP + RFC 4648 Base32 Engine:** 30s step, ±1 drift window, and `lastTotpStep` anti-replay tracking.
   - **Admin 2FA Governance & Anti-Trap Guard:** Dynamic policy (`disabled | email_only | totp_only | both`), grace period days, **Anti-Trap Checkpoint Guard** (never trap a user in a login checkpoint if mandatory 2FA is active but they haven't enrolled yet—redirect to setup instead), 8 single-use backup recovery codes, encrypted tamper-resistant **Trusted Device Cookie** (`30d`, auto-invalidated on password change or device revocation), and **15-Minute Admin Emergency Bypass Code** (with **Supreme Admin Guard** protecting User #1).

6. **Sessions, JWT Refresh Rotation, Global Revocation & Dual-Phase CSRF** ([`references/05-sessions-jwt-csrf-and-rbac.md`](references/05-sessions-jwt-csrf-and-rbac.md))
   - **Stateful Mode:** 32-byte random token, `SHA-256` hash stored in `UserSession`, `__Host-` cookie (`HttpOnly; Secure; SameSite=Lax; Path=/`, no `Domain`), session regeneration on login.
   - **JWT Mode:** Fail-fast secret validation at boot, `15m` Access Token + `1d/30d` Session-Bound Refresh Token with **Refresh Token Rotation & Reuse Detection** (replaying an old refresh token revokes all user sessions).
   - **Millisecond Global Kick (`token_version`) & `kid` Key Rotation:** Increment `user.tokenVersion` on password reset/change or admin suspension to invalidate all Web/Mobile/Desktop sessions in `<2ms`.
   - **Dual-Phase CSRF:** Signed anonymous pre-login CSRF cookie + post-login session-bound HMAC CSRF token + strict `Origin` & `Sec-Fetch-Site` validation.

7. **Hardened Email Infrastructure, Bounce Webhooks & Bilingual Templates** ([`references/04-otp-2fa-and-email-architecture.md`](references/04-otp-2fa-and-email-architecture.md))
   - **SMTP/Provider Hardening:** TLSv1.2+, `rejectUnauthorized: true`, strict timeouts (`5s–7s`), `disableFileAccess: true`, `disableUrlAccess: true`.
   - **Zero Silent Fallback in Production:** Roll back OTP creation and return `503` if SMTP fails in production; use `.dev-mail/` (`0700` permissions, no symlinks) or `debug_otp` strictly in development.
   - **Bounce/Complaint Suppression:** Verify Mailgun/Resend webhook HMAC signatures and maintain an `EmailSuppression` table.
   - **Bilingual RTL/LTR Templates:** High-contrast monospace 6-digit OTP box, expiry notice, anti-phishing warning, and both HTML + Plaintext bodies.

8. **Anti-Bot, Fraud Scoring & Permanent Identity Graveyard** ([`references/03-rate-limiting-lockout-and-antifraud.md`](references/03-rate-limiting-lockout-and-antifraud.md))
   - Hidden Honeypot input (`website_url`), Cloudflare Turnstile / reCAPTCHA verification, optional MaxMind minFraud risk scoring (fail-open on network timeout), referral IP anti-farming check, and a **Permanent `RegisteredIdentity` Graveyard** table that survives user deletion to prevent trial abuse and ban evasion.

9. **Multi-Auth OAuth Linking & Lockout Prevention** ([`references/05-sessions-jwt-csrf-and-rbac.md`](references/05-sessions-jwt-csrf-and-rbac.md))
   - Support Google, Discord, Apple, GitHub OAuth2 alongside Credentials.
   - **Unlink Lockout Guard:** Block unlinking an OAuth identity unless the user has both a verified email and a configured `passwordHash`.

10. **Hierarchical RBAC, Bitfield Permissions & Team Sub-Accounts** ([`references/05-sessions-jwt-csrf-and-rbac.md`](references/05-sessions-jwt-csrf-and-rbac.md))
    - Role hierarchy enforced via `sortOrder` (`actorOrder > targetOrder`), bitwise `AccountPermission` flags (`1, 2, 4, 8...`), 48-hour hashed `SubAccountInvitation` tokens with `SubAccountGuard` (`fail-secure`), portal separation (`WRONG_LOGIN_PORTAL`), and `mustChangePassword` enforcement.

11. **Frontend UX, Unverified Recovery Banner & Security Center** ([`references/05-sessions-jwt-csrf-and-rbac.md`](references/05-sessions-jwt-csrf-and-rbac.md))
    - Live 4-bar password strength meter + 6-item checklist, `type="button"` password eye toggle, inline **Unverified Account Recovery Banner** (`EMAIL_NOT_VERIFIED` -> one-click Send OTP & Verify), `sessionRevision` stale-401 guard, `AbortController` modal cleanup, zero sensitive `localStorage` usage, and a full **Account Security Center** (Security Health Score `0–100`, Active Device Revocation, Audit Log, GDPR/PDPL JSON export).

12. **HTTP Security Headers & Non-Blocking Forensic Audit Logging** ([`references/05-sessions-jwt-csrf-and-rbac.md`](references/05-sessions-jwt-csrf-and-rbac.md))
    - Strict `CSP`, `HSTS`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Permissions-Policy`, hidden `X-Powered-By`, and dual-tier `AuditLog` tracking.

13. **Zero-Trust Tier-0 Security Extensions (8 Enterprise Enhancements)** ([`references/07-advanced-zero-trust-and-passkeys.md`](references/07-advanced-zero-trust-and-passkeys.md))
    1. **Unicode Homograph, Confusable & Zero-Width Sanitizer:** Strip invisible/bidi override chars (`\u200B-\u200F`, `\u202A-\u202E`, `\uFEFF`), normalize `NFKC`, fold Cyrillic/Greek lookalikes (`а` -> `a`), and block mixed-script spoofing words.
    2. **Step-Up Authentication (`Sudo Mode`):** Require `lastSudoVerifiedAt < 10 minutes` before changing email/password, disabling 2FA, viewing recovery/API keys, unlinking OAuth, exporting data, or deleting the account.
    3. **Dual-Handshake Email Change + 72-Hour Emergency Revert Link:** Verify new email via 6-digit OTP while sending a **72-hour single-click Emergency Revert Link** (`EmailChangeRequest`) to the old email that restores the original email, increments `tokenVersion`, and locks out the attacker.
    4. **WebAuthn / Passkeys (`FIDO2`):** Support biometric/hardware Passkeys (`FaceID`, `TouchID`, `Windows Hello`, `YubiKey`) for passwordless login and phishing-resistant 2FA, enforcing `signCount` clone detection.
    5. **Impossible Travel, New-Device Step-Up & One-Click Account Freeze:** Trigger adaptive Step-Up OTP on unrecognized devices/countries or impossible travel (`> 800 km/h`), and include a one-click **"لم أكن أنا — جمّد حسابي فوراً" (`Emergency Freeze`)** link in security alert emails.
    6. **Last-1 Password Reuse Guard (`previousPasswordHash`) & Privacy-Preserving HIBP Check:** Reject password changes/resets that match either the current `passwordHash` or the single immediately preceding `previousPasswordHash`, and check the first 5 hex chars of `SHA-1` against the HaveIBeenPwned k-Anonymity Range API (2.5s fail-open timeout).
    7. **Cryptographic Admin Impersonation (`Shadow Session`):** 15-minute non-renewable impersonation token requiring Sudo Mode + mandatory reason, blocked from modifying target's password/email/2FA, and immune on `isSupremeAdmin`.
    8. **14-Day Soft-Delete Grace Period (`PENDING_DELETION`):** Delay permanent account deletion by 14 days (`scheduledDeletionAt`) with one-click login recovery, while permanently preserving `RegisteredIdentity` graveyard entries after purge.

---

## Execution Workflow (How to Build When Invoked)

Follow this sequence whenever asked to build or upgrade an authentication/account system:

### Step 1: Inspect Workspace & Select Stack Profile
1. Inspect existing project files (`package.json`, `composer.json`, `Cargo.toml`, `prisma/schema.prisma`, `.env.example`) to detect the stack:
   - **TypeScript / Node Stack (Next.js App Router, NestJS, Express, Fastify + Prisma/Drizzle):** Use the TypeScript services in `references/01` through `06`.
   - **Laravel / PHP Stack:** Translate the exact same 12 pillars into FormRequests (`RegisterRequest`, `LoginRequest`), Custom Rules (`NotReservedUsername`), Services (`TwoFactorEmailService`, `FraudProtectionService`), and Middleware (`SubAccountGuard`, `SecurityHeaders`).
   - **Rust / Axum / Other Backend:** Translate the 12 pillars into middleware, extractors, and transactional SQL queries.
2. If high-ambiguity product choices exist (e.g., *"Should email domains be restricted to a university/company domain or open to public providers like Gmail/Outlook?"*), ask **1 concise question**. Otherwise, default to the full 12-Pillar configuration.

### Step 2: Database Schema & Migration Setup
Read [`references/06-database-schemas-and-api-contracts.md`](references/06-database-schemas-and-api-contracts.md) and create/update the database schema with:
- `User`, `UserSession`, `OtpCode`, `UserRecoveryCode`, `UserOAuthAccount`, `RegisteredIdentity` (Graveyard), `Role`, `UserRole`, `SubAccountInvitation`, `ProfileSubstringBan`, `EmailSuppression`, and `AuditLog`.

### Step 3: Core Security & Validation Engines
1. **Identity & Forbidden Words:** Read [`references/01-identity-validation-and-forbidden-words.md`](references/01-identity-validation-and-forbidden-words.md) and implement `forbidden-words.ts` (all 5 categories in EN + AR + Arabizi), `EmailValidatorService`, `PhoneValidatorService`, and `UsernameValidatorService` (with Leet-Speak normalization).
2. **Password Engine:** Read [`references/02-password-cryptography-and-strength.md`](references/02-password-cryptography-and-strength.md) and implement `PasswordStrengthService` (`zxcvbn` + contextual user inputs) and the bounded-queue `scrypt`/`bcrypt` hasher with `verifyAgainstDummyPassword()`.
3. **Rate Limiter & Anti-Fraud:** Read [`references/03-rate-limiting-lockout-and-antifraud.md`](references/03-rate-limiting-lockout-and-antifraud.md) and implement `QwRateLimiter` (Dual-Bucket IP + SHA-256 ID, Redis + bounded 10k-entry memory fallback, RFC 429 headers, `withMinimumDuration(8000)` timing floor) plus Honeypot & Turnstile verification.
4. **OTP, Dual-Channel 2FA & Email:** Read [`references/04-otp-2fa-and-email-architecture.md`](references/04-otp-2fa-and-email-architecture.md) and implement `normalizeOtpCode()` (Arabic/Persian digits), `QwOtpEngine` (Salted HMAC-SHA256 + 5-attempt DB burn + 60s cooldown), `TotpEngine` (RFC 6238 + anti-replay `lastTotpStep`), Trusted Device cookie encryption, and hardened SMTP/Email templates.
5. **Sessions, JWT Rotation, CSRF & RBAC:** Read [`references/05-sessions-jwt-csrf-and-rbac.md`](references/05-sessions-jwt-csrf-and-rbac.md) and implement session/token rotation, `tokenVersion` instant revocation, Dual-Phase CSRF, `sortOrder` RBAC guards, and `AuditLog` recording.

### Step 4: Frontend Auth Components & Security Center UI
Build responsive, RTL/LTR-ready UI components:
1. **Registration Form:** Live 4-bar password meter + 6-rule checklist, `type="button"` password visibility toggle, username availability/validation feedback, phone input, and hidden honeypot.
2. **Login Form:** Single identifier input (`البريد الإلكتروني أو اسم المستخدم أو رقم الهاتف`), inline **Unverified Account Recovery Banner** (`EMAIL_NOT_VERIFIED`), and account lockout countdown display.
3. **OTP & 2FA Checkpoint Modal:** 6-digit input with automatic Arabic numeral conversion, 60-second resend countdown timer, channel switcher (`Authenticator App` vs. `Email OTP` vs. `Recovery Code`), and `"تذكر هذا الجهاز لمدة 30 يوماً"` (`rememberDevice`) checkbox.
4. **Account Security Center (`/account/security`):** Security Health Score (`0–100`), TOTP QR setup wizard + backup recovery codes download, Active Device Sessions list with individual/global revoke buttons, Security Activity Log, and GDPR/PDPL JSON export button.

### Step 5: Automated Verification
Run the 12-point test suite from [`references/06-database-schemas-and-api-contracts.md`](references/06-database-schemas-and-api-contracts.md) and verify zero TypeScript/linter errors before finishing.

