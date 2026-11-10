# Pillar 5 & 7: QW OTP, Dual-Channel 2FA, Trusted Devices & Hardened Email Delivery

This reference defines the exact Purpose-Bound Salted HMAC OTP engine, RFC 6238 TOTP + RFC 4648 Base32 authenticator engine, Arabic/Persian numeral normalization, Admin 2FA Policy Governance, Encrypted Tamper-Resistant Trusted Device Cookie, Emergency Admin Bypass, and Hardened Email Infrastructure extracted across `Oman`, `PPU-Complaints-Public`, `pterodactyl`, `course_online`, `vehosts`, and `store`.

---

## 1. Arabic/Persian Numeral Normalization (Mandatory Pre-Processing)

Users on Arabic keyboards frequently enter OTP and 2FA codes using Eastern Arabic (`٠١٢٣٤٥٦٧٨٩`) or Persian/Urdu (`۰۱۲۳۴۵۶۷۸۹`) numerals, or copy-paste codes with spaces/dashes (`123-456`). Every OTP/TOTP input on both frontend and backend MUST normalize numerals first while **preserving leading zeros** (e.g., `048291`):

```typescript
export function normalizeOtpCode(rawInput: string): string {
  if (!rawInput || typeof rawInput !== 'string') return '';
  return rawInput
    .replace(/[٠-٩]/g, (d) => String(d.charCodeAt(0) - 0x0660))
    .replace(/[۰-۹]/g, (d) => String(d.charCodeAt(0) - 0x06f0))
    .replace(/[^0-9]/g, ''); // Strip spaces, dashes, and non-digits
}
```

---

## 2. Purpose-Bound Salted HMAC-SHA256 OTP Engine (`PPU-Complaints-Public` Pattern)

### Why Plaintext or Unsalted Hashes Are Forbidden for 6-Digit OTPs
A 6-digit numeric OTP has only $1,000,000$ possible values (`000000` to `999999`).
- Storing the plaintext OTP in the database lets any read-only SQL injection or backup leak compromise every active verification/reset code.
- Storing an unsalted `SHA-256(code)` allows an attacker to precompute all 1 million hashes in `< 5 milliseconds`.
- **QW Standard:** Every OTP is hashed using **HMAC-SHA256** with the server's `OTP_HMAC_SECRET`, bound to the **purpose**, **userId/identifier**, and a **per-code 16-byte random salt** (`codeSalt`):

$$\text{codeHash} = \text{HMAC-SHA256}\left(\text{OTP\_SECRET},\ \texttt{"otp:v1:"} \parallel \text{purpose} \parallel \texttt{":"} \parallel \text{targetId} \parallel \texttt{":"} \parallel \text{salt} \parallel \texttt{":"} \parallel \text{code}\right)$$

### 2.1 Complete Salted HMAC OTP Service with Row-Level Locking & Persistent Attempt Counter

```typescript
import crypto from 'node:crypto';
import { normalizeOtpCode } from './normalizeOtpCode';

export type OtpPurpose =
  | 'EMAIL_VERIFICATION'
  | 'PASSWORD_RESET'
  | 'LOGIN_2FA'
  | 'PHONE_VERIFICATION'
  | 'SENSITIVE_ACTION';

export class QwOtpEngine {
  private static readonly CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
  private static readonly RESEND_COOLDOWN_MS = 60 * 1000; // 60 seconds
  private static readonly MAX_VERIFY_ATTEMPTS = 5; // Hard DB limit per issued code

  private static getHmacSecret(): string {
    const secret = process.env.OTP_HMAC_SECRET || process.env.JWT_ACCESS_SECRET;
    if (!secret || secret.length < 32) {
      if (process.env.NODE_ENV === 'production') {
        throw new Error('CRITICAL: OTP_HMAC_SECRET must be at least 32 characters in production');
      }
      return 'dev-only-fallback-otp-hmac-secret-32chars!';
    }
    return secret;
  }

  /**
   * Generates a cryptographically secure 6-digit OTP (preserving leading zeros, e.g. '042918').
   */
  static generateSixDigitCode(): string {
    return crypto.randomInt(0, 1_000_000).toString().padStart(6, '0');
  }

  static computeOtpHmac(params: {
    purpose: OtpPurpose;
    targetId: string;
    salt: string;
    code: string;
  }): string {
    const payload = `otp:v1:${params.purpose}:${params.targetId}:${params.salt}:${params.code}`;
    return crypto.createHmac('sha256', this.getHmacSecret()).update(payload, 'utf8').digest('hex');
  }

  static verifyOtpHmac(params: {
    purpose: OtpPurpose;
    targetId: string;
    salt: string;
    candidateCode: string;
    expectedHashHex: string;
  }): boolean {
    const normalized = normalizeOtpCode(params.candidateCode);
    if (normalized.length !== 6) return false;

    const candidateHashHex = this.computeOtpHmac({
      purpose: params.purpose,
      targetId: params.targetId,
      salt: params.salt,
      code: normalized,
    });

    const a = Buffer.from(candidateHashHex, 'hex');
    const b = Buffer.from(params.expectedHashHex, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }
}
```

### 2.2 Transactional Issuance & Verification Rules (`PPU-Complaints-Public` & `course_online`)
1. **Row-Level Lock on Issuance & Verification:**
   - Inside a DB transaction, lock the target user row (`SELECT id FROM "User" WHERE id = $1 FOR UPDATE`) so parallel requests cannot issue two overlapping codes or verify the same code twice concurrently.
2. **Enforce 60-Second Cooldown:**
   - Query the latest unconsumed OTP for `(targetId, purpose)`. If `Date.now() - latestOtp.createdAt.getTime() < 60_000`, throw `429 Too Many Requests` with `retryAfterSeconds`.
3. **Invalidate Previous Active Codes:**
   - Before inserting a new OTP, mark all previous unconsumed OTPs for `(targetId, purpose)` as `consumedAt = new Date()`.
4. **Atomic SMTP Rollback:**
   - If the email delivery (`emailService.sendOtp(...)`) throws an error, **roll back** (or delete) the newly created OTP record so the user is not stuck on a 60-second cooldown when the email never left the server.
5. **Persistent Failed-Attempt Counter Commit:**
   - When verifying an OTP, if `verifyOtpHmac` returns `false`:
     - Increment `failedAttempts += 1` in the database and **commit** that increment (do NOT roll it back when throwing `400 Invalid OTP`).
     - If `failedAttempts >= 5`, immediately set `consumedAt = new Date()` so the code is permanently burned and forces the user to request a fresh code.

---

## 3. Dual-Channel 2FA Engine: Authenticator App (RFC 6238 TOTP) + Email OTP (`Oman` & `pterodactyl`)

The QW account system supports **both** Authenticator Apps (Google Authenticator, Authy, 1Password, Microsoft Authenticator) and Email/SMS OTP, governed by an Admin Policy Engine.

### 3.1 Pure RFC 6238 TOTP & RFC 4648 Base32 Implementation (Zero External Native Dependencies)

```typescript
import crypto from 'node:crypto';
import { normalizeOtpCode } from './normalizeOtpCode';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export class TotpEngine {
  /**
   * Generates a 20-byte (160-bit) CSPRNG secret encoded as a 32-character Base32 string.
   */
  static generateSecret(byteLength = 20): string {
    const buffer = crypto.randomBytes(byteLength);
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < buffer.length; i++) {
      value = (value << 8) | buffer[i];
      bits += 8;
      while (bits >= 5) {
        output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) {
      output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }
    return output;
  }

  static decodeBase32(base32: string): Buffer {
    const cleaned = base32.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
    let bits = 0;
    let value = 0;
    const bytes: number[] = [];

    for (let i = 0; i < cleaned.length; i++) {
      const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
      if (idx === -1) throw new Error('Invalid Base32 character');
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bytes.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    return Buffer.from(bytes);
  }

  static generateHotp(secretBase32: string, counter: number, digits = 6): string {
    const key = this.decodeBase32(secretBase32);
    const counterBuf = Buffer.alloc(8);
    let tmp = Math.floor(counter);
    for (let i = 7; i >= 0; i--) {
      counterBuf[i] = tmp & 0xff;
      tmp = Math.floor(tmp / 256);
    }

    const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, digits);
    return otp.toString().padStart(digits, '0');
  }

  /**
   * Verifies a 6-digit TOTP token with ±1 time-step window (30s step) and replay protection.
   * Returns the matched timeCounter so the caller can store `lastTotpStep` to block replay within the same 30s window.
   */
  static verifyTotp(params: {
    secretBase32: string;
    candidateToken: string;
    windowSteps?: number;
    stepSeconds?: number;
    lastUsedCounter?: number | null;
  }): { valid: boolean; matchedCounter?: number } {
    const token = normalizeOtpCode(params.candidateToken);
    if (token.length !== 6) return { valid: false };

    const stepSeconds = params.stepSeconds ?? 30;
    const windowSteps = params.windowSteps ?? 1; // ±30s drift tolerance
    const currentCounter = Math.floor(Date.now() / 1000 / stepSeconds);

    for (let errorWindow = -windowSteps; errorWindow <= windowSteps; errorWindow++) {
      const counter = currentCounter + errorWindow;
      // Anti-Replay Guard: Reject if this exact 30s counter (or newer) was already used
      if (params.lastUsedCounter != null && counter <= params.lastUsedCounter) {
        continue;
      }
      const expected = this.generateHotp(params.secretBase32, counter, 6);
      const a = Buffer.from(token, 'utf8');
      const b = Buffer.from(expected, 'utf8');
      if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
        return { valid: true, matchedCounter: counter };
      }
    }

    return { valid: false };
  }

  static buildOtpAuthUri(params: { secretBase32: string; accountEmail: string; issuer: string }): string {
    const label = `${encodeURIComponent(params.issuer)}:${encodeURIComponent(params.accountEmail)}`;
    const query = new URLSearchParams({
      secret: params.secretBase32,
      issuer: params.issuer,
      algorithm: 'SHA1',
      digits: '6',
      period: '30',
    });
    return `otpauth://totp/${label}?${query.toString()}`;
  }
}
```

---

## 4. Admin 2FA Policy Governance, Grace Period & Anti-Trap Checkpoint (`pterodactyl` & `Oman`)

### 4.1 Dynamic System Settings (`SystemSecurityConfig`)
Allow SuperAdmins to configure 2FA globally without redeploying code:
1. `twoFactorMethodPolicy`: `'disabled' | 'email_only' | 'totp_only' | 'both'` (Default: `'both'`).
2. `twoFactorAllowUserChoice`: `boolean` (Allow users to pick their preferred default channel between Authenticator App and Email OTP).
3. `twoFactorEnforcementScope`: `'optional' | 'admins_only' | 'all_users'`.
4. `twoFactorGracePeriodDays`: `number` (e.g., `7` days from `user.createdAt` before mandatory 2FA kicks in).

### 4.2 The Anti-Trap Checkpoint Guard (`pterodactyl` Pattern)
> **Critical Bug Prevention:** If `twoFactorEnforcementScope` is set to `'all_users'` with `'totp_only'`, and a newly registered user has not yet configured their TOTP secret (`useTotp === false`), **NEVER** redirect them to the 2FA verification checkpoint during login—otherwise they are permanently locked out in a Catch-22!
- **Correct Flow:** Allow the login to complete, issue a restricted session (`mustSetup2FA: true`), and redirect them via middleware to `/account/security/setup-2fa` until they complete TOTP enrollment.

### 4.3 Backup Recovery Codes, Trusted Devices & Admin Emergency Bypass (`pterodactyl`)
1. **Single-Use Backup Recovery Codes:**
   - When a user enables TOTP 2FA, generate `8` recovery codes (`XXXX-XXXX` hex/alphanumeric), display them once with a "Download / Copy" button, and store their `SHA-256` hashes in `UserRecoveryCode`.
   - When a recovery code is used at login, delete/mark it `usedAt = new Date()` and send a security alert email.
2. **Encrypted Tamper-Resistant Trusted Device Cookie (`remember_device` for 30 Days):**
   - Payload encrypted with `AES-256-GCM` (using `APP_KEY`):
     ```json
     {
       "uid": "user_uuid",
       "uh": "sha256(user.passwordHash)",
       "uah": "sha256(normalizedBrowserFamily)",
       "iat": 1730000000,
       "exp": 1732592000
     }
     ```
   - **Automatic Invalidation:**
     - If the user changes or resets their password, `uh` changes -> all trusted device cookies across all browsers are immediately invalidated.
     - If the cookie is copied to a different browser family, `uah` mismatches -> rejected.
     - If the user or admin clicks **"Revoke All Trusted Devices"**, store `user.trustedDevicesRevokedAt = new Date()`; reject any cookie where `iat < trustedDevicesRevokedAt`.
3. **Admin 2FA Management & Supreme Admin Guard:**
   - Admins can view a user's 2FA status (`TOTP Enabled`, `Email 2FA Enabled`, `Has Trusted Devices`), trigger a **Diagnostic Test 2FA Email**, **Revoke Trusted Devices**, **Reset User 2FA**, or generate a **15-Minute Single-Use Emergency Bypass Code** (stored as `HMAC-SHA256`, expires in 900s).
   - **Supreme Admin Guard:** `User #1` (or `isSupremeAdmin === true`) is strictly immune: no other admin can reset their 2FA, generate a bypass code for them, or modify their permissions (`403 Forbidden`).

---

## 5. Hardened Email Infrastructure, Bounce Suppression & Bilingual Templates

### 5.1 Hardened SMTP Transport (`PPU-Complaints-Public` Pattern)
Configure `nodemailer` with strict TLS and SSRF/file-inclusion protections:
```typescript
import nodemailer from 'nodemailer';

export function createHardenedSmtpTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    requireTLS: process.env.NODE_ENV === 'production',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 7000,
    disableFileAccess: true, // Prevent local file attachment SSRF
    disableUrlAccess: true,  // Prevent remote URL attachment SSRF
    tls: {
      minVersion: 'TLSv1.2',
      rejectUnauthorized: process.env.NODE_ENV === 'production',
    },
  });
}
```

### 5.2 Zero Silent Fallback in Production + Safe Dev Mail Directory
- **In Production (`NODE_ENV === 'production'`):** If SMTP fails or `info.rejected.length > 0` or `info.accepted.length === 0`, throw `503 Service Unavailable (EMAIL_DELIVERY_FAILED)` and roll back the transaction. **Never** silently swallow email errors or log OTPs in production logs.
- **In Development / Test (`NODE_ENV !== 'production'`):** If `SMTP_HOST` is not configured, write email JSON payloads to a local directory (`.dev-mail/` with `0700` permissions, rejecting symlinks via `fs.lstat`, rotating at 500 files) OR return `debug_otp` strictly when `NODE_ENV === 'development'`.

### 5.3 Email Suppression List & Webhook Verification (`vehosts` Pattern)
- Before sending any email, check the `EmailSuppression` table (`WHERE email = normalizedEmail`). If suppressed (due to a previous hard bounce or spam complaint), skip sending to protect sender domain reputation.
- Provide `/api/webhooks/email/mailgun` and `/api/webhooks/email/resend` endpoints:
  - Verify HMAC-SHA256 signatures with `crypto.timingSafeEqual` and enforce a timestamp replay window (`<= 300s`).
  - Automatically upsert `bounced` / `complained` recipients into `EmailSuppression`.

### 5.4 Bilingual (RTL Arabic / LTR English) OTP Email Template Rules
- Always include **both** `html` and `text` (plaintext fallback) bodies.
- Render the 6-digit OTP inside a high-contrast monospace container (`font-family: 'Courier New', monospace; font-size: 34px; font-weight: 800; letter-spacing: 8px;`).
- State the exact expiration time (`10 دقائق` / `10 minutes`).
- Include an explicit anti-phishing warning: *"لن يطلب منك فريق الدعم هذا الرمز أبداً. إذا لم تطلب هذا الرمز، يرجى تجاهل هذه الرسالة."*
- Avoid embedding clickable verification links inside OTP emails to protect users from link-rewriting scanners and phishing habits.

