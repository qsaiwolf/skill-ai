# Reference 07: Zero-Trust Enhancements — Homograph Defense, Sudo Mode, Dual-Handshake Email Change, Passkeys (WebAuthn), Anomaly Freeze, Impersonation & 14-Day Soft Delete

This reference defines the 8 Zero-Trust enhancements that elevate the Sovereign Account System to Tier-0 financial/enterprise security.

---

## 1. Unicode Homograph, Confusable & Zero-Width Character Sanitizer

Attackers attempt to bypass username/display-name filters or impersonate admins by:

- Injecting invisible Zero-Width characters (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`, `\u2060`) or Bidi/RTL Override characters (`\u202A`–`\u202E`, `\u2066`–`\u2069`).
- Using Cyrillic, Greek, or Mathematical lookalike characters (e.g., Cyrillic `а` `\u0430` in `аdmin`) that look identical to Latin characters.

```typescript
// Invisible, zero-width, control, and bidirectional override characters
const INVISIBLE_AND_BIDI_REGEX =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g;

// Common Cyrillic/Greek/Fullwidth confusables mapped to ASCII Latin equivalents
const CONFUSABLE_MAP: Record<string, string> = {
  а: "a",
  е: "e",
  і: "i",
  о: "o",
  р: "p",
  с: "c",
  у: "y",
  х: "x",
  ѕ: "s",
  ј: "j",
  ӏ: "l",
  ԁ: "d",
  ԛ: "q",
  ԝ: "w",
  ν: "v",
  α: "a",
  ο: "o",
  ρ: "p",
  τ: "t",
  υ: "u",
  κ: "k",
};

export class UnicodeSanitizer {
  /**
   * Strips invisible/bidi characters and normalizes Unicode to NFKC.
   */
  static sanitizeText(input: string): string {
    if (!input || typeof input !== "string") return "";
    return input.normalize("NFKC").replace(INVISIBLE_AND_BIDI_REGEX, "").trim();
  }

  /**
   * Detects if a string contains raw invisible or bidirectional spoofing characters.
   */
  static hasSpoofingCharacters(input: string): boolean {
    return INVISIBLE_AND_BIDI_REGEX.test(input);
  }

  /**
   * Maps Cyrillic/Greek lookalikes to ASCII Latin so confusable handles are caught by blocklists.
   */
  static foldConfusablesToAscii(input: string): string {
    const clean = this.sanitizeText(input).toLowerCase();
    let out = "";
    for (const ch of clean) {
      out += CONFUSABLE_MAP[ch] ?? ch;
    }
    return out;
  }

  /**
   * Prevents Mixed-Script Spoofing in display names (e.g. mixing Latin + Cyrillic in the same word).
   * Allows pure Arabic, pure Latin, or separate words in Arabic/Latin, but rejects a single word mixing scripts.
   */
  static hasMixedScriptWord(displayName: string): boolean {
    const words = this.sanitizeText(displayName).split(/\s+/);
    for (const word of words) {
      const hasLatin = /[a-zA-Z]/.test(word);
      const hasCyrillicOrGreek = /[\u0370-\u03FF\u0400-\u04FF]/.test(word);
      const hasArabic = /[\u0600-\u06FF]/.test(word);
      const scriptCount = [hasLatin, hasCyrillicOrGreek, hasArabic].filter(
        Boolean,
      ).length;
      if (scriptCount > 1) return true;
    }
    return false;
  }
}
```

---

## 2. Step-Up Authentication (`Sudo Mode` — 10-Minute Re-Verification Window)

Even within an active authenticated session, high-risk operations MUST require a fresh verification within the last **10 minutes** (`SUDO_TTL_MS = 10 * 60 * 1000`):

### 2.1 Protected `Sudo` Operations

- Changing primary email or phone number
- Changing password or disabling 2FA
- Viewing/regenerating backup recovery codes or API keys
- Unlinking an OAuth provider or removing a Passkey
- Requesting full account data export (`GDPR / PDPL`) or deleting the account

### 2.2 Sudo Guard Implementation

```typescript
export const SUDO_TTL_MS = 10 * 60 * 1000; // 10 minutes

export function assertSudoModeActive(session: {
  lastSudoVerifiedAt?: Date | null;
}): void {
  const verifiedAt = session.lastSudoVerifiedAt?.getTime() ?? 0;
  if (Date.now() - verifiedAt > SUDO_TTL_MS) {
    const err = new Error(
      "Sudo re-authentication required for this sensitive action",
    );
    (err as any).status = 403;
    (err as any).code = "SUDO_REQUIRED";
    (err as any).messageAr =
      "يرجى تأكيد هويتك مجدداً (كلمة المرور أو رمز التحقق) لإتمام هذه العملية الحساسة.";
    throw err;
  }
}
```

- **Endpoint `POST /auth/sudo-verify`:** Accepts the user's current password, a valid 6-digit TOTP/Email OTP, or a Passkey assertion. On success, updates `session.lastSudoVerifiedAt = new Date()`.

---

## 3. Dual-Handshake Email Change + 72-Hour Emergency Revert Link

Never allow changing `user.email` in a single step, even with Sudo Mode. If an attacker hijacks a session, they should never be able to silently lock out the true owner.

### 3.1 The 3-Step Handshake + 72h Revert Flow

1. **Step 1 (`POST /account/email/request-change` — Requires Sudo Mode):**
   - Validate and normalize `newEmail` (check domain whitelist, disposable blocklist, and ensure `newEmail` is not already taken).
   - Generate a 6-digit Salted HMAC OTP sent to **`newEmail`** (10m expiry).
   - Generate a 32-byte `revertToken` (`revertTokenHash = sha256(revertToken)`), stored in `EmailChangeRequest` with `revertExpiresAt = now + 72 hours`.
   - Immediately send a high-priority security alert to **`oldEmail`**:
     > \*"تم طلب تغيير بريدك الإلكتروني إلى `n***w@domain.com`. إذا لم تكن أنت، اضغط هنا خلال 72 ساعة لإلغاء التغيير وتأمين حسابك فوراً."\*
2. **Step 2 (`POST /account/email/confirm-change`):**
   - User submits the 6-digit OTP received at `newEmail`.
   - Update `user.email = newEmail`, set `emailVerifiedAt = new Date()`, and keep `EmailChangeRequest` active until `revertExpiresAt` (72 hours).
3. **Step 3 (`POST /auth/email/emergency-revert` — Public Token Endpoint):**
   - If the original owner clicks the emergency revert link from `oldEmail` within 72 hours:
     - Verify `sha256(token) === emailChangeRequest.revertTokenHash` and `now < revertExpiresAt`.
     - Atomically restore `user.email = emailChangeRequest.oldEmail`.
     - Increment `user.tokenVersion += 1` and revoke **all** active sessions and trusted devices.
     - Lock password login or require an immediate password reset so the attacker is completely evicted.

---

## 4. WebAuthn / Passkeys (`FIDO2` Phishing-Resistant Authentication)

Support Passkeys (FaceID, TouchID, Windows Hello, Android Biometrics, YubiKey) both as a **Passwordless Primary Login** and as a **Hardware/Biometric 2FA Factor**.

### 4.1 Database Model (`UserPasskey`)

- `id`: String (UUID)
- `userId`: String
- `credentialId`: String (`@unique`, Base64URL)
- `publicKey`: Bytes / Base64
- `counter`: BigInt / Int (Signature counter for cloned-authenticator detection)
- `transports`: String[] (`['internal', 'hybrid', 'usb', 'nfc', 'ble']`)
- `deviceType`: String (`'singleDevice' | 'multiDevice'`)
- `backedUp`: Boolean
- `friendlyName`: String (e.g., `'iPhone 16 Pro'`, `'MacBook TouchID'`, `'YubiKey 5C'`)
- `lastUsedAt`: DateTime?

### 4.2 Security Rules for WebAuthn Verification

1. **Challenge Storage:** Generate a 32-byte random challenge stored in Redis/DB (`ttl = 5 minutes`) bound to the session/request; consume and delete it immediately on verification to prevent replay.
2. **Strict Origin & RP ID Validation:** Verify `expectedOrigin === APP_ORIGIN` and `expectedRPID === APP_DOMAIN`.
3. **Clone Detection (`signCount`):** If `verification.authenticationInfo.newCounter > 0` and `newCounter <= passkey.counter`, reject authentication immediately (`PASSKEY_CLONE_DETECTED`), revoke the compromised passkey, and alert the user.

---

## 5. Impossible Travel, New-Device Anomaly Detection & One-Click Account Freeze

### 5.1 Contextual Login Risk Evaluation

On every login, compute a device fingerprint `deviceHash = sha256(normalizedBrowserFamily + '|' + osFamily)` and compare with the user's recent `UserSession` history:

1. **New Device or New Country Detected:**
   - If the user has logged in before, and `(ipCountry !== lastLoginCountry)` or `deviceHash` has never been seen for this user:
     - **Adaptive Step-Up:** Require a 6-digit Email OTP / 2FA verification before issuing the session (even if the user has not explicitly enabled 2FA).
2. **Impossible Travel Detection:**
   - If the geographic distance or country change between `lastLoginAt` and `now` implies travel faster than `800 km/h` (or two different countries within `< 30 minutes`):
     - Require mandatory Step-Up 2FA + send a **Critical Login Alert Email** containing a **One-Click Emergency Freeze Link**.

### 5.2 One-Click Emergency Account Freeze (`POST /auth/security/emergency-freeze`)

- Every "New Device Login" or "Password Changed" email includes a signed 24-hour `freezeToken` (`HMAC-SHA256`).
- Clicking **"لم أكن أنا — جمّد حسابي فوراً" (This wasn't me — Freeze Account)**:
  1. Sets `user.status = 'LOCKED'` and `user.lockedUntil = new Date(Date.now() + 24 * 60 * 60 * 1000)`.
  2. Increments `user.tokenVersion += 1` and revokes **all** `UserSession` rows and trusted devices in `< 2ms`.
  3. Redirects the user to `/auth/forgot-password` to safely reset their password and reclaim their account.

---

## 6. Last-1 Password Reuse Prevention (`previousPasswordHash`) & k-Anonymity HIBP Breach Check

### 6.1 Prevent Reusing Current or Last-1 Password

To keep the database lean while preventing users from cycling back to their immediate previous password during a password change or reset:

- Store `previousPasswordHash: String?` directly on the `User` row.
- **On Password Change / Reset:**
  1. Verify the new password does **NOT** match `user.passwordHash` (`verifyPassword(newPassword, user.passwordHash) === false`).
  2. If `user.previousPasswordHash` is present, verify the new password does **NOT** match `user.previousPasswordHash` (`verifyPassword(newPassword, user.previousPasswordHash) === false`).
  3. If either matches, reject with `400 PASSWORD_RECENTLY_USED`:
     - EN: `"You cannot reuse your current or immediately previous password."`
     - AR: `"لا يمكنك استخدام كلمة المرور الحالية أو كلمة المرور السابقة مباشرة."`
  4. When saving the new password, rotate:
     ```typescript
     await prisma.user.update({
       where: { id: user.id },
       data: {
         previousPasswordHash: user.passwordHash,
         passwordHash: newPasswordHash,
         passwordChangedAt: new Date(),
         tokenVersion: { increment: 1 },
       },
     });
     ```

### 6.2 Privacy-Preserving HaveIBeenPwned (`k-Anonymity`) Check

Never send a user's plaintext password or full hash to an external API. Use the HIBP k-Anonymity Range API (sends only the first **5 hex characters** of the `SHA-1` hash):

```typescript
import crypto from "node:crypto";

export async function isPasswordBreachedHibp(
  password: string,
  minBreachCount = 1,
): Promise<boolean> {
  const sha1Full = crypto
    .createHash("sha1")
    .update(password, "utf8")
    .digest("hex")
    .toUpperCase();
  const prefix = sha1Full.slice(0, 5);
  const suffix = sha1Full.slice(5);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2500); // 2.5s timeout (fail-open on network outage)

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true", "User-Agent": "Sovereign-Auth-Guard" },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return false;
    const text = await res.text();

    for (const line of text.split("\n")) {
      const [hashSuffix, countStr] = line.trim().split(":");
      if (hashSuffix === suffix && Number(countStr) >= minBreachCount) {
        return true;
      }
    }
    return false;
  } catch {
    // Always fail-open if external HIBP API is unreachable so signups don't break
    return false;
  }
}
```

---

## 7. Cryptographic Admin Impersonation (`Shadow Session`)

Admins should never reset a customer's password to troubleshoot their account.

1. **Endpoint `POST /admin/users/:id/impersonate`:**
   - Requires `SUPER_ADMIN` (or `actorOrder > targetOrder`) + active **Sudo Mode** + mandatory `reason` string (`min 10 chars`).
   - **Supreme Admin Guard:** Cannot impersonate `isSupremeAdmin` or any user with `targetOrder >= actorOrder`.
2. **Scoped Shadow Token (`15m` max TTL, non-renewable):**
   - Claims: `{ sub: targetUser.id, impersonatorId: admin.id, isShadowSession: true, exp: now + 900 }`.
   - **Shadow Session Restrictions:** While `req.auth.isShadowSession === true`, block all mutations to `/account/password`, `/account/email`, `/account/2fa`, and `/account/delete`.
   - **Audit Attribution:** Every action performed during impersonation logs `userId: targetUser.id, actorId: admin.id, metadata: { impersonated: true, reason }` in `AuditLog`.

---

## 8. 14-Day Soft-Delete Account Grace Period & Scheduled Purge

When a user requests account deletion (`POST /account/delete` — Requires Sudo Mode):

1. Do **NOT** immediately `DELETE FROM "User"`.
2. Transition `user.status = 'PENDING_DELETION'` and set `user.scheduledDeletionAt = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000)` (14 days).
3. Increment `user.tokenVersion += 1`, revoke all sessions, and send a confirmation email stating that the account will be permanently purged in 14 days unless they log back in to cancel.
4. **Recovery During Grace Period:** If the user logs in while `status === 'PENDING_DELETION'` and `now < scheduledDeletionAt`, return a prompt allowing one-click **"استرجاع الحساب وإلغاء الحذف" (`POST /auth/cancel-deletion`)**, which restores `status = 'ACTIVE'` and `scheduledDeletionAt = null`.
5. **Final Purge Cron Job:** After `scheduledDeletionAt <= now`, scrub PII and delete the `User` row while **preserving** the `RegisteredIdentity` graveyard record so free trials cannot be farmed and banned users cannot evade bans.

ي
