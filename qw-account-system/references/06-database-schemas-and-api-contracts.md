# Reference 06: Complete Database Schemas, REST API Contracts & Verification Test Suite

This reference provides the complete, production-ready database schema (Prisma / PostgreSQL / MySQL adaptable to Laravel migrations or SQL) and the standard API endpoint contracts and automated test checklist for the QW Account System.

---

## 1. Complete Prisma Schema (`schema.prisma`)

```prisma
enum AccountStatus {
  PENDING_VERIFICATION
  ACTIVE
  SUSPENDED
  LOCKED
  PENDING_DELETION
  BANNED
}

enum TwoFactorMethod {
  NONE
  TOTP
  EMAIL
  PASSKEY
  BOTH
}

enum OtpPurpose {
  EMAIL_VERIFICATION
  PASSWORD_RESET
  LOGIN_2FA
  PHONE_VERIFICATION
  EMAIL_CHANGE
  SENSITIVE_ACTION
}

enum IdentityType {
  EMAIL
  PHONE
  GOOGLE
  DISCORD
  APPLE
  GITHUB
}

model User {
  id                      String         @id @default(uuid())
  email                   String         @unique
  username                String         @unique
  phone                   String?        @unique
  passwordHash            String?        // Nullable for OAuth/Passkey-only initial signup
  previousPasswordHash    String?        // Last-1 password hash to prevent immediate password reuse
  firstName               String
  lastName                String?
  avatarUrl               String?

  // Verification & Lifecycle Status
  status                  AccountStatus  @default(PENDING_VERIFICATION)
  emailVerifiedAt         DateTime?
  phoneVerifiedAt         DateTime?
  mustChangePassword      Boolean        @default(false)
  passwordChangedAt       DateTime?
  scheduledDeletionAt     DateTime?      // 14-day soft-delete grace period target timestamp

  // Security, Anomaly & Lockout Tracking
  failedLoginAttempts     Int            @default(0)
  lockedUntil             DateTime?
  lastLoginAt             DateTime?
  lastLoginIp             String?
  lastLoginCountry        String?        // Used for Impossible Travel & New-Country Step-Up detection
  lastLoginDeviceHash     String?        // SHA-256 of normalized Browser/OS for New-Device alerts
  tokenVersion            Int            @default(1) // Increment for <2ms global token revocation

  // 2FA & Trusted Device State
  twoFactorEnabled        Boolean        @default(false)
  twoFactorMethod         TwoFactorMethod @default(NONE)
  totpSecretEncrypted     String?        // AES-256-GCM encrypted Base32 secret
  totpVerifiedAt          DateTime?
  lastTotpStep            Int?           // Anti-replay counter for RFC 6238 TOTP
  trustedDevicesRevokedAt DateTime?      // Timestamp invalidating older trusted-device cookies
  adminBypassCodeHash     String?        // HMAC-SHA256 of 15-minute admin emergency bypass code
  adminBypassExpiresAt    DateTime?

  // RBAC & Supreme Admin Flag
  isSupremeAdmin          Boolean        @default(false) // Immune to other admins resetting 2FA/roles/impersonating
  permissionsMask         Int            @default(0)     // Bitfield permissions for fast checks

  // Sub-Account / Parent-Owner Hierarchy
  parentOwnerId           String?
  parentOwner             User?          @relation("UserSubAccounts", fields: [parentOwnerId], references: [id], onDelete: Cascade)
  subAccounts             User[]         @relation("UserSubAccounts")

  // Referral Anti-Fraud
  referredById            String?
  registrationIp          String?

  createdAt               DateTime       @default(now())
  updatedAt               DateTime       @updatedAt

  // Relations
  sessions                UserSession[]
  otpCodes                OtpCode[]
  recoveryCodes           UserRecoveryCode[]
  passkeys                UserPasskey[]
  emailChangeRequests     EmailChangeRequest[]
  oauthAccounts           UserOAuthAccount[]
  userRoles               UserRole[]
  auditLogs               AuditLog[]

  @@index([email])
  @@index([username])
  @@index([phone])
  @@index([status])
  @@index([parentOwnerId])
}

model UserSession {
  id                 String    @id @default(uuid())
  userId             String
  user               User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  tokenHash          String    @unique // SHA-256 of opaque session token OR refresh token
  ipAddress          String?
  countryCode        String?
  userAgent          String?
  deviceName         String?
  deviceHash         String?
  lastSudoVerifiedAt DateTime? // Step-Up (Sudo Mode) verification timestamp (valid for 10m)
  isRevoked          Boolean   @default(false)
  revokedAt          DateTime?
  revokedReason      String?
  lastActiveAt       DateTime  @default(now())
  expiresAt          DateTime
  createdAt          DateTime  @default(now())

  @@index([userId, isRevoked])
  @@index([expiresAt])
}

model UserPasskey {
  id           String    @id @default(uuid())
  userId       String
  user         User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  credentialId String    @unique // Base64URL WebAuthn credential ID
  publicKey    String    // Base64 encoded COSE public key
  counter      Int       @default(0) // Signature counter for clone detection
  transports   String[]  // ['internal', 'hybrid', 'usb', 'nfc', 'ble']
  deviceType   String    @default("singleDevice")
  backedUp     Boolean   @default(false)
  friendlyName String    @default("Passkey")
  lastUsedAt   DateTime?
  createdAt    DateTime  @default(now())

  @@index([userId])
}

model EmailChangeRequest {
  id              String    @id @default(uuid())
  userId          String
  user            User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  oldEmail        String
  newEmail        String
  revertTokenHash String    @unique // SHA-256 of 32-byte emergency revert token sent to oldEmail
  confirmedAt     DateTime?
  revertedAt      DateTime?
  revertExpiresAt DateTime  // 72 hours TTL from request time
  createdAt       DateTime  @default(now())

  @@index([userId])
  @@index([revertExpiresAt])
}

model OtpCode {
  id               String     @id @default(uuid())
  userId           String?
  user             User?      @relation(fields: [userId], references: [id], onDelete: Cascade)
  targetIdentifier String     // Normalized email or E.164 phone
  purpose          OtpPurpose
  codeHash         String     // HMAC-SHA256(secret, "otp:v1:" + purpose + ":" + target + ":" + salt + ":" + code)
  codeSalt         String     // 16-byte random hex salt
  failedAttempts   Int        @default(0) // Max 5 attempts before automatic burn
  maxAttempts      Int        @default(5)
  expiresAt        DateTime
  consumedAt       DateTime?
  requestedIp      String?
  createdAt        DateTime   @default(now())

  @@index([targetIdentifier, purpose, consumedAt])
  @@index([userId, purpose])
  @@index([expiresAt])
}

model UserRecoveryCode {
  id        String    @id @default(uuid())
  userId    String
  user      User      @relation(fields: [userId], references: [id], onDelete: Cascade)
  codeHash  String    // SHA-256 or HMAC-SHA256 of recovery code
  usedAt    DateTime?
  createdAt DateTime  @default(now())

  @@index([userId, usedAt])
}

model UserOAuthAccount {
  id                String       @id @default(uuid())
  userId            String
  user              User         @relation(fields: [userId], references: [id], onDelete: Cascade)
  provider          IdentityType
  providerAccountId String
  email             String?
  createdAt         DateTime     @default(now())

  @@unique([provider, providerAccountId])
  @@index([userId])
}

/// Permanent Identity Graveyard: NEVER deleted when a User is deleted.
/// Prevents trial abuse, ban evasion, and re-linking banned OAuth/Email identities.
model RegisteredIdentity {
  id                String       @id @default(uuid())
  identityType      IdentityType
  identityValue     String       // Normalized email, E.164 phone, or OAuth providerAccountId
  originalUserId    String
  firstRegisteredAt DateTime     @default(now())
  isBanned          Boolean      @default(false)
  banReason         String?

  @@unique([identityType, identityValue])
  @@index([originalUserId])
}

model Role {
  id          String     @id @default(uuid())
  name        String     @unique // e.g., SUPER_ADMIN, ADMIN, MODERATOR, SUPPORT, USER
  displayName String
  sortOrder   Int        @default(10) // Hierarchy enforcement: actor.sortOrder > target.sortOrder
  permissions String[]   // Array of granular permission slugs
  isSystem    Boolean    @default(false)
  users       UserRole[]
  createdAt   DateTime   @default(now())
}

model UserRole {
  userId     String
  roleId     String
  user       User     @relation(fields: [userId], references: [id], onDelete: Cascade)
  role       Role     @relation(fields: [roleId], references: [id], onDelete: Cascade)
  assignedAt DateTime @default(now())

  @@id([userId, roleId])
}

model SubAccountInvitation {
  id              String    @id @default(uuid())
  ownerId         String
  email           String
  tokenHash       String    @unique // SHA-256 of 32-byte invitation token
  permissionsMask Int       @default(1)
  expiresAt       DateTime  // 48 hours TTL
  acceptedAt      DateTime?
  createdAt       DateTime  @default(now())

  @@index([ownerId])
  @@index([email])
}

model ProfileSubstringBan {
  id        String   @id @default(uuid())
  pattern   String   @unique // Lowercase substring to block
  scopes    String[] // ['username', 'firstName', 'lastName', 'bio']
  reason    String?
  createdBy String?
  createdAt DateTime @default(now())
}

model EmailSuppression {
  id        String   @id @default(uuid())
  email     String   @unique
  reason    String   // 'HARD_BOUNCE' | 'SPAM_COMPLAINT' | 'MANUAL_ADMIN'
  provider  String?  // 'mailgun' | 'resend' | 'smtp'
  createdAt DateTime @default(now())
}

model AuditLog {
  id         String   @id @default(uuid())
  userId     String?
  user       User?    @relation(fields: [userId], references: [id], onDelete: SetNull)
  actorId    String?  // Admin or parent owner who triggered the action
  action     String   // e.g., 'LOGIN_SUCCESS', 'LOGIN_FAILED', '2FA_ENABLED', 'SESSION_REVOKED'
  severity   String   @default("INFO") // 'INFO' | 'WARN' | 'CRITICAL'
  ipAddress  String?
  userAgent  String?
  metadata   Json?
  createdAt  DateTime @default(now())

  @@index([userId, createdAt])
  @@index([action, createdAt])
}
```

---

## 2. Standard REST API Endpoint Contracts

| Method & Path | Auth | Rate Limit (IP / ID) | Purpose & Behavior |
|---------------|------|----------------------|--------------------|
| `GET /auth/csrf` | Public | `60 / 15m` | Issues pre-login signed CSRF cookie & token. |
| `POST /auth/register` | Public | `5 / 15m` | Validates Honeypot, Turnstile, Email domain/canonicalization, Phone E.164, Username 5-category forbidden dictionary, Password `zxcvbn` + `scrypt`/`bcrypt`, checks `RegisteredIdentity` graveyard, creates `PENDING_VERIFICATION` user, sends 6-digit HMAC OTP. |
| `POST /auth/verify-email` | Public | `15 / 15m` | Normalizes Arabic/Persian digits, checks Salted HMAC OTP (max 5 failed attempts in DB), activates account (`ACTIVE`), issues session/tokens. |
| `POST /auth/resend-verification` | Public | `5 / 15m` + `60s` cooldown | Enforces 60s cooldown, invalidates previous OTP, sends fresh 6-digit OTP. |
| `POST /auth/login` | Public | `10 / 15m` | Accepts Email OR Username OR Phone. Uses dummy hash on unknown user. Checks `lockedUntil`. If unverified, returns `403 EMAIL_NOT_VERIFIED` for inline recovery. If 2FA enabled (and no valid Trusted Device cookie), returns `requires2FA: true` + temporary `checkpointToken` and clears login throttle. |
| `POST /auth/2fa/verify` | Checkpoint | `15 / 15m` | Verifies TOTP (RFC 6238 with anti-replay `lastTotpStep`), Email OTP, Backup Recovery Code, or Admin Emergency Bypass Code. Optionally sets encrypted `TrustedDevice` cookie (`30d`). |
| `POST /auth/forgot-password` | Public | `5 / 15m` (IP), `3 / 15m` (ID) | Wrapped in `withMinimumDuration(8000)` (8s floor). Sends `PASSWORD_RESET` OTP if account exists; always returns generic `200 OK`. |
| `POST /auth/reset-password` | Public | `10 / 15m` | Verifies `PASSWORD_RESET` OTP + new password strength, updates `passwordHash`, increments `tokenVersion`, revokes all `UserSession` rows, invalidates trusted devices. |
| `POST /auth/refresh-token` | Refresh Cookie/Bearer | `30 / 15m` | Rotates Refresh Token & issues new Access Token. Detects reuse and revokes all user sessions on replay. |
| `POST /auth/logout` | Authenticated | `30 / 15m` | Revokes current `UserSession`, blacklists current `jti`, clears cookies. |
| `GET /account/security` | Authenticated | `60 / 15m` | Returns Security Health Score (`0–100`), active sessions, 2FA status, linked OAuth identities, and recent security audit logs. |
| `POST /account/2fa/totp/setup` | Authenticated | `10 / 15m` | Generates Base32 secret & `otpauth://` QR URI. |
| `POST /account/2fa/totp/enable` | Authenticated | `10 / 15m` | Verifies first TOTP code, enables 2FA, returns 8 single-use backup recovery codes. |
| `POST /account/sessions/revoke-all` | Authenticated | `10 / 15m` | Increments `tokenVersion` and revokes all sessions (or all except current). |
| `GET /account/export-data` | Authenticated | `3 / 1h` | Exports user profile, sessions, and audit logs as JSON (`GDPR / PDPL`). |

---

## 3. Mandatory Automated Test Suite Checklist (Vitest / Jest / PHPUnit)

Whenever building or auditing the auth system, verify these 12 test cases pass:
1. **Gmail Canonicalization & Disposable Email Rejection:** `u.s.e.r+tag@googlemail.com` normalizes to `user@gmail.com`; `test@mailinator.com` is rejected.
2. **Forbidden Username & Leet-Speak Filter:** `admin`, `s_u_p_p_o_r_t`, `a.d.m.1.n`, Arabic reserved words (`ادمن`), and Franco-Arab profanity (`sharmouta`, `3ars`) are all rejected.
3. **Contextual Password Strength & Bounded Queue:** Password containing user's email/username is rejected; 11th concurrent hash call when 2 active + 8 queued throws `503 AUTH_BUSY`.
4. **Constant-Time Unknown-User Login:** Login with non-existent identifier executes dummy hash verification and returns identical `401` payload.
5. **Account Lockout After 5 Failed Attempts:** 5 wrong passwords set `lockedUntil` (+15m); 6th attempt with the *correct* password still returns `403 ACCOUNT_LOCKED` until lockout expires.
6. **Arabic/Persian Numeral OTP Normalization:** Entering `٠٤٨٢٩١` or `۰۴۸۲۹۱` matches `048291` with leading zero preserved.
7. **Purpose-Bound Salted HMAC OTP & 5-Attempt Burn:** An OTP generated for `EMAIL_VERIFICATION` fails if submitted to `PASSWORD_RESET`; 5 wrong guesses permanently consume the OTP in DB.
8. **RFC 6238 TOTP Verification & Anti-Replay:** Valid TOTP succeeds once; submitting the exact same 6-digit TOTP a second time within the same 30-second window is rejected (`counter <= lastTotpStep`).
9. **Refresh Token Rotation & Reuse Detection:** Replaying an already-rotated refresh token immediately revokes all active sessions for that user.
10. **Millisecond Global Revocation (`token_version`):** Resetting password increments `tokenVersion` and immediately invalidates existing access tokens and trusted-device cookies.
11. **OAuth Unlink Lockout Prevention:** User with `passwordHash = null` cannot unlink their last OAuth provider until they set a password.
12. **Hierarchical RBAC & Supreme Admin Guard:** Lower admin (`ADMIN`, `sortOrder: 80`) cannot modify `SUPER_ADMIN` (`sortOrder: 100`) or reset `isSupremeAdmin` user's 2FA.

