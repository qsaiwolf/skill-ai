# Pillar 6, 9, 10, 11 & 12: Sessions, JWT Rotation, CSRF, RBAC, Sub-Accounts & Security UX

This reference defines the exact session management, JWT refresh rotation, millisecond global revocation (`token_version` + JTI blacklist + `kid` key rotation), Dual-Phase CSRF, hierarchical RBAC, Bitfield permissions, Sub-Accounts, OAuth lockout prevention, Frontend Security UX, and HTTP Security Headers extracted across `PPU-Complaints-Public`, `finflow-accounting`, `course_online`, `vehosts`, `store`, `Oman`, `pterodactyl`, `fluxer`, and `msaea`.

---

## 1. Session & Token Architecture (Two Approved Modes)

Depending on the project stack, use either **Mode A (Stateful Opaque DB Sessions)** or **Mode B (Dual JWT Access + Refresh Token Rotation with DB Session Binding)**.

### Mode A: Stateful Opaque `__Host-` Sessions (`PPU-Complaints-Public` & `fluxer`)
1. **Token Generation:** `const rawToken = crypto.randomBytes(32).toString('hex')` (64 hex chars, 256 bits of entropy).
2. **DB Storage:** Never store `rawToken` in the database. Store `tokenHash = sha256(rawToken)` in `UserSession` (`userId`, `tokenHash`, `ipAddress`, `userAgent`, `expiresAt`, `revokedAt`).
3. **Hardened Cookie Attributes:**
   - **Cookie Name:** Use `__Host-session` in production (HTTPS) and `app_session` in local HTTP dev.
   - **Flags:** `HttpOnly; Secure; SameSite=Lax; Path=/` (and **no `Domain` attribute**, as required by the `__Host-` prefix spec to prevent subdomain cookie injection).
4. **Anti-Session-Fixation:** Always destroy any pre-existing session cookie and issue a brand-new `rawToken` upon login, privilege elevation, or password change.

### Mode B: Dual JWT Access + Refresh Token Rotation (`course_online` & `finflow-accounting`)
1. **Fail-Fast Secret Validation:** At server boot, verify `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET` exist, are distinct, and are each `>= 32` characters. Refuse to start in production if missing.
2. **Short-Lived Access Token (`15m`):**
   - Payload: `{ sub: user.id, email: user.email, role: user.role, tv: user.tokenVersion, sid: session.id, jti: crypto.randomUUID() }`.
   - Signed with active `kid` (Key ID) header for zero-downtime key rotation.
3. **Session-Bound Refresh Token (`1d` default, `30d` when `rememberMe === true`):**
   - Create a `UserSession` row in DB storing `refreshTokenHash = sha256(refreshToken)` (or `bcrypt`), `ipAddress`, `userAgent`, `deviceName`, `expiresAt`, `isRevoked: false`.
   - **Refresh Token Rotation & Reuse Detection:**
     - On `POST /auth/refresh-token`: verify the JWT signature, lookup `UserSession` by `sid`, and compare `sha256(incomingRefreshToken)` against `session.refreshTokenHash`.
     - **Reuse Detection:** If the session exists and is valid, but `refreshTokenHash` does NOT match the incoming token (meaning an older rotated token was replayed by an attacker), **immediately revoke ALL sessions for that user** (`revokeAllUserSessions(user.id)`) and return `401 TOKEN_REUSE_DETECTED`.
     - Otherwise, issue a new Access Token + new Refresh Token and atomically update `session.refreshTokenHash`.

### 1.1 Millisecond Global Revocation & Zero-Downtime Key Rotation (`finflow-accounting` `TokenRevocationService`)
- **Single-Token Revocation (`JTI` Blacklist):** Store `revoked:jti:{jti}` in Redis (with TTL equal to the token's remaining lifetime, e.g., `<= 15m`).
- **All-Devices Instant Kick (`token_version`):** Include `tokenVersion: Int @default(1)` on the `User` model. When a user resets their password, enables 2FA, revokes all sessions, or is suspended by an Admin:
  1. Increment `user.tokenVersion += 1` in DB and cache `user:tv:{userId}` in Redis.
  2. Mark all `UserSession` rows for `userId` as `isRevoked = true`.
  3. Every authenticated API request checks `payload.tv === currentTokenVersion`, revoking Web, Mobile, and Desktop tokens in `< 2ms`.
- **Zero-Downtime Key Rotation (`kid` Registry):** Maintain a key map (`{ [kid]: secret }`) with an `activeKid` for signing new tokens while keeping the previous key valid for verification during its `15m` overlap window.

---

## 2. Dual-Phase CSRF & Origin Defense (`PPU-Complaints-Public` & `fluxer`)

Whenever cookies (`HttpOnly`) are used for authentication or pre-auth flows:
1. **Strict Origin & Fetch Metadata Check (All State-Changing Requests `POST / PUT / PATCH / DELETE`):**
   - Verify `Origin` header matches `APP_ORIGIN`.
   - If `Sec-Fetch-Site` is present, reject if it is not `'same-origin'` (or `'none'`).
   - Require `Content-Type: application/json` on JSON API mutations (HTML `<form>` CSRF attacks cannot send `application/json`).
2. **Pre-Login Anonymous Signed CSRF Token:**
   - `GET /auth/csrf` sets cookie `__Host-csrf` = `${randomHex}.${expiresAt}.${hmac}` (30m TTL) and returns `{ csrfToken }`.
   - Client sends `X-CSRF-Token: <token>` header; server verifies cookie matches header in constant time and validates HMAC + expiry.
3. **Post-Login Session-Bound HMAC CSRF Token:**
   - Derived deterministically via `HMAC-SHA256(CSRF_SECRET, "session-csrf:v1:" + sessionTokenHash)`. Ties the CSRF token cryptographically to the active user session.

---

## 3. Hierarchical RBAC, Bitfield Permissions & Team Sub-Accounts

### 3.1 Role Hierarchy & `sortOrder` Anti-Escalation Guard (`store` Pattern)
Assign every role an integer priority (`sortOrder`):
- `SUPER_ADMIN = 100`
- `ADMIN = 80`
- `MANAGER / MODERATOR = 50`
- `STAFF / SUPPORT = 30`
- `USER / CUSTOMER = 10`

```typescript
export function canManageTargetUser(actorHighestRoleOrder: number, targetHighestRoleOrder: number, isActorSupremeAdmin = false): boolean {
  if (isActorSupremeAdmin) return true;
  // An actor can NEVER modify, suspend, or assign roles to someone of equal or higher rank
  return actorHighestRoleOrder > targetHighestRoleOrder;
}
```
- **Self-Lockout Guard:** An Admin cannot delete their own account, suspend themselves, or remove their own `SUPER_ADMIN` role.

### 3.2 Bitfield Account Permissions (`vehosts` Pattern)
For fast, compact permission checks on sub-accounts, API keys, or JWT claims, use bitwise flags:
```typescript
export enum AccountPermission {
  VIEW_SERVICES   = 1 << 0, // 1
  MANAGE_SERVICES = 1 << 1, // 2
  VIEW_BILLING    = 1 << 2, // 4
  MANAGE_BILLING  = 1 << 3, // 8
  OPEN_TICKETS    = 1 << 4, // 16
  MANAGE_TEAM     = 1 << 5, // 32
  ADMIN_ACCESS    = 1 << 6, // 64
}

export function hasBitPermission(mask: number, required: AccountPermission, isOwner = false): boolean {
  if (isOwner) return true;
  return (mask & required) === required;
}
```

### 3.3 Team Sub-Accounts & Scoped Invitations (`vehosts` & `PPU-Complaints-Public`)
1. **Invitation Lifecycle:**
   - Primary Account Owner invites a sub-account (`email`, `permissionsMask`, optional `allowedResourceIds[]`).
   - System generates a 32-byte random token, stores `sha256(token)` in `SubAccountInvitation` with a **48-hour expiry**, and emails the invite link.
   - Invitee previews the invitation (`GET /auth/invitations/:token`) and accepts (`POST /auth/invitations/:token/accept` with `consent: true` + password/account creation).
2. **Fail-Secure `SubAccountGuard`:**
   - Sub-accounts are strictly blocked from accessing `/admin/*`, billing payment-method deletion, account deletion, or inviting other sub-accounts unless explicitly granted.
3. **Portal Separation & First-Login Password Change (`PPU-Complaints-Public` & `msaea`):**
   - If the system has separate portals (e.g., Customer/Student Portal vs. Staff/Admin Portal), reject cross-portal logins with `403 WRONG_LOGIN_PORTAL`.
   - If `user.mustChangePassword === true` (e.g., admin-provisioned staff account), block all normal API routes with `403 PASSWORD_CHANGE_REQUIRED` until `POST /auth/change-password` succeeds.

---

## 4. Multi-Auth OAuth Linking & Lockout Prevention (`pterodactyl` & `store`)

1. **Supported Providers:** Credentials (Email/Username/Phone + Password), Passwordless OTP, and OAuth2 (Google, Discord, Apple, GitHub).
2. **Unlink Lockout Prevention (`pterodactyl` `AccountIdentitiesController` Pattern):**
   - Before allowing a user to unlink an OAuth provider (`DELETE /account/identities/:provider`):
     - Verify `Boolean(user.email && user.emailVerifiedAt && user.passwordHash)`.
     - If the user registered via OAuth and has not set a password yet (`passwordHash === null`), block unlinking with `400 CANNOT_UNLINK_ONLY_AUTH_METHOD` ("Please set a password and verify your email before unlinking your OAuth account to prevent losing access").
   - Allow OAuth-only users (`passwordHash === null`) to set their initial password without requiring `currentPassword`.

---

## 5. Frontend UX, Unverified Recovery, Race-Condition Guards & Security Dashboard

### 5.1 Unverified Account Inline Recovery Banner (`course_online` Pattern)
When a user logs in with valid credentials, but `user.emailVerifiedAt === null`:
- Backend returns `403 Forbidden`:
  ```json
  {
    "code": "EMAIL_NOT_VERIFIED",
    "email": "j***e@gmail.com",
    "rawEmailToken": "<short-lived-signed-token-for-resend>",
    "message": "Your account is not verified yet.",
    "messageAr": "الحساب غير مفعل بعد. يرجى تأكيد بريدك الإلكتروني."
  }
  ```
- Frontend Login Form detects `code === 'EMAIL_NOT_VERIFIED'` and renders an inline **Amber Recovery Banner** with a one-click **"إرسال رمز التفعيل وتأكيد الحساب الآن" (Send Code & Activate Now)** button that sends the OTP and immediately opens the 6-digit OTP verification step without forcing the user to re-register.

### 5.2 Client-Side State & Race-Condition Hygiene (`PPU-Complaints-Public` & `Oman`)
1. **Zero Sensitive Browser Storage:** Never store passwords, raw OTP codes, or session secrets in `localStorage` or `sessionStorage`.
2. **`sessionRevision` Stale-401 Guard:** Maintain an in-memory integer `sessionRevision` in the frontend auth store. Increment `sessionRevision` on every login/logout. Before an in-flight background `fetch` handles a `401 Unauthorized` by clearing user state, verify `requestRevision === currentSessionRevision` so a slow request from before login never logs out the newly authenticated user.
3. **Modal `AbortController` & Generation Counter:** When the user closes an Auth/OTP modal or switches tabs (`Login <-> Register <-> Forgot Password`), abort pending requests (`abortController.abort()`) and clear transient errors/OTP inputs.

### 5.3 Account Security Center & GDPR/PDPL Data Export (`Oman` Pattern)
Every account settings page (`/account/security`) should include:
1. **Dynamic Security Health Score (`0–100`):**
   - Base account verified: `+25`
   - Strong password updated within 180 days: `+25`
   - 2FA enabled (TOTP or Email): `+30`
   - Backup recovery codes generated / Secondary identity linked: `+20`
2. **Active Sessions & Device Manager:** List all active `UserSession` rows (Browser/OS icon, IP address, City/Country, `Current Session` badge, `Last active`), with individual **"إنهاء الجلسة" (Revoke)** and **"إنهاء جميع الجلسات الأخرى" (Revoke All Other Sessions)** buttons.
3. **User-Facing Security Activity Log:** Last 20 security events (`Login`, `Failed Login`, `2FA Changed`, `Password Changed`) with IP and timestamp.
4. **One-Click Account Data Export (`GET /account/export-data`):** Export profile, sessions, and audit history as a clean JSON archive (`GDPR / PDPL` compliance).

---

## 6. HTTP Security Headers & Dual-Tier Forensic Audit Logging (`finflow-accounting`, `vehosts`, `store`)

### 6.1 Mandatory Security Headers Middleware
Apply to every response:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
- Remove `X-Powered-By` and `Server` headers; set `productionBrowserSourceMaps: false` in Next.js.

### 6.2 Non-Blocking Dual-Tier Audit Logger
Record every sensitive auth event (`USER_REGISTERED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `OTP_SENT`, `OTP_VERIFIED`, `OTP_FAILED`, `2FA_ENABLED`, `2FA_DISABLED`, `2FA_ADMIN_BYPASS`, `PASSWORD_RESET_REQUESTED`, `PASSWORD_RESET_COMPLETED`, `SESSION_REVOKED`, `ALL_SESSIONS_REVOKED`, `SUBACCOUNT_INVITED`, `ROLE_UPDATED`):
- Wrap database audit inserts in `try / catch` so an audit table failure never crashes the user's login flow, while always writing to the structured security log stream.

