# Pillar 4 & 8: Multi-Layered Rate Limiting, Account Lockout, Anti-Bot & Anti-Fraud

This reference defines the exact dual-bucket rate limiting, progressive account lockout, memory-bounded store, timing-attack floor, honeypot, Turnstile/reCAPTCHA, MaxMind minFraud, referral IP anti-fraud, and Permanent Identity Graveyard patterns extracted across `PPU-Complaints-Public`, `vehosts`, `course_online`, `Oman`, `finflow-accounting`, `store`, and `pterodactyl`.

---

## 1. Dual-Bucket Rate Limiting Matrix (IP + SHA-256 Identifier Hash)

Rate limiting by IP alone is defeated by rotating proxies; rate limiting by email alone lets an attacker lock out legitimate users or flood Redis keys. Every sensitive auth endpoint must enforce **Dual-Bucket Rate Limiting**:
- **Bucket A (IP Bucket):** Keyed by `rl:{action}:ip:{clientIp}`
- **Bucket B (Identity Bucket):** Keyed by `rl:{action}:id:{sha256(normalizedIdentifier)}` (hashing the email/identifier prevents PII leakage in Redis/logs).

### 1.1 Standard Endpoint Rate Limit Thresholds

| Action / Endpoint | IP Bucket Limit | Identifier Bucket Limit | Cooldown / Special Rule |
|-------------------|-----------------|-------------------------|-------------------------|
| `POST /auth/login` | `10` per `15 min` | `10` per `15 min` | Clear login throttle upon entering 2FA checkpoint so user isn't locked out while entering 2FA code (`vehosts`). |
| `POST /auth/register` | `5` per `15 min` (or `1 hr`) | `3` per `1 hr` | Check Honeypot + Turnstile/reCAPTCHA + MaxMind minFraud BEFORE creating user. |
| `POST /auth/send-otp` / `resend-otp` | `5` per `15 min` | `3` per `15 min` (`5` per `1 hr`) | Enforce strict **60-second cooldown** (`45s`–`60s`) between sends per identifier. |
| `POST /auth/verify-otp` / `2fa/verify` | `15` per `15 min` | `15` per `15 min` | Also enforce **persistent DB counter (`max 3 to 5 failed attempts`)** on the OTP record itself. |
| `POST /auth/forgot-password` | `5` per `15 min` | `3` per `15 min` | Enforce **Minimum 8-Second Response Floor** (`MIN_RESPONSE_MS = 8000`) to eliminate SMTP timing side-channels (`PPU-Complaints-Public`). |
| `POST /auth/reset-password` | `10` per `15 min` | `5` per `15 min` | Immediately revoke all active sessions & bump `token_version` upon success. |
| `POST /auth/refresh-token` | `30` per `15 min` | `30` per `15 min` | Rotate refresh token on every call. |
| Global API Baseline | `100` per `1 min` | — | Return standard `429` headers. |

---

## 2. Redis Primary + Bounded In-Memory Fallback Rate Limiter (`OWASP API4:2023`)

Never use an unbounded JavaScript `Map` for rate limiting—an attacker spoofing IPs can grow the Map infinitely and crash the Node.js process (`OOM`). Always enforce:
1. **Redis Primary** (`INCR` + `PEXPIRE` or Upstash `@upstash/ratelimit` sliding window) when `REDIS_URL` is configured.
2. **Bounded In-Memory Fallback** with a hard cap (`MAX_ENTRIES = 10000`) and a periodic `unref()` cleanup timer every 5 minutes that evicts expired entries (and evicts oldest entries if `size >= MAX_ENTRIES`).
3. **Standard RFC 6585 / IETF Headers** on every response:
   - `Retry-After: <seconds>`
   - `X-RateLimit-Limit: <max>`
   - `X-RateLimit-Remaining: <remaining>`
   - `X-RateLimit-Reset: <epochSeconds>`
4. **Proxy Trust Discipline:** Only read `X-Forwarded-For` when `TRUST_PROXY=true` is explicitly configured; otherwise use `req.socket.remoteAddress`.

```typescript
import crypto from 'node:crypto';

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds: number;
  resetAtEpochSeconds: number;
}

interface BucketEntry {
  count: number;
  resetAtMs: number;
}

export class QwRateLimiter {
  private static readonly MAX_MEMORY_ENTRIES = 10_000;
  private static readonly buckets = new Map<string, BucketEntry>();
  private static cleanupTimer: NodeJS.Timeout | null = null;

  static initCleanup(intervalMs = 5 * 60 * 1000): void {
    if (this.cleanupTimer) return;
    this.cleanupTimer = setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.buckets.entries()) {
        if (entry.resetAtMs <= now) {
          this.buckets.delete(key);
        }
      }
    }, intervalMs);
    this.cleanupTimer.unref?.();
  }

  static hashIdentifier(identifier: string): string {
    return crypto.createHash('sha256').update(identifier.trim().toLowerCase()).digest('hex').slice(0, 32);
  }

  static consumeMemory(key: string, limit: number, windowMs: number): RateLimitResult {
    this.initCleanup();
    const now = Date.now();
    let entry = this.buckets.get(key);

    if (!entry || entry.resetAtMs <= now) {
      // Evict oldest key if memory cap is reached (OWASP API4:2023 protection)
      if (!entry && this.buckets.size >= this.MAX_MEMORY_ENTRIES) {
        const oldestKey = this.buckets.keys().next().value;
        if (oldestKey) this.buckets.delete(oldestKey);
      }
      entry = { count: 0, resetAtMs: now + windowMs };
      this.buckets.set(key, entry);
    }

    entry.count += 1;
    const allowed = entry.count <= limit;
    const remaining = Math.max(0, limit - entry.count);
    const retryAfterSeconds = Math.max(1, Math.ceil((entry.resetAtMs - now) / 1000));
    const resetAtEpochSeconds = Math.ceil(entry.resetAtMs / 1000);

    return { allowed, limit, remaining, retryAfterSeconds, resetAtEpochSeconds };
  }

  /**
   * Dual-Bucket Check: Enforces both IP limit and Identifier limit atomically.
   */
  static checkDualBucket(params: {
    action: string;
    ip: string;
    identifier?: string;
    ipLimit: number;
    idLimit?: number;
    windowMs: number;
  }): RateLimitResult {
    const ipResult = this.consumeMemory(`rl:${params.action}:ip:${params.ip}`, params.ipLimit, params.windowMs);
    if (!ipResult.allowed || !params.identifier || !params.idLimit) {
      return ipResult;
    }

    const idHash = this.hashIdentifier(params.identifier);
    const idResult = this.consumeMemory(`rl:${params.action}:id:${idHash}`, params.idLimit, params.windowMs);
    return !idResult.allowed ? idResult : ipResult;
  }
}
```

### 2.1 Minimum 8-Second Timing Floor on Forgot-Password (`PPU-Complaints-Public` Pattern)
When a user requests a password reset, sending an actual SMTP email takes ~1–4 seconds, whereas skipping SMTP for a non-existent email takes ~5ms. To eliminate this timing side-channel:

```typescript
export async function withMinimumDuration<T>(minDurationMs: number, task: () => Promise<T>): Promise<T> {
  const startedAt = Date.now();
  try {
    return await task();
  } finally {
    const elapsed = Date.now() - startedAt;
    const remaining = minDurationMs - elapsed;
    if (remaining > 0) {
      await new Promise((resolve) => setTimeout(resolve, remaining));
    }
  }
}
// Usage in POST /auth/forgot-password:
// await withMinimumDuration(8000, async () => authService.requestPasswordReset(dto));
```

---

## 3. Account-Level Progressive Lockout (`course_online` Pattern)

In addition to IP/Bucket rate limiting, protect individual accounts in the database against distributed credential stuffing (botnets using 10,000 different IPs to guess one user's password):

1. **Database Fields on `User`:**
   - `failedLoginAttempts: Int @default(0)`
   - `lockedUntil: DateTime?`
   - `lastLoginAt: DateTime?`
   - `lastLoginIp: String?`
2. **Lockout Check (Before Password Verification):**
   ```typescript
   if (user.lockedUntil && user.lockedUntil > new Date()) {
     const remainingMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);
     throw new ForbiddenException({
       code: 'ACCOUNT_LOCKED',
       message: `Account is temporarily locked due to multiple failed login attempts. Try again in ${remainingMinutes} minutes.`,
       messageAr: `تم قفل الحساب مؤقتاً بسبب محاولات دخول فاشلة متكررة. يرجى المحاولة بعد ${remainingMinutes} دقيقة.`,
       retryAfterSeconds: Math.ceil((user.lockedUntil.getTime() - Date.now()) / 1000),
     });
   }
   ```
3. **On Failed Password Check:**
   - Increment `failedLoginAttempts`.
   - If `newAttempts >= 5`, set `lockedUntil = new Date(Date.now() + 15 * 60 * 1000)` (15 minutes, or progressive `15m -> 60m -> 24h`).
4. **On Successful Password Check:**
   - Reset `failedLoginAttempts = 0`, `lockedUntil = null`, and update `lastLoginAt = new Date()`, `lastLoginIp = clientIp`.

---

## 4. Anti-Bot, Fraud Scoring & Permanent Identity Graveyard

### 4.1 Hidden Honeypot Field (`vehosts` & `pterodactyl`)
Include a hidden input field in registration/login forms (e.g., `website_url` or `hp_verification` with `tabIndex={-1}`, `autoComplete="off"`, `aria-hidden="true"`, hidden via CSS `position: absolute; left: -9999px`):
- If `Boolean(dto.website_url)` is non-empty, reject immediately with `422/400` (or silently drop) and log a bot attempt.

### 4.2 Cloudflare Turnstile / Google reCAPTCHA Verification (`vehosts` & `course_online`)
Verify `cf-turnstile-response` (or `X-Turnstile-Token` / `g-recaptcha-response`) server-side before creating accounts or sending unauthenticated OTPs:

```typescript
export async function verifyTurnstileToken(token: string | undefined, remoteIp?: string): Promise<boolean> {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    // In production, log warning if secret is unconfigured; in dev, allow bypass
    return process.env.NODE_ENV !== 'production';
  }
  if (!token) return false;

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      secret,
      response: token,
      ...(remoteIp ? { remoteip: remoteIp } : {}),
    }),
  });
  const data = (await response.json()) as { success?: boolean };
  return Boolean(data.success);
}
```

### 4.3 MaxMind minFraud & Referral IP Anti-Fraud (`vehosts` Pattern)
1. **MaxMind Risk Score:** For e-commerce/hosting/fintech registration, query MaxMind minFraud Score API (`device.ip_address`, `device.user_agent`, `email.address`, `email.domain`). If `risk_score >= threshold` (default `60`), reject registration or flag account for manual review. Always **fail-open** on MaxMind network timeouts (`timeout: 5s`) so third-party outages do not block legitimate signups.
2. **Referral Self-Farming Guard:** When `ref` (referral code) is present during registration:
   - Reject referral credit if `referrer.id === newUser.id`.
   - Reject referral credit if `referrer.lastLoginIp === requestIp` or if another user already registered from `requestIp`.

### 4.4 Permanent Identity Graveyard (`pterodactyl` `SlenderIdentityService` Pattern)
In systems offering free trials, credits, or community access, malicious users delete their account and re-register with the same email or OAuth account (`discord_id` / `google_id`) to abuse trial quotas or evade bans.
- Maintain a dedicated **`RegisteredIdentity`** (Identity Graveyard) table that is **NEVER cascaded or deleted** when a `User` row is deleted:
  - `id`, `identityType` (`'EMAIL' | 'PHONE' | 'DISCORD' | 'GOOGLE'`), `identityValue` (normalized), `originalUserId`, `firstRegisteredAt`, `isBanned`, `banReason`.
- **Enforcement:**
  - Before registering or linking an OAuth provider, check `RegisteredIdentity`.
  - If `isBanned === true`, block registration immediately (`403 Forbidden`).
  - If `blockDeletedReRegistration` policy is enabled and `originalUserId` no longer exists (or belongs to another user), block re-registration or withhold free-tier trial credits.

