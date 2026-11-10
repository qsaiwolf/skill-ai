# Pillar 3: Password Cryptography, Bounded Worker Queue & Strength Policy

This reference defines the exact password strength evaluation, cryptographic hashing, CPU/memory DoS protection (`AUTH_BUSY` bounded worker queue), timing-safe dummy hash verification, and memory zeroization patterns extracted across `PPU-Complaints-Public`, `course_online`, `vehosts`, `finflow-accounting`, and `store`.

---

## 1. Password Input & Strength Policy

### 1.1 Hard Input Constraints
- **Minimum Length:** `8` characters (Standard SaaS) or `12` characters (High-Security / Fintech / Admin accounts).
- **Maximum Length:** `128` characters (Hard cap to prevent giant-payload hashing DoS; **never silently truncate** passwords).
- **Complexity Rules:**
  1. At least one uppercase English letter (`/[A-Z]/`).
  2. At least one lowercase English letter (`/[a-z]/`).
  3. At least one digit (`/[0-9]/`).
  4. At least one special character (`/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?~`]/`).
- **Anti-Pattern Checks:**
  - Reject 4+ identical consecutive characters (`/(.)\1{3,}/`, e.g. `aaaa`).
  - Reject common keyboard walks (`qwerty`, `asdfgh`, `zxcvbn`, `123456`, `654321`).

### 1.2 Contextual `zxcvbn` + Breach Check (`k-Anonymity HIBP`) + Last-1 Password Reuse Guard
- Pass the user's personal identifiers (`[username, emailLocalPart, firstName, lastName, phone]`) into `zxcvbn(password, userInputs)` so passwords containing the user's own name, handle, or phone number are rejected even if they contain symbols/numbers.
- Require `zxcvbnResult.score >= 2` (or `>= 3` for Admin/Staff).
- **k-Anonymity HIBP Check:** Query `https://api.pwnedpasswords.com/range/{first5HexOfSha1}` with `Add-Padding: true` and a 2.5s fail-open timeout (see [`references/07-advanced-zero-trust-and-passkeys.md`](07-advanced-zero-trust-and-passkeys.md)). In Laravel (`vehosts`), enforce `Password::min(8)->mixedCase()->numbers()->symbols()->uncompromised()`.
- **Last-1 Password Reuse Guard (`previousPasswordHash`):** On password change or reset, verify the new password does NOT match `user.passwordHash` (current) OR `user.previousPasswordHash` (the single immediately preceding password). When updating `passwordHash`, set `previousPasswordHash = user.passwordHash` (see [`references/07-advanced-zero-trust-and-passkeys.md`](07-advanced-zero-trust-and-passkeys.md)).

```typescript
import zxcvbn from 'zxcvbn';

export interface PasswordValidationResult {
  valid: boolean;
  score: number; // 0 to 4
  errors: string[];
  errorsAr: string[];
}

export class PasswordStrengthService {
  private static readonly KEYBOARD_WALKS = ['qwerty', 'asdfgh', 'zxcvbn', '123456', '654321', 'password', 'iloveyou'];

  static validate(
    password: string,
    userInputs: string[] = [],
    minScore = 2
  ): PasswordValidationResult {
    const errors: string[] = [];
    const errorsAr: string[] = [];

    if (!password || typeof password !== 'string') {
      return { valid: false, score: 0, errors: ['Password is required'], errorsAr: ['كلمة المرور مطلوبة'] };
    }

    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
      errorsAr.push('كلمة المرور يجب أن لا تقل عن 8 أحرف');
    }
    if (password.length > 128) {
      errors.push('Password must not exceed 128 characters');
      errorsAr.push('كلمة المرور يجب أن لا تتجاوز 128 حرفاً');
    }
    if (!/[A-Z]/.test(password)) {
      errors.push('Must contain at least one uppercase letter (A-Z)');
      errorsAr.push('يجب أن تحتوي على حرف كبير واحد على الأقل (A-Z)');
    }
    if (!/[a-z]/.test(password)) {
      errors.push('Must contain at least one lowercase letter (a-z)');
      errorsAr.push('يجب أن تحتوي على حرف صغير واحد على الأقل (a-z)');
    }
    if (!/[0-9]/.test(password)) {
      errors.push('Must contain at least one number (0-9)');
      errorsAr.push('يجب أن تحتوي على رقم واحد على الأقل (0-9)');
    }
    if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?~`]/.test(password)) {
      errors.push('Must contain at least one special character (!@#$%^&*)');
      errorsAr.push('يجب أن تحتوي على رمز خاص واحد على الأقل (!@#$%^&*)');
    }
    if (/(.)\1{3,}/.test(password)) {
      errors.push('Cannot contain 4 identical consecutive characters');
      errorsAr.push('لا يمكن تكرار نفس الحرف 4 مرات متتالية');
    }

    const lower = password.toLowerCase();
    if (this.KEYBOARD_WALKS.some((walk) => lower.includes(walk))) {
      errors.push('Password contains a common predictable sequence');
      errorsAr.push('كلمة المرور تحتوي على تسلسل شائع يسهل تخمينه');
    }

    const sanitizedInputs = userInputs
      .filter(Boolean)
      .flatMap((input) => [input.toLowerCase(), input.split('@')[0]?.toLowerCase()])
      .filter((v): v is string => Boolean(v && v.length >= 3));

    for (const token of sanitizedInputs) {
      if (lower.includes(token)) {
        errors.push('Password must not contain your username, name, or email');
        errorsAr.push('لا يجوز أن تحتوي كلمة المرور على اسمك أو بريدك أو اسم المستخدم');
        break;
      }
    }

    const evaluation = zxcvbn(password, sanitizedInputs);
    if (evaluation.score < minScore) {
      errors.push('Password is too weak or easy to guess');
      errorsAr.push('كلمة المرور ضعيفة ويسهل تخمينها، يرجى اختيار كلمة أقوى');
    }

    return {
      valid: errors.length === 0,
      score: evaluation.score,
      errors,
      errorsAr,
    };
  }
}
```

---

## 2. Cryptographic Hashing, Bounded Worker Queue & Memory Zeroization

Password hashing is intentionally CPU- and memory-intensive (`scrypt` at 128 MiB or `bcrypt` at 12 rounds). Without concurrency limits, an attacker sending 50 concurrent login requests will exhaust server RAM/CPU and trigger an Out-Of-Memory crash.

### 2.1 Production-Hardened `scrypt` Engine with Bounded Queue (`PPU-Complaints-Public` & `finflow-accounting`)

- **Algorithm Parameters:** `scrypt` (`N = 131072` ($2^{17}$), `r = 8`, `p = 1`, `keylen = 64` bytes, `16-byte` CSPRNG salt, `maxmem = 256 MiB`).
- **Bounded Worker Queue:** Maximum `2` active hashing operations and maximum `8` queued waiting callers. A 11th concurrent request immediately throws `503 Service Unavailable` (`AUTH_BUSY`) instead of starving the event loop.
- **Buffer Zeroization:** Always overwrite derived keys (`derivedKey.fill(0)`) inside `finally` blocks so plaintext/derived secrets do not linger in V8 heap memory.
- **Timing-Safe Dummy Hash:** Precompute a real `DUMMY_PASSWORD_HASH` at server startup. When a login request arrives for a non-existent account, run `verifyPassword(password, DUMMY_PASSWORD_HASH)` so unknown-user requests take the exact same ~150ms–300ms as real users.

```typescript
import crypto from 'node:crypto';

const SCRYPT_PARAMS = {
  N: 131072, // 2^17
  r: 8,
  p: 1,
  keyLen: 64,
  maxmem: 256 * 1024 * 1024, // 256 MiB ceiling
};

const MAX_ACTIVE_WORKERS = 2;
const MAX_QUEUED_CALLERS = 8;

let activeWorkers = 0;
const waitQueue: Array<() => void> = [];

export class AuthBusyError extends Error {
  readonly status = 503;
  readonly code = 'AUTH_BUSY';
  constructor() {
    super('Authentication server is currently busy. Please retry in a few seconds.');
  }
}

async function acquireHashSlot(): Promise<void> {
  if (activeWorkers < MAX_ACTIVE_WORKERS) {
    activeWorkers += 1;
    return;
  }
  if (waitQueue.length >= MAX_QUEUED_CALLERS) {
    throw new AuthBusyError();
  }
  await new Promise<void>((resolve) => waitQueue.push(resolve));
  activeWorkers += 1;
}

function releaseHashSlot(): void {
  activeWorkers = Math.max(0, activeWorkers - 1);
  const next = waitQueue.shift();
  if (next) next();
}

function deriveScryptKey(password: string, salt: Buffer, N: number, r: number, p: number, keyLen: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.scrypt(
      Buffer.from(password, 'utf8'),
      salt,
      keyLen,
      { N, r, p, maxmem: SCRYPT_PARAMS.maxmem },
      (err, derivedKey) => {
        if (err) reject(err);
        else resolve(derivedKey);
      }
    );
  });
}

/**
 * Hash format: scrypt$N$r$p$saltBase64$hashBase64
 */
export async function hashPassword(password: string): Promise<string> {
  if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
    throw new Error('Password length must be between 8 and 128 characters');
  }

  await acquireHashSlot();
  let derivedKey: Buffer | null = null;
  try {
    const salt = crypto.randomBytes(16);
    derivedKey = await deriveScryptKey(
      password,
      salt,
      SCRYPT_PARAMS.N,
      SCRYPT_PARAMS.r,
      SCRYPT_PARAMS.p,
      SCRYPT_PARAMS.keyLen
    );
    return [
      'scrypt',
      SCRYPT_PARAMS.N,
      SCRYPT_PARAMS.r,
      SCRYPT_PARAMS.p,
      salt.toString('base64'),
      derivedKey.toString('base64'),
    ].join('$');
  } finally {
    if (derivedKey) derivedKey.fill(0); // Memory zeroization
    releaseHashSlot();
  }
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (typeof password !== 'string' || !password || password.length > 128 || typeof storedHash !== 'string') {
    return false;
  }

  const parts = storedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') {
    return false;
  }

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = Buffer.from(parts[4], 'base64');
  const expectedKey = Buffer.from(parts[5], 'base64');

  // Strict parameter sanity check to prevent malicious DB hash parameter injection
  if (!Number.isInteger(N) || N < 16384 || N > 1048576 || (N & (N - 1)) !== 0) return false;
  if (!Number.isInteger(r) || r < 1 || r > 32) return false;
  if (!Number.isInteger(p) || p < 1 || p > 16) return false;
  if (salt.length < 16 || expectedKey.length !== 64) return false;

  await acquireHashSlot();
  let derivedKey: Buffer | null = null;
  try {
    derivedKey = await deriveScryptKey(password, salt, N, r, p, expectedKey.length);
    if (derivedKey.length !== expectedKey.length) return false;
    return crypto.timingSafeEqual(derivedKey, expectedKey);
  } finally {
    if (derivedKey) derivedKey.fill(0);
    expectedKey.fill(0);
    releaseHashSlot();
  }
}

// Precompute dummy hash once at boot for constant-time unknown-user login rejection
let DUMMY_PASSWORD_HASH: string | null = null;
export async function verifyAgainstDummyPassword(candidatePassword: string): Promise<boolean> {
  if (!DUMMY_PASSWORD_HASH) {
    DUMMY_PASSWORD_HASH = await hashPassword('Dummy_QW_Constant_Time_Guard#2026!');
  }
  await verifyPassword(candidatePassword.slice(0, 128) || 'invalid_placeholder', DUMMY_PASSWORD_HASH);
  return false;
}
```

> **Alternative (`bcrypt` in NestJS/Laravel):** If the stack mandates `bcrypt` (`bcryptjs` or PHP `Hash::make`), enforce **12 rounds** (`SALT_ROUNDS = 12`) and still wrap `bcrypt.hash` / `bcrypt.compare` inside `acquireHashSlot()` + `verifyAgainstDummyPassword()`.

---

## 3. Frontend Live Password Strength Meter & 6-Item Interactive Checklist (`course_online` Pattern)

Every registration and password-reset form must render:
1. **Password Visibility Toggle Button:** Always set `type="button"` and `tabIndex={-1}` so pressing Enter in the form never triggers the eye toggle by mistake.
2. **4-Bar Visual Strength Meter:**
   - Score 1 (Weak): 1 bar filled — `bg-rose-500` (`ضعيفة`)
   - Score 2 (Fair): 2 bars filled — `bg-amber-500` (`متوسطة`)
   - Score 3 (Good): 3 bars filled — `bg-blue-500` (`جيدة`)
   - Score 4 (Strong): 4 bars filled — `bg-emerald-500` (`قوية جداً`)
3. **Interactive 6-Rule Checklist (Green Checkmark vs. Muted Circle):**
   - `password.length >= 8` (`8 أحرف على الأقل`)
   - `/[A-Z]/.test(password)` (`حرف كبير واحد على الأقل A-Z`)
   - `/[a-z]/.test(password)` (`حرف صغير واحد على الأقل a-z`)
   - `/[0-9]/.test(password)` (`رقم واحد على الأقل 0-9`)
   - `/[!@#$%^&*...]/.test(password)` (`رمز خاص واحد على الأقل !@#$`)
   - `password.length > 0 && password === confirmPassword` (`تطابق كلمتي المرور`)

