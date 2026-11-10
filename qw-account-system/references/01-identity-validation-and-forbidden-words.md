# Pillar 1 & 2: Identity Normalization, Multi-Identifier Intake & Forbidden Words Engine

This reference defines the exact identity intake, normalization, domain governance, phone validation, and 5-category forbidden words/usernames engine extracted across `course_online`, `store`, `vehosts`, `PPU-Complaints-Public`, `pterodactyl`, `fluxer`, and `al-deeb-family`.

---

## 1. Multi-Identifier Intake (Login & Lookup)

Login endpoints must accept a single `identifier` field (or `email`/`username`/`phone`) and automatically detect its type before normalization:

1. **Email Detection:** Contains `@`. Normalize via `EmailValidatorService.normalize(identifier)` and query `WHERE email = normalizedEmail`.
2. **Phone Detection:** Matches `/^[+0-9()\-\s]{7,20}$/`. Normalize via `PhoneValidatorService.validateAndNormalize(identifier)` into E.164 format (`+9665...`) and query `WHERE phone = e164Phone`.
3. **Username Detection:** Otherwise treat as a handle. Trim, convert to lowercase (`identifier.trim().toLowerCase()`), and query `WHERE username = normalizedUsername`.

> **Security Rule:** Regardless of which identifier type is used, if no user is found, the login flow MUST still execute a dummy password hash verification (`verifyPassword(password, DUMMY_HASH)`) and return a generic `"Invalid credentials"` (`401`) message to prevent account enumeration via response timing or error messages.

---

## 2. Email Normalization & Domain Governance

### 2.1 Control-Character & Length Guards
- Reject any email containing ASCII control characters: `/[\u0000-\u001f\u007f]/`.
- Minimum length: `5`, Maximum length: `254` (RFC 5321).
- Structural Regex: `/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/`.

### 2.2 Gmail & Alias Canonicalization (Anti-Multi-Account Farming)
Prevent a single user from creating unlimited accounts using Gmail dot-tricks (`u.s.e.r@gmail.com`), plus-addressing (`user+1@gmail.com`), or domain aliases (`@googlemail.com`):

```typescript
export class EmailValidatorService {
  private static readonly ALLOWED_DOMAINS = new Set([
    // Google
    'gmail.com', 'googlemail.com',
    // Microsoft
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.sa',
    // Yahoo
    'yahoo.com', 'yahoo.co.uk', 'ymail.com',
    // Apple
    'icloud.com', 'me.com', 'mac.com',
    // Privacy & Business Providers
    'protonmail.com', 'proton.me', 'zoho.com', 'aol.com', 'gmx.com', 'mail.com',
    // Regional ISPs
    'stc.com.sa', 'mobily.com.sa',
  ]);

  private static readonly BLOCKED_DISPOSABLE_DOMAINS = new Set([
    'tempmail.com', 'temp-mail.org', 'guerrillamail.com', 'guerrillamail.info',
    'mailinator.com', 'yopmail.com', '10minutemail.com', 'throwaway.email',
    'fakeinbox.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
    'dispostable.com', 'mailnesia.com', 'maildrop.cc', 'discard.email',
    'trashmail.com', 'trashmail.net', 'mohmal.com', 'tempail.com',
    'burnermail.io', 'tempmailo.com', 'emailondeck.com', 'crazymailing.com',
  ]);

  private static readonly ALLOWED_TLD_PATTERNS = [
    /\.edu$/,
    /\.edu\.[a-z]{2}$/, // e.g., .edu.ps, .edu.sa, .edu.jo, .edu.eg
    /\.ac\.[a-z]{2}$/,  // e.g., .ac.uk
    /\.gov\.[a-z]{2}$/,
  ];

  /**
   * Canonicalizes email to prevent duplicate accounts via Gmail dots or +tags.
   */
  static normalize(email: string): string {
    const trimmed = String(email || '').trim().toLowerCase();
    const parts = trimmed.split('@');
    if (parts.length !== 2) return trimmed;

    let [local, domain] = parts;

    // Strip +tag subaddressing across all providers
    local = local.split('+')[0];

    // Canonicalize Google domains & strip dots from local part
    if (domain === 'gmail.com' || domain === 'googlemail.com') {
      local = local.replace(/\./g, '');
      domain = 'gmail.com';
    }

    return `${local}@${domain}`;
  }

  static validate(
    email: string,
    options: { enforceWhitelist?: boolean; institutionalRegex?: RegExp } = { enforceWhitelist: true }
  ): { valid: boolean; normalizedEmail?: string; error?: string; errorAr?: string } {
    if (!email || typeof email !== 'string') {
      return { valid: false, error: 'Email is required', errorAr: 'البريد الإلكتروني مطلوب' };
    }
    if (/[\u0000-\u001f\u007f]/.test(email)) {
      return { valid: false, error: 'Invalid characters in email', errorAr: 'البريد الإلكتروني يحتوي على رموز غير صالحة' };
    }

    const trimmed = email.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(trimmed) || trimmed.length > 254) {
      return { valid: false, error: 'Invalid email format', errorAr: 'صيغة البريد الإلكتروني غير صحيحة' };
    }

    // Optional strict institutional policy (e.g., PPU University: /^[0-9]{5,9}@ppu\.edu\.ps$/)
    if (options.institutionalRegex && !options.institutionalRegex.test(trimmed)) {
      return {
        valid: false,
        error: 'Email does not match institutional requirements',
        errorAr: 'البريد الإلكتروني لا يطابق شروط المؤسسة',
      };
    }

    const [local, domain] = trimmed.split('@');
    if (local.length < 2) {
      return { valid: false, error: 'Email username is too short', errorAr: 'الجزء الأول من البريد قصير جداً' };
    }

    if (this.BLOCKED_DISPOSABLE_DOMAINS.has(domain)) {
      return {
        valid: false,
        error: 'Disposable email addresses are not allowed',
        errorAr: 'عناوين البريد الإلكتروني المؤقتة أو الوهمية غير مسموح بها',
      };
    }

    if (options.enforceWhitelist) {
      const isAllowedDomain = this.ALLOWED_DOMAINS.has(domain);
      const isAllowedTld = this.ALLOWED_TLD_PATTERNS.some((pattern) => pattern.test(domain));
      if (!isAllowedDomain && !isAllowedTld) {
        return {
          valid: false,
          error: 'Email provider is not supported. Use Gmail, Outlook, Yahoo, iCloud, or an academic email.',
          errorAr: 'مزود البريد غير مدعوم. يرجى استخدام مزود معتمد مثل Gmail أو Outlook أو Yahoo أو iCloud.',
        };
      }
    }

    return { valid: true, normalizedEmail: this.normalize(trimmed) };
  }
}
```

---

## 3. Phone Number Validation & E.164 Normalization

Phone numbers must be validated with `libphonenumber-js` (or equivalent) and stored in strict **E.164** format (`+966512345678`):

```typescript
import { parsePhoneNumberFromString, CountryCode } from 'libphonenumber-js';

export class PhoneValidatorService {
  private static readonly BLOCKED_NUMBERS = new Set([
    '+966000000000', '+966111111111', '+966123456789',
    '+201000000000', '+10000000000', '+970590000000',
  ]);

  static validateAndNormalize(
    phone: string,
    defaultCountry: CountryCode = 'SA'
  ): { valid: boolean; normalizedPhone?: string; country?: string; error?: string; errorAr?: string } {
    if (!phone || typeof phone !== 'string') {
      return { valid: false, error: 'Phone number is required', errorAr: 'رقم الهاتف مطلوب' };
    }

    // Strip spaces, dashes, and parentheses; convert leading 00 to +
    let cleaned = phone.trim().replace(/[\s\-()]/g, '');
    if (cleaned.startsWith('00')) {
      cleaned = '+' + cleaned.slice(2);
    }

    try {
      const parsed = cleaned.startsWith('+')
        ? parsePhoneNumberFromString(cleaned)
        : parsePhoneNumberFromString(cleaned, defaultCountry);

      if (!parsed || !parsed.isValid()) {
        return { valid: false, error: 'Invalid phone number', errorAr: 'رقم الهاتف غير صالح' };
      }

      const e164 = parsed.format('E.164');
      const national = parsed.nationalNumber as string;

      // Reject repeating digits (e.g., 11111111) or simple sequences (1234567)
      if (
        this.BLOCKED_NUMBERS.has(e164) ||
        /^(\d)\1{6,}$/.test(national) ||
        /^1234567/.test(national)
      ) {
        return { valid: false, error: 'Fake or sequential phone numbers are not allowed', errorAr: 'رقم الهاتف غير صالح' };
      }

      return { valid: true, normalizedPhone: e164, country: parsed.country };
    } catch {
      return { valid: false, error: 'Unable to parse phone number', errorAr: 'تعذر التحقق من رقم الهاتف' };
    }
  }
}
```

---

## 4. Username Rules, Leet-Speak Normalization & 5-Category Forbidden Words Engine

Usernames, display names (`firstName`, `lastName`, `global_name`), and profile bios must pass a multi-layered filter covering structural rules, Leet-Speak de-obfuscation, and a 5-category bilingual blocklist.

### 4.1 Structural Username Rules
1. **Length:** `5` to `30` characters (for usernames); `2` to `50` characters (for first/last names).
2. **Case:** Automatically converted to lowercase (`a-z0-9._`).
3. **Start Character:** Must start with an English letter (`/^[a-z]/`).
4. **End Character:** Cannot end with `.` or `_` (`/[._]$/`).
5. **No Consecutive Separators:** Reject `..`, `__`, `._`, `_.` (`/(\.\.|__|_\.|\._)/`).
6. **Minimum Letters:** Must contain at least `3` alphabetic characters (`(username.match(/[a-z]/g) || []).length >= 3`).

### 4.2 Leet-Speak & Unicode Homograph / Zero-Width De-Obfuscation
Before checking any username or display name against the blocklist:
1. Strip all invisible Zero-Width characters (`\u200B-\u200F`, `\uFEFF`) and Bidirectional overrides (`\u202A-\u202E`), normalize with `.normalize('NFKC')`, and fold Cyrillic/Greek homograph lookalikes (`а` -> `a`, `е` -> `e`, `о` -> `o`, `р` -> `p`, `с` -> `c`, `х` -> `x`) using `UnicodeSanitizer` (see [`references/07-advanced-zero-trust-and-passkeys.md`](07-advanced-zero-trust-and-passkeys.md)).
2. Normalize common Leet-Speak character substitutions so attackers cannot bypass filters using `a_d_m_1_n` or `s.h.1.t`:

```typescript
export function normalizeLeetSpeak(input: string): string {
  return input
    .normalize('NFKC')
    .replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, '')
    .toLowerCase()
    .replace(/[@4]/g, 'a')
    .replace(/3/g, 'e')
    .replace(/[1!|]/g, 'i')
    .replace(/0/g, 'o')
    .replace(/[$5]/g, 's')
    .replace(/7/g, 't')
    .replace(/[._\-\s]/g, ''); // Strip all separators to catch 'a.d.m.i.n'
}
```

### 4.3 The 5-Category Master Forbidden Words Dictionary

Include this dictionary in every project (`src/data/forbidden-words.ts` or `app/Rules/NotReservedUsername.php`):

```typescript
// Category 1: System, Admin, Technical & Official Reserved Handles (EN + AR)
export const RESERVED_SYSTEM_WORDS = [
  'admin', 'administrator', 'root', 'system', 'sysadmin', 'owner', 'master',
  'superadmin', 'superuser', 'supervisor', 'moderator', 'mod', 'staff', 'support',
  'helpdesk', 'help', 'info', 'contact', 'sales', 'billing', 'security', 'abuse',
  'postmaster', 'webmaster', 'hostmaster', 'official', 'verified', 'bot', 'robot',
  'api', 'graphql', 'webhook', 'webhooks', 'oauth', 'auth', 'login', 'logout',
  'signin', 'signup', 'register', 'password', 'reset', 'verify', 'checkpoint',
  'dashboard', 'panel', 'console', 'portal', 'settings', 'profile', 'account',
  'user', 'users', 'client', 'clients', 'customer', 'guest', 'anonymous',
  'null', 'undefined', 'void', 'true', 'false', 'nan', 'infinity',
  'test', 'testing', 'demo', 'dev', 'staging', 'prod', 'production', 'localhost',
  'www', 'mail', 'smtp', 'imap', 'pop', 'ftp', 'ssh', 'cdn', 'assets', 'static',
  // Arabic Official & System Terms
  'ادمن', 'أدمن', 'إدمن', 'مدير', 'المدير', 'إدارة', 'ادارة', 'الإدارة',
  'مشرف', 'المشرف', 'دعم', 'الدعم', 'فريق', 'النظام', 'نظام', 'رسمي', 'موثق',
  'حساب', 'مستخدم', 'زائر', 'تجريبي', 'تطبيق', 'موقع',
];

// Critical substrings that must NEVER appear anywhere inside a non-admin username
export const CRITICAL_BANNED_SUBSTRINGS = [
  'admin', 'administrator', 'superadmin', 'moderator', 'sysadmin',
  'support', 'official', 'verified', 'security', 'helpdesk',
];

// Category 2: English Profanity, Slurs & NSFW
export const BANNED_ENGLISH_PROFANITY = [
  'fuck', 'fucker', 'fucking', 'motherfucker', 'fck', 'fuk', 'shit', 'shitty',
  'bullshit', 'bitch', 'bitches', 'ass', 'asshole', 'bastard', 'dick', 'dickhead',
  'cock', 'cocks', 'pussy', 'cunt', 'whore', 'slut', 'skank', 'fag', 'faggot',
  'nigger', 'nigga', 'retard', 'retarded', 'rape', 'rapist', 'pedo', 'pedophile',
  'porn', 'porno', 'xxx', 'sex', 'sexy', 'nsfw', 'nude', 'nudes', 'hentai',
  'boobs', 'tits', 'titties', 'penis', 'vagina', 'dildo', 'orgasm', 'masturbate',
  'blowjob', 'handjob', 'anal', 'cum', 'jizz', 'wank', 'wanker', 'twat', 'prick',
  ' piss', 'pissed', 'damn', 'hell', 'crap', 'suck', 'sucks', 'kill', 'murder',
  'terrorist', 'isis', 'daesh', 'nazi', 'hitler', 'suicide', 'scam', 'scammer',
];

// Category 3: Arabic & Franco-Arab (Arabizi) Profanity
export const BANNED_ARABIC_AND_FRANCO_PROFANITY = [
  // Arabic Script
  'شرموط', 'شرموطة', 'شرموطه', 'قحبة', 'قحبه', 'قحاب', 'عاهرة', 'عاهره', 'زانية',
  'كس', 'كسم', 'كسمك', 'كسمكم', 'زب', 'زبي', 'طيز', 'طيزك', 'نيك', 'منيوك',
  'منيوكة', 'متناك', 'متناكة', 'عرص', 'معرص', 'خول', 'خولات', 'لوطي', 'شاذ',
  'قواد', 'ديوث', 'منحط', 'سافل', 'واطي', 'وسخ', 'زبالة', 'زباله', 'حمار',
  'كلب', 'حيوان', 'خنزير', 'خرا', 'خرة', 'زق', 'يلعن', 'ملعون', 'لعنة',
  'اباحي', 'إباحي', 'سكس', 'بورن', 'عاري', 'عارية', 'انتحار', 'ارهاب', 'إرهاب',
  // Franco-Arab / Arabizi
  'sharmouta', 'sharmota', 'sharmoota', 'charmouta', 'qa7ba', 'qahba', '9a7ba',
  'kahba', 'ksmk', 'kosomak', 'kosomk', 'kossomak', 'kos', 'kuss', 'zob', 'zobi',
  'zeb', 'zebbi', 'teez', 'tiz', 'nayek', 'manyook', 'manyak', 'mnyak', 'metnak',
  '3ars', 'aars', 'khawal', '5awal', 'dayouth', 'gawwad', '9awad', 'khara', '5ara',
  'zag', 'za2', 'kalb', '7mar', 'hmara', 'khanzeer', '5anzeer',
];

// Category 4: Sacred Religious Names & Figures (Anti-Desecration in Public Handles)
export const BANNED_RELIGIOUS_TERMS = [
  'allah', 'prophet', 'muhammad', 'mohammed', 'jesus', 'moses', 'quran', 'islam',
  'الله', 'الرحمن', 'الرحيم', 'الملك', 'القدوس', 'السلام', 'المؤمن', 'المهيمن',
  'العزيز', 'الجبار', 'المتكبر', 'الخالق', 'البارئ', 'المصور', 'الغفار', 'القهار',
  'الوهاب', 'الرزاق', 'الفتاح', 'العليم', 'رب', 'الرب', 'إله', 'اله',
  'محمد', 'أحمد', 'عيسى', 'موسى', 'إبراهيم', 'ابراهيم', 'نوح', 'آدم', 'قرآن', 'القرآن',
  'جبريل', 'ميكائيل', 'إسرافيل',
];

// Category 5: Global Brand Names (Anti-Impersonation / Anti-Phishing)
export const BANNED_BRAND_NAMES = [
  'google', 'youtube', 'apple', 'microsoft', 'windows', 'amazon', 'aws', 'meta',
  'facebook', 'instagram', 'whatsapp', 'threads', 'twitter', 'tiktok', 'snapchat',
  'discord', 'telegram', 'reddit', 'linkedin', 'github', 'gitlab', 'openai',
  'chatgpt', 'anthropic', 'claude', 'stripe', 'paypal', 'visa', 'mastercard',
  'binance', 'coinbase', 'cloudflare', 'vercel', 'netflix', 'spotify', 'playstation',
  'xbox', 'nintendo', 'steam', 'epicgames', 'riotgames',
];

export const ALL_BANNED_WORDS = new Set([
  ...RESERVED_SYSTEM_WORDS,
  ...BANNED_ENGLISH_PROFANITY,
  ...BANNED_ARABIC_AND_FRANCO_PROFANITY,
  ...BANNED_RELIGIOUS_TERMS,
  ...BANNED_BRAND_NAMES,
]);
```

### 4.4 Complete Username & Display Name Validator

```typescript
export class UsernameValidatorService {
  static validate(username: string): { valid: boolean; normalized?: string; error?: string; errorAr?: string } {
    if (!username || typeof username !== 'string') {
      return { valid: false, error: 'Username is required', errorAr: 'اسم المستخدم مطلوب' };
    }

    const clean = username.trim().toLowerCase();

    if (clean.length < 5 || clean.length > 30) {
      return {
        valid: false,
        error: 'Username must be between 5 and 30 characters',
        errorAr: 'اسم المستخدم يجب أن يكون بين 5 و 30 حرفاً',
      };
    }

    if (!/^[a-z]/.test(clean)) {
      return {
        valid: false,
        error: 'Username must start with an English letter',
        errorAr: 'اسم المستخدم يجب أن يبدأ بحرف إنجليزي',
      };
    }

    if (!/^[a-z0-9._]+$/.test(clean)) {
      return {
        valid: false,
        error: 'Username may only contain letters, numbers, dots (.), and underscores (_)',
        errorAr: 'اسم المستخدم يقبل فقط الحروف الإنجليزية، الأرقام، النقطة (.) والشرطة السفلية (_)',
      };
    }

    if (/[._]$/.test(clean) || /(\.\.|__|_\.|\._)/.test(clean)) {
      return {
        valid: false,
        error: 'Username cannot end with or contain consecutive dots/underscores',
        errorAr: 'لا يمكن أن ينتهي اسم المستخدم بنقطة أو شرطة سفلية أو يحتوي على رموز متتالية',
      };
    }

    const letterCount = (clean.match(/[a-z]/g) || []).length;
    if (letterCount < 3) {
      return {
        valid: false,
        error: 'Username must contain at least 3 letters',
        errorAr: 'اسم المستخدم يجب أن يحتوي على 3 حروف على الأقل',
      };
    }

    // 1. Direct & Separator-Stripped Match
    const stripped = clean.replace(/[._]/g, '');
    const deLeeted = normalizeLeetSpeak(clean);

    if (ALL_BANNED_WORDS.has(clean) || ALL_BANNED_WORDS.has(stripped) || ALL_BANNED_WORDS.has(deLeeted)) {
      return {
        valid: false,
        error: 'This username is reserved or not allowed',
        errorAr: 'اسم المستخدم هذا محجوز أو غير مسموح به',
      };
    }

    // 2. Substring Match against Critical Reserved & Profanity Terms
    const substringCheckPool = [
      ...CRITICAL_BANNED_SUBSTRINGS,
      ...BANNED_ENGLISH_PROFANITY.filter((w) => w.length >= 4),
      ...BANNED_ARABIC_AND_FRANCO_PROFANITY.filter((w) => w.length >= 4),
    ];

    for (const banned of substringCheckPool) {
      if (clean.includes(banned) || stripped.includes(banned) || deLeeted.includes(banned)) {
        return {
          valid: false,
          error: 'This username contains restricted words',
          errorAr: 'اسم المستخدم هذا يحتوي على كلمات محظورة أو محجوزة',
        };
      }
    }

    return { valid: true, normalized: clean };
  }
}
```

### 4.5 Dynamic Admin-Managed Profile Substring Bans (`fluxer` Pattern)
For platforms with user profiles (`username`, `global_name`, `bio`, `pronouns`), provide a database-backed `ProfileSubstringBan` table managed from the Admin Panel:
- **Columns:** `id`, `pattern` (case-insensitive substring), `scopes` (`['username', 'global_name', 'bio', 'pronouns']`), `reason` (private audit note), `createdBy`, `createdAt`.
- **Enforcement:** Query cached `ProfileSubstringBan` patterns on registration and profile updates, rejecting any input matching a banned substring for that field's scope.

